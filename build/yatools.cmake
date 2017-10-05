#   Copyright (C) 2017 The YaCo Authors
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

set(bin_dir     ${bin_dir}/YaTools/bin)
set(bin_d_dir   ${bin_d_dir}/YaTools/bin)

if("$ENV{IDASDK_DIR}" STREQUAL "")
    message(FATAL_ERROR "missing IDASDK_DIR environment variable")
endif()
get_filename_component(idasdk_dir "$ENV{IDASDK_DIR}" REALPATH)
message("-- Using IDASDK_DIR=${idasdk_dir}")

if("$ENV{IDA_DIR}" STREQUAL "")
    message(FATAL_ERROR "missing IDA_DIR environment variable")
endif()
get_filename_component(ida_dir "$ENV{IDA_DIR}" REALPATH)
message("-- Using IDA_DIR=${ida_dir}")

if(MSVC)
    # disable 'conditional expression is constant'
    set_cx_flags("" "/wd4127" "/wd4127")
    include_directories("${ya_dir}/deps/optional-lite")
endif()

include(${ya_dir}/build/yadeps.cmake)

# IDA works with Python 2.7, which is mandatory to build swig tools
find_package(PythonLibs 2.7 REQUIRED)

# yatools helpers
function(setup_yatools target)
    if(WIN32)
        target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS)
    else()
        set_property(TARGET ${target} PROPERTY CXX_STANDARD 14)
        target_link_libraries(${target} PUBLIC stdc++fs)
    endif()
endfunction()

function(make_deploy_dir dir dst src)
    file(MAKE_DIRECTORY ${dir})
    if(WIN32)
        file(TO_NATIVE_PATH "${dir}/${dst}" dst_)
        file(TO_NATIVE_PATH "${src}" src_)
        execute_process(COMMAND cmd /c mklink /J /D "${dst_}" "${src_}" 2>NUL)
    else()
        execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${src} ${dir}/${dst})
    endif()
endfunction()

# yatools
get_files(files "${ya_dir}/YaLibs/YaToolsLib" OPTIONS recurse)
get_files(files2 "${ya_dir}/YaLibs")
set(yatools_files ${files} ${files2})
make_target(yatools yatools ${files} ${files2} OPTIONS flatbuffers git_version recurse static_runtime)
setup_yatools(yatools)
target_include_directories(yatools PUBLIC
    "${ya_dir}/YaLibs/YaToolsLib"
)
target_link_libraries(yatools PUBLIC
    farmhash
    flatbuffers
    libxml2
)

# export yatools dependencies
set(deploy_dir $<$<CONFIG:Debug>:${bin_d_dir}>$<$<CONFIG:RelWithDebInfo>:${bin_dir}>$<$<CONFIG:Release>:${bin_dir}>)
make_deploy_dir(${bin_d_dir}/.. YaCo ${ya_dir}/YaCo)
make_deploy_dir(${bin_dir}/.. YaCo ${ya_dir}/YaCo)
add_custom_command(TARGET yatools POST_BUILD
    # make sure deploy_dir exists
    COMMAND ${CMAKE_COMMAND} -E make_directory ${deploy_dir}
    # python dependencies
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${async_dir}   ${deploy_dir}/async
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${pympler_dir} ${deploy_dir}/pympler
    # ida plugins
    COMMAND ${CMAKE_COMMAND} -E copy ${ya_dir}/YaCo/yaco_plugin.py     ${deploy_dir}/../..
    # flatbuffers bindings
    COMMAND ${CMAKE_COMMAND} -E copy_directory "${fb_dir}/python/flatbuffers" "${deploy_dir}/flatbuffers"
    # generated yadb bindings
    COMMAND ${CMAKE_COMMAND} -E copy_directory "${CMAKE_CURRENT_BINARY_DIR}/yadb" "${deploy_dir}/yadb"
)

# yatools tests
add_target(yatools_tests yatools/tests "${ya_dir}/YaLibs/tests/YaToolsLib_test" OPTIONS test recurse static_runtime)
setup_yatools(yatools_tests)
target_include_directories(yatools_tests PRIVATE
    "${ya_dir}/YaLibs/tests"
)
target_link_libraries(yatools_tests PRIVATE
    gtest
    yatools
)

# yagit
get_files(files "${ya_dir}/YaLibs/YaGitLib")
filter_out(files "test[.]")
make_target(yagit yatools ${files} OPTIONS static_runtime)
setup_yatools(yagit)
target_include_directories(yagit PUBLIC "${ya_dir}/YaLibs/YaGitLib")
target_link_libraries(yagit PUBLIC git2 ssh2)

# yagit tests
add_custom_command(OUTPUT cleanup.rule
    COMMAND ${CMAKE_COMMAND} -E remove_directory "${CMAKE_CURRENT_BINARY_DIR}/temp_folder_unittest"
    COMMENT "cleaning up temp directory"
)
set_source_files_properties(cleanup.rule PROPERTIES SYMBOLIC true)
source_group(cmake FILES cleanup.rule)
get_files(files "${ya_dir}/YaLibs/tests/YaGitLib_test")
make_target(yagit_tests yatools/tests ${files} cleanup.rule OPTIONS test static_runtime)
setup_yatools(yagit_tests)
target_include_directories(yagit_tests PRIVATE "${ya_dir}/YaLibs/tests")
target_link_libraries(yagit_tests PRIVATE
    gtest
    yagit
)

# add tool
function(add_tool target dir)
    add_target(${target} yatools/tools "${ya_dir}/${dir}" OPTIONS executable static_runtime)
    setup_yatools(${target})
    target_link_libraries(${target} PRIVATE yatools ${ARGN})
    set_target_output_directory(${target} "")
endfunction()

# yaxml2fb
add_tool(yaxml2fb YaToolsUtils/YaToolsXMLToFB)

# yafb2xml
add_tool(yafb2xml YaToolsUtils/YaToolsFBToXML)

# yacachemerger
add_tool(yacachemerger YaToolsUtils/YaToolsCacheMerger)

# yadbdbmerger
add_tool(yadbdbmerger YaToolsUtils/YaToolsYADBDBMerger)

# depres
add_tool(depres YaToolsUtils/depres)

# swig modules
function(add_swig_mod target name)
    add_swig_module(${target} yatools/swig ${ARGN})
    target_include_directories(_${target} PRIVATE ${PYTHON_INCLUDE_DIRS})
    if(MSVC)
        # ida does not install debug python libraries
        # so we need to target release libraries
        target_compile_definitions(_${target} PRIVATE SWIG_PYTHON_INTERPRETER_NO_DEBUG)
        target_link_libraries(_${target} PRIVATE ${PYTHON_LIBRARY_RELEASE})
    else()
        target_link_libraries(_${target} PRIVATE ${PYTHON_LIBRARIES})
    endif()
    if(WIN32)
        # avoid warning on round
        target_compile_definitions(_${target} PRIVATE HAVE_ROUND)
        setup_target(_${target} warnings static_runtime)
    else()
        set_property(TARGET _${target} PROPERTY CXX_STANDARD 11)
    endif()
    set_target_output_name(_${target} _${name} _${name})
    set_target_output_directory(_${target} "")
    set_target_properties(_${target} PROPERTIES INSTALL_RPATH "$ORIGIN/")
    deploy_to_bin(_${target} "${CMAKE_CURRENT_BINARY_DIR}/${name}.py" "")
endfunction()

# yatools_py
function(add_yatools_py bits)
    # set constants
    set(os_ LINUX)
    set(xbits_ 64)
    if(bits EQUAL 64)
        set(xbits_ 32)
    endif()
    if(WIN32)
        set(os_ NT)
    endif()

    # yaida
    get_files(yaida_files "${ya_dir}/YaLibs/YaToolsIDALib")
    make_target(yaida${bits} yatools ${yaida_files} OPTIONS static_runtime)
    setup_yatools(yaida${bits})
    target_include_directories(yaida${bits} PUBLIC "${idasdk_dir}/include")
    target_compile_definitions(yaida${bits} PUBLIC __${os_}__ __IDP__ __X64__)
    target_link_libraries(yaida${bits}
        PUBLIC
        yatools
        PRIVATE
        zlib
    )
    if(WIN32)
        target_link_libraries(yaida${bits} PRIVATE
            "${idasdk_dir}/lib/x64_win_vc_${bits}/ida.lib"
            "${idasdk_dir}/lib/x64_win_vc_64/pro.lib"
        )
    endif()
    if(bits EQUAL 64)
        target_compile_definitions(yaida${bits} PUBLIC __EA64__)
    endif()

    # yaida swig
    get_files(files "${ya_dir}/YaLibs/YaToolsPy")
    filter_out(files "YaToolsPy${xbits_}.i")
    set(yaswig_deps ${yatools_files} ${yaida_files} ${files})
    filter_in(yaswig_deps "[.]h$" "[.]hpp$")
    add_swig_mod(yatools_py${bits} YaToolsPy${bits} ${files} DEPS ${yaswig_deps} INCLUDES
        "${CMAKE_CURRENT_BINARY_DIR}/yatools_"
        "${ya_dir}/YaLibs/YaGitLib"
        "${ya_dir}/YaLibs/YaToolsIDALib"
        "${ya_dir}/YaLibs/YaToolsLib"
        "${ya_dir}/YaLibs/YaToolsPy"
    )
    target_link_libraries(_yatools_py${bits} PRIVATE
        yagit
        yaida${bits}
    )
endfunction()
add_yatools_py(32)
add_yatools_py(64)

# testdata
find_package(PythonInterp)
function(make_testdata dst dir dll idaq)
    set(dst_ ${${dst}})
    set(output "${root_dir}/testdata/${dir}/database/database.yadb")
    list(APPEND dst_ ${output})
    add_test(NAME "make_${dir}_testdata"
        COMMAND ${PYTHON_EXECUTABLE} "${ya_dir}/tests/make_testdata.py"
        "${root_dir}" "${deploy_dir}" "${dir}/${dll}" "${ida_dir}/${idaq}"
        WORKING_DIRECTORY "${ya_dir}/tests"
    )
    set(${dst} ${dst_} PARENT_SCOPE)
endfunction()
set(testdata_outputs)
make_testdata(testdata_outputs "qt54_svg" "Qt5Svgd.dll" "ida64")
make_testdata(testdata_outputs "qt57_svg" "Qt5Svgd.dll" "ida")

# integration_tests
add_target(integration_tests yatools/tests "${ya_dir}/YaLibs/tests/integration" OPTIONS test static_runtime)
setup_yatools(integration_tests)
target_include_directories(integration_tests PRIVATE
    "${ya_dir}/YaLibs/tests"
)
target_link_libraries(integration_tests PRIVATE
    gtest
    yatools
)
set_property(TEST integration_tests APPEND PROPERTY DEPENDS make_qt54_svg_testdata)
set_property(TEST integration_tests APPEND PROPERTY DEPENDS make_qt57_svg_testdata)

# yaco_tests
function(make_yaco_test bitness idaq)
    set(suffix ${bitness}_tests)
    add_test(NAME yaco${suffix}
        COMMAND ${PYTHON_EXECUTABLE} ${ya_dir}/tests/run_tests.py
        ${deploy_dir} ya ${CMAKE_CURRENT_BINARY_DIR} ${idaq}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
    add_test(NAME svg${suffix}
        COMMAND ${PYTHON_EXECUTABLE} ${ya_dir}/tests/run_tests.py
        ${deploy_dir} svg ${CMAKE_CURRENT_BINARY_DIR} ${idaq}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
endfunction()
make_yaco_test(32 "ida64")
make_yaco_test(64 "ida")
