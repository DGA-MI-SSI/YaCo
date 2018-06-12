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
get_filename_component(idasdk_dir "$ENV{IDASDK_DIR}" ABSOLUTE)
message("-- Using IDASDK_DIR=${idasdk_dir}")

if("$ENV{IDA_DIR}" STREQUAL "")
    message(FATAL_ERROR "missing IDA_DIR environment variable")
endif()
get_filename_component(ida_dir "$ENV{IDA_DIR}" ABSOLUTE)
message("-- Using IDA_DIR=${ida_dir}")

if(MSVC)
    # disable 'conditional expression is constant'
    set_cx_flags("" "/wd4127" "/wd4127")
    include_directories("${ya_dir}/deps/optional-lite")
endif()

include(${ya_dir}/build/yadeps.cmake)

# IDA works with Python 2.7, which is mandatory to build swig tools
# ask for pythonlibs first or it may not get python x64 libraries
find_package(PythonLibs   2.7 REQUIRED)
find_package(PythonInterp 2.7 REQUIRED)

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
    # yaco library
    COMMAND ${CMAKE_COMMAND} -E copy ${ya_dir}/YaDiff/merge_idb.py ${deploy_dir}
    # ida plugins
    COMMAND ${CMAKE_COMMAND} -E copy ${ya_dir}/YaCo/yaco_plugin.py ${deploy_dir}/../..
    # flatbuffers bindings
    COMMAND ${CMAKE_COMMAND} -E copy_directory "${fb_dir}/python/flatbuffers" "${deploy_dir}/flatbuffers"
    # capstone bindings
    COMMAND ${CMAKE_COMMAND} -E copy_directory "${cap_dir}/bindings/python/capstone" "${deploy_dir}/capstone"
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

# yagit_tests
add_test(NAME yagit_tests_init
    COMMAND ${CMAKE_COMMAND} -E remove_directory "${CMAKE_CURRENT_BINARY_DIR}/temp_folder_unittest"
)
get_files(files "${ya_dir}/YaLibs/tests/YaGitLib_test")
make_target(yagit_tests yatools/tests ${files} OPTIONS test static_runtime)
setup_yatools(yagit_tests)
target_include_directories(yagit_tests PRIVATE "${ya_dir}/YaLibs/tests")
set_property(TEST yagit_tests APPEND PROPERTY DEPENDS yagit_tests_init)
target_link_libraries(yagit_tests PRIVATE
    gtest
    yagit
)

# yadifflib
add_target(yadifflib yatools "${ya_dir}/YaDiff/YaDiffLib" OPTIONS static_runtime recurse)
setup_yatools(yadifflib)
target_include_directories(yadifflib PUBLIC
    "${ya_dir}/YaDiff/YaDiffLib"
)
target_link_libraries(yadifflib PUBLIC
    yatools
    yagit
    capstone
)

# yadifflib_tests
add_target(yadifflib_tests yatools/tests "${ya_dir}/YaDiff/tests/YaDiffLib_test" OPTIONS test recurse static_runtime)
setup_yatools(yadifflib_tests)
target_include_directories(yadifflib_tests PRIVATE "${ya_dir}/YaDiff/tests/" "${ya_dir}/YaLibs/tests")
target_link_libraries(yadifflib_tests PRIVATE
    gtest
    yadifflib
)

# add tool
function(add_tool target dir)
    add_target(${target} yatools/tools "${ya_dir}/${dir}" OPTIONS executable static_runtime)
    setup_yatools(${target})
    target_link_libraries(${target} PRIVATE yatools ${ARGN})
    set_target_output_directory(${target} "")
endfunction()

# yadiff
add_tool(yadiff YaDiff yadifflib)

# yaxml2fb
add_tool(yaxml2fb YaToolsUtils/YaToolsXMLToFB)

# yafb2xml
add_tool(yafb2xml YaToolsUtils/YaToolsFBToXML)

# yacachemerger
add_tool(yacachemerger YaToolsUtils/YaToolsCacheMerger)

# yadbtovector
add_tool(yadbtovector YaToolsUtils/YaToolsYaDBToVectors yadifflib)

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
    deploy_to_bin(_${target} "${CMAKE_CURRENT_BINARY_DIR}/${name}.py" "")
endfunction()

# yatools_py
function(add_yatools_py bits)
    # set constants
    set(xbits_ 64)
    if(bits EQUAL 64)
        set(xbits_ 32)
    endif()
    set(os_)
    if(WIN32)
        set(os_ NT)
    elseif(APPLE)
        set(os_ MAC)
    elseif(UNIX)
        set(os_ LINUX)
    endif()

    # yaida
    get_files(yaida_files "${ya_dir}/YaLibs/YaToolsIDALib")
    make_target(yaida${bits} yatools ${yaida_files} OPTIONS static_runtime)
    setup_yatools(yaida${bits})
    target_include_directories(yaida${bits} PUBLIC "${idasdk_dir}/include" "${CMAKE_CURRENT_BINARY_DIR}/yatools_")
    target_compile_definitions(yaida${bits} PUBLIC __${os_}__ __IDP__ __X64__)
    target_link_libraries(yaida${bits}
        PUBLIC
        yatools
        yagit
        PRIVATE
        zlib
    )
    if(WIN32)
        target_link_libraries(yaida${bits} PRIVATE
            "${idasdk_dir}/lib/x64_win_vc_${bits}/ida.lib"
            "${idasdk_dir}/lib/x64_win_vc_64/pro.lib"
        )
    elseif(APPLE)
        set(libbits)
        if(bits EQUAL 64)
            set(libbits 64)
        endif()
        target_link_libraries(yaida${bits} PRIVATE
            "${idasdk_dir}/lib/x64_mac_gcc_${bits}/libida${libbits}.dylib"
            "${idasdk_dir}/lib/x64_mac_gcc_64/pro.a"
        )
    elseif(UNIX)
        target_link_libraries(yaida${bits} PRIVATE
            "${idasdk_dir}/lib/x64_linux_gcc_64/pro.a"
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
        "${ya_dir}/YaDiff/YaDiffLib"
        "${ya_dir}/YaLibs/YaGitLib"
        "${ya_dir}/YaLibs/YaToolsIDALib"
        "${ya_dir}/YaLibs/YaToolsLib"
        "${ya_dir}/YaLibs/YaToolsPy"
    )
    target_link_libraries(_yatools_py${bits} PRIVATE
        yadifflib
        yagit
        yaida${bits}
    )
endfunction()
add_yatools_py(32)
add_yatools_py(64)

# testdata
function(make_testdata target bin src idaq)
    set(output "${root_dir}/testdata/${target}/database/database.yadb")
    set(no_pdb "--no-pdb")
    if("${target}" STREQUAL "${src}")
        set(no_pdb "")
    endif()
    add_test(NAME "make_testdata_${target}"
        COMMAND ${PYTHON_EXECUTABLE} "${ya_dir}/tests/make_testdata.py"
        ${no_pdb} "${root_dir}/testdata/${target}" "${deploy_dir}" "${root_dir}/tests/${src}/${bin}" "${ida_dir}/${idaq}"
        WORKING_DIRECTORY "${ya_dir}/tests"
    )
endfunction()
make_testdata(qt54_svg        Qt5Svgd.dll qt54_svg ida64)
make_testdata(qt54_svg_no_pdb Qt5Svgd.dll qt54_svg ida64)
make_testdata(cmder           Cmder.exe   cmder    ida64)
make_testdata(vim_0197        vim.basic   vim_0197 ida64)
make_testdata(vim_1453        vim.basic   vim_1453 ida64)

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
set_property(TEST integration_tests APPEND PROPERTY DEPENDS make_testdata_qt54_svg)
set_property(TEST integration_tests APPEND PROPERTY DEPENDS make_testdata_qt54_svg_no_pdb)

# unit_tests
execute_process(COMMAND
    ${PYTHON_EXECUTABLE} "${ya_dir}/tests/runtests.py" --list
    WORKING_DIRECTORY "${ya_dir}/tests"
    OUTPUT_VARIABLE test_names
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(REGEX MATCHALL "[a-zA-Z0-9._]+" test_names ${test_names})
foreach(test ${test_names})
    string(REGEX REPLACE ".+Fixture\." "" shortname ${test})
    message("-- Configuring yatools/tests/${shortname}")
    add_test(NAME ${shortname}
        COMMAND "${PYTHON_EXECUTABLE}" "${ya_dir}/tests/runtests.py" -f${test} -b "${deploy_dir}"
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
    set_property(TEST ${shortname} APPEND PROPERTY DEPENDS make_testdata_qt54_svg_no_pdb)
    set_property(TEST ${shortname} APPEND PROPERTY DEPENDS make_testdata_cmder)
endforeach()

# merge_idb_tests
add_test(NAME merge_idb_tests
    COMMAND ${PYTHON_EXECUTABLE} "${ya_dir}/tests/test_yadiff.py"
    "${deploy_dir}/.."
    "${PYTHON_EXECUTABLE}"
    ${root_dir}/testdata/vim_0197/vim.basic.i64
    ${root_dir}/testdata/vim_1453/vim.basic.i64
)
set_property(TEST merge_idb_tests APPEND PROPERTY ENVIRONMENT "YATOOLS_DIR=${deploy_dir}/..")
set_property(TEST merge_idb_tests APPEND PROPERTY DEPENDS make_testdata_vim_0197)
set_property(TEST merge_idb_tests APPEND PROPERTY DEPENDS make_testdata_vim_1453)
