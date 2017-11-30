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

# yatools dependencies
get_filename_component(async_dir    "${ya_dir}/deps/async-0.6.1"    REALPATH)
get_filename_component(farm_dir     "${ya_dir}/deps/farmhash-1.1"   REALPATH)
get_filename_component(git_dir      "${ya_dir}/deps/libgit2-0.26.0" REALPATH)
get_filename_component(gtest_dir    "${ya_dir}/deps/gtest-1.7.0"    REALPATH)
get_filename_component(ico_dir      "${ya_dir}/deps/libiconv-1.14"  REALPATH)
get_filename_component(mbed_dir     "${ya_dir}/deps/mbedtls-2.4.2"  REALPATH)
get_filename_component(pympler_dir  "${ya_dir}/deps/pympler"        REALPATH)
get_filename_component(ssh2_dir     "${ya_dir}/deps/libssh2-1.8.0"  REALPATH)
get_filename_component(swig_dir     "${ya_dir}/deps/swig-3.0.7"     REALPATH)
get_filename_component(xml_dir      "${ya_dir}/deps/libxml2-2.7.8"  REALPATH)

if(WIN32)
    # force add winsock2 & crypt32
    set(CMAKE_REQUIRED_LIBRARIES ws2_32 crypt32)
    # check for snprintf
    check_symbol_exists(snprintf stdio.h HAVE_SNPRINTF)
    # select need winsock2.h
    check_symbol_exists(select winsock2.h HAVE_SELECT)
    # check for crypt32
    check_symbol_exists(CryptDecodeObjectEx "windows.h;wincrypt.h" HAVE_LIBCRYPT32)
endif()

# charset
get_filename_component(ch_dir  "${ico_dir}/libcharset" REALPATH)
get_files(files ${ch_dir}/lib ${ch_dir}/include)
autoconfigure(files includes libcharset "${ch_dir}/config.h.in"
    "\n#define HAVE_WORKING_O_NOFOLLOW 0"
)
set(out_dir ${CMAKE_CURRENT_BINARY_DIR}/libcharset_)
configure_file("${ch_dir}/include/localcharset.h.in" "${out_dir}/include/localcharset.h" COPYONLY)
make_target(charset yatools/deps ${files} OPTIONS external static_runtime)
target_include_directories(charset
    PUBLIC
    ${ch_dir}/include
    ${out_dir}/include
    PRIVATE
    ${includes}
)
target_compile_definitions(charset PRIVATE LIBDIR) # fix compilation...
if(WIN32)
    target_compile_definitions(charset PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# iconv
get_files(files ${ico_dir} ${ico_dir}/lib ${ico_dir}/srclib ${ico_dir}/include)
# set config.h.in variables
set(DLL_VARIABLE)
set(USE_MBSTATE_T 0)
set(BROKEN_WCHAR_H 0)
set(ICONV_CONST const)
autoconfigure(files includes iconv "${ico_dir}/config.h.in"
    "\n#define EILSEQ      64"
    "\n#define ICONV_CONST const"
)
if(HAVE_WCRTOMB OR HAVE_MBRTOWC)
    set(USE_MBSTATE_T 1)
endif()
set(out_dir ${CMAKE_CURRENT_BINARY_DIR}/iconv_)
# configure remaining headers
cfg_file(files "${out_dir}/config.h.in" "${out_dir}/config.h")
cfg_file(files "${ico_dir}/include/iconv.h.in" "${out_dir}/include/iconv.h")
cfg_file(files "${ico_dir}/srclib/alloca.in.h" "${out_dir}/alloca.h")
filter_out(files
    "areadlink[.]c$"
    "canonicalize-lgpl[.]c$"
    "careadlinkat[.]c$"
    "error[.]c$"
    "genaliases[.]c$"
    "genaliases2[.]c$"
    "genflags[.]c$"
    "gentranslit[.]c$"
    "memmove[.]c$"
    "progreloc[.]c$"
    "read[.]c$"
    "readlink[.]c$"
    "relocwrapper[.]c$"
    "safe-read[.]c$"
    "sigprocmask[.]c$"
    "stat[.]c$"
    "strerror-override[.]c$"
)
make_target(iconv yatools/deps ${files} OPTIONS external static_runtime)
target_include_directories(iconv
    PUBLIC
    "${ico_dir}/include"
    "${out_dir}/include"
    PRIVATE
    "${includes}"
    "${ico_dir}/srclib"
)
target_link_libraries(iconv PUBLIC charset)
if(WIN32)
    target_compile_definitions(iconv PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# libxml2
get_files(files ${xml_dir})
get_files(includes ${xml_dir}/include OPTIONS recurse)
autoconfigure(files includes libxml2 "${xml_dir}/config.h.in"
    "\n#define ICONV_CONST const"
    "\n#define HAVE_VA_COPY 1"
    "\n#undef  HAVE_ZLIB_H"
    "\n#if defined(WIN32) && defined(NEED_SOCKETS)"
    "\n#include <wsockcompat.h>"
    "\n#endif"
)
filter_out(files
    "runsuite[.]c$"
    "runtest[.]c$"
    "runxmlconf[.]c$"
    "test.+[.]c$"
    "trio[.]c$"
    "xmlcatalog[.]c$"
    "xmllint[.]c$"
)
make_target(libxml2 yatools/deps ${files} OPTIONS external static_runtime)
target_include_directories(libxml2
    PUBLIC
    "${xml_dir}/include"
    PRIVATE
    "${includes}"
)
target_link_libraries(libxml2 PUBLIC
    iconv
)
if(WIN32)
    target_compile_definitions(libxml2
        PUBLIC
        LIBXML_STATIC
        PRIVATE
        _CRT_SECURE_NO_WARNINGS
    )
endif()

# regex
set(regex_dir "${git_dir}/deps/regex")
get_files(files ${regex_dir})
filter_out(files
    "regcomp[.]c"
    "regexec[.]c"
    "regex_internal[.]c"
)
make_target(regex yatools/deps ${files} OPTIONS external static_runtime)
target_include_directories(regex PUBLIC ${regex_dir})

# zlib
set(zlib_dir "${git_dir}/deps/zlib")
add_target(zlib yatools/deps ${zlib_dir} OPTIONS external static_runtime)
target_include_directories(zlib PUBLIC ${zlib_dir})
target_include_directories(zlib PUBLIC "${git_dir}/include")
target_compile_definitions(zlib PRIVATE STDC)
target_link_libraries(zlib PUBLIC regex)

# http_parser
set(htp_dir "${git_dir}/deps/http-parser")
add_target(http_parser yatools/deps ${htp_dir} OPTIONS external static_runtime)
target_include_directories(http_parser PUBLIC "${htp_dir}")

# mbedtls
add_target(mbedtls yatools/deps "${mbed_dir}/library" "${mbed_dir}/include" OPTIONS external static_runtime)
target_include_directories(mbedtls PUBLIC "${mbed_dir}/include")

# ssh2
get_files(files "${ssh2_dir}/src" "${ssh2_dir}/include" OPTIONS recurse)
include("${ssh2_dir}/cmake/CheckNonblockingSocketSupport.cmake")
check_nonblocking_socket_support()
autoconfigure(files includes ssh2 "${ssh2_dir}/src/libssh2_config_cmake.h.in")
make_target(ssh2 yatools/deps ${files} OPTIONS external static_runtime)
target_compile_definitions(ssh2 PRIVATE
    LIBSSH2_DH_GEX_NEW=1    # new diffie-hellman syntax
    LIBSSH2_HAVE_ZLIB       # enable zlib compression
    LIBSSH2_MBEDTLS         # select mbedtls crypto backend
)
target_include_directories(ssh2 PUBLIC
    "${ssh2_dir}/include"
    PRIVATE
    "${includes}"
)
if(WIN32)
    if(HAVE_INTTYPES_H)
        target_compile_definitions(ssh2 PRIVATE
            _MSC_INTTYPES_H_ # prevent conflict with git2/inttypes.h
        )
    endif()
    target_link_libraries(ssh2 PUBLIC
        user32
        ws2_32
    )
endif()
target_link_libraries(ssh2 PUBLIC
    mbedtls
    zlib
)

# git2 nsec option
function(setup_git2_mtime target)
    include(CheckStructHasMember)

    check_struct_has_member("struct stat" st_mtim      "sys/types.h;sys/stat.h" HAVE_STRUCT_STAT_ST_MTIM LANGUAGE C)
    check_struct_has_member("struct stat" st_mtimespec "sys/types.h;sys/stat.h" HAVE_STRUCT_STAT_ST_MTIMESPEC LANGUAGE C)
    check_struct_has_member("struct stat" st_mtime_nsec sys/stat.h              HAVE_STRUCT_STAT_MTIME_NSEC LANGUAGE C)

    if(HAVE_STRUCT_STAT_ST_MTIM)
        check_struct_has_member("struct stat" st_mtim.tv_nsec sys/stat.h HAVE_STRUCT_STAT_NSEC LANGUAGE C)
    elseif(HAVE_STRUCT_STAT_ST_MTIMESPEC)
        check_struct_has_member("struct stat" st_mtimespec.tv_nsec sys/stat.h HAVE_STRUCT_STAT_NSEC LANGUAGE C)
    else()
        set(HAVE_STRUCT_STAT_NSEC true)
    endif()

    if(HAVE_STRUCT_STAT_NSEC OR WIN32)
        target_compile_definitions(${target} PRIVATE GIT_USE_NSEC)
    endif()

    if(HAVE_STRUCT_STAT_ST_MTIM)
        target_compile_definitions(${target} PRIVATE GIT_USE_STAT_MTIM)
    elseif(HAVE_STRUCT_STAT_ST_MTIMESPEC)
        target_compile_definitions(${target} PRIVATE GIT_USE_STAT_MTIMESPEC)
    elseif(HAVE_STRUCT_STAT_ST_MTIME_NSEC)
        target_compile_definitions(${target} PRIVATE GIT_USE_STAT_MTIME_NSEC)
    endif()
endfunction()

# git2
find_package(Threads)
get_files(files "${git_dir}/src" "${git_dir}/include" OPTIONS recurse)
filter_out(files "precompiled[.]c")
if(WIN32)
    filter_out(files
        "${re_sep}unix${re_sep}"
        "hash${re_sep}hash_generic[.]"
    )
else()
    filter_out(files "win32")
endif()
make_target(git2 yatools/deps ${files} OPTIONS external static_runtime)
target_include_directories(git2 PUBLIC
    "${git_dir}/src"
    "${git_dir}/include"
)
target_compile_definitions(git2 PRIVATE
    GIT_SSH
    GIT_THREADS
    GIT_USE_ICONV
)
setup_git2_mtime(git2)
target_link_libraries(git2 PUBLIC
    http_parser
    iconv
    ssh2
    ${CMAKE_THREAD_LIBS_INIT}
)
if(WIN32)
    target_compile_definitions(git2 PRIVATE GIT_SHA1_WIN32 GIT_WIN32)
    target_link_libraries(git2 PUBLIC advapi32)
endif()

# flatbuffer
include(flatbuffer.cmake)

# gtest
get_files(files "${gtest_dir}/src" "${gtest_dir}/include")
filter_out(files "${re_sep}gtest-all[.]cc$")
make_target(gtest yatools/deps ${files} OPTIONS external static_runtime)
target_include_directories(gtest PUBLIC "${gtest_dir}/include")
target_include_directories(gtest PRIVATE ${gtest_dir})
if(NOT WIN32)
    find_package(Threads)
    target_link_libraries(gtest PUBLIC Threads::Threads)
endif()

# swig
# annoying autoconfigure stuff
get_filename_component(tmp_dir "${CMAKE_CURRENT_BINARY_DIR}/swig_" REALPATH)
configure_file("${swig_dir}/Source/Include/swigwarn.h" "${tmp_dir}/swigwarn.h")
file(WRITE "${tmp_dir}/swigconfig.h.in" "
#include <stdbool.h>
#define HAVE_BOOL

#define PACKAGE_BUGREPORT   \"nobody\"
#define PACKAGE_VERSION     \"3.0.7\"
#define SWIG_CXX            \"${CMAKE_CXX_COMPILER_ID}\"
#define SWIG_LIB            \"\"
#define SWIG_LIB_WIN_UNIX   \"\"
#define SWIG_PLATFORM       \"${CMAKE_CXX_PLATFORM_ID}\"
")
set(swig_dirs
    ${tmp_dir}
    "${swig_dir}/Source/CParse"
    "${swig_dir}/Source/DOH"
    "${swig_dir}/Source/Modules"
    "${swig_dir}/Source/Preprocessor"
    "${swig_dir}/Source/Swig"
)
set(PACKAGE_VERSION "3.0.7")
add_target(swig yatools/deps ${swig_dirs} OPTIONS external configure executable static_runtime)
target_include_directories(swig PRIVATE ${swig_dirs})
if(WIN32)
    target_compile_definitions(swig PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

set(SWIG_EXECUTABLE "$<TARGET_FILE:swig>")
set(SWIG_DIR "${swig_dir}/Lib")
file(GLOB_RECURSE swig_cmake "${CMAKE_ROOT}/*/UseSWIG.cmake")
include(${swig_cmake})

# farmhash
get_files(files "${farm_dir}/src")
filter_out(files "-test[.]cc$")
make_target(farmhash yatools/deps ${files} OPTIONS external static_runtime)
target_include_directories(farmhash PUBLIC "${farm_dir}/src")
if(WIN32)
    target_compile_definitions(farmhash PRIVATE FARMHASH_NO_BUILTIN_EXPECT)
endif()
