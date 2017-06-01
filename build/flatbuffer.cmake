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

# flatbuffer directories
get_filename_component(fb_dir "${ya_dir}/deps/flatbuffers-1.4.0" REALPATH)

# flatc
get_files(files "${fb_dir}/src" "${fb_dir}/include" "${fb_dir}/grpc/src/compiler")
filter_out(files
    "flathash[.]cpp"
)
make_target(flatc yatools/deps ${files} OPTIONS external executable static_runtime)
target_include_directories(flatc PRIVATE
    "${fb_dir}/grpc"
    "${fb_dir}/include"
)
if(NOT WIN32)
    set_property(TARGET flatc PROPERTY CXX_STANDARD 11)
endif()

# flatbuffers
filter_in(files
    "idl_parser[.]cpp"
    "idl_gen_text[.]cpp"
    "reflection[.]cpp"
)
make_target(flatbuffers yatools/deps ${files} OPTIONS external static_runtime)
target_include_directories(flatbuffers PUBLIC
    "${fb_dir}/include"
)
if(NOT WIN32)
    set_property(TARGET flatbuffers PROPERTY CXX_STANDARD 11)
endif()

set(FLATBUFFERS_FLATC_EXECUTABLE "$<TARGET_FILE:flatc>")
set(FLATBUFFERS_INCLUDE_DIR      "${fb_dir}/include")
