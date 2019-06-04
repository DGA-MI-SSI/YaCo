cmake_minimum_required(VERSION 3.1.0)
project(yatools)

enable_testing()

include(common.cmake)

if(NOT "${ARCH}" STREQUAL "x64")
  message(FATAL_ERROR "Unsupported arch ${ARCH}: support only x64")
endif()

get_filename_component(root_dir     ${CMAKE_CURRENT_SOURCE_DIR}/..  ABSOLUTE)
get_filename_component(bin_d_dir    ${root_dir}/bin/yaco_d_${ARCH}  ABSOLUTE)
get_filename_component(bin_dir      ${root_dir}/bin/yaco_${ARCH}    ABSOLUTE)

set(ya_dir ${root_dir})
include(yatools.cmake)

# bundle
add_custom_target(bundle
    COMMAND ${PYTHON_EXECUTABLE} ${root_dir}/build/package.py
    "${bin_dir}/../.." "${root_dir}/bin" ${OS}_${ARCH} --git "${GIT_EXECUTABLE}"
    WORKING_DIRECTORY "${root_dir}"
)
set_target_properties(bundle PROPERTIES FOLDER _cmake)
exclude_target(bundle)
