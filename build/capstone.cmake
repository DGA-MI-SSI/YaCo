# capstone directories
get_filename_component(cap_dir "${root_dir}/deps/capstone-3.0.4" REALPATH)

# capstone
get_files(files "${cap_dir}") # no recursion here
get_files(arch_files "${cap_dir}/arch" OPTIONS recurse)
make_target(capstone yatools/deps ${files} ${arch_files} OPTIONS external static_runtime)

target_include_directories(capstone PUBLIC
    "${cap_dir}"
    "${cap_dir}/include"
)

target_compile_definitions(capstone PRIVATE
    CAPSTONE_DIET_NO
    CAPSTONE_HAS_ARM
    CAPSTONE_HAS_ARM64
    CAPSTONE_HAS_MIPS
    CAPSTONE_HAS_POWERPC
    CAPSTONE_HAS_SPARC
    CAPSTONE_HAS_SYSZ
    CAPSTONE_HAS_X86
    CAPSTONE_HAS_XCORE
    CAPSTONE_USE_SYS_DYN_MEM
    CAPSTONE_X86_ATT_DISABLE_NO
    CAPSTONE_X86_REDUCE_NO
)

set_target_output_directory(capstone "")
