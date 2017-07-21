#   Copyright (C) 2017 YaKaPatcher
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

import sys
import idaapi
import logging
import ctypes
import struct
import binascii
from ctypes.util import find_library

logging.basicConfig()
logger = logging.getLogger("YaCoPatch")
logger.setLevel(logging.DEBUG)

def linux_ida_module_baseaddr(use_64, init_kernel_baseoffset):
    if not use_64:
        # get handle on libida.so
        libida_so = ctypes.cdll.LoadLibrary("libida.so")
    else:
        # get handle on libida64.so
        libida_so = ctypes.cdll.LoadLibrary("libida64.so")
    # get init_kernel address in libida.so
    f_init_kernel = libida_so.init_kernel
    p_init_kernel = ctypes.cast(f_init_kernel, ctypes.c_void_p)
    libida_baseaddr = p_init_kernel.value - init_kernel_baseoffset

    # get libc
    libc_name = find_library("c")
    libc_so = ctypes.cdll.LoadLibrary(libc_name)

    # unprotect page
    libc_so.mprotect(libida_baseaddr, 0x2FA000, 0x7)

    return libida_baseaddr

def windows_ida_module_baseaddr(use_64):
    if use_64:
        libida_baseaddr = ctypes.windll.kernel32.GetModuleHandleA("ida64.wll")  # @UndefinedVariable
    else:
        libida_baseaddr = ctypes.windll.kernel32.GetModuleHandleA("ida.wll")  # @UndefinedVariable
    if libida_baseaddr == 0:
        raise Exception("Unable to get ida(64).wll module handle.")

    # unprotect lib
    old = ctypes.c_uint32()
    if ctypes.windll.kernel32.VirtualProtect(libida_baseaddr, 0x198000, 0x40, ctypes.byref(old)) != 1:  # PAGE_EXECUTE_READWRITE @UndefinedVariable
        logger.debug("Unable to unprotect module.")
        raise Exception("Unable to unprotect module.")

    return libida_baseaddr

def patch_ida_module():
    logger.debug("Patching IDA module...")

    # check 32/64 bit
    if idaapi.BADADDR == 0xffffffff:
        use_64 = False
    else:
        use_64 = True

    if sys.platform == "linux2":
        build_hook_fn = build_hook_linux
    elif sys.platform == "win32":
        build_hook_fn = build_hook_windows
        libida_baseaddr = windows_ida_module_baseaddr(use_64)
    else:
        raise Exception("Unhandled platform")

    events_offset = []

    if idaapi.IDA_SDK_VERSION == 695:
        """
        IDA 695
        """
        import YaCoPatch_695
        if sys.platform == "linux2":
            # linux
            if not use_64:
                init_kernel_baseoffset = 0x00030400
            else:
                init_kernel_baseoffset = 0x00031720
            libida_baseaddr = linux_ida_module_baseaddr(use_64, init_kernel_baseoffset)

            if not use_64:
                # linux 32
                hooks_offsets = YaCoPatch_695.ida_695_linux_32_hooks_offsets(libida_baseaddr)

            else:
                # linux 64
                hooks_offsets = YaCoPatch_695.ida_695_linux_64_hooks_offsets(libida_baseaddr)

        elif sys.platform == "win32":

            # windows
            if not use_64:
                # windows 32
                hooks_offsets = YaCoPatch_695.ida_695_windows_32_hooks_offsets(libida_baseaddr)

            else:
                # windows 64
                hooks_offsets = YaCoPatch_695.ida_695_windows_64_hooks_offsets(libida_baseaddr)

    elif idaapi.IDA_SDK_VERSION == 680:
        """
        IDA 680
        """
        import YaCoPatch_680
        if sys.platform == "win32":
            # windows
            if not use_64:
                hooks_offsets = YaCoPatch_680.ida_680_windows_32_hooks_offsets(libida_baseaddr)
                events_offset = [0x6e58f, 0x6e63e]

            else:
                hooks_offsets = YaCoPatch_680.ida_680_windows_64_hooks_offsets(libida_baseaddr)
                events_offset = [0x76cfa, 0x76d33]
        else:
            raise Exception("Unhandled platform")

    else:
        logger.error("Unhandled IDA version, use IDA 6.8 or IDA 6.95")
        return

    for event_offset in events_offset:
        # PATCHING AREA (EXTRA) COMMENT EVENT (update and delete) (ie pre/post comments)
        b = (ctypes.c_char * 1).from_address(libida_baseaddr + event_offset)
        if b[0] == '\x3b':
            b[0] = '\x01'
            logger.debug("IDA DLL area comment patched")
        elif b[0] == '\x01':
            logger.debug("IDA DLL already patched !")
            return
        else:
            logger.error("IDA DLL mismatch !")
            raise Exception("IDA DLL mismatch !")

    # PATCHING REGVAR EVENT
    try:
        build_hook_fn(hooks_offsets['regvar_hook_addr'], hooks_offsets['regvar_hook_return_addr'], hooks_offsets['regvar_handler_bytes'])
        logger.debug("IDA Module regvar patched")
    except KeyError:
        logger.debug("Unable to patch IDA Module regvar")

    # PATCHING REGVAR RENAME EVENT
    try:
        build_hook_fn(hooks_offsets['rename_hook_addr'], hooks_offsets['rename_hook_return_addr'], hooks_offsets['rename_handler_bytes'])
        logger.debug("IDA Module regvar rename patched")
    except KeyError:
        logger.debug("Unable to patch IDA Module regvar rename")

    # PATCHING TOGGLE SIGN EVENT
    try:
        build_hook_fn(hooks_offsets['toogle_hook_addr'], hooks_offsets['toogle_hook_return_addr'], hooks_offsets['toggle_sign_handler_bytes'])
        logger.debug("IDA Module toggle sign patched")
    except KeyError:
        logger.debug("Unable to patch IDA Module toggle sign")

    # PATCHING MARK COMMENT EVENT AND DELETE MARK
    try:
        build_hook_fn(hooks_offsets['mark_comment_hook_addr'], hooks_offsets['mark_comment_hook_return_addr'], hooks_offsets['mark_comment_handler_bytes'])
        logger.debug("IDA Module mark comments patched")
    except KeyError:
        logger.debug("Unable to patch IDA Module mark comments")

    # PATCHING AREA COMMENT EVENT
    try:
        build_hook_fn(hooks_offsets['add_hidden_area_hook_addr'], hooks_offsets['add_hidden_area_hook_return_addr'], hooks_offsets['add_hidden_area_handler_bytes'])
        logger.debug("IDA Module area comments patched")
    except KeyError:
        logger.debug("Unable to patch IDA Module area comments")

    # PATCHING FUNCTION FLAGS EVENT
    try:
        build_hook_fn(hooks_offsets['function_flags_hook_addr'], hooks_offsets['function_flags_hook_return_addr'], hooks_offsets['function_flags_handler_bytes'])
        logger.debug("IDA Module function flags patched")
    except KeyError:
        logger.debug("Unable to patch IDA Module function flags")

    # PATCHING ENUM WIDTH EVENT
    try:
        build_hook_fn(hooks_offsets['enum_width_hook_addr'], hooks_offsets['enum_width_hook_return_addr'], hooks_offsets['enum_width_handler_bytes'])
        logger.debug("IDA Module enum width patched")
    except KeyError:
        logger.debug("Unable to patch IDA Module enum width")

    logger.debug("IDA Module patched")

def pack_address(address):
    return struct.pack("I", address)

def build_trampoline(handler_address):
    """
    push @handler
    ret
    """
    # push handler address
    trampoline = '\x68'  # push
    trampoline += pack_address(handler_address)

    # ret
    trampoline += '\xc3'

    return trampoline

def build_hook_windows(hook_addr, hook_return_addr, handler_bytes):
    # RETURN
    handler_return_bytes = build_trampoline(hook_return_addr)
    original_code_size = hook_return_addr - hook_addr
    handler_size = len(handler_bytes) + original_code_size + len(handler_return_bytes)

    # -- allocate handler
    handler_addr = ctypes.windll.kernel32.VirtualAlloc(
        None, handler_size, 0x1000, 0x40)  # MEM_COMMIT / EXECUTE_READ_WRITE  # @UndefinedVariable
    if handler_addr == None:
        raise Exception("Unable to VirtualAllocEx to build hook !")

    # -- write handler
    b = (ctypes.c_char * handler_size).from_address(handler_addr)
    i = 0
    for byte in handler_bytes:
        b[i] = byte
        i += 1

    # -- write original code
    original_code_size = hook_return_addr - hook_addr
    original_code_bytes = (ctypes.c_char * original_code_size).from_address(hook_addr)

    for j in xrange(0, original_code_size):
        b[i] = original_code_bytes[j]
        i += 1

    # -- write return
    for byte in handler_return_bytes:
        b[i] = byte
        i += 1

    # write hook
    # HOOK
    hook_bytes = build_trampoline(handler_addr)

    old = ctypes.c_uint32()
    if ctypes.windll.kernel32.VirtualProtect(hook_addr, len(hook_bytes), 0x40, ctypes.byref(old)) != 1:  # @UndefinedVariable
        raise Exception("Unable to unprotect module.")
    b = (ctypes.c_char * len(hook_bytes)).from_address(hook_addr)
    i = 0
    for byte in hook_bytes:
        b[i] = byte
        i += 1

def build_hook_linux(hook_addr, hook_return_addr, handler_bytes):
    # RETURN
    handler_return_bytes = build_trampoline(hook_return_addr)
    original_code_size = hook_return_addr - hook_addr
    handler_size = len(handler_bytes) + original_code_size + len(handler_return_bytes)

    # -- allocate handler
    # get libc
    libc_name = find_library("c")
    libc_so = ctypes.cdll.LoadLibrary(libc_name)
    handler_addr = libc_so.valloc(handler_size)  # @UndefinedVariable
    if handler_addr == 0:
        raise Exception("Unable to malloc to build hook !")
    if libc_so.mprotect(handler_addr, handler_size, 0x7) != 0:  # PROT_READ / PROT_WRITE / PROT_EXEC
        raise Exception("Unable to unprotect buffer !")

    # -- write handler
    b = (ctypes.c_char * handler_size).from_address(handler_addr)
    i = 0
    for byte in handler_bytes:
        b[i] = byte
        i += 1

    # -- write original code
    original_code_size = hook_return_addr - hook_addr
    original_code_bytes = (ctypes.c_char * original_code_size).from_address(hook_addr)

    for j in xrange(0, original_code_size):
        b[i] = original_code_bytes[j]
        i += 1

    # -- write return
    for byte in handler_return_bytes:
        b[i] = byte
        i += 1

    # write hook
    # HOOK
    hook_bytes = build_trampoline(handler_addr)

    b = (ctypes.c_char * len(hook_bytes)).from_address(hook_addr)
    i = 0
    for byte in hook_bytes:
        b[i] = byte
        i += 1

