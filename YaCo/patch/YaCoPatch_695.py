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

import YaCoPatch

#
# IDA 695
#
# linux
def ida_695_linux_32_hooks_offsets(libida_baseaddr):
    hooks_offsets = {}

    send_event_offset = 0x976e0
    hooks_offsets['send_event_addr'] = libida_baseaddr + send_event_offset

    regvar_hook_offset = 0x171782
    hooks_offsets['regvar_hook_addr']= libida_baseaddr + regvar_hook_offset
    hooks_offsets['regvar_hook_return_addr'] = hooks_offsets['regvar_hook_addr']+ 0x8

    hooks_offsets['regvar_handler_bytes'] = build_regvar_handler_linux_32(hooks_offsets['send_event_addr'])

    rename_regvar_hook_offset = 0x17111e
    hooks_offsets['rename_hook_addr'] = libida_baseaddr + rename_regvar_hook_offset
    hooks_offsets['rename_hook_return_addr'] = hooks_offsets['rename_hook_addr']+ 0x8

    hooks_offsets['rename_handler_bytes'] = build_rename_regvar_handler_linux_32(hooks_offsets['send_event_addr'])

    toggle_hook_offset = 0x8436a
    hooks_offsets['toogle_hook_addr'] = libida_baseaddr + toggle_hook_offset
    hooks_offsets['toogle_hook_return_addr'] = hooks_offsets['toogle_hook_addr'] + 0x8

    hooks_offsets['toggle_sign_handler_bytes'] = build_toggle_sign_handler_linux_32(hooks_offsets['send_event_addr'])

    mark_comment_hook_offset = 0x9bce4
    hooks_offsets['mark_comment_hook_addr'] = libida_baseaddr + mark_comment_hook_offset
    hooks_offsets['mark_comment_hook_return_addr'] = hooks_offsets['mark_comment_hook_addr'] + 0x9

    hooks_offsets['mark_comment_handler_bytes'] = build_mark_comment_handler_linux_32(hooks_offsets['send_event_addr'])

    add_hidden_area_hook_offset = 0x6d2f8
    hooks_offsets['add_hidden_area_hook_addr'] = libida_baseaddr + add_hidden_area_hook_offset
    hooks_offsets['add_hidden_area_hook_return_addr'] = hooks_offsets['add_hidden_area_hook_addr'] + 0x7

    hooks_offsets['add_hidden_area_handler_bytes'] = build_add_hidden_area_handler_linux_32(hooks_offsets['send_event_addr'])

    function_flags_hook_offset = 0x137f8b
    hooks_offsets['function_flags_hook_addr'] = libida_baseaddr + function_flags_hook_offset
    hooks_offsets['function_flags_hook_return_addr'] = hooks_offsets['function_flags_hook_addr'] + 0x9

    hooks_offsets['function_flags_handler_bytes'] = build_function_flags_handler_linux_32(hooks_offsets['send_event_addr'])

    enum_width_hook_offset = 0x8a415
    hooks_offsets['enum_width_hook_addr'] = libida_baseaddr + enum_width_hook_offset
    hooks_offsets['enum_width_hook_return_addr'] = hooks_offsets['enum_width_hook_addr'] + 0x8

    hooks_offsets['enum_width_handler_bytes'] = build_enum_width_handler_linux_32(hooks_offsets['send_event_addr'])

    return hooks_offsets

def ida_695_linux_64_hooks_offsets(libida_baseaddr):
    hooks_offsets = {}

    send_event_offset = 0xac3d0
    hooks_offsets['send_event_addr'] = libida_baseaddr + send_event_offset

    regvar_hook_offset = 0x199248
    hooks_offsets['regvar_hook_addr']= libida_baseaddr + regvar_hook_offset
    hooks_offsets['regvar_hook_return_addr'] = hooks_offsets['regvar_hook_addr']+ 0x7

    hooks_offsets['regvar_handler_bytes'] = build_regvar_handler_linux_64(hooks_offsets['send_event_addr'])

    rename_regvar_hook_offset = 0x198a19
    hooks_offsets['rename_hook_addr'] = libida_baseaddr + rename_regvar_hook_offset
    hooks_offsets['rename_hook_return_addr'] = hooks_offsets['rename_hook_addr']+ 0x8

    hooks_offsets['rename_handler_bytes'] = build_rename_regvar_handler_linux_64(hooks_offsets['send_event_addr'])

    toggle_hook_offset = 0x92ea2
    hooks_offsets['toogle_hook_addr'] = libida_baseaddr + toggle_hook_offset
    hooks_offsets['toogle_hook_return_addr'] = hooks_offsets['toogle_hook_addr'] + 0xC

    hooks_offsets['toggle_sign_handler_bytes'] = build_toggle_sign_handler_linux_64(hooks_offsets['send_event_addr'])

    mark_comment_hook_offset = 0xb11d1
    hooks_offsets['mark_comment_hook_addr'] = libida_baseaddr + mark_comment_hook_offset
    hooks_offsets['mark_comment_hook_return_addr'] = hooks_offsets['mark_comment_hook_addr'] + 0x8

    hooks_offsets['mark_comment_handler_bytes'] = build_mark_comment_handler_linux_64(hooks_offsets['send_event_addr'])

    add_hidden_area_hook_offset = 0x75412
    hooks_offsets['add_hidden_area_hook_addr'] = libida_baseaddr + add_hidden_area_hook_offset
    hooks_offsets['add_hidden_area_hook_return_addr'] = hooks_offsets['add_hidden_area_hook_addr'] + 0x8

    hooks_offsets['add_hidden_area_handler_bytes'] = build_add_hidden_area_handler_linux_64(hooks_offsets['send_event_addr'])

    function_flags_hook_offset = 0x158ad4
    hooks_offsets['function_flags_hook_addr'] = libida_baseaddr + function_flags_hook_offset
    hooks_offsets['function_flags_hook_return_addr'] = hooks_offsets['function_flags_hook_addr'] + 0x7

    hooks_offsets['function_flags_handler_bytes'] = build_function_flags_handler_linux_64(hooks_offsets['send_event_addr'])

    enum_width_hook_offset = 0x9b4b1
    hooks_offsets['enum_width_hook_addr'] = libida_baseaddr + enum_width_hook_offset
    hooks_offsets['enum_width_hook_return_addr'] = hooks_offsets['enum_width_hook_addr'] + 0x8

    hooks_offsets['enum_width_handler_bytes'] = build_enum_width_handler_linux_64(hooks_offsets['send_event_addr'])

    return hooks_offsets

# windows
def ida_695_windows_32_hooks_offsets(libida_baseaddr):
    hooks_offsets = {}

    send_event_offset = 0x146690
    hooks_offsets['send_event_addr'] = libida_baseaddr + send_event_offset

    regvar_hook_offset = 0x927c8
    hooks_offsets['regvar_hook_addr']= libida_baseaddr + regvar_hook_offset
    hooks_offsets['regvar_hook_return_addr'] = hooks_offsets['regvar_hook_addr']+ 0x8

    hooks_offsets['regvar_handler_bytes'] = build_regvar_handler_windows_32(hooks_offsets['send_event_addr'])

    rename_regvar_hook_offset = 0x92b19
    hooks_offsets['rename_hook_addr'] = libida_baseaddr + rename_regvar_hook_offset
    hooks_offsets['rename_hook_return_addr'] = hooks_offsets['rename_hook_addr']+ 0x6

    hooks_offsets['rename_handler_bytes'] = build_rename_regvar_handler_windows_32(hooks_offsets['send_event_addr'])

    toggle_hook_offset = 0x569d0
    hooks_offsets['toogle_hook_addr'] = libida_baseaddr + toggle_hook_offset
    hooks_offsets['toogle_hook_return_addr'] = hooks_offsets['toogle_hook_addr'] + 0x6

    hooks_offsets['toggle_sign_handler_bytes'] = build_toggle_sign_handler_windows_32(hooks_offsets['send_event_addr'])

    mark_comment_hook_offset = 0xff65a
    hooks_offsets['mark_comment_hook_addr'] = libida_baseaddr + mark_comment_hook_offset
    hooks_offsets['mark_comment_hook_return_addr'] = hooks_offsets['mark_comment_hook_addr'] + 0x6

    hooks_offsets['mark_comment_handler_bytes'] = build_mark_comment_handler_windows_32(hooks_offsets['send_event_addr'])

    add_hidden_area_hook_offset = 0xec8b2
    hooks_offsets['add_hidden_area_hook_addr'] = libida_baseaddr + add_hidden_area_hook_offset
    hooks_offsets['add_hidden_area_hook_return_addr'] = hooks_offsets['add_hidden_area_hook_addr'] + 0x6

    hooks_offsets['add_hidden_area_handler_bytes'] = build_add_hidden_area_handler_windows_32(hooks_offsets['send_event_addr'])

    function_flags_hook_offset = 0x785d6
    hooks_offsets['function_flags_hook_addr'] = libida_baseaddr + function_flags_hook_offset
    hooks_offsets['function_flags_hook_return_addr'] = hooks_offsets['function_flags_hook_addr'] + 0x7

    hooks_offsets['function_flags_handler_bytes'] = build_function_flags_handler_windows_32(hooks_offsets['send_event_addr'])

    enum_width_hook_offset = 0x7f58a
    hooks_offsets['enum_width_hook_addr'] = libida_baseaddr + enum_width_hook_offset
    hooks_offsets['enum_width_hook_return_addr'] = hooks_offsets['enum_width_hook_addr'] + 0x6

    hooks_offsets['enum_width_handler_bytes'] = build_enum_width_handler_windows_32(hooks_offsets['send_event_addr'])

    return hooks_offsets

def ida_695_windows_64_hooks_offsets(libida_baseaddr):
    hooks_offsets = {}

    send_event_offset = 0x15d830
    hooks_offsets['send_event_addr'] = libida_baseaddr + send_event_offset

    regvar_hook_offset = 0x9f58a
    hooks_offsets['regvar_hook_addr']= libida_baseaddr + regvar_hook_offset
    hooks_offsets['regvar_hook_return_addr'] = hooks_offsets['regvar_hook_addr']+ 0x6

    hooks_offsets['regvar_handler_bytes'] = build_regvar_handler_windows_64(hooks_offsets['send_event_addr'])

    rename_regvar_hook_offset = 0x9fc09
    hooks_offsets['rename_hook_addr'] = libida_baseaddr + rename_regvar_hook_offset
    hooks_offsets['rename_hook_return_addr'] = hooks_offsets['rename_hook_addr']+ 0x6

    hooks_offsets['rename_handler_bytes'] = build_rename_regvar_handler_windows_64(hooks_offsets['send_event_addr'])

    toggle_hook_offset = 0x5d975
    hooks_offsets['toogle_hook_addr'] = libida_baseaddr + toggle_hook_offset
    hooks_offsets['toogle_hook_return_addr'] = hooks_offsets['toogle_hook_addr'] + 0xA

    hooks_offsets['toggle_sign_handler_bytes'] = build_toggle_sign_handler_windows_64(hooks_offsets['send_event_addr'])

    mark_comment_hook_offset = 0x114b43
    hooks_offsets['mark_comment_hook_addr'] = libida_baseaddr + mark_comment_hook_offset
    hooks_offsets['mark_comment_hook_return_addr'] = hooks_offsets['mark_comment_hook_addr'] + 0x6

    hooks_offsets['mark_comment_handler_bytes'] = build_mark_comment_handler_windows_64(hooks_offsets['send_event_addr'])

    add_hidden_area_hook_offset = 0x100fa5
    hooks_offsets['add_hidden_area_hook_addr'] = libida_baseaddr + add_hidden_area_hook_offset
    hooks_offsets['add_hidden_area_hook_return_addr'] = hooks_offsets['add_hidden_area_hook_addr'] + 0x6

    hooks_offsets['add_hidden_area_handler_bytes'] = build_add_hidden_area_handler_windows_64(hooks_offsets['send_event_addr'])

    function_flags_hook_offset = 0x81a56
    hooks_offsets['function_flags_hook_addr'] = libida_baseaddr + function_flags_hook_offset
    hooks_offsets['function_flags_hook_return_addr'] = hooks_offsets['function_flags_hook_addr'] + 0x6

    hooks_offsets['function_flags_handler_bytes'] = build_function_flags_handler_windows_64(hooks_offsets['send_event_addr'])

    enum_width_hook_offset = 0x8afea
    hooks_offsets['enum_width_hook_addr'] = libida_baseaddr + enum_width_hook_offset
    hooks_offsets['enum_width_hook_return_addr'] = hooks_offsets['enum_width_hook_addr'] + 0x6

    hooks_offsets['enum_width_handler_bytes'] = build_enum_width_handler_windows_64(hooks_offsets['send_event_addr'])

    return hooks_offsets

#
# REGVAR
#
def build_regvar_handler_windows_32(send_event_addr):

    return build_regvar_handler_linux_32(send_event_addr)

def build_regvar_handler_linux_32(send_event_addr):
    handler_send_event_bytes = '\x60'  # pusha
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x10'  # add $0x10, %esp
    handler_send_event_bytes += '\x61' # popa

    return handler_send_event_bytes

def build_regvar_handler_windows_64(send_event_addr):
    handler_send_event_bytes = '\x60' # pusha
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x53'  # push %ebx
    handler_send_event_bytes += '\x56'  # push %esi
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x10'  # add $0x10, %esp
    handler_send_event_bytes += '\x61' # popa

    return handler_send_event_bytes

def build_regvar_handler_linux_64(send_event_addr):
    handler_send_event_bytes = '\x60' # pusha
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x8b\x45\x04'  # mov 0x04(%ebp),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x8b\x45\x00'  # mov 0x00(%ebp),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x10'  # add $0x10, %esp
    handler_send_event_bytes += '\x61' # popa

    return handler_send_event_bytes

#
# RENAME REGVAR
#
def build_rename_regvar_handler_windows_32(send_event_addr):
    handler_send_event_bytes = '\x60'  # pusha
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x56'  # push %esi
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x10'  # add $0x10, %esp
    handler_send_event_bytes += '\x61' # popa

    return handler_send_event_bytes

def build_rename_regvar_handler_linux_32(send_event_addr):
    handler_send_event_bytes = '\x60'  # pusha
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x8b\x07'  # mov    (%edi),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x10'  # add $0x10, %esp
    handler_send_event_bytes += '\x61' # popa

    return handler_send_event_bytes

def build_rename_regvar_handler_windows_64(send_event_addr):
    handler_send_event_bytes = '\x60' # pusha
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x8b\x43\x04'  # mov 0x4(%ebx),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x8b\x03'  # mov (%ebx),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x10'  # add $0x10, %esp
    handler_send_event_bytes += '\x61' # popa

    return handler_send_event_bytes

def build_rename_regvar_handler_linux_64(send_event_addr):
    handler_send_event_bytes = '\x60' # pusha
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x8b\x47\x04'  # mov 0x04(%edi),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x8b\x07'  # mov 0x00(%edi),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x10'  # add $0x10, %esp
    handler_send_event_bytes += '\x61' # popa

    return handler_send_event_bytes

#
# TOGGLE SIGN
#
def build_toggle_sign_handler_windows_32(send_event_addr):

    return build_toggle_sign_handler_linux_32(send_event_addr)

def build_toggle_sign_handler_linux_32(send_event_addr):
    handler_send_event_bytes = '\x60'  # pusha
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x56'  # push %esi
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x10'  # add $0x10, %esp
    handler_send_event_bytes += '\x61' # popa

    return handler_send_event_bytes

def build_toggle_sign_handler_windows_64(send_event_addr):
    handler_send_event_bytes = '\x60' # pusha
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x56'  # push %esi
    handler_send_event_bytes += '\x57'  # push %edi
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x10'  # add $0x10, %esp
    handler_send_event_bytes += '\x61' # popa

    return handler_send_event_bytes

def build_toggle_sign_handler_linux_64(send_event_addr):
    handler_send_event_bytes = '\x60' # pusha
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x55'  # push %ebp
    handler_send_event_bytes += '\x57'  # push %edi
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x10'  # add $0x10, %esp
    handler_send_event_bytes += '\x61' # popa

    return handler_send_event_bytes

#
# BOOKMARK
#
def build_mark_comment_handler_windows_32(send_event_addr):
    handler_send_event_bytes = '\x60'  # pusha
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x8b\x85\xf8\x00\x00\x00'  # mov 0xf8(%ebp),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x10'  # add $0x10, %esp
    handler_send_event_bytes += '\x61' # popa

    return handler_send_event_bytes

def build_mark_comment_handler_linux_32(send_event_addr):
    handler_send_event_bytes = '\x60'  # pusha
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x10'  # add $0x10, %esp
    handler_send_event_bytes += '\x61' # popa

    return handler_send_event_bytes

def build_mark_comment_handler_windows_64(send_event_addr):
    handler_send_event_bytes = '\x60'  # pusha
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x8b\x85\xf4\x00\x00\x00'  # mov 0xf4(%ebp),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x8b\x85\xf8\x00\x00\x00'  # mov 0xf8(%ebp),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x10'  # add $0x10, %esp
    handler_send_event_bytes += '\x61' # popa

    return handler_send_event_bytes

def build_mark_comment_handler_linux_64(send_event_addr):
    handler_send_event_bytes = '\x60'  # pusha
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x57'  # push %edi
    handler_send_event_bytes += '\x56'  # push %esi
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x10'  # add $0x10, %esp
    handler_send_event_bytes += '\x61' # popa

    return handler_send_event_bytes

#
# HIDDEN AREA
#
def build_add_hidden_area_handler_windows_32(send_event_addr):
    handler_send_event_bytes = '\x60'  # pusha
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x8b\x06'  # mov (%esi), %eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x10'  # add $0x10, %esp
    handler_send_event_bytes += '\x61' # popa

    return handler_send_event_bytes

def build_add_hidden_area_handler_linux_32(send_event_addr):
    handler_send_event_bytes = '\x60'  # pusha
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x55'  # push %ebp
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x10'  # add $0x10, %esp
    handler_send_event_bytes += '\x61' # popa

    return handler_send_event_bytes

def build_add_hidden_area_handler_windows_64(send_event_addr):
    handler_send_event_bytes = '\x60'  # pusha
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x8b\x46\x04'  # mov 0x4(%esi), %eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x8b\x06'  # mov (%esi), %eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x10'  # add $0x10, %esp
    handler_send_event_bytes += '\x61' # popa

    return handler_send_event_bytes

def build_add_hidden_area_handler_linux_64(send_event_addr):
    handler_send_event_bytes = '\x60'  # pusha
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x8b\x47\x04'  # mov 0x04(%edi),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x8b\x07'  # mov 0x00(%edi),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x10'  # add $0x10, %esp
    handler_send_event_bytes += '\x61' # popa

    return handler_send_event_bytes

#
# FUNCTION FLAGS
#
def build_function_flags_handler_windows_32(send_event_addr):
    handler_send_event_bytes = '\x60'  # pusha
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x8b\x07'  # mov 0x00(%edi),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x10'  # add $0x10, %esp
    handler_send_event_bytes += '\x61' # popa

    return handler_send_event_bytes

def build_function_flags_handler_linux_32(send_event_addr):
    handler_send_event_bytes = '\x60'  # pusha
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x8b\x00'  # mov (%ebx), %eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x10'  # add $0x10, %esp
    handler_send_event_bytes += '\x61' # popa

    return handler_send_event_bytes

def build_function_flags_handler_windows_64(send_event_addr):
    return build_function_flags_handler_linux_64(send_event_addr)

def build_function_flags_handler_linux_64(send_event_addr):
    handler_send_event_bytes = '\x60'  # pusha
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x8b\x45\x04'  # mov 0x04(%ebp),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x8b\x45\x00'  # mov 0x00(%ebp),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x10'  # add $0x10, %esp
    handler_send_event_bytes += '\x61' # popa

    return handler_send_event_bytes

#
# ENUM WIDTH
#
def build_enum_width_handler_windows_32(send_event_addr):
    return build_enum_width_handler_linux_32(send_event_addr)

def build_enum_width_handler_linux_32(send_event_addr):
    handler_send_event_bytes = '\x60'  # pusha
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x56'  # push %esi
    handler_send_event_bytes += '\x6a\x07'  # push $0x7
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x10'  # add $0x10, %esp
    handler_send_event_bytes += '\x61' # popa

    return handler_send_event_bytes

def build_enum_width_handler_windows_64(send_event_addr):
    handler_send_event_bytes = '\x60'  # pusha
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x57'  # push %edi
    handler_send_event_bytes += '\x56'  # push %esi
    handler_send_event_bytes += '\x6a\x07'  # push $0x7
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x10'  # add $0x10, %esp
    handler_send_event_bytes += '\x61' # popa

    return handler_send_event_bytes

def build_enum_width_handler_linux_64(send_event_addr):
    handler_send_event_bytes = '\x60'  # pusha
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x56'  # push %esi
    handler_send_event_bytes += '\x57'  # push %edi
    handler_send_event_bytes += '\x6a\x07'  # push $0x7
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x10'  # add $0x10, %esp
    handler_send_event_bytes += '\x61' # popa

    return handler_send_event_bytes

