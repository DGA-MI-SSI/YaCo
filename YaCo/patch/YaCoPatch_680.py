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
# IDA 680
#
# windows
def ida_680_windows_32_hooks_offsets(libida_baseaddr):
    hooks_offsets = {}

    send_event_offset = 0x1265d0
    hooks_offsets['send_event_addr'] = libida_baseaddr + send_event_offset

    regvar_hook_offset = 0x6c332
    hooks_offsets['regvar_hook_addr']= libida_baseaddr + regvar_hook_offset
    hooks_offsets['regvar_hook_return_addr'] = hooks_offsets['regvar_hook_addr']+ 0x8

    hooks_offsets['regvar_handler_bytes'] = build_regvar_handler_windows_32(hooks_offsets['send_event_addr'])

    rename_regvar_hook_offset = 0x6c1ab
    hooks_offsets['rename_hook_addr'] = libida_baseaddr + rename_regvar_hook_offset
    hooks_offsets['rename_hook_return_addr'] = hooks_offsets['rename_hook_addr']+ 0x8

    hooks_offsets['rename_handler_bytes'] = build_rename_regvar_handler_windows_32(hooks_offsets['send_event_addr'])

    toggle_hook_offset = 0xf11c0
    hooks_offsets['toogle_hook_addr'] = libida_baseaddr + toggle_hook_offset
    hooks_offsets['toogle_hook_return_addr'] = hooks_offsets['toogle_hook_addr'] + 0x6

    hooks_offsets['toggle_sign_handler_bytes'] = build_toggle_sign_handler_windows_32(hooks_offsets['send_event_addr'])

    mark_comment_hook_offset = 0x98d47
    hooks_offsets['mark_comment_hook_addr'] = libida_baseaddr + mark_comment_hook_offset
    hooks_offsets['mark_comment_hook_return_addr'] = hooks_offsets['mark_comment_hook_addr'] + 0x8

    hooks_offsets['mark_comment_handler_bytes'] = build_mark_comment_handler_windows_32(hooks_offsets['send_event_addr'])

    add_hidden_area_hook_offset = 0xe8077
    hooks_offsets['add_hidden_area_hook_addr'] = libida_baseaddr + add_hidden_area_hook_offset
    hooks_offsets['add_hidden_area_hook_return_addr'] = hooks_offsets['add_hidden_area_hook_addr'] + 0x7

    hooks_offsets['add_hidden_area_handler_bytes'] = build_add_hidden_area_handler_windows_32(hooks_offsets['send_event_addr'])

    enum_width_hook_offset = 0xf7a2a
    hooks_offsets['enum_width_hook_addr'] = libida_baseaddr + enum_width_hook_offset
    hooks_offsets['enum_width_hook_return_addr'] = hooks_offsets['enum_width_hook_addr'] + 0x8

    hooks_offsets['enum_width_handler_bytes'] = build_enum_width_handler_windows_32(hooks_offsets['send_event_addr'])

    return hooks_offsets

def ida_680_windows_64_hooks_offsets(libida_baseaddr):
    hooks_offsets = {}

    send_event_offset = 0x13C720
    hooks_offsets['send_event_addr'] = libida_baseaddr + send_event_offset

    regvar_hook_offset = 0x74132
    hooks_offsets['regvar_hook_addr']= libida_baseaddr + regvar_hook_offset
    hooks_offsets['regvar_hook_return_addr'] = hooks_offsets['regvar_hook_addr']+ 0x8

    hooks_offsets['regvar_handler_bytes'] = build_regvar_handler_windows_64(hooks_offsets['send_event_addr'])

    rename_regvar_hook_offset = 0x73F8B
    hooks_offsets['rename_hook_addr'] = libida_baseaddr + rename_regvar_hook_offset
    hooks_offsets['rename_hook_return_addr'] = hooks_offsets['rename_hook_addr']+ 0x9

    hooks_offsets['rename_handler_bytes'] = build_rename_regvar_handler_windows_64(hooks_offsets['send_event_addr'])

    toggle_hook_offset = 0x101655
    hooks_offsets['toogle_hook_addr'] = libida_baseaddr + toggle_hook_offset
    hooks_offsets['toogle_hook_return_addr'] = hooks_offsets['toogle_hook_addr'] + 0x6

    hooks_offsets['toggle_sign_handler_bytes'] = build_toggle_sign_handler_windows_64(hooks_offsets['send_event_addr'])

    mark_comment_hook_offset = 0xA32C0
    hooks_offsets['mark_comment_hook_addr'] = libida_baseaddr + mark_comment_hook_offset
    hooks_offsets['mark_comment_hook_return_addr'] = hooks_offsets['mark_comment_hook_addr'] + 0xb

    hooks_offsets['mark_comment_handler_bytes'] = build_mark_comment_handler_windows_64(hooks_offsets['send_event_addr'])

    add_hidden_area_hook_offset = 0xF706B
    hooks_offsets['add_hidden_area_hook_addr'] = libida_baseaddr + add_hidden_area_hook_offset
    hooks_offsets['add_hidden_area_hook_return_addr'] = hooks_offsets['add_hidden_area_hook_addr'] + 0x7

    hooks_offsets['add_hidden_area_handler_bytes'] = build_add_hidden_area_handler_windows_64(hooks_offsets['send_event_addr'])

    enum_width_hook_offset = 0x10988A
    hooks_offsets['enum_width_hook_addr'] = libida_baseaddr + enum_width_hook_offset
    hooks_offsets['enum_width_hook_return_addr'] = hooks_offsets['enum_width_hook_addr'] + 0x7

    hooks_offsets['enum_width_handler_bytes'] = build_enum_width_handler_windows_64(hooks_offsets['send_event_addr'])

    return hooks_offsets

def build_regvar_handler_windows_32(send_event_addr):
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x8b\x44\x24\x48'  # mov 0x48(%esp), %eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x0c'  # add $0xC, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes

def build_regvar_handler_windows_64(send_event_addr):
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x68\xd0\x07\x00\x00'  # push $0x7d0
    handler_send_event_bytes += '\x8b\x44\x24\x60'  # mov 0x60(%esp),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x8b\x44\x24\x60'  # mov 0x60(%esp),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x14'  # add $0x14, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes

def build_rename_regvar_handler_windows_32(send_event_addr):
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x8b\x03'  # mov    (%ebx),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x0c'  # add $0xC, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes

def build_rename_regvar_handler_windows_64(send_event_addr):
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x68\xd0\x07\x00\x00'  # push $0x7d0
    handler_send_event_bytes += '\x8b\x43\x04'  # mov 0x4(%ebx),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x8b\x03'  # mov (%ebx),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x14'  # add $0x14, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes

def build_toggle_sign_handler_windows_32(send_event_addr):
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x56'  # push %esi
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x0c'  # add $0xc, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes

def build_toggle_sign_handler_windows_64(send_event_addr):
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x68\xd0\x07\x00\x00'  # push $0x7d0
    handler_send_event_bytes += '\x56'  # push %esi
    handler_send_event_bytes += '\x57'  # push %edi
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x14'  # add $0x14, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes

def build_mark_comment_handler_windows_32(send_event_addr):
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x8b\x44\x24\x40'  # mov 0x40(%esp),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x0c'  # add $0xC, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes

def build_mark_comment_handler_windows_64(send_event_addr):
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x68\xd0\x07\x00\x00'  # push $0x7d0
    handler_send_event_bytes += '\x8b\x85\x14\x04\x00\x00'  # mov 0x414(%ebp),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x8b\x85\x10\x04\x00\x00'  # mov 0x410(%ebp),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x14'  # add $0x14, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes

def build_delete_mark_comment_handler_windows_64(send_event_addr):
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x68\xd0\x07\x00\x00'  # push $0x7d0
    handler_send_event_bytes += '\x8b\x46\x2c'  # mov 0x2c(%esi),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x8b\x46\x28'  # mov 0x28(%esi),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x14'  # add $0x14, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes

def build_add_hidden_area_handler_windows_32(send_event_addr):
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x0c'  # add $0xC, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes

def build_add_hidden_area_handler_windows_64(send_event_addr):
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x68\xd0\x07\x00\x00'  # push $0x7d0
    handler_send_event_bytes += '\x51'  # push %ecx
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x14'  # add $0x14, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes

def build_enum_width_handler_windows_32(send_event_addr):
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x56'  # push %esi
    handler_send_event_bytes += '\x6a\x07'  # push $0x7
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x08'  # add $0x8, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes

def build_enum_width_handler_windows_64(send_event_addr):
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x57'  # push %edi
    handler_send_event_bytes += '\x56'  # push %esi
    handler_send_event_bytes += '\x6a\x07'  # push $0x7
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += YaCoPatch.pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x0C'  # add $0x14, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes

