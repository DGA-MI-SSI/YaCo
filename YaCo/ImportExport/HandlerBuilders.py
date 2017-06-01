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

import ctypes
import struct

from ctypes.util import find_library


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


def build_toggle_sign_handler_64(send_event_addr):
    # HANDLER
    """
       0:	50                   	push   %eax
       1:	6a 00                	push   $0x0
       3:	68 d0 07 00 00       	push   $0x7d0
       8:	56                   	push   %esi
       9:	57                   	push   %edi
       a:	6a 01                	push   $0x1
       c:	b8 fd fd fd fd       	mov    $0xfdfdfdfd,%eax
      11:	ff d0                	call   *%eax
      13:	83 c4 14             	add    $0x14,%esp
      16:	58                   	pop    %eax

    """
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x68\xd0\x07\x00\x00'  # push $0x7d0
    handler_send_event_bytes += '\x56'  # push %esi
    handler_send_event_bytes += '\x57'  # push %edi
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x14'  # add $0x14, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_toggle_sign_handler_linux_64(send_event_addr):
    # HANDLER
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x68\xd0\x07\x00\x00'  # push $0x7d0
    handler_send_event_bytes += '\x53'  # push %ebx
    handler_send_event_bytes += '\x56'  # push %esi
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x14'  # add $0x14, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_regvar_handler_64(send_event_addr):
    # HANDLER
    """
            0:	50                   	push   %eax
            1:	6a 00                	push   $0x0
            3:	68 d0 07 00 00       	push   $0x7d0
            8:   8b 44 24 5C             mov    0x60(%esp),%eax
            c:   50                      push   %eax
            d:   8b 44 24 60             mov    0x60(%esp),%eax
            11:   50                      push   %eax
            12:   6a 01                   push   $0x1
            14:   b8 fd fd fd fd          mov    $0xfdfdfdfd,%eax
            19:   ff d0                   call   *%eax
            1b:   83 c4 14                add    $0x14,%esp
            1e:   58                      pop    %eax


    """
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x68\xd0\x07\x00\x00'  # push $0x7d0
    handler_send_event_bytes += '\x8b\x44\x24\x60'  # mov 0x60(%esp),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x8b\x44\x24\x60'  # mov 0x60(%esp),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x14'  # add $0x14, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_regvar_handler_linux_64(send_event_addr):
    # HANDLER
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x68\xd0\x07\x00\x00'  # push $0x7d0
    handler_send_event_bytes += '\x8b\x44\x24\x1C'  # mov 0x1C(%esp),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x8b\x44\x24\x1C'  # mov 0x1C(%esp),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x14'  # add $0x14, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_rename_regvar_handler_64(send_event_addr):
    # HANDLER
    """
0:   50                      push   %eax
1:   6a 00                   push   $0x0
3:   68 d0 07 00 00          push   $0x7d0
8:   8b 43 04                mov    0x4(%ebx),%eax
b:   50                      push   %eax
c:   8b 03                   mov    (%ebx),%eax
e:   50                      push   %eax
f:   6a 01                   push   $0x1
11:   b8 fd fd fd fd          mov    $0xfdfdfdfd,%eax
16:   ff d0                   call   *%eax
18:   83 c4 14                add    $0x14,%esp
1b:   58                      pop    %eax

    """
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x68\xd0\x07\x00\x00'  # push $0x7d0
    handler_send_event_bytes += '\x8b\x43\x04'  # mov 0x4(%ebx),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x8b\x03'  # mov (%ebx),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x14'  # add $0x14, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_rename_regvar_handler_linux_64(send_event_addr):
    # HANDLER
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x68\xd0\x07\x00\x00'  # push $0x7d0
    handler_send_event_bytes += '\x8b\x47\x04'  # mov 0x4(%ebx),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x8b\x07'  # mov (%ebx),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x14'  # add $0x14, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_mark_comment_handler_64(send_event_addr):
    # HANDLER
    """
       0:	50                   	push   %eax
       1:	6a 00                	push   $0x0
       3:	68 d0 07 00 00       	push   $0x7d0
       8:	8b 87 14 04 00 00    	mov    0x414(%edi),%eax
       e:	50                   	push   %eax
       f:	8b 87 10 04 00 00    	mov    0x410(%edi),%eax
      15:	50                   	push   %eax
      16:	6a 01                	push   $0x1
      18:	b8 fd fd fd fd       	mov    $0xfdfdfdfd,%eax
      1d:	ff d0                	call   *%eax
      1f:	83 c4 14             	add    $0x14,%esp
      22:	58                   	pop    %eax
    """

    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x68\xd0\x07\x00\x00'  # push $0x7d0
    handler_send_event_bytes += '\x8b\x85\x14\x04\x00\x00'  # mov 0x414(%ebp),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x8b\x85\x10\x04\x00\x00'  # mov 0x410(%ebp),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x14'  # add $0x14, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_mark_comment_handler_linux_64(send_event_addr):
    # HANDLER
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x68\xd0\x07\x00\x00'  # push $0x7d0
    handler_send_event_bytes += '\x8b\x86\x14\x04\x00\x00'  # mov 0x414(%esi),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x8b\x86\x10\x04\x00\x00'  # mov 0x410(%esi),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x14'  # add $0x14, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_delete_mark_comment_handler_64(send_event_addr):
    # HANDLER
    """
    0:	50                   	push   %eax
    1:	6a 00                	push   $0x0
    3:	68 d0 07 00 00       	push   $0x7d0
    8:	8b 46 2c             	mov    0x2c(%esi),%eax
    b:	50                   	push   %eax
    c:	8b 46 28             	mov    0x28(%esi),%eax
    f:	50                   	push   %eax
    10:	6a 01                	push   $0x1
    12:	b8 fd fd fd fd       	mov    $0xfdfdfdfd,%eax
    17:	ff d0                	call   *%eax
    19:	83 c4 14             	add    $0x14,%esp
    1c:	58                   	pop    %eax
    """

    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x68\xd0\x07\x00\x00'  # push $0x7d0
    handler_send_event_bytes += '\x8b\x46\x2c'  # mov 0x2c(%esi),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x8b\x46\x28'  # mov 0x28(%esi),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x14'  # add $0x14, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_add_hidden_area_handler_64(send_event_addr):
    # HANDLER
    """
0:	50                   	push   %eax
1:	6a 00                	push   $0x0
3:	68 d0 07 00 00       	push   $0x7d0
8:	55                   	push   %ebp
9:	53                   	push   %ebx
a:	6a 01                	push   $0x1
c:	b8 fd fd fd fd       	mov    $0xfdfdfdfd,%eax
11:	ff d0                	call   *%eax
13:	83 c4 14             	add    $0x14,%esp
16:	58                   	pop    %eax
    """

    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x68\xd0\x07\x00\x00'  # push $0x7d0
    handler_send_event_bytes += '\x55'  # push %ebp
    handler_send_event_bytes += '\x53'  # push %ebx
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x14'  # add $0x14, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_add_hidden_area_handler_linux_64(send_event_addr):
    # HANDLER
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x68\xd0\x07\x00\x00'  # push $0x7d0
    handler_send_event_bytes += '\x57'  # push %edi
    handler_send_event_bytes += '\x55'  # push %ebp
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x14'  # add $0x14, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_function_flags_handler_64(send_event_addr):
    # HANDLER
    # HANDLER
    """
0:	50                   	push   %eax
1:	6a 00                	push   $0x0
3:	68 d0 07 00 00       	push   $0x7d0
8:	8b 46 04             	mov    0x4(%esi),%eax
b:	50                   	push   %eax
c:	8b 06                	mov    (%esi),%eax
e:	50                   	push   %eax
f:	6a 01                	push   $0x1
11:	b8 fd fd fd fd       	mov    $0xfdfdfdfd,%eax
16:	ff d0                	call   *%eax
18:	83 c4 14             	add    $0x14,%esp
1b:	58                   	pop    %eax

    """
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x68\xd0\x07\x00\x00'  # push $0x7d0
    handler_send_event_bytes += '\x8b\x46\x04'  # mov 0x4(%esi), %eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x8b\x06'  # mov (%esi), %eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x14'  # add $0x14, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_function_flags_handler_linux_64(send_event_addr):
    # HANDLER
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x68\xd0\x07\x00\x00'  # push $0x7d0
    handler_send_event_bytes += '\x8b\x43\x04'  # mov 0x4(%ebx), %eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x8b\x03'  # mov (%ebx), %eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x14'  # add $0x14, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_enum_width_handler_64(send_event_addr):
    # HANDLER
    """
0:	50                   	push   %eax
1:	56                   	push   %edi
2:	57                   	push   %esi
3:	6a 07                	push   $0x7
5:	b8 fd fd fd fd       	mov    $0xfdfdfdfd,%eax
a:	ff d0                	call   *%eax
c:	83 c4 0c             	add    $0xc,%esp
f:	58                   	pop    %eax
    """

    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x57'  # push %edi
    handler_send_event_bytes += '\x56'  # push %esi
    handler_send_event_bytes += '\x6a\x07'  # push $0x7
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x0C'  # add $0x14, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_enum_width_handler_linux_64(send_event_addr):
    # HANDLER
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x53'  # push %ebx
    handler_send_event_bytes += '\x56'  # push %esi
    handler_send_event_bytes += '\x6a\x07'  # push $0x7
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x0C'  # add $0x14, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_toggle_sign_handler_32(send_event_addr):
    # HANDLER
    """
       0:	50                   	push   %eax
       1:	6a 00                	push   $0x0
       3:	56                   	push   %esi
       4:	6a 01                	push   $0x1
       6:	b8 fd fd fd fd       	mov    $0xfdfdfdfd,%eax
       b:	ff d0                	call   *%eax
       d:	83 c4 0c             	add    $0xc,%esp
      10:	58                   	pop    %eax
    """
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x56'  # push %esi
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x0c'  # add $0xc, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_toggle_sign_handler_linux_32(send_event_addr):
    # HANDLER
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x53'  # push %edx
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x0c'  # add $0xc, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_regvar_handler_32(send_event_addr):
    # HANDLER
    """
    0:   50                      push   %eax
    1:   6a 00                   push   $0x0
    3:   8b 44 24 48             mov    0x48(%esp),%eax
    7:   50                      push   %eax
    8:   6a 01                   push   $0x1
    a:   b8 fd fd fd fd          mov    $0xfdfdfdfd,%eax
    f:   ff d0                   call   *%eax
    11:   83 c4 0c                add    $0xc,%esp
    14:   58                      pop    %eax

    """
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x8b\x44\x24\x48'  # mov 0x48(%esp), %eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x0c'  # add $0xC, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_regvar_handler_linux_32(send_event_addr):
    # HANDLER
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x8b\x44\x24\x14'  # mov 0x14(%esp), %eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x0c'  # add $0xC, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_rename_regvar_handler_32(send_event_addr):
    # HANDLER
    """
0:   50                      push   %eax
1:   6a 00                   push   $0x0
3:   8b 03                   mov    (%ebx),%eax
5:   50                      push   %eax
6:   6a 01                   push   $0x1
8:   b8 fd fd fd fd          mov    $0xfdfdfdfd,%eax
d:   ff d0                   call   *%eax
f:   83 c4 0c                add    $0xc,%esp
12:   58                      pop    %eax

    """
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x8b\x03'  # mov    (%ebx),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x0c'  # add $0xC, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_rename_regvar_handler_linux_32(send_event_addr):
    # HANDLER
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x8b\x07'  # mov    (%edi),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x0c'  # add $0xC, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_mark_comment_handler_32(send_event_addr):
    # HANDLER
    """
       0:	50                   	push   %eax
       1:	6a 00                	push   $0x0
       3:	8b 85 0c 04 00 00    	mov    0x40c(%ebp),%eax
       9:	50                   	push   %eax
       a:	6a 01                	push   $0x1
       c:	b8 fd fd fd fd       	mov    $0xfdfdfdfd,%eax
      11:	ff d0                	call   *%eax
      13:	83 c4 0c             	add    $0xc,%esp
      16:	58                   	pop    %eax
    """

    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x8b\x85\x0c\x04\x00\x00'  # mov 0x40c(%ebp),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x0c'  # add $0xC, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_mark_comment_handler_linux_32(send_event_addr):
    # HANDLER
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x8b\x44\x24\x78'  # mov 0x78(%esp),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x0c'  # add $0xC, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_delete_mark_comment_handler_32(send_event_addr):
    # HANDLER
    """
    0:	50                   	push   %eax
    1:	6a 00                	push   $0x0
    3:	8b 46 24             	mov    0x24(%esi),%eax
    6:	50                   	push   %eax
    7:	6a 01                	push   $0x1
    9:	b8 fd fd fd fd       	mov    $0xfdfdfdfd,%eax
    e:	ff d0                	call   *%eax
    10:	83 c4 0c             	add    $0xc,%esp
    13:	58                   	pop    %eax
    """

    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x8b\x46\x24'  # mov    0x24(%esi),%eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x0c'  # add $0xC, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_add_hidden_area_handler_32(send_event_addr):
    # HANDLER
    """
0:	50                   	push   %eax
1:	6a 00                	push   $0x0
3:	56                   	push   %esi
4:	6a 01                	push   $0x1
6:	b8 fd fd fd fd       	mov    $0xfdfdfdfd,%eax
b:	ff d0                	call   *%eax
d:	83 c4 0c             	add    $0xc,%esp
10:	58                   	pop    %eax

    """

    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x56'  # push %esi
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x0c'  # add $0xC, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_add_hidden_area_handler_linux_32(send_event_addr):
    # HANDLER
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x52'  # push %edx
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x0c'  # add $0xC, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_function_flags_handler_32(send_event_addr):
    # HANDLER
    """
0:	50                   	push   %eax
1:	6a 00                	push   $0x0
3:	8b 06                	mov    (%esi),%eax
5:	50                   	push   %eax
6:	6a 01                	push   $0x1
8:	b8 fd fd fd fd       	mov    $0xfdfdfdfd,%eax
d:	ff d0                	call   *%eax
f:	83 c4 0c             	add    $0xc,%esp
12:	58                   	pop    %eax

    """

    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x8b\x06'  # mov (%esi), %eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x0c'  # add $0xC, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_function_flags_handler_linux_32(send_event_addr):
    # HANDLER
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x00'  # push $0x0
    handler_send_event_bytes += '\x8b\x03'  # mov (%ebx), %eax
    handler_send_event_bytes += '\x50'  # push %eax
    handler_send_event_bytes += '\x6a\x01'  # push $0x1
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x0c'  # add $0xC, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_enum_width_handler_32(send_event_addr):
    # HANDLER
    """
0:	50                   	push   %eax
1:	56                   	push   %esi
2:	6a 07                	push   $0x7
4:	b8 fd fd fd fd       	mov    $0xfdfdfdfd,%eax
9:	ff d0                	call   *%eax
b:	83 c4 08             	add    $0x8,%esp
e:	58                   	pop    %eax


    """

    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x56'  # push %esi
    handler_send_event_bytes += '\x6a\x07'  # push $0x7
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x08'  # add $0x8, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_enum_width_handler_linux_32(send_event_addr):
    # HANDLER
    handler_send_event_bytes = '\x50'  # push %eax
    handler_send_event_bytes += '\x53'  # push %ebx
    handler_send_event_bytes += '\x6a\x07'  # push $0x7
    handler_send_event_bytes += '\xb8'
    handler_send_event_bytes += pack_address(send_event_addr)  # mov send_event_addr, %eax
    handler_send_event_bytes += '\xff\xd0'  # call %eax
    handler_send_event_bytes += '\x83\xc4\x08'  # add $0x8, %esp
    handler_send_event_bytes += '\x58'

    return handler_send_event_bytes


def build_hook_windows(hook_addr, hook_return_addr, handler_bytes):
    # RETURN
    handler_return_bytes = build_trampoline(hook_return_addr)
    original_code_size = hook_return_addr - hook_addr
    handler_size = len(handler_bytes) + original_code_size + len(handler_return_bytes)

    # -- allocate handler
    handler_addr = ctypes.windll.kernel32.VirtualAlloc(
        None, handler_size, 0x1000, 0x40)  # MEM_COMMIT / EXECUTE_READ_WRITE  # @UndefinedVariable
    if (handler_addr is None):
        raise "Unable to VirtualAllocEx to build hook !"

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
    if ctypes.windll.kernel32.VirtualProtect(hook_addr, len(hook_bytes), 0x40, ctypes.byref(old)) != 1:
        # @UndefinedVariable
        raise "Unable to unprotect module."
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
    if (handler_addr is None):
        raise "Unable to malloc to build hook !"
    if (libc_so.mprotect(handler_addr, handler_size, 0x7) != 0):  # PROT_READ / PROT_WRITE / PROT_EXEC
        raise "Unable to unprotect buffer !"

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
