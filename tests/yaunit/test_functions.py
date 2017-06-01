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

import idaapi
import idc
import unittest
import yaunit

flag_types = [
    idc.FUNC_NORET,
    idc.FUNC_FAR,
    idc.FUNC_LIB,
    idc.FUNC_STATIC,
    idc.FUNC_FRAME,
    idc.FUNC_USERFAR,
    idc.FUNC_HIDDEN,
    idc.FUNC_THUNK,
    idc.FUNC_BOTTOMBP,
]


class Fixture(unittest.TestCase):

    def yatest_function_name(self):
        addr = yaunit.get_next_function()
        self.assertTrue(idc.MakeNameEx(addr, 'some_new_function_name', idc.SN_PUBLIC))
        yaunit.save('function_name', addr)

    def yacheck_function_name(self):
        addr = yaunit.load('function_name')
        self.assertEqual('some_new_function_name', idc.NameEx(idaapi.BADADDR, addr))

    @unittest.skip("not working")
    def yatest_function_flags(self):
        addrs = []
        for i, k in enumerate(flag_types):
            addr = yaunit.get_next_function()
            flags = idc.GetFunctionFlags(addr)
            self.assertNotEqual(flags, -1)
            self.assertEqual(idc.SetFunctionFlags(addr, flags | k), 1)
            addrs.append(addr)
        yaunit.save('function_flags', addrs)

    @unittest.skip("not working")
    def yacheck_function_flags(self):
        addrs = yaunit.load('function_flags')
        for i, k in enumerate(flag_types):
            addr = addrs[i]
            flags = idc.GetFunctionFlags(addr)
            self.assertNotEqual(flags, -1)
            self.assertEqual(flags & k, k)

    def yatest_function_local_vars(self):
        addr = yaunit.get_next_function(yaunit.has_locals)
        frame = idaapi.get_frame(addr)
        offset = 0
        frame_size = idaapi.get_struc_size(frame.id)
        while offset < frame_size:
            if idc.SetMemberName(frame.id, offset, 'local_var'):
                break
            offset += 1
        yaunit.save('function_with_local_vars', addr)

    def yacheck_function_local_vars(self):
        addr = yaunit.load('function_with_local_vars')
        frame = idaapi.get_frame(addr)
        frame_size = idaapi.get_struc_size(frame.id)
        offset = 0
        last_name = None
        while offset < frame_size and last_name is None:
            last_name = idc.GetMemberName(frame.id, offset)
            offset += 1
        self.assertEqual(last_name, 'local_var')
