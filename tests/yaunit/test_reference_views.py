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

class Fixture(unittest.TestCase):

    def setUp(self):
        self.operand = 1
        self.reference_addr = 0xcafebabe

    def yatest_reference_views(self):
        addr = yaunit.get_next_function()
        f = idaapi.get_flags_novalue(addr)
        while not idaapi.isNum1(f) and not idaapi.isOff(f, 1):
            addr += idc.ItemSize(addr)
            f = idaapi.get_flags_novalue(addr)
        self.assertTrue(idaapi.set_offset(addr, self.operand, self.reference_addr))
        yaunit.save('reference_view_addr', addr)

    @unittest.skip("flaky")
    def yacheck_reference_views(self):
        addr = yaunit.load('reference_view_addr')
        ti = idaapi.opinfo_t()
        f = idc.GetFlags(addr)
        self.assertTrue(idaapi.get_opinfo(addr, self.operand, f, ti))
        self.assertTrue(ti.ri.type())
        self.assertEqual(ti.ri.base, self.reference_addr)
