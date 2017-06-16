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

# operand, isOperand
tests = [
    (0, idaapi.isNum0, 0xcafebabe+0),
    (1, idaapi.isNum1, 0xcafebabe+1),
]

class Fixture(unittest.TestCase):

    def yatest_reference_views(self):
        eas = []
        for (operand, is_num, reference) in tests:
            ea = yaunit.get_next_function()
            f = idaapi.get_flags_novalue(ea)
            while not is_num(f) and not idaapi.isOff(f, operand):
                ea += idc.ItemSize(ea)
                f = idaapi.get_flags_novalue(ea)
            self.assertTrue(idaapi.set_offset(ea, operand, reference))
            eas.append(ea)
        yaunit.save('reference_views', eas)

    def yacheck_reference_views(self):
        eas = yaunit.load('reference_views')
        idx = 0
        for ea in eas:
            (operand, is_num, reference) = tests[idx]
            idx += 1
            ti = idaapi.opinfo_t()
            f = idc.GetFlags(ea)
            self.assertTrue(idaapi.get_opinfo(ea, operand, f, ti))
            self.assertTrue(ti.ri.type())
            self.assertEqual(ti.ri.base, reference)
