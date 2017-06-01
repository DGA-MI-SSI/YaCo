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
import idautils
import idc
import unittest
import yaunit

class Fixture(unittest.TestCase):

    def get_address_for_operand(self, offset, op):
        def has_reg_item(ea):
            items = list(idautils.FuncItems(ea))
            if offset >= len(items):
                return False
            return idc.GetOpType(items[offset], op) == idc.o_reg
        ea = yaunit.get_next_function(has_reg_item)
        return list(idautils.FuncItems(ea))[offset]

    def yatest_rename_register(self):
        eas = []
        for offset in range(0, 2):
            for operand in range(0, 2):
                for i in range(0, 2):
                    ea = self.get_address_for_operand(offset, operand)
                    key = 'rename_register_%d_%d_%d' % (offset, operand, i)
                    eas.append((ea, operand, key))
                    func = idaapi.get_func(ea)
                    self.assertIsNotNone(func)
                    end = ea + idc.ItemSize(ea) if i == 0 else func.endEA
                    text = idc.GetOpnd(ea, operand)
                    self.assertEqual(idaapi.add_regvar(func, ea, end, text, key, None), idaapi.REGVAR_ERROR_OK)
        yaunit.save('registers', eas)

    @unittest.skip("not implemented")
    def yacheck_rename_register(self):
        eas = yaunit.load('registers')
        for ea, op, key in eas:
            self.assertEqual(idc.GetOpnd(ea, op), key)
