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

operand_types = [
    idaapi.FF_0NUMD,
    idaapi.FF_0NUMH,
    #idaapi.FF_0OFF,
]

operand_names = {
    idaapi.FF_0NUMD:    'decimal',
    idaapi.FF_0NUMH:    'hexadecimal',
    idaapi.FF_0OFF:     'offset',
}

class Fixture(unittest.TestCase):

    def is_op(self, ea, op):
        all_ops = 0
        for x in operand_types:
            all_ops |= x
        flags = idaapi.get_flags_novalue(ea)
        if op == 0:
            ops = idaapi.get_optype_flags0(flags)
        else:
            ops = idaapi.get_optype_flags1(flags) >> 4
        return ops & all_ops

    def get_addr(self, op):
        def is_op(ea): return idc.GetOpType(ea, op) & idaapi.o_imm
        while True:
            ea = yaunit.get_next_function()
            if is_op(ea):
                return ea
            for eai in idautils.FuncItems(ea):
                if is_op(eai):
                    return eai

    def yatest_operands(self):
        values = []
        for otype in operand_types:
            for operand in range(0, 2):
                for signed in [True, False]:
                    ea = self.get_addr(operand)
                    values.append(ea)
                    if otype == idaapi.FF_0NUMD:
                        self.assertTrue(idaapi.op_dec(ea, operand))
                    elif otype == idaapi.FF_0NUMH:
                        self.assertTrue(idaapi.op_hex(ea, operand))
                    elif otype == idaapi.FF_0OFF:
                        self.assertTrue(idaapi.set_op_type(ea, idaapi.offflag(), operand))
                    if signed:
                        self.assertTrue(idaapi.toggle_sign(ea, operand))
        yaunit.save('operands', values)

    def yacheck_operands(self):
        values = yaunit.load('operands')
        for otype in operand_types:
            for operand in range(0, 2):
                for signed in [True, False]:
                    ea, values = values[0], values[1:]
                    flags = idaapi.get_flags_novalue(ea)
                    oflags = [idaapi.get_optype_flags0(flags), idaapi.get_optype_flags1(flags) >> 4]
                    self.assertEqual(oflags[operand] & otype, otype)
                    self.assertEqual(idaapi.is_invsign(ea, flags, operand), signed)
