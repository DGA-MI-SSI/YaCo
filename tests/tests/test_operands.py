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

#!/bin/python

import run_all_tests

class Fixture(run_all_tests.Fixture):

    def test_operands(self):
        wd, a, b = self.setup_repos()
        ea = 0x66013B90
        self.idado(a, """
ea = 0x%x
idaapi.op_dec(ea+0x1A, 0)
idaapi.op_dec(ea+0x24, 1)
idaapi.toggle_sign(ea+0x24, 1)
idaapi.op_hex(ea+0x27, 1)
idaapi.toggle_sign(ea+0x27, 1)
""" % ea)
        self.idacheck(b, self.has(ea+0x17, "1 << ya.OBJECT_TYPE_BASIC_BLOCK", """
    <offsets>
      <valueview offset="0000000000000011" operand="00000000">offset-off32</valueview>
      <valueview offset="000000000000001A" operand="00000000">unsigneddecimal</valueview>
      <valueview offset="0000000000000024" operand="00000001">signeddecimal</valueview>
      <valueview offset="0000000000000027" operand="00000001">signedhexadecimal</valueview>
      <valueview offset="0000000000000033" operand="00000000">offset-off32</valueview>
    </offsets>
"""))
        self.idado(b, """
ea = 0x%x
idaapi.op_hex(ea+0x1A, 0)
idaapi.toggle_sign(ea+0x24, 1)
idaapi.op_hex(ea+0x24, 1)
idaapi.toggle_sign(ea+0x27, 1)
idaapi.op_dec(ea+0x27, 1)
""" % ea)
        self.idacheck(a, self.has(ea+0x17, "1 << ya.OBJECT_TYPE_BASIC_BLOCK", """
    <offsets>
      <valueview offset="0000000000000011" operand="00000000">offset-off32</valueview>
      <valueview offset="000000000000001A" operand="00000000">unsignedhexadecimal</valueview>
      <valueview offset="0000000000000024" operand="00000001">unsignedhexadecimal</valueview>
      <valueview offset="0000000000000027" operand="00000001">unsigneddecimal</valueview>
      <valueview offset="0000000000000033" operand="00000000">offset-off32</valueview>
    </offsets>
"""))
