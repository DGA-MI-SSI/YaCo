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

import runtests

set_operands = """
ea = 0x66013B90
idaapi.op_dec(ea+0x1A, 0)
idaapi.op_dec(ea+0x24, 1)
idaapi.toggle_sign(ea+0x24, 1)
idaapi.op_hex(ea+0x27, 1)
idaapi.toggle_sign(ea+0x27, 1)
"""

reset_operands = """
ea = 0x66013B90
idaapi.clr_op_type(ea+0x1A, 0)
idaapi.clr_op_type(ea+0x24, 1)
idaapi.clr_op_type(ea+0x27, 1)
"""

class Fixture(runtests.Fixture):

    def test_operands(self):
        a, b = self.setup_repos()
        ea = 0x66013B90
        a.run(
            self.script(set_operands),
            self.save_ea(ea),
        )
        a.check_git(added=["binary", "segment", "segment_chunk", "function",
            "stackframe", "stackframe_member", "stackframe_member", "basic_block"])
        b.run(
            self.check_ea(ea),
            self.script(reset_operands),
            self.save_ea(ea),
        )
        b.check_git(modified=["basic_block"])
        a.run(
            self.check_ea(ea),
        )
