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

set_reference_views = """
ea = 0x66013B00
idaapi.op_offset(ea+0xF,  0, idaapi.get_default_reftype(ea+0xF),  idaapi.BADADDR, 0xdeadbeef)
idaapi.op_offset(ea+0x17, 1, idaapi.get_default_reftype(ea+0x17), idaapi.BADADDR, 0xbeefdead)
"""

reset_reference_views = """
ea = 0x66013B00
idaapi.op_offset(ea+0xF,  0, idaapi.get_default_reftype(ea+0xF))
idaapi.op_offset(ea+0x17, 1, idaapi.get_default_reftype(ea+0x17))
"""

class Fixture(runtests.Fixture):

    def test_reference_views(self):
        a, b = self.setup_repos()
        ea = 0x66013B00
        a.run(
            self.script(set_reference_views),
            self.save_ea(ea),
        )
        a.check_git(added=["binary", "segment", "segment_chunk", "function",
            "stackframe", "stackframe_member", "stackframe_member", "basic_block",
            "reference_info", "reference_info"])
        b.run(
            self.check_ea(ea),
            self.script(reset_reference_views),
            self.save_ea(ea),
        )
        # FIXME deleted=["reference_info"] * 2
        b.check_git(modified=["basic_block"])
        a.run(
            self.check_ea(ea),
        )
