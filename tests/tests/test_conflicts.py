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
import difflib


class Fixture(runtests.Fixture):

    # currently applied struc conflicts are not detected
    # and silently overwritten by the last commit
    def test_conflict_applied_struc(self):
        a, b = self.setup_repos()

        # create two structs with similar layout
        a.run(
            self.script("""
# touch target basic block & clear git noise later on
ea = 0x6602A7AF
idc.set_name(ea, "nope")

eida = idaapi.add_struc(-1, "name_a", False)
idc.add_struc_member(eida, "a_top", 0, idaapi.FF_DATA, -1, 8)
idc.add_struc_member(eida, "a_bot", 8, idaapi.FF_DATA, -1, 4)

eidb = idaapi.add_struc(-1, "name_b", False)
idc.add_struc_member(eidb, "b_top", 0, idaapi.FF_DATA, -1, 8)
idc.add_struc_member(eidb, "b_bot", 8, idaapi.FF_DATA, -1, 4)
"""),
            self.save_strucs(),
        )

        # apply first struc in first base
        set_tid = """
def set_tid(ea, n, name):
    path = idaapi.tid_array(1)
    path[0] = idc.get_struc_id(name)
    insn = ida_ua.insn_t()
    insn_len = ida_ua.decode_insn(insn, ea)
    idaapi.op_stroff(insn, n, path.cast(), 1, 0)

"""
        b.run(
            self.check_strucs(),
            self.script(set_tid + """
ea = 0x6602A7B8
set_tid(ea, 1, "name_b")
"""),
            self.save_last_ea(),
        )
        b.check_git(modified=["basic_block"])
        want = self.eas[self.last_ea]

        # apply second struc in second base
        a.run_no_sync(
            self.script(set_tid + """
ea = 0x6602A7B8
set_tid(ea, 1, "name_a")
"""),
            self.save_last_ea(),
        )
        a.check_git(modified=["basic_block"])

        # overwrite value & check first ea saved
        b.run(
            self.check_last_ea(),
            self.script(set_tid + """
ea = 0x6602A7B8
set_tid(ea, 1, "name_b")
"""),
            self.save_last_ea(),
        )
        got = self.eas[self.last_ea]
        if want[1] != got[1]:
            self.fail("\n" + "".join(difflib.unified_diff(want[1].splitlines(1), got[1].splitlines(1), want[0], got[0])))
