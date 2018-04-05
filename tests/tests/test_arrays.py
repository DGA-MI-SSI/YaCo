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

class Fixture(runtests.Fixture):

    def test_struc_arrays(self):
        a, b = self.setup_repos()
        a.run(
            self.script("""
idc.add_struc_member(idaapi.add_struc(-1, "sa", False), "fa", 0, idaapi.FF_DATA, -1, 4)
idc.add_struc_member(idaapi.add_struc(-1, "sb", False), "fb", 0, idaapi.FF_DATA, -1, 5)
idaapi.add_struc(-1, "sc", False)
"""),
            self.save_strucs(),
        )
        a.check_git(added=["struc"] * 3 + ["strucmember"] * 2)
        b.run(
            self.check_strucs(),
            self.script("""
sa = idc.get_struc_id("sa")
sc = idc.get_struc_id("sc")
sa_size = idaapi.get_struc_size(sa) * 3
idc.add_struc_member(sc, "fa", 0, idaapi.FF_STRU | idaapi.FF_DATA, sa, sa_size, -1)
"""),
            self.save_strucs(),
        )
        b.check_git(added=["strucmember"], modified=["struc"] * 2)
        a.run(
            self.check_strucs(),
            self.script("""
sa = idc.get_struc_id("sa")
sb = idc.get_struc_id("sb")
sc = idc.get_struc_id("sc")
sa_size = idaapi.get_struc_size(sa) * 3
sb_size = idaapi.get_struc_size(sb) * 5
idc.add_struc_member(sc, "fb", sa_size, idaapi.FF_STRU | idaapi.FF_DATA, sb, sb_size, -1)
"""),
            self.save_strucs(),
        )
        a.check_git(added=["strucmember"], modified=["struc"] * 2)
        b.run(
            self.check_strucs(),
        )

    def test_struc_array_hole(self):
        a, b = self.setup_repos()
        a.run(
            self.script("""
sa = idaapi.add_struc(-1, "sa", False)
sb = idaapi.add_struc(-1, "sb", False)
sc = idaapi.add_struc(-1, "sc", False)
idc.add_struc_member(sa, "field_0", 0, idaapi.FF_DATA, -1, 4)
idc.add_struc_member(sb, "field_0", 0, idaapi.FF_DATA, -1, 6)
sa_size = idaapi.get_struc_size(sa) * 3
sb_size = idaapi.get_struc_size(sb) * 5
idc.add_struc_member(sc, "field_0", 0, idaapi.FF_STRU | idaapi.FF_DATA, sa, sa_size, -1)
idc.add_struc_member(sc, "field_C", sa_size, idaapi.FF_STRU | idaapi.FF_DATA, sb, sb_size, -1)
"""),
            self.save_strucs(),
        )
        a.check_git(added=["struc"] * 3 + ["strucmember"] * 4)
        b.run(
            self.check_strucs(),
            self.script("""
sa = idc.get_struc_id("sa")
sb = idc.get_struc_id("sb")
sc = idc.get_struc_id("sc")
sa_size = idaapi.get_struc_size(sa) * 2
sb_size = idaapi.get_struc_size(sb) * 2
idaapi.del_struc_member(idaapi.get_struc(sc), 0)
idc.add_struc_member(sc, "field_0", 0, idaapi.FF_STRU | idaapi.FF_DATA, sa, sa_size, -1)
fcb_offset = idaapi.get_struc_size(sa) * 3
idaapi.del_struc_member(idaapi.get_struc(sc), fcb_offset)
idc.add_struc_member(sc, "field_C", fcb_offset, idaapi.FF_STRU | idaapi.FF_DATA, sb, sb_size, -1)
"""),
            self.save_strucs(),
        )
        b.check_git(modified=["struc"] * 3 + ["strucmember"] * 2)
        a.run(
            self.check_strucs(),
        )
