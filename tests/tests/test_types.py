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

    def test_set_data_as_array_type(self):
        a, b = self.setup_cmder()

        # apply a type without deleting items first
        a.run(
            self.script("""
sid = idaapi.add_struc(-1, "sa", False)
idc.add_struc_member(sid, "off", 0, idaapi.FF_DWORD, -1, 4)
idc.add_struc_member(sid, "tag", 4, idaapi.FF_STRLIT, -1, 4)
mid = idc.get_member_id(sid, 0)
idc.SetType(mid, "void*")

ea = 0x4161E8
pt = idc.parse_decl("sa[228]", 0)
idc.apply_type(ea, pt)
"""),
            self.save_strucs(),
            self.save_last_ea(),
        )
        a.check_git(added=["binary", "segment", "segment_chunk", "data", "struc", "strucmember", "strucmember"])

        b.run(
            self.check_last_ea(),
            self.check_strucs(),
        )
        b.check_git(added=["binary", "segment", "segment_chunk", "data", "struc", "strucmember", "strucmember"])

        # delete all items & make sure type is applied on the whole size
        b.run(
            self.script("""
ea = 0x4161E8
pt = idc.parse_decl("sa[228]", 0)
ida_bytes.del_items(ea, 0, 228 * 8)
idc.apply_type(ea, pt)
"""),
            self.save_last_ea(),
        )
        b.check_git(modified=["segment_chunk", "data"])

        a.run(
            self.check_last_ea(),
        )
