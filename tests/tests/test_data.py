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

    def test_cmt_on_unexplored_data(self):
        a, b = self.setup_cmder()
        a.run(
            self.script("""
ea = 0x413B53
ida_bytes.set_cmt(ea, "some comment", 0)
"""),
            self.save_last_ea(),
        )
        a.check_git(added=["binary", "segment", "segment_chunk", "data"])

        b.run(
            self.check_last_ea(),
        )
        self.check_range(b, 0x413B40, 0x413BA4, """
0x413b40: data: data byte ref labl
0x413b53: unexplored: unkn comm
0x413b9c: data: data strlit ref labl name
""")

    def test_extra_line_on_unexplored_data(self):
        a, b = self.setup_cmder()
        a.run(
            self.script("""
ea = 0x413B53
ida_lines.add_extra_line(ea, True, "some prev line")
"""),
            self.save_last_ea(),
        )
        a.check_git(added=["binary", "segment", "segment_chunk", "data"])

        b.run(
            self.check_last_ea(),
        )
        self.check_range(b, 0x413B40, 0x413BA4, """
0x413b40: data: data byte ref labl
0x413b53: unexplored: unkn line
0x413b9c: data: data strlit ref labl name
""")
