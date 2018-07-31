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

    def test_extra_line_on_data(self):
        a, b = self.setup_cmder()
        a.run(
            self.script("""
ea = 0x414204
ida_lines.add_extra_line(ea, True, "some prev line")
ea = 0x41421C
ida_lines.add_extra_line(ea, True, "some prev line")
"""),
            self.save_ea(0x414204),
            self.save_ea(0x41421C),
        )
        a.check_git(added=["binary", "segment", "segment_chunk"] + ["data"] * 2)

        b.run(
            self.check_ea(0x414204),
            self.check_ea(0x41421C),
            self.script("""
ea = 0x414204
ida_lines.del_extra_cmt(ea, ida_lines.E_PREV)
ea = 0x41421C
ida_lines.del_extra_cmt(ea, ida_lines.E_PREV)
"""),
            self.save_ea(0x414204),
            self.save_ea(0x41421C),
        )
        b.check_git(modified=["segment_chunk", "data"], deleted=["data"])

        a.run(
            self.check_ea(0x414204),
            self.check_ea(0x41421C),
        )

    def test_invsign_on_data(self):
        a, b = self.setup_cmder()

        # IDA does not always send signbit events
        # abuse create_byte as a workaround
        a.run(
            self.script("""
ea = 0x414204
ida_bytes.create_byte(ea, 1)
ida_bytes.toggle_sign(ea, 0)
ea = 0x41421C
ida_bytes.create_byte(ea, 1)
ida_bytes.toggle_sign(ea, 0)
"""),
            self.save_ea(0x414204),
            self.save_ea(0x41421C),
        )
        a.check_git(added=["binary", "segment", "segment_chunk"] + ["data"] * 2)

        # untoggle sign
        b.run(
            self.check_ea(0x414204),
            self.check_ea(0x41421C),
            self.script("""
ea = 0x414204
ida_bytes.create_byte(ea, 1)
ida_bytes.toggle_sign(ea, 0)
ea = 0x41421C
ida_bytes.create_byte(ea, 1)
ida_bytes.toggle_sign(ea, 0)
"""),
            self.save_ea(0x414204),
            self.save_ea(0x41421C),
        )
        # one data is modified, one data become uninteresting & is deleted
        b.check_git(modified=["segment_chunk", "data"], deleted=["data"])

        a.run(
            self.check_ea(0x414204),
            self.check_ea(0x41421C),
        )

    def test_bnot_on_data(self):
        a, b = self.setup_cmder()

        # IDA does not always send bnot events
        # abuse create_byte as a workaround
        a.run(
            self.script("""
ea = 0x414204
ida_bytes.create_byte(ea, 1)
ida_bytes.toggle_bnot(ea, 0)
ea = 0x41421C
ida_bytes.create_byte(ea, 1)
ida_bytes.toggle_bnot(ea, 0)
"""),
            self.save_ea(0x414204),
            self.save_ea(0x41421C),
        )
        a.check_git(added=["binary", "segment", "segment_chunk"] + ["data"] * 2)

        # untoggle bnot
        b.run(
            self.check_ea(0x414204),
            self.check_ea(0x41421C),
            self.script("""
ea = 0x414204
ida_bytes.create_byte(ea, 1)
ida_bytes.toggle_bnot(ea, 0)
ea = 0x41421C
ida_bytes.create_byte(ea, 1)
ida_bytes.toggle_bnot(ea, 0)
"""),
            self.save_ea(0x414204),
            self.save_ea(0x41421C),
        )
        # one data is modified, one data become uninteresting & is deleted
        b.check_git(modified=["segment_chunk", "data"], deleted=["data"])

        a.run(
            self.check_ea(0x414204),
            self.check_ea(0x41421C),
        )
