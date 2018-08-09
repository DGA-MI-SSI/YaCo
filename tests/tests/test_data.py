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

    def test_cmt_on_data(self):
        a, b = self.setup_cmder()
        a.run(
            self.script("""
ea = 0x414204
ida_bytes.set_cmt(ea, "some comment", 0)
ea = 0x41421C
ida_bytes.set_cmt(ea, "some comment", 0)
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
ida_bytes.set_cmt(ea, "", 0)
ea = 0x41421C
ida_bytes.set_cmt(ea, "", 0)
"""),
            self.save_ea(0x414204),
            self.save_ea(0x41421C),
        )
        b.check_git(modified=["segment_chunk", "data"], deleted=["data"])

        a.run(
            self.check_ea(0x414204),
            self.check_ea(0x41421C),
        )

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

    def test_op_type_on_data(self):
        a, b = self.setup_cmder()

        a.run(
            self.script("""
ea = 0x414204
ida_bytes.op_seg(ea, 0)
ea = 0x41421C
ida_bytes.op_dec(ea, 0)
"""),
            self.save_ea(0x414204),
            self.save_ea(0x41421C),
        )
        a.check_git(added=["binary", "segment", "segment_chunk"] + ["data"] * 2)

        # remove op types
        b.run(
            self.check_ea(0x414204),
            self.check_ea(0x41421C),
            self.script("""
ea = 0x414204
ida_bytes.clr_op_type(ea, 0)
ea = 0x41421C
ida_bytes.del_items(ea, 0, 4)
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

    def test_op_offset_on_data(self):
        a, b = self.setup_cmder()

        # ensure one ea is always "interesting" by setting a name
        # FIXME we cannot handle a data item which become uninteresting
        # *before*  it is at least stored once in cache...
        a.run(
            self.script("""
ea = 0x414714
idaapi.set_name(ea, "somename")
ida_bytes.clr_op_type(ea, 0)
ea = 0x414718
ida_bytes.del_items(ea, 0, 4)
"""),
        )

        # add offset op type
        a.run(
            self.script("""
ea = 0x414714
ida_offset.op_offset(ea, 0, ida_nalt.REF_OFF32)
ea = 0x414718
ida_offset.op_offset(ea, 0, ida_nalt.REF_OFF32)
"""),
            self.save_ea(0x414714),
            self.save_ea(0x414718),
        )
        a.check_git(modified=["segment_chunk", "data"], added=["data"])

        b.run(
            self.check_ea(0x414714),
            self.check_ea(0x414718),
            self.script("""
ea = 0x414714
ida_bytes.clr_op_type(ea, 0)
ea = 0x414718
ida_bytes.del_items(ea, 0, 4)
"""),
            self.save_ea(0x414714),
            self.save_ea(0x414718),
        )
        b.check_git(modified=["segment_chunk", "data"], deleted=["data"])

        a.run(
            self.check_ea(0x414714),
            self.check_ea(0x414718),
        )

    def test_align_data(self):
        a, b = self.setup_cmder()

        a.run(
            self.script("""
ea = 0x41470C
idaapi.set_name(ea, "somename")
ea = 0x414CC0
ida_bytes.create_align(ea, 0x40, 0)
"""),
            self.save_last_ea(),
        )
        a.check_git(added=["binary", "segment", "segment_chunk", "data", "data"])

        b.run(
            self.check_last_ea(),
            self.script("""
ea = 0x41470C
ida_bytes.del_items(ea, idc.DELIT_EXPAND, 4)
ea = 0x414CC0
ida_bytes.del_items(ea, idc.DELIT_EXPAND, 0x40)
"""),
            self.save_ea(0x41470C),
            self.save_ea(0x414CC0),
        )
        b.check_git(modified=["segment_chunk", "data"], deleted=["data"])

        a.run(
            self.check_ea(0x41470C),
            self.check_ea(0x414CC0),
        )

    def test_data_types_only(self):
        a, b = self.setup_cmder()

        a.run(
            self.script("""
ea = 0x415096
ida_bytes.create_word(ea, 2)
ea = 0x4150A0
idc.SetType(ea, "GUID")
"""),
            self.save_ea(0x415096),
            self.save_ea(0x4150A0),
        )
        a.check_git(added=["binary", "segment", "segment_chunk", "data", "data"])

        b.run(
            self.check_ea(0x415096),
            self.check_ea(0x4150A0),
            self.script("""
ea = 0x415096
ida_bytes.create_byte(ea, 1)
ea = 0x4150A0
ida_bytes.del_items(ea, 0, 0x10)
"""),
            self.save_ea(0x415096),
            self.save_ea(0x4150A0),
        )
        b.check_git(modified=["segment_chunk"], deleted=["data"] * 2)

        a.run(
            self.check_ea(0x415096),
            self.check_ea(0x4150A0),
        )
