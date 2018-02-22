#!/bin/python

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


import runtests
import unittest


class Fixture(runtests.Fixture):

    def test_touch_function(self):
        a, b = self.setup_repos()
        ea = 0x66032B50
        a.run(
            self.script("""
ea = 0x66032B50
frame = idaapi.get_frame(ea)
idaapi.set_member_name(frame, 0, "somevar")
"""),
        )
        a.check_git(
            added=[
                "binary", "segment", "segment_chunk", "function", "basic_block",
                "stackframe", "stackframe_member", "stackframe_member",
            ]
        )

    def test_rename_function(self):
        a, b = self.setup_repos()
        ea = 0x6602E530
        a.run(
            self.script("""
ea = 0x6602E530
idaapi.set_name(ea, "funcname_01", idaapi.SN_PUBLIC)
"""),
            self.save_ea(ea),
        )
        b.run(
            self.check_ea(ea),
            self.script("""
ea = 0x6602E530
idaapi.set_name(ea, "")
"""),
            self.save_ea(ea),
        )
        b.check_git(modified=["basic_block"])
        a.run(
            self.check_ea(ea),
        )

    def test_rename_stackframe_members(self):
        a, b = self.setup_repos()
        ea = 0x6602E530
        a.run(
            self.script("""
ea = 0x6602E530
frame = idaapi.get_frame(ea)
idaapi.set_member_name(frame, 0x4,  "local_b")
idaapi.set_member_name(frame, 0x20, "arg_b")
"""),
            self.save_ea(ea),
        )
        b.run(
            self.check_ea(ea),
            # now rename a single stack member from b
            # only one file will be modified under git
            # check whether the rename is still applied
            self.script("""
ea = 0x6602E530
frame = idaapi.get_frame(ea)
idaapi.set_member_name(frame, 0x4,  "another_name")
"""),
            self.save_ea(ea),
        )
        b.check_git(modified=["stackframe_member"])
        a.run(
            self.check_ea(ea),
        )

    def test_create_function(self):
        a, b = self.setup_repos()
        ea = 0x6600EDF0
        a.run(
            self.script("""
ea = 0x6600EDF0
idc.add_func(ea)
"""),
            self.save_ea(ea)
        )
        # FIXME a.check_git(SOMETHING)
        b.run(
            self.check_ea(ea),
        )

    def test_create_and_rename_function(self):
        a, b = self.setup_repos()
        ea = 0x6602E530
        a.run(
            self.script("""
ea = 0x6602E530
idc.add_func(ea)
ida_auto.plan_and_wait(ea, idc.find_func_end(ea))
idaapi.set_name(ea, "new_function_E530")
"""),
            self.save_ea(ea)
        )
        a.check_git(added=["binary", "segment", "segment_chunk", "segment_chunk"] +
            ["function", "stackframe"] * 3 + ["stackframe_member"] * 13 +
            ["basic_block"] * 18)
        b.run(
            self.check_ea(ea),
        )

    def test_delete_function_only(self):
        a, b = self.setup_repos()

        # we fix parent xref first so results are not polluted
        # with parent xrefs changes
        # touch parent xref
        parent_ea = 0x66053110
        b.run(
            self.script("""
ea = 0x66053110
idc.set_name(ea, "nope")
"""),
            self.save_ea(parent_ea),
        )
        b.check_git(added=["binary", "segment", "segment_chunk", "data"])

        # remove parent xref
        ea = 0x66005510
        a.run(
            self.check_ea(parent_ea),
            self.script("""
parent_ea = 0x66053110
idc.del_items(parent_ea, idc.DELIT_EXPAND, 0x4)
"""),
            self.save_ea(parent_ea),
        )
        a.check_git(modified=["segment_chunk"], deleted=["data"])

        # touch function
        b.run(
            self.check_ea(parent_ea),
            self.script("""
ea = 0x66005510
frame = idaapi.get_frame(ea)
offset = idc.get_first_member(frame.id)
idaapi.set_member_name(frame, offset, "zorg")
"""),
            self.save_ea(ea),
        )
        b.check_git(added=["segment", "segment_chunk", "function",
            "stackframe", "stackframe_member", "basic_block"])

        # lower function to code
        a.run(
            self.check_ea(ea),
            self.script("""
ea = 0x66005510
idc.del_func(ea)
"""),
            self.save_ea(ea),
        )
        a.check_git(added=["code"], deleted=["function", "stackframe", "stackframe_member", "basic_block"], modified=["segment_chunk"])

        # lower code to undefined data
        b.run(
            self.check_ea(ea),
            self.script("""
ea = 0x66005510
idc.del_items(ea, idc.DELIT_SIMPLE, 0xD)
"""),
            self.save_ea(ea),
        )
        b.check_git(deleted=["code"], modified=["segment_chunk"])
        a.run(
            self.check_ea(ea),
        )

    @unittest.skip("not implemented yet")
    def test_transform_code_to_function(self):
        a, b = self.setup_repos()
        ea = 0x6600100F
        a.run(
            self.script("""
ea = 0x6600100F
idc.del_items(ea, idc.DELIT_SIMPLE, 5)
"""),
            self.save_ea(ea)
        )
        b.run(
            self.check_ea(ea),
            self.script("""
idc.create_data(0x6600100F, FF_BYTE, 1, ida_idaapi.BADADDR)
idc.make_array(0x6600100F, 5)"""),
            self.save_ea(ea)
        )
        a.run(self.check_ea(ea))

    def test_create_function_then_undefined_func(self):
        a, b = self.setup_repos()
        ea = 0x6600EF30
        a.run(
            self.script("""
ea = 0x6600EF30
idc.add_func(ea)
ida_auto.plan_and_wait(ea, idc.find_func_end(ea))
idaapi.set_name(ea, "new_function_EF30")
"""),
            self.save_ea(ea)
        )
        # FIXME a.check_git(SOMETHING)
        b.run(
            self.check_ea(ea)
        )

    @unittest.skip("not implemented yet")
    def test_transform_function_to_byte_array(self):
        a, b = self.setup_repos()
        ea = 0x6600100F
        a.run(
            self.script("""
ea = 0x6600100F
idc.del_items(ea, idc.DELIT_SIMPLE, 5)
"""),
            self.save_ea(ea)
        )
        b.run(
            self.check_ea(ea),
            self.script("""
idc.create_data(0x6600100F, FF_BYTE, 1, ida_idaapi.BADADDR)
idc.make_array(0x6600100F, 5)"""),
            self.save_ea(ea)
        )
        a.run(self.check_ea(ea))

    def test_create_function_from_code(self):
        a, b = self.setup_repos()
        ea = 0x6600EF30
        a.run(
            self.script("""
ea = 0x6600EF30
idc.add_func(ea)
ida_auto.plan_and_wait(ea, idc.find_func_end(ea))
# idaapi.set_name(ea, "new_function_EF30")
"""),
            self.save_ea(ea)
        )
        b.run(
            self.check_ea(ea)
        )

    def test_create_function_then_undefined_func(self):
        a, b = self.setup_repos()
        ea = 0x6600EF30
        a.run(
            self.script("""
ea = 0x6600EF30
idc.add_func(ea)
ida_auto.plan_and_wait(ea, idc.find_func_end(ea))
idaapi.set_name(ea, "new_function_EF30")
"""),
            self.save_ea(ea)
        )
        b.run(
            self.check_ea(ea),
            self.script("""
ea = 0x6600EF30
idc.del_items(ea, idc.DELIT_EXPAND, 0x2c)
idc.create_dword(ea)
idc.make_array(ea, 11)
"""),
            self.save_ea(ea)
        )
        a.run(
            self.check_ea(ea)
        )

    @unittest.skip("not implemented yet")
    def test_create_data_then_function(self):
        a, b = self.setup_repos()
        ea = 0x6600EF30
        # first delete code to create DWord array
        a.run(
            self.script("""
ea = 0x6600EF30
idc.del_items(ea, idc.DELIT_EXPAND, 0x2c)
idc.create_dword(ea)
idc.make_array(ea, 11)
"""),
            self.save_ea(ea)
        )
        # then delete array to create code
        b.run(
            self.check_ea(ea),
        )
        b.run(
            self.script("""
ea = 0x6600EF30
idc.del_items(ea, idc.DELIT_EXPAND, 0x2c)
idc.create_insn(ea)
ida_auto.plan_and_wait(ea, ea+0x2c)
"""),
            self.save_ea(ea)
        )
        # finally create function
        a.run(
            self.check_ea(ea),
            self.script("""
ea = 0x6600EF30
idc.add_func(ea)
ida_auto.plan_and_wait(ea, idc.find_func_end(ea))
idaapi.set_name(ea, "new_function_EF30_2")"""),
            self.save_ea(ea)
        )
        b.run(
            self.check_ea(ea)
        )

    def test_rename_and_undefine_func(self):
        a, b = self.setup_repos()
        ea = 0x6600EF70
        a.run(
            self.script("""
ea = 0x6600EF70
idaapi.set_name(ea, "new_function_EF30")
"""),
            self.save_ea(ea)
        )
        b.run(
            self.check_ea(ea),
            self.script("""
ea = 0x6600EF70
idc.del_items(ea, idc.DELIT_EXPAND, 0x2c)
"""),
            self.save_ea(ea)
        )
        b.check_git(added=["data"], deleted=["function", "stackframe",
            "stackframe_member", "stackframe_member", "basic_block"], modified=["segment_chunk"])
        a.run(
            self.check_ea(ea)
        )
