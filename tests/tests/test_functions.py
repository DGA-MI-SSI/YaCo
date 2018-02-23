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
        a.run(
            self.script("""
ea = 0x6602E530
idaapi.set_name(ea, "funcname_01", idaapi.SN_PUBLIC)
"""),
            self.save_last_ea(),
        )
        b.run(
            self.check_last_ea(),
            self.script("""
ea = 0x6602E530
idaapi.set_name(ea, "")
"""),
            self.save_last_ea(),
        )
        b.check_git(modified=["basic_block"])
        a.run(
            self.check_last_ea(),
        )

    def test_rename_stackframe_members(self):
        a, b = self.setup_repos()
        a.run(
            self.script("""
ea = 0x6602E530
frame = idaapi.get_frame(ea)
idaapi.set_member_name(frame, 0x4,  "local_b")
idaapi.set_member_name(frame, 0x20, "arg_b")
"""),
            self.save_last_ea(),
        )
        b.run(
            self.check_last_ea(),
            # now rename a single stack member from b
            # only one file will be modified under git
            # check whether the rename is still applied
            self.script("""
ea = 0x6602E530
frame = idaapi.get_frame(ea)
idaapi.set_member_name(frame, 0x4,  "another_name")
"""),
            self.save_last_ea(),
        )
        b.check_git(modified=["stackframe_member"])
        a.run(
            self.check_last_ea(),
        )

    def test_create_and_rename_function(self):
        a, b = self.setup_repos()
        a.run(
            self.script("""
ea = 0x6602E530
idc.add_func(ea)
ida_auto.plan_and_wait(ea, idc.find_func_end(ea))
idaapi.set_name(ea, "new_function_E530")
"""),
            self.save_last_ea(),
        )
        a.check_git(added=["binary", "segment", "segment_chunk", "segment_chunk"] +
            ["function", "stackframe"] * 3 + ["stackframe_member"] * 13 +
            ["basic_block"] * 18)
        b.run(
            self.check_last_ea(),
        )

    def test_function_to_code_to_undef_and_back_again(self):
        a, b = self.setup_repos()

        # we fix parent xref first so results are not polluted
        # with parent xrefs changes
        # touch parent xref
        b.run(
            self.script("""
ea = 0x66053110
idc.set_name(ea, "nope")
"""),
            self.save_last_ea(),
        )
        b.check_git(added=["binary", "segment", "segment_chunk", "data"])

        # remove parent xref
        a.run(
            self.check_last_ea(),
            self.script("""
ea = 0x66053110
idc.del_items(ea, idc.DELIT_EXPAND, 0x4)
"""),
            self.save_last_ea(),
        )
        a.check_git(modified=["segment_chunk"], deleted=["data"])

        # touch function
        b.run(
            self.check_last_ea(),
            self.script("""
ea = 0x66005510
frame = idaapi.get_frame(ea)
offset = idc.get_first_member(frame.id)
idaapi.set_member_name(frame, offset, "zorg")
"""),
            self.save_last_ea(),
        )
        b.check_git(added=["segment", "segment_chunk", "function",
            "stackframe", "stackframe_member", "basic_block"])

        # lower function to code
        a.run(
            self.check_last_ea(),
            self.script("""
ea = 0x66005510
idc.del_func(ea)
"""),
            self.save_last_ea(),
        )
        a.check_git(added=["code"], deleted=["function", "stackframe", "stackframe_member", "basic_block"], modified=["segment_chunk"])

        # lower code to undefined data
        b.run(
            self.check_last_ea(),
            self.script("""
ea = 0x66005510
idc.del_items(ea, idc.DELIT_SIMPLE, 0xD)
"""),
            self.save_last_ea(),
        )
        b.check_git(deleted=["code"], modified=["segment_chunk"])

        # set code again
        a.run(
            self.check_last_ea(),
            self.script("""
ea = 0x66005510
ida_auto.auto_make_code(ea)
ida_auto.auto_wait()
"""),
            self.save_last_ea(),
        )
        a.check_git(added=["code"], modified=["segment_chunk"])

        # set function again
        b.run(
            self.check_last_ea(),
            self.script("""
ea = 0x66005510
idc.add_func(ea)
ida_auto.plan_and_wait(ea, idc.find_func_end(ea))
"""),
            self.save_last_ea(),
        )
        # default stackframe_member is ignored
        b.check_git(added=["function", "stackframe", "basic_block"], modified=["segment_chunk"], deleted=["code"])
        a.run(
            self.check_last_ea(),
        )

    def test_create_function_then_undefined_func(self):
        a, b = self.setup_repos()
        a.run(
            self.script("""
ea = 0x6600EF30
idc.add_func(ea)
ida_auto.plan_and_wait(ea, idc.find_func_end(ea))
idaapi.set_name(ea, "new_function_EF30")
"""),
            self.save_last_ea(),
        )
        b.run(
            self.check_last_ea(),
        )

    def test_transform_function_to_byte_array(self):
        a, b = self.setup_repos()
        a.run(
            self.script("""
ea = 0x6600100F
idc.del_items(ea, idc.DELIT_SIMPLE, 5)
"""),
            self.save_last_ea(),
        )
        a.check_git(added=["binary", "segment", "segment_chunk", "segment_chunk",
            "function", "stackframe", "stackframe_member", "stackframe_member",
            "basic_block", "data"])
        b.run(
            self.check_last_ea(),
            self.script("""
ea = 0x6600100F
idc.create_data(ea, FF_BYTE, 1, ida_idaapi.BADADDR)
idc.make_array(ea, 5)
"""),
            self.save_last_ea(),
        )
        b.check_git(modified=["data"])
        a.run(
            self.check_last_ea(),
        )

    def test_create_function_from_code(self):
        a, b = self.setup_repos()
        a.run(
            self.script("""
ea = 0x6600EF30
idc.add_func(ea)
ida_auto.plan_and_wait(ea, idc.find_func_end(ea))
"""),
            self.save_last_ea(),
        )
        b.run(
            self.check_last_ea(),
        )

    def test_create_function_then_undefined_func(self):
        a, b = self.setup_repos()
        a.run(
            self.script("""
ea = 0x6600EF30
idc.add_func(ea)
ida_auto.plan_and_wait(ea, idc.find_func_end(ea))
idaapi.set_name(ea, "new_function_EF30")
"""),
            self.save_last_ea(),
        )
        b.run(
            self.check_last_ea(),
            self.script("""
ea = 0x6600EF30
idc.del_items(ea, idc.DELIT_EXPAND, 0x2c)
idc.create_dword(ea)
idc.make_array(ea, 11)
"""),
            self.save_last_ea(),
        )
        a.run(
            self.check_last_ea(),
        )

    def test_code_to_data_to_func_and_back(self):
        a, b = self.setup_repos()

        # reset parent xref
        a.run(
            self.script("""
ea = 0x66002658
idc.del_items(ea, idc.DELIT_EXPAND, 5)
idc.create_byte(ea)
idc.make_array(ea, 5)
idaapi.set_name(0x6600EF30, "somename")
"""),
            self.save_last_ea(),
        )
        # 0x6600EF30 is func on win32 & code on linux
        # skip git checks

        # lower function to code
        b.run(
            self.check_last_ea(),
            self.script("""
ea = 0x6600EF30
idc.del_func(ea)
"""),
            self.save_last_ea(),
        )
        # once again, cannot check git
        # because ea is already code on linux

        # replace code with dword array
        a.run(
            self.check_last_ea(),
            self.script("""
ea = 0x6600EF30
idc.del_items(ea, idc.DELIT_EXPAND, 0x2c)
idc.create_dword(ea)
idc.make_array(ea, 11)
"""),
            self.save_last_ea(),
        )
        a.check_git(added=["data"], deleted=["code"])

        # replace array with code
        b.run(
            self.check_last_ea(),
            self.script("""
ea = 0x6600EF30
idc.del_items(ea, idc.DELIT_EXPAND, 0x2c)
ida_auto.auto_make_code(ea)
ida_auto.auto_wait()
"""),
            self.save_last_ea(),
        )
        b.check_git(added=["code"], deleted=["data"])

        # restore function
        a.run(
            self.check_last_ea(),
            self.script("""
ea = 0x6600EF30
idc.add_func(ea)
ida_auto.plan_and_wait(ea, idc.find_func_end(ea))
idaapi.set_name(ea, "new_function_EF30_2")
"""),
            self.save_last_ea(),
        )
        a.check_git(deleted=["code"], modified=["segment_chunk"],
            added=["function", "stackframe"] + ["stackframe_member"] * 2 + ["basic_block"] * 3)
        b.run(
            self.check_last_ea(),
        )

    def test_rename_and_undefine_func(self):
        a, b = self.setup_repos()
        a.run(
            self.script("""
ea = 0x6600EF70
idaapi.set_name(ea, "new_function_EF30")
"""),
            self.save_last_ea(),
        )
        b.run(
            self.check_last_ea(),
            self.script("""
ea = 0x6600EF70
idc.del_items(ea, idc.DELIT_EXPAND, 0x2c)
"""),
            self.save_last_ea(),
        )
        b.check_git(added=["data"], deleted=["function", "stackframe",
            "stackframe_member", "stackframe_member", "basic_block"], modified=["segment_chunk"])
        a.run(
            self.check_last_ea(),
        )
