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

    def test_func_to_code_to_undef_and_back(self):
        a, b = self.setup_repos()

        # remove parent xref noise first
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

    def test_func_to_data(self):
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

    def transform_func_6600EF30_into_code(self, a, b):
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
        # skip git checks as ea has no parent xref on linux
        # lower function to code
        b.run(
            self.check_last_ea(),
            self.script("""
ea = 0x6600EF30
idc.del_func(ea)
ida_auto.auto_make_code(ea)
ida_auto.auto_wait()
"""),
            self.save_last_ea(),
        )
        # once again, cannot do git checks
        # because ea is already code on linux
        a.run(
            self.check_last_ea(),
        )

    def test_code_to_func_to_data(self):
        a, b = self.setup_repos()
        self.transform_func_6600EF30_into_code(a, b)

        # code to func
        a.run(
            self.script("""
ea = 0x6600EF30
idc.add_func(ea)
ida_auto.plan_and_wait(ea, idc.find_func_end(ea))
idaapi.set_name(ea, "new_function_EF30")
"""),
            self.save_last_ea(),
        )
        func = ["function", "stackframe"] + ["stackframe_member"] * 2 + ["basic_block"] * 3
        a.check_git(added=func, modified=["segment_chunk"], deleted=["code"])

        # func to data
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
        b.check_git(added=["data"], modified=["segment_chunk"], deleted=func)
        a.run(
            self.check_last_ea(),
        )

    def test_code_to_data_to_code(self):
        a, b = self.setup_repos()
        self.transform_func_6600EF30_into_code(a, b)

        # code to data
        a.run(
            self.script("""
ea = 0x6600EF30
idc.del_items(ea, idc.DELIT_EXPAND, 0x2c)
idc.create_dword(ea)
idc.make_array(ea, 11)
"""),
            self.save_last_ea(),
        )
        a.check_git(added=["data"], deleted=["code"])

        # data to code
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

    def test_data_to_func_to_code(self):
        a, b = self.setup_repos()
        self.transform_func_6600EF30_into_code(a, b)

        # code to data
        a.run(
            self.script("""
ea = 0x6600EF30
idc.del_items(ea, idc.DELIT_EXPAND, 0x2c)
idc.create_dword(ea)
idc.make_array(ea, 11)
"""),
            self.save_last_ea(),
        )
        a.check_git(added=["data"], deleted=["code"])

        # data to func
        b.run(
            self.script("""
ea = 0x6600EF30
idc.del_items(ea, idc.DELIT_EXPAND, 0x2c)
idc.add_func(ea)
ida_auto.plan_and_wait(ea, idc.find_func_end(ea))
"""),
            self.save_last_ea(),
        )
        func = ["function", "stackframe"] + ["stackframe_member"] * 2 + ["basic_block"] * 3
        b.check_git(added=func, modified=["segment_chunk"], deleted=["data"])

        # func to code
        a.run(
            self.script("""
ea = 0x6600EF30
idc.del_func(ea)
"""),
            self.save_last_ea(),
        )
        a.check_git(added=["code"], modified=["segment_chunk"], deleted=func)
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

    def test_data_to_block(self):
        a, b = self.setup_repos()
        a.run(
            self.script("""
ea = 0x66023DA0
frame = idaapi.get_frame(ea)
idaapi.set_member_name(frame, 0x8,  "another_name")
"""),
            self.save_last_ea(),
        )
        a.check_git(added=["binary", "segment", "segment_chunk", "function", "stackframe"] +
            ["stackframe_member"] * 18 + ["basic_block"] * 23)

        b.run(
            self.check_last_ea(),
            self.script("""
ea = 0x66024004
idaapi.create_insn(ea)
ida_auto.auto_wait()
"""),
            self.save_last_ea(),
        )
        b.check_git(modified=["function", "basic_block"], added=["basic_block"] * 2)

        a.run(
            self.check_last_ea(),
            self.script("""
ea = 0x66024004
idc.del_items(ea, idc.DELIT_EXPAND, 0xE)
ida_auto.auto_wait()
"""),
            self.save_last_ea(),
        )
        # FIXME data inside functions is a bit glitchy
        a.check_git(added=["data"] * 2, deleted=["basic_block"] * 2, modified=["basic_block", "function", "segment_chunk"])

        b.run(
            self.check_last_ea(),
        )
