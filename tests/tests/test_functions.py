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

import run_all_tests

set_function_name = """
ea = 0x6602E530
idaapi.set_name(ea, "funcname_01", idaapi.SN_PUBLIC)
"""

function_name = """
    <userdefinedname flags="0x00000052">funcname_01</userdefinedname>
"""

reset_function_name = """
ea = 0x6602E530
idaapi.set_name(ea, "")
"""

set_stackvar_names = """
ea = 0x6602E530
frame = idaapi.get_frame(ea)
idaapi.set_member_name(frame, 0x4,  "local_b")
idaapi.set_member_name(frame, 0x20, "arg_b")
"""

function_xrefs = """
    <xrefs>
      <xref offset="0x0000000000000000">3F51703267741413</xref>
      <xref offset="0x0000000000000004">9E4BF9B751B76EE4</xref>
      <xref offset="0x0000000000000008">DF49282D07F6D35D</xref>
      <xref offset="0x000000000000000C">68554BC584D35C79</xref>
      <xref offset="0x0000000000000010">2A38CD5584A021F0</xref>
      <xref offset="0x000000000000001C">638EC77150FA3C4B</xref>
      <xref offset="0x0000000000000020">3B75F00131A38ACC</xref>
      <xref offset="0x0000000000000024">4F64947E1EBC12C0</xref>
    </xrefs>
"""

local_b_var = """
<stackframe_member>
  <id>9E4BF9B751B76EE4</id>
  <version>
    <size>0x0000000000000004</size>
    <parent_id>569EF65FD6CB6A6F</parent_id>
    <address>4</address>
    <userdefinedname>local_b</userdefinedname>
"""

arg_b_var = """
<stackframe_member>
  <id>3B75F00131A38ACC</id>
  <version>
    <size>0x0000000000000004</size>
    <parent_id>569EF65FD6CB6A6F</parent_id>
    <address>20</address>
    <userdefinedname>arg_b</userdefinedname>
"""

rename_stackvars_again = """
ea = 0x6602E530
frame = idaapi.get_frame(ea)
idaapi.set_member_name(frame, 0x4,  "another_name")
"""

another_var = """
<stackframe_member>
  <id>9E4BF9B751B76EE4</id>
  <version>
    <size>0x0000000000000004</size>
    <parent_id>569EF65FD6CB6A6F</parent_id>
    <address>4</address>
    <userdefinedname>another_name</userdefinedname>
"""

class Fixture(run_all_tests.Fixture):

    def test_rename_function(self):
        a, b = self.setup_repos()
        ea = 0x6602E530
        a.run(set_function_name)
        b.check(self.has(ea, "1 << ya.OBJECT_TYPE_BASIC_BLOCK", function_name))
        b.run(reset_function_name)
        a.check(self.nothas(ea, "1 << ya.OBJECT_TYPE_BASIC_BLOCK", function_name))

    def test_rename_stackframe_members(self):
        a, b = self.setup_repos()
        ea = 0x6602E530
        stack_mask = "(1 << ya.OBJECT_TYPE_FUNCTION) | (1 << ya.OBJECT_TYPE_STACKFRAME)"
        stackvar_mask = stack_mask + " | (1 << ya.OBJECT_TYPE_STACKFRAME_MEMBER)"
        a.run(set_stackvar_names)
        b.check(
            self.has(ea, stack_mask, function_xrefs),
            self.has(ea, stackvar_mask, local_b_var),
            self.has(ea, stackvar_mask, arg_b_var),
        )
        # now rename a single stack member from b
        # only one file will be modified under git
        # check whether the rename is still applied
        b.run(rename_stackvars_again)
        a.check(self.has(ea, stackvar_mask, another_var))
