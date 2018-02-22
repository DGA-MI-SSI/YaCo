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

set_function_name = """
ea = 0x6602E530
idaapi.set_name(ea, "funcname_01", idaapi.SN_PUBLIC)
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

rename_stackvars_again = """
ea = 0x6602E530
frame = idaapi.get_frame(ea)
idaapi.set_member_name(frame, 0x4,  "another_name")
"""

create_function = """
ea = 0x6602E530
idc.MakeFunction(ea)
"""

create_and_rename_function = """
ea = 0x6602E530
idc.MakeFunction(ea)
idaapi.set_name(ea, "new_function_E530")
"""


class Fixture(runtests.Fixture):

    def test_rename_function(self):
        a, b = self.setup_repos()
        ea = 0x6602E530
        a.run(
            self.script(set_function_name),
            self.save_ea(ea),
        )
        b.run(
            self.check_ea(ea),
            self.script(reset_function_name),
            self.save_ea(ea),
        )
        a.run(
            self.check_ea(ea),
        )

    def test_rename_stackframe_members(self):
        a, b = self.setup_repos()
        ea = 0x6602E530
        a.run(
            self.script(set_stackvar_names),
            self.save_ea(ea),
        )
        b.run(
            self.check_ea(ea),
            # now rename a single stack member from b
            # only one file will be modified under git
            # check whether the rename is still applied
            self.script(rename_stackvars_again),
            self.save_ea(ea),
        )
        a.run(
            self.check_ea(ea),
        )

    def test_create_function(self):
        a, b = self.setup_repos()
        ea = 0x6600EDF0
        a.run(
            self.script(create_function),
            self.save_ea(ea)
        )
        b.run(
            self.check_ea(ea),
        )

    def test_create_and_rename_function(self):
        a, b = self.setup_repos()
        ea = 0x6600EDF0
        a.run(
            self.script(create_and_rename_function),
            self.save_ea(ea)
        )
        b.run(
            self.check_ea(ea),
        )
