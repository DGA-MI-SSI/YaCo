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

    def test_register_views(self):
        a, b = self.setup_repos()
        a.run(
            self.script("""
ea = 0x66014090
func = idaapi.get_func(ea)
idaapi.add_regvar(func, ea+0x1C, ea+0x28, "eax", "eax_a", None)
idaapi.add_regvar(func, ea+0x22, ea+0x28, "ebp", "ebp_b", None)
"""),
            self.save_last_ea(),
        )
        a.check_git(added=["binary", "segment", "segment_chunk", "function"] + ["basic_block"] * 4)
        b.run(
            self.check_last_ea(),
            self.script("""
ea = 0x66014090
func = idaapi.get_func(ea)
idaapi.del_regvar(func, ea+0x22, ea+0x28, "ebp")
"""),
            self.save_last_ea(),
        )
        b.check_git(modified=["basic_block"])
        a.run(
            self.check_last_ea(),
            self.script("""
ea = 0x66014090
func = idaapi.get_func(ea)
idaapi.del_regvar(func, ea+0x1C, ea+0x28, "eax")
"""),
            self.save_last_ea(),
        )
        a.check_git(modified=["basic_block"])
        b.run(
            self.check_last_ea(),
        )
