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

class Fixture(run_all_tests.Fixture):

    def test_register_views(self):
        wd, a, b = self.setup_repos()
        self.idado(a, """
ea = 0x66013830
func = idaapi.get_func(ea)
idaapi.add_regvar(func, ea, ea+0x10, "ebp", "ebp_a", None)
idaapi.add_regvar(func, ea+0x10, ea+0x20, "ebp", "ebp_b", None)
""")
        offsets = """
    <offsets>
      <registerview offset="0000000000000000" end_offset="0000000000000010" register="ebp">ebp_a</registerview>
      <registerview offset="0000000000000010" end_offset="0000000000000020" register="ebp">ebp_b</registerview>
    </offsets>
"""
        self.idacheck(b, self.has(0x66013830, "ya.OBJECT_TYPE_BASIC_BLOCK", offsets))
        self.idado(b, """
ea = 0x66013830
func = idaapi.get_func(ea)
idaapi.del_regvar(func, ea, ea+0x10, "ebp")
idaapi.del_regvar(func, ea+0x10, ea+0x20, "ebp")
""")
        self.idacheck(a, self.nothas(0x66013830, "ya.OBJECT_TYPE_BASIC_BLOCK", offsets))
