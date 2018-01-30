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

set_registers = """
ea = 0x66013830
func = idaapi.get_func(ea)
idaapi.add_regvar(func, ea, ea+0x10, "ebp", "ebp_a", None)
idaapi.add_regvar(func, ea+0x10, ea+0x20, "ebp", "ebp_b", None)
"""

reset_registers = """
ea = 0x66013830
func = idaapi.get_func(ea)
idaapi.del_regvar(func, ea, ea+0x10, "ebp")
idaapi.del_regvar(func, ea+0x10, ea+0x20, "ebp")
"""

class Fixture(run_all_tests.Fixture):

    def test_register_views(self):
        a, b = self.setup_repos()
        ea = 0x66013830
        a.run(
            self.script(set_registers),
            self.save_ea(ea),
        )
        b.run(
            self.check_ea(ea),
            self.script(reset_registers),
            self.save_ea(ea),
        )
        a.run(
            self.check_ea(ea),
        )
