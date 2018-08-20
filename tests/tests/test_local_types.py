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

    def test_struc_renames_with_imports(self):
        a, b = self.setup_cmder()

        a.run(
            self.script("""
for x in xrange(0, 4):
    idaapi.add_struc(-1, "struc_a_%d" % x, False)
ida_typeinf.import_type(ida_typeinf.get_idati(), -1, "OSVERSIONINFO")
"""),
            self.save_strucs(),
        )

        b.run_no_sync(
            self.script("""
ida_typeinf.import_type(ida_typeinf.get_idati(), -1, "OSVERSIONINFO")
for x in xrange(0, 4):
    idaapi.add_struc(-1, "struc_b_%d" % x, False)
"""),
        )

        a.run(
            self.save_local_types(),
        )
        b.run(
            self.check_local_types(),
        )
