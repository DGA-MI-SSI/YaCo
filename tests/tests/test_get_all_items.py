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

import inspect
import os
import runtests
import sys
import unittest


class Fixture(runtests.Fixture):

    def check_range(self, a, start, end, want):
        a.run(
            self.save_item_range(start, end),
        )
        self.check_item_range(want)

    def test_get_all_items(self):
        a, _ = self.setup_repos()
        self.check_range(a, 0x66023FE9, 0x66024012, """
0x66023fe9: block:9
0x66023ff0: data:1
0x66024004: data:1
""")
        self.check_range(a, 0x66001000, 0x6600100F, """
0x66001005: block:1
0x6600100a: block:1
""")
        self.check_range(a, 0x6600DA80, 0x6600DAEA, """
0x6600da80: block:1
""")
        self.check_range(a, 0x6605E140, 0x6605E198, """
0x6605e140: data:0
""")
        self.check_range(a, 0x6605E1B6, 0x6605E1EB, """
""")
        self.check_range(a, 0x66066EE8, 0x66066EF4, """
""")
        expected = """
0x66071e09: unexplored:1
"""
        if sys.platform == "win32":
            expected = """
0x66071e04: data:0
0x66071e08: unexplored:0
0x66071e09: unexplored:1
0x66071e0a: unexplored:0
0x66071e0b: unexplored:0
"""
        self.check_range(a,  0x66071e04, 0x66071e0c, expected)

    @unittest.skip("only use manually")
    def test_full_all_items(self):
        full = None
        golden_filename = "test_get_all_items." + sys.platform + ".700.golden"
        expected_path = os.path.join(os.path.dirname(inspect.getsourcefile(lambda:0)), golden_filename)
        with open(expected_path, "rb") as fh:
            full = fh.read()
        a, _ = self.setup_repos()
        self.check_range(a, 0x66001000, 0x66073F5C, full)
