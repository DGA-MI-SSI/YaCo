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

    def test_push_pull(self):
        a, b = self.setup_repos()
        
        a.run(
            self.script("""
ea = 0x66013830
func = idaapi.get_func(ea)
idaapi.add_regvar(func, ea, ea+0x10, "ebp", "ebp_a", None)
idaapi.add_regvar(func, ea+0x10, ea+0x20, "ebp", "ebp_b", None)
"""),
        )
        entities= ["binary", "segment", "segment_chunk", "function", "basic_block", "local_type"]
        a.check_git(added=entities)

        # push idb, cache will be deleted
        b.run(
            self.script("""
import yaco_plugin
yaco_plugin.yaco.sync_and_push_idb()
"""),
        )
        b.check_git(deleted=entities)

        # pull idb
        a.run_no_sync(
            self.script("""
import yaco_plugin
yaco_plugin.yaco.discard_and_pull_idb()
"""),
        )
        a.check_git(deleted=entities)
