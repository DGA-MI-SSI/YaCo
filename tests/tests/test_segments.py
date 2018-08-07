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

    def test_put_function_undefined_segment(self):
        a, b = self.setup_cmder()
        a.run(
            self.script("""
ea = 0x41BCC0
ida_bytes.put_bytes(ea, b"\\x90\\x90\\x90\\x90\\xc3")
idc.add_func(ea)
ida_auto.plan_and_wait(ea, idc.find_func_end(ea))
"""),
            self.save_last_ea(),
        )
        a.check_git(added=["binary", "segment", "segment_chunk", "function", "basic_block", "stackframe"])
        b.run(
            self.check_last_ea(),
        )

    def test_punch_data_hole_into_function(self):
        a, b = self.setup_cmder()

        # create a function candidate containing undefined data bytes
        # we need to force push because deleting tracked data is easier
        a.run(
            self.script("""
ea = 0x402E75
idc.del_func(ea)
idaapi.set_name(ea, "funcname")
ida_bytes.del_items(ea+0x1D, 0, 3)
ida_bytes.create_word(ea+0x1D, 2)
"""),
        )
        a.check_git(added=["binary", "segment", "segment_chunk", "code", "code", "data"])

        a.run(
            self.script("""
import yaco_plugin
yaco_plugin.yaco.sync_and_push_idb()
"""),
        )
        a.check_git(deleted=["binary", "segment", "segment_chunk", "code", "code", "data"])

        b.run_no_sync(
            self.script("""
import yaco_plugin
yaco_plugin.yaco.discard_and_pull_idb()
"""),
        )

        a.run(
            self.script("""
ea = 0x402E75
ida_bytes.del_items(ea+0x1D, 0, 3)
idc.add_func(ea, ea+0x32)
ida_auto.plan_and_wait(ea, idc.find_func_end(ea))
"""),
            self.save_last_ea(),
        )
        a.check_git(added=["binary", "segment", "segment_chunk", "function", "stackframe", "basic_block"] + ["stackframe_member"] * 3)

        b.run(
            self.check_last_ea(),
        )
