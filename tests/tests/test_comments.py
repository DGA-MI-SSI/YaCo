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

    def test_comments(self):
        a, b = self.setup_repos()
        a.run(
            self.script( """
ea = 0x66013850
func = idaapi.get_func(ea)
idaapi.set_func_cmt(func, "cmt 01", True)
idaapi.set_func_cmt(func, "cmt 02", False)
idaapi.set_cmt(ea+1, "cmt 03", True)
idaapi.set_cmt(ea+3, "cmt 04", False)
idaapi.set_cmt(ea+6, "cmt 05", True)
idaapi.set_cmt(ea+6, "cmt 06", False)
idaapi.update_extra_cmt(ea+6, idaapi.E_PREV + 0, "cmt 07")
idaapi.update_extra_cmt(ea+6, idaapi.E_PREV + 1, "cmt 08")
idaapi.update_extra_cmt(ea+6, idaapi.E_NEXT + 0, "cmt 09")
idaapi.update_extra_cmt(ea+6, idaapi.E_NEXT + 1, "cmt 0a")
"""),
            self.save_last_ea(),
        )
        a.check_git(added=["binary", "segment", "segment_chunk", "function", "basic_block"])
        b.run(
            self.check_last_ea(),
            self.script("""
ea = 0x66013850
func = idaapi.get_func(ea)
idaapi.set_func_cmt(func, "", True)
idaapi.set_func_cmt(func, "", False)
idaapi.set_cmt(ea+1, "", True)
idaapi.set_cmt(ea+3, "", False)
idaapi.set_cmt(ea+6, "", True)
idaapi.set_cmt(ea+6, "", False)
idaapi.update_extra_cmt(ea+6, idaapi.E_PREV + 0, "")
idaapi.update_extra_cmt(ea+6, idaapi.E_PREV + 1, "")
idaapi.update_extra_cmt(ea+6, idaapi.E_NEXT + 0, "")
idaapi.update_extra_cmt(ea+6, idaapi.E_NEXT + 1, "")
"""),
            self.save_last_ea(),
        )
        b.check_git(modified=["function", "basic_block"])
        a.run(
            self.check_last_ea(),
        )
