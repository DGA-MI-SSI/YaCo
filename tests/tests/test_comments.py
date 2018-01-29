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

set_function_comments = """
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
"""

block_comments = """
    <offsets>
      <comments offset="0000000000000001" type="repeatable_comment">cmt 03</comments>
      <comments offset="0000000000000003" type="nonrepeatable_comment">cmt 04</comments>
      <comments offset="0000000000000006" type="nonrepeatable_comment">cmt 06</comments>
      <comments offset="0000000000000006" type="repeatable_comment">cmt 05</comments>
      <comments offset="0000000000000006" type="anterior_comment">cmt 07
cmt 08</comments>
      <comments offset="0000000000000006" type="posterior_comment">cmt 09
cmt 0a</comments>
      <comments offset="0000000000000009" type="nonrepeatable_comment">this</comments>
      <valueview offset="0000000000000003" operand="00000001">unsignedhexadecimal</valueview>
    </offsets>
"""

function_comments = """
    </signatures>
    <repeatable_headercomment>cmt 01</repeatable_headercomment>
    <nonrepeatable_headercomment>cmt 02</nonrepeatable_headercomment>
    <xrefs>
"""

reset_function_comments = """
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
"""

default_block_comments = """
    <offsets>
      <comments offset="0000000000000009" type="nonrepeatable_comment">this</comments>
      <valueview offset="0000000000000003" operand="00000001">unsignedhexadecimal</valueview>
    </offsets>
"""

no_function_comments = """
    </signatures>
    <xrefs>
"""

class Fixture(run_all_tests.Fixture):

    def test_comments(self):
        a, b = self.setup_repos()
        a.run(set_function_comments)
        ea = 0x66013850
        b.check(
            self.has(ea, "1 << ya.OBJECT_TYPE_BASIC_BLOCK", block_comments),
            self.has(ea, "1 << ya.OBJECT_TYPE_FUNCTION", function_comments),
        )
        b.run(reset_function_comments)
        a.check(
            self.has(ea, "1 << ya.OBJECT_TYPE_BASIC_BLOCK", default_block_comments),
            self.has(ea, "1 << ya.OBJECT_TYPE_FUNCTION", no_function_comments),
        )
