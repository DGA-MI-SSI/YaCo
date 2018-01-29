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

set_reference_views = """
ea = 0x66013B00
idaapi.op_offset(ea+0xF,  0, idaapi.get_default_reftype(ea+0xF),  idaapi.BADADDR, 0xdeadbeef)
idaapi.op_offset(ea+0x17, 1, idaapi.get_default_reftype(ea+0x17), idaapi.BADADDR, 0xbeefdead)
"""

xrefs = """
    <xrefs>
      <xref offset="0x0000000000000004">B38DAEC3453D8D05</xref>
      <xref offset="0x0000000000000007" operand="0x0000000000000001">B38DAEC3453D8D05</xref>
      <xref offset="0x000000000000000A" operand="0x0000000000000001">995BE41724AE2214</xref>
      <xref offset="0x000000000000000F">57DD1848475C188D</xref>
      <xref offset="0x0000000000000014" operand="0x0000000000000001">B38DAEC3453D8D05</xref>
      <xref offset="0x0000000000000017" operand="0x0000000000000001">67EB8A6CC403AA02</xref>
      <xref offset="0x0000000000000020" operand="0x0000000000000001">B38DAEC3453D8D05</xref>
    </xrefs>
"""

refa = """
<reference_info>
  <id>57DD1848475C188D</id>
  <version>
    <size>0x0000000000000000</size>
    <address>DEADBEEF</address>
    <flags>0x2</flags>
    <signatures/>
    <xrefs/>
    <matchingsystem>
      <address>00000000DEADBEEF</address>
      <equipment>None</equipment>
      <os>None</os>
    </matchingsystem>
  </version>
</reference_info>
"""

refb = """
<reference_info>
  <id>67EB8A6CC403AA02</id>
  <version>
    <size>0x0000000000000000</size>
    <address>BEEFDEAD</address>
    <flags>0x2</flags>
    <signatures/>
    <xrefs/>
    <matchingsystem>
      <address>00000000BEEFDEAD</address>
      <equipment>None</equipment>
      <os>None</os>
    </matchingsystem>
  </version>
</reference_info>
"""

reset_reference_views = """
ea = 0x66013B00
idaapi.op_offset(ea+0xF,  0, idaapi.get_default_reftype(ea+0xF))
idaapi.op_offset(ea+0x17, 1, idaapi.get_default_reftype(ea+0x17))
"""

default_xrefs = """
    <xrefs>
      <xref offset="0x0000000000000004">B38DAEC3453D8D05</xref>
      <xref offset="0x0000000000000007" operand="0x0000000000000001">B38DAEC3453D8D05</xref>
      <xref offset="0x000000000000000A" operand="0x0000000000000001">995BE41724AE2214</xref>
      <xref offset="0x0000000000000014" operand="0x0000000000000001">B38DAEC3453D8D05</xref>
      <xref offset="0x0000000000000020" operand="0x0000000000000001">B38DAEC3453D8D05</xref>
    </xrefs>
"""

class Fixture(run_all_tests.Fixture):

    def test_reference_views(self):
        a, b = self.setup_repos()
        ea = 0x66013B00
        a.run(set_reference_views)
        b.check(
            self.has(ea, "1 << ya.OBJECT_TYPE_BASIC_BLOCK", xrefs),
            self.has(ea, "1 << ya.OBJECT_TYPE_BASIC_BLOCK", refa),
            self.has(ea, "1 << ya.OBJECT_TYPE_BASIC_BLOCK", refb),
        )
        b.run(reset_reference_views)
        a.check(
            self.has(ea, "1 << ya.OBJECT_TYPE_BASIC_BLOCK", default_xrefs),
            self.nothas(ea, "1 << ya.OBJECT_TYPE_BASIC_BLOCK", refa),
            self.nothas(ea, "1 << ya.OBJECT_TYPE_BASIC_BLOCK", refb),
        )
