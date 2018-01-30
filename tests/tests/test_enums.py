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

import re
import run_all_tests

add_enums = """
# flags, bits, bitfield, fields
enums = [
    (idaapi.hexflag(),  0, False, [1, 16]),
    (idaapi.charflag(), 0, False, [ord('a'), ord('z')]),
    (idaapi.decflag(),  1, False, [0, 1]),
    (idaapi.octflag(),  0, False, [0, 8]),
    (idaapi.binflag(),  0, True,  [1, 4]),
]

idx = 0
def get_cmt():
    global idx
    idx += 1
    return "cmt_%02x" % idx

eidx = 0
for (flags, bits, bitfield, fields) in enums:
    name = "enum_%x" % eidx
    eidx += 1
    eid = idc.AddEnum(-1, name, flags)
    if bits != 0:
        idaapi.set_enum_width(eid, bits)
    if bitfield:
       idaapi.set_enum_bf(eid, True)
    for rpt in [False, True]:
        idaapi.set_enum_cmt(eid, get_cmt(), rpt)
    fidx = 0
    for f in fields:
        field = "%s_%x" % (name, fidx)
        fidx += 1
        if bitfield:
           idaapi.add_enum_member(eid, field, f, f)
        else:
            idaapi.add_enum_member(eid, field, f, -1)
        cid = idaapi.get_enum_member_by_name(field)
        for rpt in [False, True]:
            set_enum_member_cmt(cid, get_cmt(), rpt)
"""

class Fixture(run_all_tests.Fixture):

    def test_enums(self):
        a, b = self.setup_repos()
        a.run(
            self.script(add_enums),
            self.save_enum("enum_0"),
            self.save_enum("enum_1"),
            self.save_enum("enum_2"),
            self.save_enum("enum_3"),
            self.save_enum("enum_4"),
        )
        b.run(
            self.check_enum("enum_0"),
            self.check_enum("enum_1"),
            self.check_enum("enum_2"),
            self.check_enum("enum_3"),
            self.check_enum("enum_4"),
        )
