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

constants = """
block_ea = 0x66045614

# flags, bits, bitfield, ea, operand, fields
enums = [
    (idaapi.hexflag(),  0, False, block_ea+0x00, 0, [0, 0x40, 16]),
    (idaapi.charflag(), 0, False, block_ea+0x19, 1, [ord('a'), ord('z'), ord('$')]),
    (idaapi.decflag(),  1, False, block_ea+0x02, 0, [0, 10, 16]),
    (idaapi.octflag(),  0, False, block_ea+0x06, 1, [0, 8, 13, 16]),
    (idaapi.binflag(),  0, True,  block_ea+0x04, 0, [1, 2]),
]
"""

add_enums = """
idx = 0
def get_cmt():
    global idx
    idx += 1
    return "cmt_%02x" % idx

eidx = 0
for (flags, bits, bitfield, ea, operand, fields) in enums:
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
    idaapi.op_enum(ea, operand, eid, 0)
"""

unapply_enums = """
for (flags, bits, bitfield, ea, operand, fields) in enums:
    idaapi.clr_op_type(ea, operand)
"""

apply_enums = """
eidx = 0
for (flags, bits, bitfield, ea, operand, fields) in enums:
    name = "enum_%x" % eidx
    eidx += 1
    eid = idaapi.get_enum(name)
    idaapi.op_enum(ea, operand, eid, 0)
"""

del_enums = """
eidx = 0
for (flags, bits, bitfield, ea, operand, fields) in enums:
    name = "enum_%x" % eidx
    eidx += 1
    eid = idaapi.get_enum(name)
    idaapi.del_enum(eid)
"""

class Fixture(runtests.Fixture):

    def test_enums(self):
        a, b = self.setup_repos()
        a.run(
            self.script("idc.AddEnum(-1, 'name_a', idaapi.hexflag())"),
            self.save_enum("name_a"),
        )
        b.run(
            self.check_enum("name_a"),
            self.script("idaapi.set_enum_name(idaapi.get_enum('name_a'), 'name_b')"),
            self.save_enum("name_a"),
            self.save_enum("name_b"),
        )
        self.assertEqual(self.enums["name_a"], "")
        a.run(
            self.check_enum("name_a"),
            self.check_enum("name_b"),
            self.script("idaapi.del_enum(idaapi.get_enum('name_b'))"),
            self.save_enum("name_b"),
        )
        self.assertEqual(self.enums["name_b"], "")

    def test_enum_members(self):
        a, b = self.setup_repos()
        a.run(
            self.script("idaapi.add_enum_member(idc.AddEnum(-1, 'name_c', idaapi.hexflag()), 'field_a', 0, -1)"),
            self.save_enum("name_a"),
        )
        b.run(
            self.check_enum("name_a"),
            self.script("idaapi.set_enum_member_name(idaapi.get_enum_member_by_name('field_a'), 'field_b')"),
            self.save_enum("name_a"),
        )
        a.run(
            self.check_enum("name_a"),
            self.script("idaapi.set_enum_name(idaapi.get_enum('name_a'), 'name_b')"),
            self.save_enum("name_a"),
            self.save_enum("name_b"),
        )
        self.assertEqual(self.enums["name_a"], "")
        b.run(
            self.check_enum("name_a"),
            self.check_enum("name_b"),
            self.script("idaapi.del_enum_member(idaapi.get_enum('name_b'), 0, 0, -1)"),
            self.save_enum("name_b"),
        )
        a.run(
            self.check_enum("name_b"),
        )

    def test_enum_types(self):
        a, b = self.setup_repos()
        ea = 0x66045614
        a.run(
            self.script(constants + add_enums),
            self.save_enum("enum_0"),
            self.save_enum("enum_1"),
            self.save_enum("enum_2"),
            self.save_enum("enum_3"),
            self.save_enum("enum_4"),
            self.save_ea(ea)
        )
        b.run(
            self.check_ea(ea),
            self.check_enum("enum_0"),
            self.check_enum("enum_1"),
            self.check_enum("enum_2"),
            self.check_enum("enum_3"),
            self.check_enum("enum_4"),
            self.script(constants + unapply_enums),
            self.save_ea(ea),
        )
        a.run(
            self.check_ea(ea),
            self.script(constants + apply_enums),
            self.save_ea(ea),
        )
        b.run(
            self.check_ea(ea),
            self.script(constants + del_enums),
            self.save_enum("enum_0"),
            self.save_enum("enum_1"),
            self.save_enum("enum_2"),
            self.save_enum("enum_3"),
            self.save_enum("enum_4"),
            self.save_ea(ea),
        )
        a.run(
            self.check_ea(ea),
            self.check_enum("enum_0"),
            self.check_enum("enum_1"),
            self.check_enum("enum_2"),
            self.check_enum("enum_3"),
            self.check_enum("enum_4"),
        )
