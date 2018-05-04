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

    def test_enums(self):
        a, b = self.setup_repos()
        a.run(
            self.script("idaapi.add_enum(idaapi.BADADDR, 'name_a', idaapi.hexflag())"),
            self.save_enum("name_a"),
        )
        a.check_git(added=["enum"])
        b.run(
            self.check_enum("name_a"),
            self.script("idaapi.set_enum_name(idaapi.get_enum('name_a'), 'name_b')"),
            self.save_enum("name_a"),
            self.save_enum("name_b"),
        )
        b.check_git(moved=["enum"])
        self.assertEqual(self.enums["name_a"][1], "")
        a.run(
            self.check_enum("name_a"),
            self.check_enum("name_b"),
            self.script("idaapi.del_enum(idaapi.get_enum('name_b'))"),
            self.save_enum("name_b"),
        )
        a.check_git(deleted=["enum"])
        self.assertEqual(self.enums["name_b"][1], "")

    def test_enum_members(self):
        a, b = self.setup_repos()
        a.run(
            self.script("idaapi.add_enum_member(idaapi.add_enum(idaapi.BADADDR, 'name_a', idaapi.hexflag()), 'field_a', 0, -1)"),
            self.save_enum("name_a"),
        )
        a.check_git(added=["enum", "enum_member"])
        b.run(
            self.check_enum("name_a"),
            self.script("idaapi.set_enum_member_name(idaapi.get_enum_member_by_name('field_a'), 'field_b')"),
            self.save_enum("name_a"),
        )
        b.check_git(modified=["enum"], moved=["enum_member"])
        a.run(
            self.check_enum("name_a"),
            self.script("idaapi.set_enum_name(idaapi.get_enum('name_a'), 'name_b')"),
            self.save_enum("name_a"),
            self.save_enum("name_b"),
        )
        a.check_git(moved=["enum", "enum_member"])
        self.assertEqual(self.enums["name_a"][1], "")
        b.run(
            self.check_enum("name_a"),
            self.check_enum("name_b"),
            self.script("idaapi.del_enum_member(idaapi.get_enum('name_b'), 0, 0, -1)"),
            self.save_enum("name_b"),
        )
        b.check_git(deleted=["enum_member"], modified=["enum"])
        a.run(
            self.check_enum("name_b"),
        )

    def test_enum_types(self):
        a, b = self.setup_repos()
        constants = """
ea = 0x66045614

# flags, bits, bitfield, ea, operand, fields
enums = [
    (idaapi.hexflag(),  0, False, ea+0x00, 0, [0, 0x40, 16]),
    (idaapi.charflag(), 0, False, ea+0x19, 1, [ord('a'), ord('z'), ord('$')]),
    (idaapi.decflag(),  1, False, ea+0x02, 0, [0, 10, 16]),
    (idaapi.octflag(),  0, False, ea+0x06, 1, [0, 8, 13, 16]),
    (idaapi.binflag(),  0, True,  ea+0x04, 0, [1, 2]),
]
"""
        a.run(
            self.script(constants + """
idx = 0
def get_cmt():
    global idx
    idx += 1
    return "cmt_%02x" % idx

eidx = 0
for (flags, bits, bitfield, ea, operand, fields) in enums:
    name = "enum_%x" % eidx
    eidx += 1
    eid = idaapi.add_enum(idaapi.BADADDR, name, flags)
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
"""),
            self.save_enum("enum_0"),
            self.save_enum("enum_1"),
            self.save_enum("enum_2"),
            self.save_enum("enum_3"),
            self.save_enum("enum_4"),
            self.save_last_ea()
        )
        self.assertNotEqual(self.enums["enum_0"][1], "")
        self.assertNotEqual(self.enums["enum_1"][1], "")
        self.assertNotEqual(self.enums["enum_2"][1], "")
        self.assertNotEqual(self.enums["enum_3"][1], "")
        self.assertNotEqual(self.enums["enum_4"][1], "")
        b.run(
            self.check_last_ea(),
            self.check_enum("enum_0"),
            self.check_enum("enum_1"),
            self.check_enum("enum_2"),
            self.check_enum("enum_3"),
            self.check_enum("enum_4"),
            self.script(constants +  """
for (flags, bits, bitfield, ea, operand, fields) in enums:
    idaapi.clr_op_type(ea, operand)
"""),
            self.save_last_ea(),
        )
        b.check_git(modified=["basic_block"])
        a.run(
            self.check_last_ea(),
            self.script(constants + """
eidx = 0
for (flags, bits, bitfield, ea, operand, fields) in enums:
    name = "enum_%x" % eidx
    eidx += 1
    eid = idaapi.get_enum(name)
    idaapi.op_enum(ea, operand, eid, 0)
"""),
            self.save_last_ea(),
        )
        a.check_git(modified=["basic_block"])
        b.run(
            self.check_last_ea(),
            self.script(constants + """
eidx = 0
for (flags, bits, bitfield, ea, operand, fields) in enums:
    name = "enum_%x" % eidx
    eidx += 1
    eid = idaapi.get_enum(name)
    idaapi.del_enum(eid)
"""),
            self.save_enum("enum_0"),
            self.save_enum("enum_1"),
            self.save_enum("enum_2"),
            self.save_enum("enum_3"),
            self.save_enum("enum_4"),
            self.save_last_ea(),
        )
        b.check_git(deleted=["enum"] * 5 + ["enum_member"] * 15)
        self.assertMultiLineEqual(self.enums["enum_0"][1], "")
        self.assertMultiLineEqual(self.enums["enum_1"][1], "")
        self.assertMultiLineEqual(self.enums["enum_2"][1], "")
        self.assertMultiLineEqual(self.enums["enum_3"][1], "")
        self.assertMultiLineEqual(self.enums["enum_4"][1], "")
        a.run(
            self.check_last_ea(),
            self.check_enum("enum_0"),
            self.check_enum("enum_1"),
            self.check_enum("enum_2"),
            self.check_enum("enum_3"),
            self.check_enum("enum_4"),
        )

    def test_enum_bf(self):
        a, b = self.setup_repos()
        a.run(
            self.script("idaapi.add_enum(idaapi.BADADDR, 'name_a', idaapi.hexflag())"),
            self.save_enum("name_a"),
        )
        a.check_git(added=["enum"])
        b.run(
            self.check_enum("name_a"),
            self.script("idaapi.set_enum_bf(idaapi.get_enum('name_a'), True)"),
            self.save_enum("name_a"),
        )
        b.check_git(modified=["enum"])
        a.run(
            self.check_enum("name_a"),
            self.script("idaapi.set_enum_bf(idaapi.get_enum('name_a'), False)"),
            self.save_enum("name_a"),
        )
        a.check_git(modified=["enum"])
        b.run(
            self.check_enum("name_a"),
        )

    def test_enum_cmt(self):
        a, b = self.setup_repos()
        a.run(
            self.script("idaapi.add_enum(idaapi.BADADDR, 'name_a', idaapi.hexflag())"),
            self.save_enum("name_a"),
        )
        a.check_git(added=["enum"])
        b.run(
            self.check_enum("name_a"),
            self.script("idaapi.set_enum_cmt(idaapi.get_enum('name_a'), 'some_comment', False)"),
            self.save_enum("name_a"),
        )
        b.check_git(modified=["enum"])
        a.run(
            self.check_enum("name_a"),
            self.script("idaapi.set_enum_cmt(idaapi.get_enum('name_a'), '', False)"),
            self.save_enum("name_a"),
        )
        a.check_git(modified=["enum"])
        b.run(
            self.check_enum("name_a"),
        )
