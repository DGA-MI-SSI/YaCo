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

constants = """
field_sizes = {
    idaapi.FF_BYTE:    1,
    idaapi.FF_WORD:    2,
    idaapi.FF_DWRD:    4,
    idaapi.FF_QWRD:    8,
    idaapi.FF_OWRD:   16,
    idaapi.FF_DOUBLE:  8,
    idaapi.FF_FLOAT:   4,
    idaapi.FF_ASCI:    1,
    idaapi.FF_STRU:    1,
}

string_sizes = {
    idc.STRTYPE_C:       1,
    idc.STRTYPE_LEN2:    2,
    idc.STRTYPE_LEN4:    4,
    idc.STRTYPE_PASCAL:  1,
    idc.STRTYPE_TERMCHR: 1,
    idc.STRTYPE_LEN2_16: 2,
    idc.STRTYPE_LEN4_16: 4,
    idc.STRTYPE_C_16:    2,
}

def get_size(field_type, string_type):
    if field_type != idaapi.FF_ASCI:
        return field_sizes[field_type]
    return string_sizes[string_type]
"""

field_types = """
create_field = [
    ( 0, 1, idaapi.FF_BYTE,    -1, None, False),
    ( 1, 2, idaapi.FF_BYTE,    -1, "some comment", False),
    ( 2, 3, idaapi.FF_BYTE,    -1, "some repeatable comment", True),
    ( 0, 1, idaapi.FF_WORD,    -1, None, False),
    ( 0, 1, idaapi.FF_DWRD,    -1, None, False),
    ( 0, 1, idaapi.FF_QWRD,    -1, None, False),
    ( 0, 1, idaapi.FF_OWRD,    -1, None, False),
    ( 0, 1, idaapi.FF_DOUBLE,  -1, None, False),
    ( 0, 1, idaapi.FF_FLOAT,   -1, None, False),
    (54, 1, idaapi.FF_WORD,    -1, None, False),
    ( 0, 8, idaapi.FF_DWRD,    -1, None, False),
    (54, 8, idaapi.FF_DWRD,    -1, None, False),
    ( 1, 8, idaapi.FF_ASCI,    idc.STRTYPE_C, None, False),
    ( 0, 8, idaapi.FF_ASCI,    idc.STRTYPE_LEN2, None, False),
    ( 0, 8, idaapi.FF_ASCI,    idc.STRTYPE_LEN4, None, False),
    ( 0, 8, idaapi.FF_ASCI,    idc.STRTYPE_PASCAL, None, False),
    ( 0, 8, idaapi.FF_ASCI,    idc.STRTYPE_LEN2_16, None, False),
    ( 0, 8, idaapi.FF_ASCI,    idc.STRTYPE_LEN4_16, None, False),
    ( 0, 8, idaapi.FF_ASCI,    idc.STRTYPE_C_16, None, False),
]
"""

class Fixture(run_all_tests.Fixture):

    def test_strucs(self):
        a, b = self.setup_repos()
        a.run(
            self.script("""
eid = idaapi.add_struc(-1, "name_a", False)
idaapi.set_struc_cmt(eid, "cmt_01", True)
idaapi.set_struc_cmt(eid, "cmt_02", False)
"""),
            self.save_struc("name_a"),
        )
        b.run(
            self.check_struc("name_a"),
            self.script("idaapi.set_struc_name(idaapi.get_struc_id('name_a'), 'name_b')"),
            self.save_struc("name_a"),
            self.save_struc("name_b"),
        )
        self.assertEqual(self.strucs["name_a"], "")
        self.assertNotEqual(self.strucs["name_b"], "")
        a.run(
            self.check_struc("name_a"),
            self.check_struc("name_b"),
            self.script("idaapi.del_struc(idaapi.get_struc(idaapi.get_struc_id('name_b')))"),
            self.save_struc("name_b"),
        )
        self.assertEqual(self.strucs["name_b"], "")

    def test_struc_members(self):
        a, b = self.setup_repos()
        a.run(
            self.script("idc.add_struc_member(idaapi.add_struc(-1, 'name_a', False), 'field_a', 0, idaapi.FF_DATA, -1, 1)"),
            self.save_struc("name_a"),
        )
        b.run(
            self.check_struc("name_a"),
            self.script("idaapi.set_member_name(idaapi.get_struc(idaapi.get_struc_id('name_a')), 0, 'field_b')"),
            self.save_struc("name_a"),
        )
        a.run(
            self.check_struc("name_a"),
            self.script("idaapi.set_struc_name(idaapi.get_struc_id('name_a'), 'name_b')"),
            self.save_struc("name_a"),
            self.save_struc("name_b"),
        )
        self.assertEqual(self.strucs["name_a"], "")
        self.assertNotEqual(self.strucs["name_b"], "")
        b.run(
            self.check_struc("name_a"),
            self.check_struc("name_b"),
            self.script("idaapi.del_struc_member(idaapi.get_struc(idaapi.get_struc_id('name_b')), 0)"),
            self.save_struc("name_b"),
        )
        a.run(
            self.check_struc("name_b"),
        )

    def test_sub_structs(self):
        a, b = self.setup_repos()
        a.run(
            self.script("""
idx = 0
sub_tests = [
    (0, 1),  (13, 1),
    (0, 16), (13, 16),
]
for offset, count in sub_tests:
    top = idaapi.add_struc(-1, "top_%x" % idx, False)
    bot = idaapi.add_struc(-1, "bot_%x" % idx, False)
    idx += 1
    for i in xrange(0, count):
        idc.add_struc_member(bot, "subf_%02x" % i, offset + i, idaapi.FF_BYTE | idaapi.FF_DATA, -1, 1)
    idc.add_struc_member(top, "sub_struct", offset, idaapi.FF_STRU | idaapi.FF_DATA, bot, idaapi.get_struc_size(bot), -1)
"""),
            self.save_strucs(),
        )
        b.run(
            self.check_strucs(),
        )

    def test_struc_fields(self):
        a, b = self.setup_repos()
        a.run(
            self.script(constants + field_types + """
idx = 0
for offset, count, field_type, string_type, comment, repeatable in create_field:
    size = count * get_size(field_type, string_type)
    name = "cfield_%02x" % idx
    idx += 1
    sid = idaapi.add_struc(-1, name, False)
    idc.add_struc_member(sid, "field_" + name, offset, field_type | idaapi.FF_DATA, string_type, size)
    if comment is not None:
        idc.set_member_cmt(sid, offset, comment, repeatable)
"""),
            self.save_strucs()
        )
        b.run(
            self.check_strucs(),
        )

    def test_field_prototypes(self):
        a, b = self.setup_repos()
        a.run(
            self.script(constants + """
set_field_prototype = [
    (idaapi.FF_BYTE,  'some_name1', 'char'),
    (idaapi.FF_DWRD,  'some_name2', 'char *'),
    (idaapi.FF_DWRD,  'some_name3', 'some_name3 *'),
]
for field_type, name, proto in set_field_prototype:
    sid = idaapi.add_struc(-1, name, 0)
    idc.add_struc_member(sid, "field", 0, field_type | idaapi.FF_DATA, -1, get_size(field_type, -1))
    mid = idc.get_member_id(sid, 0)
    idc.SetType(mid, proto)
"""),
            self.save_strucs(),
        )
        b.run(
            self.check_strucs(),
        )
