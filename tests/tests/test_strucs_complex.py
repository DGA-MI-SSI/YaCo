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

# layout for complex_struc1 & complex_struc2
#       00000000 struc_1         struc ; (sizeof=0x157)
#       00000000 field_0         db ?
#       00000001 field_1         dd ?
#       00000005 field_5         db ?
#       00000006 field_6         db 9 dup(?)
#       0000000F field_F         struc_2 ?
#       00000028 field_28        struc_2 2 dup(?)
#       0000005A                 db ? ; undefined
#       0000005B                 db ? ; undefined
#       0000005C                 db ? ; undefined
#       0000005D                 db ? ; undefined
#       0000005E                 db ? ; undefined
#       0000005F                 db ? ; undefined
#       00000060 field_44        dw 13 dup(?)
#       0000007A field_5E        dd 17 dup(?)
#       000000BE field_A2        dq 19 dup(?)
#       00000156 field_156       db ?
#       00000157 field_157       struc_2 2 dup(?)
#       00000189 field_189       db ?
#       0000018A struc_1         ends
#       00000000 ; ---------------------------------------------------------------------------
#       00000000 struc_2         struc ; (sizeof=0x19)   ; XREF: struc_1
#       00000000                 db ? ; undefined
#       00000001                 db ? ; undefined
#       00000002 field_0         db ?
#       00000003 field_1         db 13 dup(?)
#       00000010 field_E         dq ?
#       00000018 field_16        db ?
#       00000019 struc_2         ends

complex_constants = """
# offset, name, ftype, strid, count
complex_struc1 = [
    (0x0000,  "byte",           idaapi.FF_BYTE, -1,  1),
    (0x0001,  "dword",          idaapi.FF_DWRD, -1,  1),
    (0x0005,  "byte",           idaapi.FF_BYTE, -1,  1),
    (0x0006,  "byte_array",     idaapi.FF_BYTE, -1,  9),
    (0x000F,  "struc",          idaapi.FF_STRU,  1,  1),
    (0x0028,  "struc_array",    idaapi.FF_STRU,  1,  2),
    (0x005A,  None,             None,           -1,  6),
    (0x0060,  "word",           idaapi.FF_WORD, -1, 13),
    (0x007A,  "dword",          idaapi.FF_DWRD, -1, 17),
    (0x00BE,  "qword_array",    idaapi.FF_QWRD, -1, 19),
    (0x0156,  "byte",           idaapi.FF_BYTE, -1,  1),
    (0x0157,  "struc_array",    idaapi.FF_STRU,  1,  2),
    (0x0189,  "byte",           idaapi.FF_BYTE, -1,  1),
]
complex_struc1_size = 0x0189+1

complex_struc2 = [
    (0x0000,  None,             None,           -1,  2),
    (0x0002,  "byte",           idaapi.FF_BYTE, -1,  1),
    (0x0003,  "byte_array",     idaapi.FF_BYTE, -1, 13),
    (0x0010,  "qword",          idaapi.FF_QWRD, -1,  1),
    (0x0018,  "byte",           idaapi.FF_BYTE, -1,  1),
]

complex_struc3 = [
    (0x0000,  "byte",           idaapi.FF_BYTE, -1,  1),
    (0x0001,  "dword",          idaapi.FF_DWRD, -1,  1),
    (0x0005,  "byte",           idaapi.FF_BYTE, -1,  1),
]
complex_struc3_size = 0x6

def create_field(sid, offset, name, ftype, strid, count):
        if ftype is None or name is None:
            return
        name = 'f%.04X_%s' % (offset, name)
        size = get_size(ftype, strid) if ftype is not None else 1
        idc.add_struc_member(sid, name, offset, ftype | idaapi.FF_DATA, strid, size * count)

def create_complex(sid_a, sid_b):
    for offset, name, ftype, strid, count in complex_struc2:
        create_field(sid_b, offset, name, ftype, strid, count)
    size = idaapi.get_struc_size(sid_b)
    for offset, name, ftype, strid, count in complex_struc1:
        if strid != -1:
            count *= size
            strid  = sid_b
        create_field(sid_a, offset, name, ftype, strid, count)
"""

class Fixture(runtests.Fixture):

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
        a.check_git(added=["struc"] * 19 + ["strucmember"] * 19)
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
        a.check_git(added=["struc", "strucmember"] * 3)
        b.run(
            self.check_strucs(),
        )

    def test_complex_struc(self):
        a, b = self.setup_repos()
        a.run(
            self.script(constants + complex_constants + """
sid0 = idaapi.add_struc(-1, "top", False)
sid1 = idaapi.add_struc(-1, "complex_bot_struc", False)
create_complex(sid0, sid1)
"""),
            self.save_strucs(),
        )
        a.check_git(["struc"] * 2 + ["strucmember"] * 16)
        self.assertRegexpMatches(self.strucs, "complex_bot_struc")
        ea = 0x6601EF30
        b.run(
            self.check_strucs(),
            self.script(constants + complex_constants + """
frame = idaapi.get_frame(0x6601EF30)
offset = idc.get_first_member(frame.id)
while offset != idaapi.BADADDR:
    mid = idc.get_member_id(frame.id, offset)
    if not idaapi.is_special_member(mid):
        idaapi.del_struc_member(frame, offset)
    offset = idc.get_next_offset(frame.id, offset)
sid1 = idaapi.add_struc(-1, "complex_bot_stack", False)
create_complex(frame.id, sid1)
"""),
            self.save_ea(ea),
        )
        b.check_git(added=["binary", "segment", "segment_chunk", "function",
            "stackframe"] + ["stackframe_member"] * 12 + ["basic_block"] * 54 +
            ["struc"] + ["strucmember"] * 4)
        self.assertRegexpMatches(self.eas[ea], "complex_bot_stack")
        a.run(
            self.check_ea(ea),
        )

    def test_create_struc_in_stack_vars(self):
        a, b = self.setup_repos()
        ea = 0x6601EF30
        a.run(
            self.script(constants + complex_constants + """
def create_complex2(sid, complex_struc):
    for offset, name, ftype, strid, count in complex_struc:
        create_field(sid, offset, name, ftype, strid, count)
    return idaapi.get_struc_size(sid)

sid1 = idaapi.add_struc(-1, "complex_bot_stack", False)
create_complex2(sid1, complex_struc3)
frame = idaapi.get_frame(0x6601EF30)
offset = idc.get_first_member(frame.id)
mid = idc.get_member_id(frame.id, offset)
idc.SetType(mid, "complex_bot_stack*")
idaapi.set_member_name(frame, offset, "zorg")
"""),
            self.save_ea(ea),
            self.save_strucs(),
        )
        b.run(
            self.check_ea(ea),
            self.check_strucs(),
            self.script("""
frame = idaapi.get_frame(0x6601EF30)
offset = idc.get_first_member(frame.id)
idaapi.set_member_name(frame, offset, "new_name")
"""),
            self.save_ea(ea),
            self.save_strucs(),
        )
        b.check_git(modified=["stackframe_member"])
        a.run(
            self.check_ea(ea),
            self.check_strucs(),
        )
