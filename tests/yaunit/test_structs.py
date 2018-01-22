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

import ida_ua
import idaapi
import idautils
import idc
import re
import unittest
import yaunit

re_ptr    = re.compile(r'\s*\*\s*')
def fix_ptr_type(value):
    if value is None:
        return None
    return re_ptr.sub('*', value)


field_types = {
    -1:                 '',
    idaapi.FF_BYTE:     'FF_BYTE',
    idaapi.FF_WORD:     'FF_WORD',
    idaapi.FF_DWRD:     'FF_DWRD',
    idaapi.FF_QWRD:     'FF_QWRD',
    idaapi.FF_OWRD:     'FF_OWRD',
    idaapi.FF_DOUBLE:   'FF_DOUBLE',
    idaapi.FF_FLOAT:    'FF_FLOAT',
    idaapi.FF_ASCI:     'FF_ASCI',
}

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

string_types = {
    -1:                  '',
    idc.STRTYPE_C:       'c',
    idc.STRTYPE_LEN2:    'len2',
    idc.STRTYPE_LEN4:    'len4',
    idc.STRTYPE_PASCAL:  'pascal',
    idc.STRTYPE_LEN2_16: 'ulen2',
    idc.STRTYPE_LEN4_16: 'ulen4',
    idc.STRTYPE_C_16:    'unicode',
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

# name, comment, repeatable
create_struct = [
    ("SomeName_T",          None, False),
    ("SomeNameWithCom_T",   "some comment", False),
    ("SomeNameWithRCom_T",  "repeatable comment", True),
]

# offset, count, field_type, string_type, comment, repeatable
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

# offset, count
create_sub = [
    ( 0,  1),
    (13,  1),
    ( 0, 16),
    (13, 16),
]

# field_type, name, prototype
set_field_prototype = [
    (idaapi.FF_BYTE,  'some_name1', 'char'),
    (idaapi.FF_DWRD,  'some_name2', 'char *'),
    (idaapi.FF_DWRD,  'some_name3', 'some_name3 *'),
]

# layout for complex_struc1 & complex_struc2
"""
        00000000 struc_1         struc ; (sizeof=0x157)
        00000000 field_0         db ?
        00000001 field_1         dd ?
        00000005 field_5         db ?
        00000006 field_6         db 9 dup(?)
        0000000F field_F         struc_2 ?
        00000028 field_28        struc_2 2 dup(?)
        0000005A                 db ? ; undefined
        0000005B                 db ? ; undefined
        0000005C                 db ? ; undefined
        0000005D                 db ? ; undefined
        0000005E                 db ? ; undefined
        0000005F                 db ? ; undefined
        00000060 field_44        dw 13 dup(?)
        0000007A field_5E        dd 17 dup(?)
        000000BE field_A2        dq 19 dup(?)
        00000156 field_156       db ?
        00000157 field_157       struc_2 2 dup(?)
        00000189 field_189       db ?
        0000018A struc_1         ends
        00000000 ; ---------------------------------------------------------------------------
        00000000 struc_2         struc ; (sizeof=0x19)   ; XREF: struc_1
        00000000                 db ? ; undefined
        00000001                 db ? ; undefined
        00000002 field_0         db ?
        00000003 field_1         db 13 dup(?)
        00000010 field_E         dq ?
        00000018 field_16        db ?
        00000019 struc_2         ends
"""

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


def get_size(field_type, string_type):
    if field_type != idaapi.FF_ASCI:
        return field_sizes[field_type]
    return string_sizes[string_type]


def get_name(field_type, string_type, offset, size):
    return field_types[field_type] + '_' + string_types[string_type] + '_' + hex(offset)[2:] + '_' + hex(size)[2:]


def hhex(v): return hex(v)[2:]


class Fixture(unittest.TestCase):

    # create struct
    def yatest_create_struct(self):
        for name, comment, repeatable in create_struct:
            sid = idc.AddStrucEx(-1, name, 0)
            self.assertNotEqual(sid, -1)
            if comment is not None:
                err = idc.SetStrucComment(sid, comment, repeatable)
                self.assertNotEqual(err, 0)

    def yacheck_create_struct(self):
        for name, comment, repeatable in create_struct:
            sid = idc.GetStrucIdByName(name)
            self.assertNotEqual(sid, idaapi.BADADDR)
            self.assertEqual(idc.GetStrucComment(sid, repeatable), comment)

    # create sub struct
    def yatest_create_sub(self):
        for offset, count in create_sub:
            name = 'substruct_' + hhex(offset) + '_' + hhex(count)
            sida = idc.AddStrucEx(-1, name + '_sub1', 0)
            self.assertNotEqual(sida, -1)
            sidb = idc.AddStrucEx(-1, name + '_sub2', 0)
            self.assertNotEqual(sidb, -1)
            for i in xrange(0, 16):
                self.assertEqual(idc.AddStrucMember(sidb, 'sub_' + hhex(i), i, idaapi.FF_BYTE | idaapi.FF_DATA, -1, 1), 0)
            self.assertEqual(idc.AddStrucMember(sida, 'sub_struc', offset, idaapi.FF_STRU | idaapi.FF_DATA, sidb, count * 16), 0)

    def check_field(self, sid, ftype, strid, offset, size, name):
        if ftype is None:
            for i in range(offset, offset + size):
                self.assertIsNone(idc.GetMemberName(sid, i))
                self.assertEqual(idc.GetMemberFlag(sid, i), -1)
            return

        try:
            self.assertNotEqual(idc.GetMemberName(sid, offset - 1), name)
        except:
            pass
        for k in range(offset, offset + size):
            self.assertEqual(idc.GetMemberName(sid, k), name)
            self.assertEqual(idc.GetMemberSize(sid, k), size)
            self.assertEqual(idc.GetMemberFlag(sid, k) & idaapi.DT_TYPE, ftype & 0xFFFFFFFF)
            if strid != -1:
                st = idaapi.get_struc(sid)
                mb = idaapi.get_member(st, offset)
                op = idaapi.opinfo_t()
                idaapi.retrieve_member_info(op, mb)
                self.assertEqual(op.tid, strid)
        self.assertNotEqual(idc.GetMemberName(sid, offset + size), name)

    def yacheck_create_sub(self):
        for offset, count in create_sub:
            name = 'substruct_' + hhex(offset) + '_' + hhex(count)
            sida = idc.GetStrucIdByName(name + '_sub1')
            self.assertNotEqual(sida, idaapi.BADADDR)
            sidb = idc.GetStrucIdByName(name + '_sub2')
            self.assertNotEqual(sidb, idaapi.BADADDR)
            self.check_field(sida, idaapi.FF_STRU, sidb, offset, count * idc.GetStrucSize(sidb), 'sub_struc')

    # create struct field
    def yatest_create_struct_field(self):
        for offset, count, field_type, string_type, comment, repeatable in create_field:
            size = count * get_size(field_type, string_type)
            name = get_name(field_type, string_type, offset, size)
            sid = idc.AddStrucEx(0, 'struct_' + name, 0)
            self.assertNotEqual(sid, -1)
            err = idc.add_struc_member(sid, 'field_' + name, offset, field_type | idaapi.FF_DATA, string_type, size)
            self.assertEqual(err, 0)
            if comment is not None:
                self.assertNotEqual(idc.SetMemberComment(sid, offset, comment, repeatable), 0)

    def yacheck_create_struct_field(self):
        for offset, count, field_type, string_type, comment, repeatable in create_field:
            size = count * get_size(field_type, string_type)
            name = get_name(field_type, string_type, offset, size)
            sid = idc.GetStrucIdByName('struct_' + name)
            self.assertNotEqual(sid, idaapi.BADADDR)
            fname = 'field_' + name
            self.check_field(sid, field_type, string_type, offset, size, fname)
            if comment is not None:
                for k in range(offset, offset + size - 1):
                    self.assertEqual(idc.GetMemberComment(sid, k, repeatable), comment)

    # set field prototype
    def yatest_set_field_prototype(self):
        for field_type, name, prototype in set_field_prototype:
            sid = idc.AddStrucEx(-1, name, 0)
            self.assertNotEqual(sid, -1)
            self.assertEqual(idc.AddStrucMember(sid, 'field', 0, field_type | idaapi.FF_DATA, -1, get_size(field_type, -1)), 0)
            mid = idc.GetMemberId(sid, 0)
            self.assertNotEqual(mid, -1)
            self.assertTrue(idc.SetType(mid, prototype))

    def yacheck_set_field_prototype(self):
        for field_type, name, prototype in set_field_prototype:
            sid = idc.GetStrucIdByName(name)
            self.assertNotEqual(sid, idaapi.BADADDR)
            for k in range(0, get_size(field_type, -1) - 1):
                self.assertEqual(field_type, idc.GetMemberFlag(sid, k) & idaapi.DT_TYPE)
                mid = idc.GetMemberId(sid, k)
                self.assertEqual(prototype, idc.GetType(mid))

    # two structures referencing each other
    def yatest_reference_loop(self):
        mids = []
        for k in range(0, 2):
            sid = idc.AddStrucEx(-1, 'refloop' + str(k), 0)
            self.assertNotEqual(sid, -1)
            self.assertEqual(idc.AddStrucMember(sid, 'refloop_field' + str(k), 0, idaapi.FF_DWRD, -1, 4), 0)
            mid = idc.GetMemberId(sid, 0)
            self.assertNotEqual(mid, -1)
            mids.append(mid)
        for k in range(0, 2):
            self.assertTrue(idc.SetType(mids[k], 'refloop' + str(1 - k) + ' *'))

    def yacheck_reference_loop(self):
        for k in range(0, 2):
            sid = idc.GetStrucIdByName('refloop' + str(k))
            self.assertNotEqual(sid, idaapi.BADADDR)
            self.assertEqual(idc.GetMemberName(sid, 0), 'refloop_field' + str(k))
            mid = idc.GetMemberId(sid, 0)
            self.assertNotEqual(mid, -1)
            self.assertEqual(idc.GetType(mid), 'refloop' + str(1 - k) + ' *')

    # apply structure on operand
    def find_operand_addr(self):
        while True:
            addr = yaunit.get_next_function()
            self.assertNotEqual(addr, idaapi.BADADDR)
            for ea in idautils.FuncItems(addr):
                flags = idaapi.get_flags_novalue(ea)
                if idaapi.isNum1(flags):
                    return ea

    def custom_op_stroff(self, ea, path, path_len):
        insn = ida_ua.insn_t()
        insn_len = ida_ua.decode_insn(insn, ea)
        self.assertNotEqual(insn_len, 0)
        return idaapi.op_stroff(insn, 1, path, path_len, 0)

    def yatest_apply_struct(self):
        addrs = []
        # -1: struct, n: union
        for k in range(-1, 4):
            # find an integer operand in any function
            addr = self.find_operand_addr()
            addrs.append(addr)

            # create struct
            sid = idc.AddStrucEx(-1, 'apply_struct_%x' % (k + 1), 0)
            self.assertNotEqual(sid, -1)
            ftype = idaapi.FF_BYTE | idaapi.FF_DATA

            # apply struct only
            if k == -1:
                # add struct fields
                for x in xrange(0, 0x60):
                    self.assertEqual(idc.AddStrucMember(sid, 'field_%x' % x, -1, ftype, -1, 1), 0)
                path = idaapi.tid_array(1)
                path[0] = sid
                self.assertNotEqual(self.custom_op_stroff(addr, path.cast(), 1), idaapi.BADADDR)
                continue

            # create union
            uid = idc.AddStrucEx(-1, 'apply_union_%x' % (k + 1), 1)
            self.assertNotEqual(uid, -1)
            for x in xrange(1, 0x10):
                self.assertEqual(idc.AddStrucMember(uid, 'union_%x' % x, -1, ftype, -1, 1), 0)

            # add struct fields
            for x in xrange(0, 0x60):
                self.assertEqual(idc.AddStrucMember(sid, 'field_%x' % x, -1, idaapi.struflag(), uid, 1), 0)

            # apply selected union field
            fid = idc.GetMemberId(uid, k)
            self.assertNotEqual(fid, -1)
            path = idaapi.tid_array(2)
            path[0] = sid
            path[1] = fid
            self.assertNotEqual(self.custom_op_stroff(addr, path.cast(), 2), idaapi.BADADDR)
        yaunit.save('apply_struct', addrs)

    def yacheck_apply_struct(self):
        addrs = yaunit.load('apply_struct')
        for k in range(-1, 4):
            # retrieve struct id
            addr = addrs[k + 1]
            sid = idc.GetStrucIdByName('apply_struct_%x' % (k + 1))
            self.assertNotEqual(sid, idaapi.BADADDR)

            # begin to check if something is applied
            flags = idaapi.get_flags_novalue(addr)
            self.assertTrue(idaapi.isStroff(flags, 1))
            ti = idaapi.opinfo_t()
            flags = idc.GetFlags(addr)
            self.assertTrue(idaapi.get_opinfo(addr, 1, flags, ti))

            # apply struct only
            if k == -1:
                # check struct is applied
                self.assertEqual(ti.path.ids[0], sid)
                continue

            # check union is selected & applied at target address
            uid = idc.GetStrucIdByName('apply_union_%x' % (k + 1))
            self.assertNotEqual(uid, idaapi.BADADDR)
            fid = idc.GetMemberId(uid, k)
            self.assertNotEqual(fid, -1)

            # check union is applied
            self.assertEqual([x for x in ti.path.ids if x], [sid, fid])

    # create complex struct
    def get_function_sid(self, in_stack, local_size=1):
        if not in_stack:
            return 'create_struct_complex', idc.AddStrucEx(0, 'create_struct_complex', 0)
        ea = yaunit.get_next_function(lambda ea : yaunit.has_locals(ea, local_size))
        frame = idaapi.get_frame(ea)
        self.assertNotEqual(frame, None)
        offset = idc.GetFirstMember(frame.id)
        while offset != idaapi.BADADDR:
            idc.DelStrucMember(frame.id, offset)
            offset = idc.GetFirstMember(frame.id)
        return ea, frame.id

    def get_function_sid_without_del(self, in_stack, local_size=1, count_from_first_var=False):
        if not in_stack:
            return 'create_struct_complex', idc.AddStrucEx(0, 'create_struct_complex', 0)
        ea = yaunit.get_next_function(lambda ea : yaunit.has_locals(ea, local_size, count_from_first_var))
        frame = idaapi.get_frame(ea)
        self.assertNotEqual(frame, None)
        offset = idc.GetFirstMember(frame.id)
        return ea, frame.id

    def create_field(self, sid, offset, name, ftype, strid, count):
        if ftype is None or name is None:
            return
        name = 'field_%.04X_%s' % (offset, name)
        size = get_size(ftype, strid) if ftype is not None else 1
        self.assertEqual(idc.AddStrucMember(sid, name, offset, ftype | idaapi.FF_DATA, strid, size * count), 0)

    def create_complex(self, sida, sidb):
        for offset, name, ftype, strid, count in complex_struc2:
            self.create_field(sidb, offset, name, ftype, strid, count)
        size = idc.GetStrucSize(sidb)
        for offset, name, ftype, strid, count in complex_struc1:
            if strid != -1:
                count *= size
                strid  = sidb
            self.create_field(sida, offset, name, ftype, strid, count)

    def create_complex2(self, sida, complex_struc):
        for offset, name, ftype, strid, count in complex_struc:
            self.create_field(sida, offset, name, ftype, strid, count)
        return idc.GetStrucSize(sida)

    def test_create_struct_complex(self, in_stack):
        ident, sida = self.get_function_sid(in_stack, local_size=complex_struc1_size)
        self.assertNotEqual(sida, -1)
        sidb = idc.AddStrucEx(0, 'create_struct_complex_sub_%d' % in_stack, 0)
        self.assertNotEqual(sidb, -1)
        self.create_complex(sida, sidb)
        yaunit.save('create_struct_complex_%d' % in_stack, ident)

    def check_create_struct_complex(self, in_stack):
        ident = yaunit.load('create_struct_complex_%d' % in_stack)

        # get first struct id
        sida = None
        if ident == 'create_struct_complex':
            self.assertFalse(in_stack)
            sida = idc.GetStrucIdByName('create_struct_complex')
        else:
            self.assertTrue(in_stack)
            frame = idaapi.get_frame(ident)
            self.assertIsNotNone(frame)
            sida = frame.id
        self.assertNotEqual(sida, idaapi.BADADDR)

        # get second struct id
        sidb = idc.GetStrucIdByName('create_struct_complex_sub_%d' % in_stack)
        self.assertNotEqual(sidb, idaapi.BADADDR)

        # check second struct
        for offset, name, ftype, strid, count in complex_struc2:
            size = get_size(ftype, strid) if ftype is not None else 1
            name = 'field_%.04X_%s' % (offset, name)
            self.check_field(sidb, ftype, strid, offset, count * size, name)

        # check first struct
        sizeb = idc.GetStrucSize(sidb)
        for offset, name, ftype, strid, count in complex_struc1:
            size = get_size(ftype, strid) if ftype is not None else 1
            if strid == 1:
                size *= sizeb
                strid = sidb
            name = 'field_%.04X_%s' % (offset, name)
            self.check_field(sida, ftype, strid, offset, count * size, name)

    def yatest_create_struct_complex(self):
        self.test_create_struct_complex(False)

    def yacheck_create_struct_complex(self):
        self.check_create_struct_complex(False)

    def yatest_create_struct_complex_in_stack(self):
        self.test_create_struct_complex(True)

    def yacheck_create_struct_complex_in_stack(self):
        self.check_create_struct_complex(True)

    def yatest_create_struct_in_stack_vars(self):
        """
        test creation of struct from stack vars
        used to find a bug when creating struct for stack vars and naming vars
        """
        # create structure
        ident, sida = self.get_function_sid_without_del(True, local_size=complex_struc3_size, count_from_first_var=True)
        self.assertNotEqual(sida, -1)
        sidb = idc.AddStrucEx(0, 'create_struct_in_stack_vars', 0)
        self.assertNotEqual(sidb, -1)
        size = self.create_complex2(sidb, complex_struc3)
        self.assertEqual(complex_struc3_size, size)
        # set first var prototype
        offset = idc.GetFirstMember(sida)
        member_id = idc.GetMemberId(sida, offset)
        self.assertNotEqual(member_id, -1)
        self.assertTrue(idc.SetType(member_id, "create_struct_in_stack_vars* x;"))
        self.assertEqual("create_struct_in_stack_vars *",
                         idc.GetType(idc.GetMemberId(sida, offset)))
        yaunit.save("create_struct_in_stack_vars", sida)
        yaunit.save("create_struct_in_stack_vars_offset", offset)

    def yacheck_create_struct_in_stack_vars(self):
        sida = yaunit.load("create_struct_in_stack_vars")
        offset = yaunit.load("create_struct_in_stack_vars_offset")
        stype = idc.GetType(idc.GetMemberId(sida, offset))
        self.assertNotEqual(None, stype)
        stype = fix_ptr_type(stype)
        
        self.assertEqual("create_struct_in_stack_vars*", stype)

    def yatest_create_struct_in_stack_vars_with_renaming(self):
        """
        test creation of struct from stack vars
        used to find a bug (structure is correctly applied on var if renamed)
        """
        # create structure
        ident, sida = self.get_function_sid_without_del(True, local_size=complex_struc3_size, count_from_first_var=True)
        self.assertNotEqual(sida, -1)
        sidb = idc.AddStrucEx(0, 'create_struct_in_stack_vars_with_renaming', 0)
        self.assertNotEqual(sidb, -1)
        size = self.create_complex2(sidb, complex_struc3)
        self.assertEqual(complex_struc3_size, size)
        # set first var prototype
        offset = idc.GetFirstMember(sida)
        member_id = idc.GetMemberId(sida, offset)
        self.assertNotEqual(member_id, -1)
        self.assertTrue(idc.SetType(member_id, "create_struct_in_stack_vars_with_renaming* x;"))
        self.assertEqual("create_struct_in_stack_vars_with_renaming *",
                         idc.GetType(idc.GetMemberId(sida, offset)))
        idc.SetMemberName(sida, offset, "var1")
        yaunit.save("create_struct_in_stack_vars_with_renaming", sida)
        yaunit.save("create_struct_in_stack_vars_with_renaming_offset", offset)

    def yacheck_create_struct_in_stack_vars_with_renaming(self):
        sida = yaunit.load("create_struct_in_stack_vars_with_renaming")
        offset = yaunit.load("create_struct_in_stack_vars_with_renaming_offset")
        self.assertEqual("var1", idc.GetMemberName(sida, offset))

        stype = fix_ptr_type(idc.GetType(idc.GetMemberId(sida, offset)))
        self.assertEqual("create_struct_in_stack_vars_with_renaming*",
                         stype)
