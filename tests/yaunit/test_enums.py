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

import idaapi
import idautils
import idc
import unittest
import yaunit

flags = [
    idaapi.hexflag(),
    idaapi.charflag(),
    idaapi.decflag(),
    idaapi.octflag(),
    idaapi.binflag(),
]

# name, enum_width 0->default, is bitfield, num_fields
tests = [
    ('std',         0, False, 0),
    ('std',         4, False, 0),
    ('bit',         0, True,  0),
    ('std_fields',  0, False, 0x20),
    ('bit_fields',  0, True,  0x20),
]

def walk_enum(eid):
    def get_enums(bmask):
        value = idc.GetFirstConst(eid, bmask)
        while value != idaapi.BADADDR:
            yield value, bmask
            value = idc.GetNextConst(eid, value, bmask)
    # iterate on every bmask
    bmask = idc.GetFirstBmask(eid)
    while bmask != idaapi.BADADDR:
        for v, m in get_enums(bmask):
            yield v, m
        bmask = idc.GetNextBmask(eid, bmask)
    # iterate on regular constants
    for v, m in get_enums(-1):
        yield v, m

def get_ea():
    while True:
        ea = yaunit.get_next_function()
        for eai in idautils.FuncItems(ea):
            flags = idaapi.get_flags_novalue(eai)
            if idaapi.isNum1(flags) and not idaapi.isEnum(flags, 1):
                return eai

class Fixture(unittest.TestCase):

    def yatest_enums(self):
        values = []
        for flag in flags:
            for prefix, enum_width, is_bitfield, num_fields in tests:
                name = '%s_%x_%d_%x' % (prefix, enum_width, is_bitfield, flag)
                ea = None
                eid = idc.AddEnum(-1, name, flag)
                self.assertNotEqual(eid, idaapi.BADADDR)
                if enum_width != 0:
                    idc.SetEnumWidth(eid, enum_width)
                if is_bitfield:
                    self.assertTrue(idc.SetEnumBf(eid, True))
                idc.SetEnumCmt(eid, prefix + 'cmt', False)
                idc.SetEnumCmt(eid, prefix + 'rpt', True)
                for n in range(0, num_fields):
                    field = '%s_%d' % (name , n)
                    cid = None
                    if is_bitfield:
                        self.assertEqual(idc.AddConstEx(eid, field, 1 << n, 1 << n), 0)
                    else:
                        self.assertEqual(idc.AddConst(eid, field, n), 0)
                    if n == 0:
                        ea = get_ea()
                        self.assertNotEqual(idaapi.op_enum(ea, 1, eid, 0), idaapi.BADADDR)
                    cid = idc.GetConstByName(field)
                    self.assertTrue(idc.SetConstCmt(cid, field + 'cmt', False))
                    #self.assertTrue(idc.SetConstCmt(cid, field + 'rpt', True))
                values.append((name, ea))
        yaunit.save('enums', values)

    def yacheck_enums(self):
        values = yaunit.load('enums')
        for flag in flags:
            for prefix, enum_width, is_bitfield, num_fields in tests:
                name, ea, values = str(values[0][0]), values[0][1], values[1:]
                eid = idc.GetEnum(name)
                self.assertNotEqual(eid, idaapi.BADADDR)
                self.assertEqual(idc.GetEnumFlag(eid), flag)
                self.assertEqual(idc.GetEnumName(eid), name)
                self.assertEqual(idc.IsBitfield(eid), is_bitfield)
                self.assertEqual(idc.GetEnumCmt(eid, False), prefix + 'cmt')
                self.assertEqual(idc.GetEnumCmt(eid, True),  prefix + 'rpt')
                if enum_width != 0:
                    self.assertEqual(idc.GetEnumWidth(eid), enum_width)
                n = 0
                for value, bmask in walk_enum(eid):
                    self.assertLessEqual(n, num_fields)
                    v = 1 << n if is_bitfield else n
                    self.assertEqual(value, value, v)
                    cid = idc.GetConstEx(eid, v, 0, bmask)
                    self.assertNotEqual(cid, idaapi.BADADDR)
                    field = '%s_%d' % (name, n)
                    self.assertEqual(idc.GetConstName(cid), field)
                    # FIXME comments are not working
                    #self.assertEqual(idc.GetConstCmt(cid, False), field + 'cmt')
                    #self.assertEqual(idc.GetConstCmt(cid, True),  field + 'rpt')
                    n += 1
                self.assertEqual(n, num_fields)
                if ea != None:
                    self.assertEqual(idaapi.get_enum_id(ea, 1)[0], eid)
