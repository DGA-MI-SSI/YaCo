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

    def test_sub_strucs(self):
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
    idc.add_struc_member(top, "sub_struc", offset, idaapi.FF_STRU | idaapi.FF_DATA, bot, idaapi.get_struc_size(bot), -1)
"""),
            self.save_strucs(),
        )
        b.run(
            self.check_strucs(),
        )

    def test_struc_loop(self):
        a, b = self.setup_repos()
        a.run(
            self.script("""
mids = []
for k in range(0, 2):
    sid = idaapi.add_struc(-1, "loop_%x" % k, 0)
    idc.add_struc_member(sid, "field", 0, idaapi.FF_DWRD, -1, 4)
    mid = idc.get_member_id(sid, 0)
    mids.append(mid)
for k in range(0, 2):
    idc.SetType(mids[k], "loop_%x*" % (1 - k))
"""),
            self.save_strucs(),
        )
        b.run(
            self.check_strucs(),
        )

    def test_apply_strucs(self):
        a, b = self.setup_repos()
        ea = 0x66013D10
        targets = """
targets = [
    (0x66013D23, 1, 3),
    (0x66013D26, 1, 7),
    (0x66013D2C, 0, 13),
]
"""
        a.run(
            self.script(targets + """
sid = idaapi.add_struc(-1, "t0", False)
for x in xrange(0, 0x60):
    idc.add_struc_member(sid, "dat_%x" % x, x, idaapi.FF_BYTE | idaapi.FF_DATA, -1, 1)
sidu = idaapi.add_struc(-1, "u0", True)
for x in xrange(0, 0x10):
    idc.add_struc_member(sidu, "datu_%x" %x, 0, idaapi.struflag(), sid, idaapi.get_struc_size(sid))

def custom_op_stroff(ea, n, path, path_len):
    insn = ida_ua.insn_t()
    insn_len = ida_ua.decode_insn(insn, ea)
    return idaapi.op_stroff(insn, n, path, path_len, 0)

path = idaapi.tid_array(1)
path[0] = sid
custom_op_stroff(0x66013D1D, 0, path.cast(), 1)

for ea, n, offset in targets:
    path = idaapi.tid_array(2)
    path[0] = sidu
    path[1] = idc.get_member_id(sidu, offset)
    custom_op_stroff(ea, n, path.cast(), 2)
"""),
            self.save_strucs(),
            self.save_ea(ea),
        )
        self.assertRegexpMatches(self.eas[ea], "path_idx")
        b.run(
            self.check_ea(ea),
            self.check_strucs(),
            self.script(targets + """
for ea, n, offset in targets:
    idaapi.clr_op_type(ea, n)
"""),
            self.save_ea(ea),
        )
        self.assertNotRegexpMatches(self.eas[ea], "path_idx")
        a.run(
            self.check_ea(ea),
        )
