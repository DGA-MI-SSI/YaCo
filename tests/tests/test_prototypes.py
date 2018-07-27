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

import difflib
import inspect
import os
import runtests


class Fixture(runtests.Fixture):

    def check_golden(self, repo_path, name):
        expected_dir = os.path.abspath(os.path.dirname(inspect.getsourcefile(lambda:0)))
        expected_path = os.path.join(expected_dir, name + ".golden")

        # read actual values
        got = None
        with open(os.path.join(repo_path, name), "rb") as fh:
            got = fh.read()

        # enable to update golden file
        if False:
            with open(expected_path, "wb") as fh:
                fh.write(got)

        # read expected values
        expected = None
        with open(expected_path, "rb") as fh:
            expected = fh.read()

        if expected != got:
            self.fail(''.join(difflib.unified_diff(expected.splitlines(1), got.splitlines(1), name + ".golden", name)))

    def test_prototypes(self):
        a, b = self.setup_repos()
        a.run_bare(
            self.script("""
import idautils
import idc

_functions = sorted([k for k in idautils.Functions()])

def get_all_functions():
    for ea in _functions:
        yield ea

def walk_datas():
    for seg_start in idautils.Segments():
        seg_end = idc.SegEnd(seg_start)
        for ea in ya.get_all_items(seg_start, seg_end):
            flags = idc.GetFlags(ea)
            func = idaapi.get_func(ea)
            if idaapi.isFunc(flags) or (func and idc.isCode(flags)):
                # function
                continue
            if not func and idc.isCode(flags):
                # code
                continue
            yield ea

def walk_struct_members():
    for (idx, sid, name) in idautils.Structs():
        s = idaapi.get_struc(sid)
        for (offset, name, size) in idautils.StructMembers(sid):
            m = idaapi.get_member(s, offset)
            yield m.id

def get_ea(ea):
    return "%x" % ea

def get_member(ea):
    return idaapi.get_member_fullname(ea)

def get_set_type(name, ea, fr, ff, identify, setter):
    fntype = ya.get_type(ea)
    if not len(fntype):
        return
    # workaround broken usercall arguments on 32-bit binaries in ida64
    if "__usercall" in fntype:
        fntype = re.sub("@<r(\w)x>", "@<e\\\\1x>", fntype)
    line = "%s:%s: %s\\n" % (name, identify(ea), fntype)
    fr.write(line)
    idc.SetType(ea, "")
    ok = setter(ea, fntype)
    if not ok:
        ff.write(line)
        return
    check = ya.get_type(ea)
    if check != fntype:
        ff.write("%s:%s:\\n    got  %s\\n    want %s\\n" % (name, identify(ea), fntype, check))

read = "test_prototypes.read.700"
fail = "test_prototypes.fail.700"
with open(read, "wb") as fr:
    with open(fail, "wb") as ff:
        # check functions
        for ea in get_all_functions():
            get_set_type("func", ea, fr, ff, get_ea, ya.set_type_at)
        # check datas
        for ea in walk_datas():
            get_set_type("data", ea, fr, ff, get_ea, ya.set_type_at)
        # check struct members
        for mid in walk_struct_members():
            get_set_type("stru", mid, fr, ff, get_member, ya.set_struct_member_type_at)
"""),
        )
        read = "test_prototypes.read.700"
        fail = "test_prototypes.fail.700"
        self.check_golden(a.path, fail)
        # do not check read values by default, as they change too much between ida versions
        if False:
            self.check_golden(a.path, read)

    def test_usercall(self):
        a, b = self.setup_cmder()
        a.run(
            self.script("""
ea = 0x40197E
idc.SetType(ea, "int __usercall WinMain@<eax>(HINSTANCE hInstance@<eax>, HINSTANCE hPrevInstance@<ebx>, LPSTR lpCmdLine@<edx>, int nShowCmd@<ecx>);")
"""),
            self.save_last_ea(),
        )
        a.check_git(added=["binary", "segment", "segment_chunk", "function", "basic_block"])
        b.run(
            self.check_last_ea(),
        )
