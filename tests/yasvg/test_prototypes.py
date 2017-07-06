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

import difflib
import idaapi
import idautils
import idc
import inspect
import logging
import os
import re
import sys
import unittest
import yasvg

logger = logging.getLogger("YaCo")

if idc.__EA64__:
    import YaToolsPy64 as ya
else:
    import YaToolsPy32 as ya

hash_provider = ya.YaToolsHashProvider()
exporter = ya.MakeExporter(hash_provider, ya.SkipFrame)

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

class Fixture(unittest.TestCase):

    def check_golden(self, name):
        expected_dir = os.path.abspath(os.path.dirname(inspect.getsourcefile(lambda:0)))
        expected_path = os.path.join(expected_dir, name + ".golden")

        # read actual values
        got = None
        with open(name, "rb") as fh:
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

    # read all prototypes & compare them with golden source
    # apply them back & check we do not have new failures
    def yasvg_read_prototypes(self):
        read = "test_prototypes.read"
        fail = "test_prototypes.fail"
        read += "." + sys.platform + "." + str(idaapi.IDA_SDK_VERSION)
        fail += "." + sys.platform + "." + str(idaapi.IDA_SDK_VERSION)

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
                fntype = re.sub("@<r(\w)x>", "@<e\\1x>", fntype)
            line = "%s:%s: %s\n" % (name, identify(ea), fntype)
            fr.write(line)
            idc.SetType(ea, "")
            ok = setter(ea, fntype)
            if not ok:
                ff.write(line)
                return
            check = ya.get_type(ea)
            if check != fntype:
                ff.write("%s:%s:\n    got  %s\n    want %s\n" % (name, identify(ea), fntype, check))

        with open(read, "wb") as fr:
            with open(fail, "wb") as ff:
                # check functions
                for ea in yasvg.get_all_functions():
                    get_set_type("func", ea, fr, ff, get_ea, exporter.set_type)
                # check datas
                for ea in walk_datas():
                    get_set_type("data", ea, fr, ff, get_ea, exporter.set_type)
                # check struct members
                for mid in walk_struct_members():
                    get_set_type("stru", mid, fr, ff, get_member, exporter.set_struct_member_type)
        self.check_golden(fail)
        # do not check read values by default, as they change too much between ida versions
        if False:
            self.check_golden(read)
