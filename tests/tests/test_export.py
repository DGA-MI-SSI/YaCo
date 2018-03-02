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
import StringIO

def iterate(get, size):
    for i in range(0, size):
        yield get(i)

golden_filename = "test_export.700.golden"

class Fixture(runtests.Fixture):

    def check_golden(self, got):
        expected_path = os.path.join(os.path.dirname(inspect.getsourcefile(lambda:0)), golden_filename)

        # enable to update golden file
        if False:
            with open(expected_path, "wb") as fh:
                fh.write(got)

        # read expected values
        expected = None
        with open(expected_path, "rb") as fh:
            expected = fh.read()

        if expected != got:
            self.fail(''.join(difflib.unified_diff(expected.splitlines(1), got.splitlines(1), golden_filename, "got")))

    def test_export(self):
        a, b = self.setup_repos()
        a.run(
            self.script("""
import idc
import os
name, _ = os.path.splitext(idc.get_idb_path())
os.makedirs("database")
ya.export_from_ida(name, "database/database.yadb")
"""),
        )
        import yadb.Root
        data = None
        with open(os.path.join(a.path, "database", "database.yadb"), 'rb') as fh:
            data = bytearray(fh.read())
        root = yadb.Root.Root.GetRootAsRoot(data, 0)
        def tostr(index):
            return root.Strings(index).decode()
        def getname(version):
            name = version.Username()
            return tostr(name.Value()) if name else ""
        data = {}
        versions = [
            ("bin", root.Binaries,          root.BinariesLength(),          lambda x: x.Address()),
            ("str", root.Structs,           root.StructsLength(),           lambda x: getname(x)),
            ("stm", root.StructMembers,     root.StructMembersLength(),     lambda x: (getname(data[x.ParentId()]), x.Address())),
            ("enu", root.Enums,             root.EnumsLength(),             lambda x: getname(x)),
            ("enm", root.EnumMembers,       root.EnumMembersLength(),       lambda x: (getname(data[x.ParentId()]), x.Address())),
            ("seg", root.Segments,          root.SegmentsLength(),          lambda x: x.Address()),
            ("chk", root.SegmentChunks,     root.SegmentChunksLength(),     lambda x: x.Address()),
            ("fun", root.Functions,         root.FunctionsLength(),         lambda x: x.Address()),
            ("stk", root.Stackframes,       root.StackframesLength(),       lambda x: x.Address()),
            ("stm", root.StackframeMembers, root.StackframeMembersLength(), lambda x: (data[x.ParentId()].Address(), x.Address())),
            ("ref", root.ReferenceInfos,    root.ReferenceInfosLength(),    lambda x: x.Address()),
            ("cod", root.Codes,             root.CodesLength(),             lambda x: x.Address()),
            ("dat", root.Datas,             root.DatasLength(),             lambda x: x.Address()),
            ("bbk", root.BasicBlocks,       root.BasicBlocksLength(),       lambda x: x.Address()),
        ]
        got = StringIO.StringIO()
        got.write("objects: %d\n" % root.ObjectsLength())
        for (prefix, getter, size, getkey) in versions:
            got.write("\n%s: %d\n" % (prefix, size))
            values = []
            for it in iterate(getter, size):
                data[it.ObjectId()] = it
                name = getname(it)
                prototype = tostr(it.Prototype())
                values.append((getkey(it), prefix, it.Address(), name, prototype))
            values.sort(cmp=lambda x, y: cmp(x[0], y[0]))
            for (key, prefix, ea, name, prototype) in values:
                line = "%s_%-2x %s %s" % (prefix, ea, name, prototype)
                got.write(line.rstrip() + "\n")
        self.check_golden(got.getvalue())
