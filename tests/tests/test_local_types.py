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

    def test_local_type_reload(self):
        a, b = self.setup_cmder()
        a.run(
            self.script("""
ida_typeinf.import_type(ida_typeinf.get_idati(), -1, "OSVERSIONINFO")
"""),
            self.save_local_types(),
        )
        a.check_git(added=["local_type"] * 4)

        a.run(
            self.check_local_types(),
        )

    def test_struc_renames_with_imports(self):
        a, b = self.setup_cmder()

        a.run(
            self.script("""
for x in xrange(0, 4):
    idaapi.add_struc(-1, "struc_a_%d" % x, False)
ida_typeinf.import_type(ida_typeinf.get_idati(), -1, "OSVERSIONINFO")
"""),
            self.save_local_type("CHAR"),
            self.save_local_type("OSVERSIONINFO"),
            self.save_local_type("OSVERSIONINFOA"),
            self.save_local_type("_OSVERSIONINFOA"),
        )
        a.check_git(added=["struc"] * 4 + ["local_type"] * 4)
        local_types = self.local_types

        b.run_no_sync(
            self.script("""
ida_typeinf.import_type(ida_typeinf.get_idati(), -1, "OSVERSIONINFO")
for x in xrange(0, 4):
    idaapi.add_struc(-1, "struc_b_%d" % x, False)
"""),
            self.sync(),
            self.save_local_types(),
            self.save_strucs(),
        )
        b.check_git(added=["struc"] * 4)

        self.local_types = local_types
        a.run(
            self.check_local_type("CHAR"),
            self.check_local_type("OSVERSIONINFO"),
            self.check_local_type("OSVERSIONINFOA"),
            self.check_local_type("_OSVERSIONINFOA"),
            self.check_local_types(),
            self.check_strucs(),
        )
        b.run(
            self.check_local_type("CHAR"),
            self.check_local_type("OSVERSIONINFO"),
            self.check_local_type("OSVERSIONINFOA"),
            self.check_local_type("_OSVERSIONINFOA"),
            self.check_local_types(),
            self.check_strucs(),
        )

    def test_local_types(self):
        a, b = self.setup_cmder()
        a.run(
            self.script("""
tif = ida_typeinf.tinfo_t()
ida_typeinf.parse_decl(tif, None, "struct { int a; };", 0)
tif.set_named_type(None, "somename")
ida_typeinf.parse_decl(tif, None, "struct { int a; };", 0)
tif.set_named_type(None, "somename_2")
"""),
            self.save_local_types(),
        )
        a.check_git(added=["local_type"] * 2)

        b.run(
            self.check_local_types(),
            self.script("""
tif = ida_typeinf.tinfo_t()
tif.get_named_type(None, "somename")
ord = tif.get_ordinal()
ida_typeinf.del_numbered_type(None, ord)
idc.set_local_type(ord, "struct anothername { int p[2]; };", 0)
"""),
            self.save_local_types(),
        )
        b.check_git(modified=["local_type"])

        a.run(
            self.check_local_types(),
            self.script("""
tif = ida_typeinf.tinfo_t()
tif.get_named_type(None, "anothername")
ord = tif.get_ordinal()
ida_typeinf.del_numbered_type(None, ord)
"""),
            self.save_local_types(),
        )
        a.check_git(deleted=["local_type"])

        b.run(
            self.check_local_types(),
        )

    def test_conflicting_local_types(self):
        a, b = self.setup_cmder()

        a.run(
            self.script("""
tif = ida_typeinf.tinfo_t()
ida_typeinf.parse_decl(tif, None, "struct { int a; };", 0)
tif.set_named_type(None, "somename")
"""),
            self.sync(),
            self.script("""
ea = 0x401E07
idaapi.set_name(ea, "somesub")
"""),
            self.save_local_types(),
        )
        a.check_git(added=["binary", "segment", "segment_chunk", "function", "basic_block"])
        types = self.types

        b.run_no_sync(
            self.script("""
tif = ida_typeinf.tinfo_t()
ida_typeinf.parse_decl(tif, None, "struct { char name[256]; };", 0)
tif.set_named_type(None, "somename")
"""),
            self.sync(),
            self.script("""
ea = 0x401E07
idaapi.set_name(ea, "anothersub")
"""),
        )
        b.check_git(modified=["basic_block"])

        self.types = types
        b.run(
            self.check_local_types(),
        )
        b.check_git(modified=["basic_block"])

    def test_apply_local_type(self):
        a, b = self.setup_cmder()

        a.run(
            self.script("""
tif = ida_typeinf.tinfo_t()
ida_typeinf.parse_decl(tif, None, "struct { int a; };", 0)
tif.set_named_type(None, "somename")
ea = 0x4157C8
idaapi.set_name(ea, "name")
idc.SetType(ea, "somename*")
"""),
            self.save_local_types(),
            self.save_last_ea(),
        )
        a.check_git(added=["binary", "segment", "segment_chunk", "data", "local_type"])

        b.run(
            self.check_local_types(),
            self.check_last_ea(),
            self.script("""
tif = ida_typeinf.tinfo_t()
tif.get_named_type(None, "somename")
ord = tif.get_ordinal()
ida_typeinf.del_numbered_type(None, ord)
idc.set_local_type(ord, "struct anothername { int p[2]; };", 0)
"""),
            self.save_local_types(),
            self.save_last_ea(),
        )
        b.check_git(modified=["local_type"])

        a.run(
            self.check_local_types(),
            self.check_last_ea(),
        )

        b.run(
            self.check_local_types(),
            self.check_last_ea(),
        )

    def test_local_type_renames(self):
        a, b = self.setup_cmder()

        a.run(
            self.script("""
tif = ida_typeinf.tinfo_t()
ida_typeinf.parse_decl(tif, None, "struct { int a; };", 0)
tif.set_named_type(None, "somename")
ea = 0x4157C8
idc.SetType(ea, "somename*")
"""),
            self.sync(),
            self.script("""
tif = ida_typeinf.tinfo_t()
tif.get_named_type(None, "somename")
ord = tif.get_ordinal()
ida_typeinf.del_numbered_type(None, ord)
idc.set_local_type(ord, "struct anothername { int p[2]; };", 0)
"""),
            self.save_local_types(),
            self.save_last_ea(),
        )
        a.check_git(modified=["local_type"])

        # we check whether we are able to track
        # local type renames and still apply them
        # correctly
        b.run(
            self.check_local_types(),
            self.check_last_ea(),
        )
