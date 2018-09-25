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

helpers = """
def create_local_type(name, strtype):
    tif = ida_typeinf.tinfo_t()
    ida_typeinf.parse_decl(tif, None, strtype, 0)
    tif.set_named_type(None, name)

def rename_local_type(oldname, newname):
    tif = ida_typeinf.tinfo_t()
    tif.get_named_type(None, oldname)
    ord = tif.get_ordinal()
    strtype = tif._print("", ida_typeinf.PRTYPE_DEF)
    ida_typeinf.parse_decl(tif, None, strtype + ";", 0)
    tif.set_numbered_type(None, ord, ida_typeinf.NTF_REPLACE, newname)
"""

class Fixture(runtests.Fixture):

    def test_local_type_reload(self):
        a, b = self.setup_cmder()
        a.run(
            self.script("""
ida_typeinf.import_type(ida_typeinf.get_idati(), -1, "OSVERSIONINFO")
"""),
            self.save_types(),
        )
        a.check_git(added=["local_type"] * 4)

        a.run(
            self.check_types(),
        )

    def test_struc_renames_with_imports(self):
        a, b = self.setup_cmder()

        a.run(
            self.script("""
for x in xrange(0, 4):
    idaapi.add_struc(-1, "struc_a_%d" % x, False)
ida_typeinf.import_type(ida_typeinf.get_idati(), -1, "OSVERSIONINFO")
"""),
        )
        a.check_git(added=["struc"] * 4 + ["local_type"] * 4)

        b.run_no_sync(
            self.script("""
ida_typeinf.import_type(ida_typeinf.get_idati(), -1, "OSVERSIONINFO")
for x in xrange(0, 4):
    idaapi.add_struc(-1, "struc_b_%d" % x, False)
"""),
            self.sync(),
            self.save_types(),
        )
        b.check_git(added=["struc"] * 4)

        self.assertRegexpMatches(self.types[1], "CHAR")
        self.assertRegexpMatches(self.types[1], "OSVERSIONINFO")
        self.assertRegexpMatches(self.types[1], "OSVERSIONINFOA")
        self.assertRegexpMatches(self.types[1], "_OSVERSIONINFOA")
        a.run(
            self.check_types(),
        )
        b.run(
            self.check_types(),
        )

    def test_local_types(self):
        a, b = self.setup_cmder()
        a.run(
            self.script(helpers + """
create_local_type("somename_1", "struct { int a; };")
create_local_type("somename_2", "struct { int a; };")
"""),
            self.save_types(),
        )
        a.check_git(added=["local_type"] * 2)

        b.run(
            self.check_types(),
            self.script("""
tif = ida_typeinf.tinfo_t()
tif.get_named_type(None, "somename_1")
ord = tif.get_ordinal()
ida_typeinf.del_numbered_type(None, ord)
idc.set_local_type(ord, "struct anothername { int p[2]; };", 0)
"""),
            self.save_types(),
        )
        b.check_git(modified=["local_type"])

        a.run(
            self.check_types(),
            self.script("""
tif = ida_typeinf.tinfo_t()
tif.get_named_type(None, "anothername")
ord = tif.get_ordinal()
ida_typeinf.del_numbered_type(None, ord)
"""),
            self.save_types(),
        )
        a.check_git(deleted=["local_type"])

        b.run(
            self.check_types(),
        )

    def test_conflicting_local_types(self):
        a, b = self.setup_cmder()

        a.run(
            self.script(helpers + """
create_local_type("somename", "struct { int a; };")
"""),
            self.sync(),
            self.script("""
ea = 0x401E07
idaapi.set_name(ea, "somesub")
"""),
            self.save_types(),
        )
        a.check_git(added=["binary", "segment", "segment_chunk", "function", "basic_block"])
        types = self.types

        b.run_no_sync(
            self.script(helpers + """
create_local_type("somename", "struct { char name[256]; };")
ea = 0x401E07
idaapi.set_name(ea, "anothersub")
"""),
            self.sync(),
        )
        b.check_git(modified=["basic_block"])

        self.types = types
        b.run(
            self.check_types(),
        )
        b.check_git(modified=["basic_block"])

    def test_local_type_renames(self):
        a, b = self.setup_cmder()

        a.run(
            self.script(helpers + """
create_local_type("somename", "struct { int a; };")
ea = 0x4157C8
idc.SetType(ea, "somename*")
"""),
            self.sync(),
            self.script(helpers + """
rename_local_type("somename", "anothername")
"""),
            self.save_types(),
            self.save_last_ea(),
        )
        a.check_git(modified=["local_type"])

        # we check whether we are able to track
        # local type renames and still apply them
        # correctly
        b.run(
            self.check_types(),
            self.check_last_ea(),
        )
        a.run(
            self.check_types(),
            self.check_last_ea(),
        )

    def test_type_rename_on_stack_member(self):
        a, b = self.setup_cmder()

        a.run(
            self.script(helpers + """
ea = 0x40197E
idaapi.set_name(ea, "")
create_local_type("somelocal", "struct { int a; };")
sid = idaapi.add_struc(-1, "sometype", False)
idc.add_struc_member(sid, "dat", 0, ida_bytes.dword_flag(), -1, 4)
frame = idaapi.get_frame(ea)
"""), # ignore local type & struc created events
            self.sync(),
            self.script("""
idc.SetType(idc.get_member_id(frame.id, idc.get_member_offset(frame.id, "var_34")), "somelocal[2]")
idc.SetType(idc.get_member_id(frame.id, idc.get_member_offset(frame.id, "var_20")), "const somelocal*")
idc.SetType(idc.get_member_id(frame.id, idc.get_member_offset(frame.id, "var_1C")), "sometype[2]")
idc.SetType(idc.get_member_id(frame.id, idc.get_member_offset(frame.id, "var_4")),  "const sometype*")
"""),
            self.save_types(),
            self.save_last_ea(),
        )
        a.check_git(added=["stackframe"] + ["stackframe_member"] * 8)

        b.run(
            self.check_types(),
            self.check_last_ea(),
            self.script(helpers + """
rename_local_type("somelocal", "anotherlocal")
"""),
            self.save_types(),
            self.save_last_ea(),
        )
        b.check_git(modified=["local_type"] + ["stackframe_member"] * 2)

        a.run(
            self.check_types(),
            self.check_last_ea(),
            self.script("""
# rename struc
sid = idaapi.get_struc_id("sometype")
idaapi.set_struc_name(sid, "anothertype")
"""),
            self.save_types(),
            self.save_last_ea(),
        )
        a.check_git(modified=["struc"])

        b.run(
            self.check_types(),
            self.check_last_ea(),
        )
