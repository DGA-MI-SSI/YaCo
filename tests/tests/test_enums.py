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
from textwrap import dedent


class Fixture(runtests.Fixture):

    def test_enums(self):
        a, b = self.setup_repos()
        a.run(
            self.script("idaapi.add_enum(idaapi.BADADDR, 'name_a', idaapi.hexflag())"),
            self.save_types(),
        )
        a.check_git(added=["enum"])
        b.run(
            self.check_types(),
            self.script("idaapi.set_enum_name(idaapi.get_enum('name_a'), 'name_b')"),
            self.save_types(),
        )
        b.check_git(modified=["enum"])
        a.run(
            self.check_types(),
            self.script("idaapi.del_enum(idaapi.get_enum('name_b'))"),
            self.save_types(),
        )
        a.check_git(deleted=["enum"])
        b.run(
            self.check_types(),
        )

    def test_enum_members(self):
        a, b = self.setup_repos()
        a.run(
            self.script("idaapi.add_enum_member(idaapi.add_enum(idaapi.BADADDR, 'name_a', idaapi.hexflag()), 'field_a', 0, -1)"),
            self.save_types(),
        )
        a.check_git(added=["enum", "enum_member"])
        b.run(
            self.check_types(),
            self.script("idaapi.set_enum_member_name(idaapi.get_enum_member_by_name('field_a'), 'field_b')"),
            self.save_types(),
        )
        b.check_git(modified=["enum"], added=["enum_member"], deleted=["enum_member"])
        a.run(
            self.check_types(),
            self.script("idaapi.set_enum_name(idaapi.get_enum('name_a'), 'name_b')"),
            self.save_types(),
        )
        a.check_git(modified=["enum"])
        b.run(
            self.check_types(),
            self.script("idaapi.del_enum_member(idaapi.get_enum('name_b'), 0, 0, -1)"),
            self.save_types(),
        )
        b.check_git(deleted=["enum_member"], modified=["enum"])
        a.run(
            self.check_types(),
        )

    def test_enum_types(self):
        a, b = self.setup_repos()
        constants = dedent("""
            ea = 0x66045614

            # flags, bits, bitfield, ea, operand, fields
            enums = [
                (idaapi.hexflag(),  0, False, ea+0x00, 0, [0, 0x40, 16]),
                (idaapi.charflag(), 0, False, ea+0x19, 1, [ord('a'), ord('z'), ord('$')]),
                (idaapi.decflag(),  1, False, ea+0x02, 0, [0, 10, 16]),
                (idaapi.octflag(),  0, False, ea+0x06, 1, [0, 8, 13, 16]),
                (idaapi.binflag(),  0, True,  ea+0x04, 0, [1, 2]),
            ]
            """)
        a.run(
            self.script(constants + dedent("""
                idx = 0
                def get_cmt():
                    global idx
                    idx += 1
                    return "cmt_%02x" % idx

                eidx = 0
                for (flags, bits, bitfield, ea, operand, fields) in enums:
                    name = "enum_%x" % eidx
                    eidx += 1
                    eid = idaapi.add_enum(idaapi.BADADDR, name, flags)
                    if bits != 0:
                        idaapi.set_enum_width(eid, bits)
                    if bitfield:
                       idaapi.set_enum_bf(eid, True)
                    for rpt in [False, True]:
                        idaapi.set_enum_cmt(eid, get_cmt(), rpt)
                    fidx = 0
                    for f in fields:
                        field = "%s_%x" % (name, fidx)
                        fidx += 1
                        if bitfield:
                           idaapi.add_enum_member(eid, field, f, f)
                        else:
                            idaapi.add_enum_member(eid, field, f, -1)
                        cid = idaapi.get_enum_member_by_name(field)
                        for rpt in [False, True]:
                            set_enum_member_cmt(cid, get_cmt(), rpt)
                    idaapi.op_enum(ea, operand, eid, 0)
                """)),
            self.save_types(),
            self.save_last_ea()
        )
        b.run(
            self.check_last_ea(),
            self.check_types(),
            self.script(constants +  dedent("""
                for (flags, bits, bitfield, ea, operand, fields) in enums:
                    idaapi.clr_op_type(ea, operand)
                """)),
            self.save_last_ea(),
        )
        b.check_git(modified=["basic_block"])
        a.run(
            self.check_last_ea(),
            self.script(constants + dedent("""
                eidx = 0
                for (flags, bits, bitfield, ea, operand, fields) in enums:
                    name = "enum_%x" % eidx
                    eidx += 1
                    eid = idaapi.get_enum(name)
                    idaapi.op_enum(ea, operand, eid, 0)
                """)),
            self.save_last_ea(),
        )
        a.check_git(modified=["basic_block"])
        b.run(
            self.check_last_ea(),
            self.script(constants + dedent("""
                eidx = 0
                for (flags, bits, bitfield, ea, operand, fields) in enums:
                    name = "enum_%x" % eidx
                    eidx += 1
                    eid = idaapi.get_enum(name)
                    idaapi.del_enum(eid)
                """)),
            self.save_types(),
            self.save_last_ea(),
        )
        b.check_git(deleted=["enum"] * 5 + ["enum_member"] * 15)
        a.run(
            self.check_last_ea(),
            self.check_types(),
        )

    def test_enum_bf(self):
        a, b = self.setup_repos()
        a.run(
            self.script("idaapi.add_enum(idaapi.BADADDR, 'name_a', idaapi.hexflag())"),
            self.save_types(),
        )
        a.check_git(added=["enum"])
        b.run(
            self.check_types(),
            self.script("idaapi.set_enum_bf(idaapi.get_enum('name_a'), True)"),
            self.save_types(),
        )
        b.check_git(modified=["enum"])
        a.run(
            self.check_types(),
            self.script("idaapi.set_enum_bf(idaapi.get_enum('name_a'), False)"),
            self.save_types(),
        )
        a.check_git(modified=["enum"])
        b.run(
            self.check_types(),
        )

    def test_enum_cmt(self):
        a, b = self.setup_repos()
        a.run(
            self.script("idaapi.add_enum(idaapi.BADADDR, 'name_a', idaapi.hexflag())"),
            self.save_types(),
        )
        a.check_git(added=["enum"])
        b.run(
            self.check_types(),
            self.script("idaapi.set_enum_cmt(idaapi.get_enum('name_a'), 'some_comment', False)"),
            self.save_types(),
        )
        b.check_git(modified=["enum"])
        a.run(
            self.check_types(),
            self.script("idaapi.set_enum_cmt(idaapi.get_enum('name_a'), '', False)"),
            self.save_types(),
        )
        a.check_git(modified=["enum"])
        b.run(
            self.check_types(),
        )

    def test_renamed_enums_are_still_applied(self):
        a, b = self.setup_cmder()

        a.run(
            self.script("""
eid = idaapi.add_enum(idaapi.BADADDR, "somename", idaapi.hexflag())
idaapi.add_enum_member(eid, "somevalue", 0x8)
idaapi.add_enum_member(eid, "anothervalue", 0x18)
"""),
            self.sync(),
            self.script("""
eid = idaapi.get_enum("somename")
ea = 0x40199D
idaapi.op_enum(ea, 0, eid, 0)
ea = 0x4019BE
idaapi.op_enum(ea, 1, eid, 0)
"""),
            self.save_types(),
            self.save_ea(0x40199D),
            self.save_ea(0x4019BE),
        )
        a.check_git(added=["binary", "segment", "segment_chunk", "function"] + ["basic_block"] * 2)

        b.run(
            self.check_types(),
            self.check_ea(0x40199D),
            self.check_ea(0x4019BE),
            self.script("""
idaapi.set_enum_name(idaapi.get_enum("somename"), "anothername")
"""),
            self.save_types(),
            self.save_ea(0x40199D),
            self.save_ea(0x4019BE),
        )
        b.check_git(modified=["enum"])

        a.run(
            self.check_types(),
            self.check_ea(0x40199D),
            self.check_ea(0x4019BE),
        )

    def test_create_same_enum_independently(self):
        a, b = self.setup_cmder()

        a.run(
            self.script("""
eid = idaapi.add_enum(idaapi.BADADDR, "somename", idaapi.hexflag())
idaapi.add_enum_member(eid, "somevalue", 0x4)
"""),
            # create an arbitrary commit which should stay
            # as the last commit in history
            self.sync(),
            self.script("""
ea = 0x401E07
idaapi.set_name(ea, "somesub")
"""),
            self.save_types(),
        )
        defgit = ["binary", "segment", "segment_chunk", "function", "basic_block"]
        a.check_git(added=defgit)
        types = self.types

        # create a conflicting enum
        # it should be removed from history
        b.run_no_sync(
            self.script("""
eid = idaapi.add_enum(idaapi.BADADDR, "somename", idaapi.hexflag())
idaapi.add_enum_member(eid, "somevalue", 0x4)
"""),
            self.sync(),
        )
        b.check_git(added=defgit)

        self.types = types
        b.run(
            self.check_types(),
        )
        b.check_git(added=defgit)

    def test_potential_enum_conflict(self):
        a, b = self.setup_cmder()

        a.run(
            self.script("""
idaapi.add_enum(idaapi.BADADDR, "someenum", idaapi.hexflag())
"""),
            # now remove potentially conflicting commit
            self.sync(),
            self.script("""
idaapi.del_enum(idaapi.get_enum("someenum"))
"""),
        )
        a.check_git(deleted=["enum"])

        # create a potentially conflicting enum
        b.run_no_sync(
            self.script("""
idaapi.add_enum(idaapi.BADADDR, "someenum", idaapi.hexflag())
"""),
            self.sync(),
            self.save_types(),
        )
        b.check_git(added=["enum"])

        a.run(
            self.check_types(),
        )
