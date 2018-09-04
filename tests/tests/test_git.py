#!/bin/python

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


import runtests
import unittest
import os
import tempfile
import shutil


class Fixture(runtests.Fixture):

    def test_invalid_git(self):
        a, b = self.setup_repos()

        # remove git directory & replace it with a file
        os.rename(os.path.join(a.path, ".git"), os.path.join(a.path, ".git.old"))
        with open(os.path.join(a.path, ".git"), "wb") as fh:
            fh.write("nothing")

        # start yaco again and expect no crashes
        a.run(
            self.script("idc.AddEnum(-1, 'name', idaapi.hexflag())"),
        )

    def test_git_submodule(self):
        a, b = self.setup_repos()

        # setup git repo 'd' containing submodule 'a' at path 'modules/z'
        d = os.path.abspath(os.path.join(a.path, "..", "d"))
        os.makedirs(os.path.join(d, "modules"))
        runtests.sysexec(d, ["git", "init"])
        with open(os.path.join(d, "modules", ".gitignore"), "wb") as fh:
            fh.write("dummy file")
        runtests.sysexec(d, ["git", "add", "-A"])
        runtests.sysexec(d, ["git", "commit", "-m", "init"])
        runtests.sysexec(d, ["git", "submodule", "add", "../c", "modules/z"])

        # 'e' now contains our submodule
        target = "Qt5Svgd.dll"
        pe = os.path.abspath(os.path.join(d, "modules", "z"))
        e = runtests.Repo(self, pe, target)

        # initialize YaCo
        e.run_script("""
import yaco_plugin
yaco_plugin.start()
""", target=target + ".i64")

        # check changes are properly propagated
        e.run(
            self.script("idaapi.add_enum(idaapi.BADADDR, 'name_a', idaapi.hexflag())"),
            self.save_enum("name_a"),
        )
        e.check_git(added=["enum"])

        a.run(
            self.check_enum("name_a"),
        )

    def commit_version(self, repo, version):
        with open(os.path.join(repo.path, "yaco.version"), "wb") as fh:
            fh.write("%s\n" % version)
        runtests.sysexec(repo.path, ["git", "add", "yaco.version"])
        runtests.sysexec(repo.path, ["git", "commit", "-m", "version: force %s" % version])

    def expect_version(self, repo, want):
        with open(os.path.join(repo.path, "yaco.version"), "rb") as fh:
            got = fh.read().strip()
            self.assertEqual(want, got)

    def get_current_version(self):
        return runtests.sysexec(self.yaco_dir, ["git", "describe", "--long", "--dirty"]).strip()

    # 2.2-14: struc ids now depend on random tag
    min_valid_version = "v2.2-14-g00000000"

    def test_git_upgrade_version(self):
        a, b = self.setup_cmder()

        # force git update with older version
        self.commit_version(a, self.min_valid_version)
        a.run()

        # check version has been upgraded
        want = self.get_current_version()
        self.expect_version(a, want)

    def test_git_older_version(self):
        a, b = self.setup_cmder()

        # force git update with newer version
        want = "v99.0-0-g00000000"
        self.commit_version(a, want)
        a.run()

        # check version has been upgraded
        self.expect_version(a, want)

    def test_git_conflict_version(self):
        a, b = self.setup_cmder()

        va, vb = [self.min_valid_version, "v99.0-0-g00000000"]
        self.commit_version(a, va)
        self.commit_version(b, vb)

        # simulate activity
        a.run(
            self.script("""
ea = 0x401C97
idaapi.set_name(ea, "nonamea")
"""),
        )
        b.run(
            self.script("""
ea = 0x401F1F
idaapi.set_name(ea, "nonameb")
"""),
        )
        a.run(
            self.script("""
ea = 0x401006
idaapi.set_name(ea, "nonamec")
"""),
        )

        # we expect latest version to win
        self.expect_version(a, vb)
        self.expect_version(b, vb)
