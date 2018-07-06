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
