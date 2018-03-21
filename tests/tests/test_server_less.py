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

    def test_server_less(self):
        indir, target = "qt54_svg_no_pdb", "Qt5Svgd.dll"
        work_dir = tempfile.mkdtemp(prefix='repo_', dir=self.out_dir)
        self.dirs.append(work_dir)
        indir = os.path.join(self.tests_dir, "..", "testdata", indir)
        pa = os.path.abspath(os.path.join(work_dir, "a"))
        os.makedirs(pa)
        shutil.copy(os.path.join(indir, target), pa)
        a = runtests.Repo(self, pa, target)

        # create idb
        a.run_script("", target)

        # start yaco with default remote origin
        a.run_script("""
import yaco_plugin
yaco_plugin.start()
""", target=target + ".i64")

        # remove invalid remote origin
        runtests.sysexec(pa, ["git", "remote", "rm", "origin"])

        # start yaco again, server less & check one change & one save
        a.run(
            self.script("idc.AddEnum(-1, 'name', idaapi.hexflag())"),
        )
        a.check_git(added=["enum"])
