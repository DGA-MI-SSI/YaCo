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
