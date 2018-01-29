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

import argparse
import difflib
import inspect
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

def get_ida_dir():
    try:
        return os.path.abspath(os.environ['IDA_DIR'])
    except KeyError:
        print("error: missing IDA_DIR environment variable")
        sys.exit(-1)

def remove_dir(dirname):
    # really remove read-only files
    def del_rw(action, name, exc):
        os.chmod(name, stat.S_IWRITE)
        os.remove(name)
    shutil.rmtree(dirname, onerror=del_rw)

def sysexec(cwd, *args):
    output = subprocess.check_output(*args, cwd=cwd, stderr=subprocess.STDOUT, shell=platform.system() != "Windows")
    if False:
        print output

ida_start = """
import idaapi
import idc
import sys

sys.path.append(idc.ARGV[1])
sys.path.append(idc.ARGV[2])
if idc.__EA64__:
    import YaToolsPy64 as ya
else:
    import YaToolsPy32 as ya
import YaCo

idc.Wait()
YaCo.start()
# start
"""

ida_end = """
# end
idc.SaveBase("")
idc.Exit(0)
"""

class Fixture(unittest.TestCase):

    def setUp(self):
        self.dirs = []
        self.tests_dir = os.path.abspath(os.path.join(inspect.getsourcefile(lambda:0), ".."))
        self.bin_dir = os.path.abspath(os.path.join(self.tests_dir, "..", "bin", "yaco_x64", "YaTools", "bin"))
        self.yaco_dir = os.path.abspath(os.path.join(self.tests_dir, "..", "YaCo"))
        self.ida_dir = get_ida_dir()
        self.out_dir = os.path.abspath(os.path.join(self.tests_dir, "..", "tmp"))
        sys.path.append(self.bin_dir)
        sys.path.append(self.yaco_dir)

    def tearDown(self):
        for d in self.dirs:
            remove_dir(d)

    def idado(self, path, script, init=False):
        import exec_ida
        args = ["-Oyaco:disable_plugin", "-A"]
        target = "Qt5Svgd.i64"
        if not init:
            target = "Qt5Svgd_local.i64"
        cmd = exec_ida.Exec(os.path.join(self.ida_dir, "ida64"), os.path.join(path, target), *args)
        cmd.set_idle(True)
        fd, fname = tempfile.mkstemp(dir=path, suffix=".py")
        os.write(fd, ida_start + script + ida_end)
        os.close(fd)
        cmd.with_script(fname, self.bin_dir, self.yaco_dir)
        err = cmd.run()
        self.assertEqual(err, None, "%s" % err)
        return path

    def idacheck(self, path, *checks):
        scripts = """
idc.SaveBase("")
"""
        todo = []
        for (script, check) in checks:
            fd, fname = tempfile.mkstemp(dir=path, suffix=".xml")
            os.close(fd)
            scripts += """
with open("%s", "wb") as fh:
    fh.write(%s)
""" % (re.sub("\\\\", "/", fname), script)
            todo.append((check, fname))

        self.idado(path, scripts)
        for (check, name) in todo:
            check(name)

    def check_count(self, ea, otype, want, count):
        script = "ya.export_xml(0x%x, %s)" % (ea, otype)
        def check(name):
            data = None
            with open(name, "rb") as fh:
                data = fh.read()
            if data.count(want) != count:
                if count == 1:
                    self.fail("".join(difflib.unified_diff(want.splitlines(1), data.splitlines(1), name)))
                else:
                    self.fail(data)
        return script, check

    def has(self, ea, otype, want):
        return self.check_count(ea, otype, want, 1)

    def nothas(self, ea, otype, want):
        return self.check_count(ea, otype, want, 0)

    def init_repo(self, wd_dir, qt_dir, path):
        path = os.path.join(wd_dir, path)
        shutil.copytree(qt_dir, path)
        self.idado(path, "YaCo.start()", init=True)
        return path

    def set_master(self, repo, master):
        sysexec(repo, ["git", "remote", "add", "origin", master])
        sysexec(repo, ["git", "fetch", "origin"])

    # set two linked repos
    def setup_repos(self):
        work_dir = tempfile.mkdtemp(prefix='repo_', dir=self.out_dir)
        self.dirs.append(work_dir)
        qt54 = os.path.join(self.tests_dir, "..", "testdata", "qt54_svg")
        a = self.init_repo(work_dir, qt54, "a")
        sysexec(a, ["git", "remote", "rm", "origin"])
        b = os.path.abspath(os.path.join(work_dir, "b"))
        shutil.copytree(a, b)
        c = os.path.abspath(os.path.join(work_dir, "c"))
        sysexec(a, ["git", "clone", "--bare", ".", c])
        self.set_master(a, c)
        self.set_master(b, c)
        return work_dir, a, b

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", type=int, default=2, help="verbosity level")
    parser.add_argument("-f", "--filter", type=str, default="", help="filter tests")
    args = parser.parse_args()
    path = os.path.abspath(os.path.join(inspect.getsourcefile(lambda:0), "..", "tests"))
    tests = unittest.defaultTestLoader.discover(path, pattern="*" + args.filter + "*.py")
    unittest.TextTestRunner(verbosity=args.verbose).run(tests)
