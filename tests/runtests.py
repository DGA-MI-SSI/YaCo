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


import argparse
import difflib
import inspect
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import runtests
from textwrap import dedent


# Globals
#     YaTools path string
current_dir = os.path.abspath(os.path.join(__file__, ".."))
#     Mask for ea
ea_defmask = "(~0 & ~(1 << ya.OBJECT_TYPE_STRUCT) & ~(1 << ya.OBJECT_TYPE_ENUM)) & ~(1 << ya.OBJECT_TYPE_SEGMENT_CHUNK)"
#     Command at IDA start
with open(os.path.join(current_dir, "inc_runtests_ida_start.py"), 'r') as f_in:
    ida_start = f_in.read()
#     Command at IDA end
ida_end = "\nidc.save_database('') ; idc.qexit(0)"


def dbgprint(*args):
    """ Help : print if debug """
    b_debug = True
    if b_debug:
        print(args)


def get_ida_dir():
    """ Get environment variable `IDA_DIR" """
    try:
        return os.path.abspath(os.environ['IDA_DIR'])
    except KeyError:
        print("error: missing IDA_DIR environment variable")
        sys.exit(-1)


def remove_dir(dirname):
    """ Remove directory, even read-only files """
    # Define function to Chmod Writable
    def del_rw(action, name, exc):
        os.chmod(name, stat.S_IWRITE)
        os.remove(name)

    # Remove anyway TODO uncomment
    # shutil.rmtree(dirname, onerror=del_rw)


def sysexec(cwd, *args):
    """ Execute args in cwd and return bytes_output """
    # Log
    dbgprint("-->[IN] " + cwd + ": " + " ".join(*args) + "---")

    # Fork
    output = subprocess.check_output(
            *args, cwd=cwd, stderr=subprocess.STDOUT, shell=False)

    # Log
    dbgprint("<--[OUT] " + output.decode() + "---")

    # Return
    return output




class Repo():
    """ Repertory Git class """

    def __init__(self, ctx, path, target):
        self.ctx = ctx
        self.path = path
        self.target = target

    def run_script(self, script, target):
        # Load ida.exe
        import exec_ida
        args = ["-Oyaco:disable_plugin", "-A"]
        cmd = exec_ida.Exec(os.path.join(self.ctx.ida_dir, "ida64"), os.path.join(self.path, target), *args)
        cmd.set_idle(True)

        # Write temporary test script
        fd, fname = tempfile.mkstemp(dir=self.path, prefix="exec_", suffix=".py")
        b_generated = (ida_start + script + ida_end).encode()
        os.write(fd, b_generated)
        os.close(fd)

        # Run generated script
        cmd.with_script(fname, self.ctx.bin_dir, self.ctx.yaco_dir)
        err = cmd.run()
        self.ctx.assertEqual(err, None, "%s" % err)

    def run_with(self, use_yaco, sync_first, *args):
        # Declare scritp in IDA
        scripts = ""

        # Load YaCo in script if want
        if use_yaco:
            scripts += dedent("""
                # start
                import yaco_plugin
                yaco_plugin.start()
                ya.enable_testing_mode() """)

        # Synchronize db if want
        if sync_first:
            scripts += dedent("""
                # sync first
                idc.save_database("")
                """)

        # Fill scirpt and call check(name)
        todo = []
        for (script, check) in args:
            if check is None:
                scripts += script
                continue
            fd, fname = tempfile.mkstemp(dir=self.path, prefix="data_%02d_" % self.ctx.idx(), suffix=".xml")
            os.close(fd)
            template = dedent("""
                with open("%s", "wb") as fh:
                    fh.write(%s)
                """)
            scripts += template % (re.sub("\\\\", "/", fname), script)
            todo.append((check, fname))

        target = self.target + ("_local.i64" if use_yaco else ".i64")
        self.run_script(scripts, target)

        # Call all check scripts
        for (check, name) in todo:
            # TODO remove
            from inspect import getsource
            s_code = getsource(check)
            dbgprint("CODE :\n", s_code)
            dbgprint("Name :\n", name)
            # Not remove
            check(name)


    def run(self, *args):
        return self.run_with(True, True, *args)

    def run_no_sync(self, *args):
        return self.run_with(True, False, *args)

    def run_bare(self, *args):
        return self.run_with(False, False, *args)

    def check_git(self, added=None, modified=None, deleted=None):
        """ Check YaGit file versus argument dictionnary """
        # Fill default if needed
        if not added:
            added = []
        if not modified:
            modified = []
        if not deleted:
            deleted = []
        want_state = {"added": added, "modified": modified, "deleted": deleted}
        got_added, got_modified, got_deleted = [], [], []

        # Git diff
        output = sysexec(self.path, ["git", "diff", "--name-status", "HEAD~1..HEAD"])
        files = output.split(b"\n")


        def add_simple(line):
            # Closure: Get state (Append, Modified, Deleted) and path (otype/md5.xml)
            state, path = line.split()
            otype = re.split(b"[\\\/]", path)[1].decode()
            dbgprint('Git : Add simple:', state, ',', path, 'AND', otype)

            # Discriminate Path
            if state == b'A':
                got_added.append(otype)
            if state == b'M':
                got_modified.append(otype)
            if state == b'D':
                got_deleted.append(otype)


        def add_moved(line):
            # Closure: Get state
            _, path_a, path_b = line.split()
            otype_a = re.split(b"[\\\/]", path_a)[1].decode()
            otype_b = re.split(b"[\\\/]", path_b)[1].decode()
            dbgprint('Git : Add moved:', otype_a, ',', otype_b)

            # Append coreespondingly
            got_deleted.append(otype_a)
            got_added.append(otype_b)


        # Parse git diff
        for line in files:
            # Pass if empty
            if not len(line): continue

            # Add simple
            try: add_simple(line)
            except: pass

            # Add moved
            try: add_moved(line)
            except: pass

        # Sort result
        for x in [added, modified, deleted, got_added, got_modified, got_deleted]:
            x.sort()

        # Compare want_state and got_state
        got_state = {"added": got_added, "modified": got_modified, "deleted": got_deleted}
        self.ctx.assertEqual(want_state, got_state)


class Fixture(unittest.TestCase):
    out_dir = "out"

    def setUp(self):
        args = get_args()
        self.maxDiff = None
        self.dirs = []
        self.counter = 0
        self.tests_dir = os.path.abspath(os.path.join(inspect.getsourcefile(lambda:0), ".."))
        self.yaco_dir = os.path.abspath(os.path.join(self.tests_dir, "..", "YaCo"))
        self.ida_dir = get_ida_dir()
        self.out_dir = os.path.abspath(os.path.join(self.tests_dir, "..", Fixture.out_dir))
        self.bin_dir = args.bindir
        sys.path.append(self.bin_dir)
        sys.path.append(self.yaco_dir)

    def tearDown(self):
        for d in self.dirs:
            remove_dir(d)

    def idx(self):
        self.counter += 1
        return self.counter - 1

    def script(self, script):
        self.types = {}
        self.eas = {}
        self.item_range = None
        for line in script.splitlines():
            line = line.strip()
            ea = re.sub(r"^ea = (0x[a-fA-F0-9]+)$", r"\1", line)
            if ea != line:
                self.last_ea = int(ea, 16)
        return script, None

    def empty(self):
        return "", None

    def sync(self):
        return self.script("idc.save_database('')")

    def check_diff(self, want_filename, want, filter=None):
        """ Return Closure checker """
        def check(name):
            # Get in <- Closure and arg
            data = None
            with open(name, "rb") as fh:
                data = fh.read()
                if filter:
                    data = filter(data)

            # Stringify
            s_data = data.decode()
            s_want = want.decode()

            # Fail if differs
            if s_data != s_want:
                self.fail("\n" + "".join(
                    difflib.unified_diff(s_want.splitlines(1),
                                         s_data.splitlines(1), want_filename, name)))
        return check


    def save_types(self):
        """ Export types : enums and Structs """
        script = "ya.export_xml_types()"

        def callback(filename):
            with open(filename, "rb") as fh:
                self.types = [filename, fh.read()]
        return script, callback


    def check_types(self):
        script = "ya.export_xml_types()"
        filename, want = self.types
        return script, self.check_diff(filename, want)


    def save_ea(self, ea):
        script = "ya.export_xml(0x%x, %s)" % (ea, ea_defmask)

        def callback(filename):
            with open(filename, "rb") as fh:
                self.eas[ea] = [filename, fh.read()]
        return script, callback


    def save_last_ea(self):
        """ Save last value of ea (cursor) """
        print("tin_save_last_ea:", "0x%x" % self.last_ea)
        self.assertIsNotNone(self.last_ea)
        return self.save_ea(self.last_ea)


    def check_last_ea(self):
        """ Check xml ea is self.last_ea """
        self.assertIsNotNone(self.last_ea)
        return self.check_ea(self.last_ea)


    def check_ea(self, ea):
        script = "ya.export_xml(0x%x, %s)" % (ea, ea_defmask)
        filename, want = self.eas[ea]
        return script, self.check_diff(filename, want)


    def save_item_range(self, start, end):
        script = "export_range(0x%x, 0x%x)" % (start, end)
        def callback(filename):
            self.item_range = filename
        return script, callback

    def check_item_range(self, want):
        want = want.lstrip()
        filename = self.item_range
        return self.check_diff("", want)(filename)

    def check_range(self, a, start, end, want):
        a.run(
            self.save_item_range(start, end),
        )
        if not want:
            return self.item_range
        self.check_item_range(want)

    def set_master(self, repo, master):
        sysexec(repo, ["git", "remote", "add", "origin", master])
        sysexec(repo, ["git", "fetch", "origin"])

    def setup_repos_with(self, indir, target):
        """ Set two linked repos """
        # Create output directory if can
        try: os.makedirs(self.out_dir)
        except: pass

        # Create temporary directories
        work_dir = tempfile.mkdtemp(prefix='repo_', dir=self.out_dir)
        self.dirs.append(work_dir)
        indir = os.path.join(self.tests_dir, "..", "testdata", indir)
        a = os.path.abspath(os.path.join(work_dir, "a"))
        b = os.path.abspath(os.path.join(work_dir, "b"))
        c = os.path.abspath(os.path.join(work_dir, "c"))

        # Git init @a
        os.makedirs(a)
        shutil.copy(os.path.join(indir, target + ".i64"), a)
        sysexec(a, ["git", "init"])
        sysexec(a, ["git", "config", "user.name", "User A"])
        sysexec(a, ["git", "config", "user.email", "user.a@mail.com"])
        sysexec(a, ["git", "add", "-A"])
        sysexec(a, ["git", "commit", "-m", "init"])
        sysexec(a, ["git", "clone", "--bare", ".", c])

        self.set_master(a, c)
        ra, rb = Repo(self, a, target), Repo(self, b, target)

        # Start YaCo @a
        print("tin_target: ", target)
        ra.run_script(
                "import yaco_plugin; yaco_plugin.start()",
                target + ".i64")

        # Copy @a -> @b
        shutil.copytree(a, b)

        # Config @b
        sysexec(b, ["git", "config", "user.name", "User B"])
        sysexec(b, ["git", "config", "user.email", "user.b@mail.com"])

        # Return ra, rb
        return ra, rb

    def setup_repos(self):
        return self.setup_repos_with("qt54_svg_no_pdb", "Qt5Svgd.dll")

    def setup_cmder(self):
        return self.setup_repos_with("cmder", "Cmder.exe")


def get_args():
    """ Get argument : argparse <- command line """

    # Create parser object
    parser = argparse.ArgumentParser()

    # Declare options
    parser.add_argument("--list", action="store_true", default=False, help="list test targets")
    parser.add_argument("-v", "--verbose", type=int, default=2, help="verbosity level")
    parser.add_argument("-f", "--filter", type=str, default="", help="filter tests")
    yatools_bin_dir = os.path.abspath(os.path.join(current_dir, "..", "bin", "yaco_x64", "YaTools", "bin"))
    parser.add_argument("-b", "--bindir", type=os.path.abspath, default=yatools_bin_dir, help="binary directory")
    parser.add_argument("-nc", "--no-cleanup", action="store_true", help="do not remove temp folders")
    parser.add_argument("-tf", "--temp_folder", default="out", help="temporary folder for test (default: out)")

    # Return object
    return parser.parse_args()


def get_tests(args):
    """ Get tests list : from /tests/tests """
    tests = unittest.TestSuite()
    for s in unittest.defaultTestLoader.discover(os.path.join(current_dir, "tests")):
        for f in s:
            # Check if ready to fight
            if isinstance(f, unittest.loader._FailedTest): break

            # Append test to list
            for test in f:
                if args.list:
                    print(test.id())
                if test.id().endswith(args.filter):
                    tests.addTest(test)
    # Return list
    return tests


def main():
    """ Main """
    # Get argument
    args = get_args()
    if args.no_cleanup:
        def nop(_):
            pass
        runtests.remove_dir = nop
    runtests.Fixture.out_dir = args.temp_folder

    # Get test list
    tests = get_tests(args)
    if args.list:
        sys.exit(0)

    # Run tests
    result = unittest.TextTestRunner(verbosity=args.verbose).run(tests)

    # Exit
    res = 0 if not result.errors and not result.failures else -1
    return res

if __name__ == '__main__':
    sys.exit(main())
