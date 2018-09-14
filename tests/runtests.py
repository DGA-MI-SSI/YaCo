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
    if False:
        print cwd + ": " + " ".join(*args)
    output = subprocess.check_output(*args, cwd=cwd, stderr=subprocess.STDOUT, shell=False)
    if False:
        print output
    return output

ida_start = """
import idaapi
import idautils
import idc
import sys

sys.path.append(idc.ARGV[1])
sys.path.append(idc.ARGV[2])
if idc.__EA64__:
    import YaToolsPy64 as ya
else:
    import YaToolsPy32 as ya

def dump_type(ea):
    flags = idaapi.get_flags(ea)
    if idc.is_code(flags):
        return "block" if idaapi.get_func(ea) else "code"
    if idc.is_data(flags):
        return "data"
    return "unexplored"

# MS_CLS
type_flags = {
    ida_bytes.FF_CODE: "code",
    ida_bytes.FF_DATA: "data",
    ida_bytes.FF_TAIL: "tail",
    ida_bytes.FF_UNK:  "unkn",
}

# MS_CODE
code_flags = {
    ida_bytes.FF_FUNC: "func",
    ida_bytes.FF_IMMD: "immd",
    ida_bytes.FF_JUMP: "jump",
}

# DT_TYPE
data_flags = {
    ida_bytes.FF_BYTE:     "byte",
    ida_bytes.FF_WORD:     "word",
    ida_bytes.FF_DWORD:    "dword",
    ida_bytes.FF_QWORD:    "qword",
    ida_bytes.FF_TBYTE:    "tbyte",
    ida_bytes.FF_STRLIT:   "strlit",
    ida_bytes.FF_STRUCT:   "struct",
    ida_bytes.FF_OWORD:    "oword",
    ida_bytes.FF_FLOAT:    "float",
    ida_bytes.FF_DOUBLE:   "double",
    ida_bytes.FF_PACKREAL: "packreal",
    ida_bytes.FF_ALIGN:    "align",
    ida_bytes.FF_CUSTOM:   "custom",
    ida_bytes.FF_YWORD:    "yword",
    ida_bytes.FF_ZWORD:    "zword",
}

# MS_COMM
comm_flags = {
    ida_bytes.FF_COMM:   "comm",
    ida_bytes.FF_REF:    "ref",
    ida_bytes.FF_LINE:   "line",
    ida_bytes.FF_NAME:   "name",
    ida_bytes.FF_LABL:   "labl",
    ida_bytes.FF_FLOW:   "flow",
    ida_bytes.FF_SIGN:   "sign",
    ida_bytes.FF_BNOT:   "bnot",
    ida_bytes.FF_UNUSED: "unused",
}

# MS_0TYPE
op0_flags = {
    ida_bytes.FF_0NUMH: "0:numh",
    ida_bytes.FF_0NUMD: "0:numd",
    ida_bytes.FF_0CHAR: "0:char",
    ida_bytes.FF_0SEG:  "0:seg",
    ida_bytes.FF_0OFF:  "0:off",
    ida_bytes.FF_0NUMB: "0:numb",
    ida_bytes.FF_0NUMO: "0:numo",
    ida_bytes.FF_0ENUM: "0:enum",
    ida_bytes.FF_0FOP:  "0:fop",
    ida_bytes.FF_0STRO: "0:stro",
    ida_bytes.FF_0STK:  "0:stk",
    ida_bytes.FF_0FLT:  "0:flt",
    ida_bytes.FF_0CUST: "0:cust",
}

# MS_1TYPE
op1_flags = {
    ida_bytes.FF_1NUMH: "1:numh",
    ida_bytes.FF_1NUMD: "1:numd",
    ida_bytes.FF_1CHAR: "1:char",
    ida_bytes.FF_1SEG:  "1:seg",
    ida_bytes.FF_1OFF:  "1:off",
    ida_bytes.FF_1NUMB: "1:numb",
    ida_bytes.FF_1NUMO: "1:numo",
    ida_bytes.FF_1ENUM: "1:enum",
    ida_bytes.FF_1FOP:  "1:fop",
    ida_bytes.FF_1STRO: "1:stro",
    ida_bytes.FF_1STK:  "1:stk",
    ida_bytes.FF_1FLT:  "1:flt",
    ida_bytes.FF_1CUST: "1:cust",
}

def dump_flags(ea):
    flags = idaapi.get_flags(ea)
    reply = []
    for k in type_flags:
        if (flags & ida_bytes.MS_CLS) == (k & 0xFFFFFFFF):
            reply.append(type_flags[k])
    if ida_bytes.is_code(flags):
        for k in code_flags:
            if (flags & ida_bytes.MS_CODE) & k:
                reply.append(code_flags[k])
    if ida_bytes.is_data(flags):
        for k in data_flags:
            if (flags & ida_bytes.DT_TYPE) == (k & 0xFFFFFFFF):
                reply.append(data_flags[k])
    for k in comm_flags:
        if (flags & ida_bytes.MS_COMM) & k:
            reply.append(comm_flags[k])
    for k in op0_flags:
        if (flags & ida_bytes.MS_0TYPE) == (k & 0xFFFFFFFF):
            reply.append(op0_flags[k])
    for k in op1_flags:
        if (flags & ida_bytes.MS_1TYPE) == (k & 0xFFFFFFFF):
            reply.append(op1_flags[k])
    return " ".join(reply)

def export_range(start, end):
    data = ""
    count = 0
    for ea in ya.get_all_items(start, end):
        type = idc.get_type(ea)
        type = " " + type if type else ""
        name = idaapi.get_name(ea)
        name = " " + name if name else ""
        data += "0x%x: %s: %s\\n" % (ea, dump_type(ea), dump_flags(ea))
        count += 1
    if count > 100:
        data += "%d item(s)" % count
    return data

idc.Wait()
"""

ida_end = """
# end
idc.save_database("")
idc.qexit(0)
"""


class Repo():

    def __init__(self, ctx, path, target):
        self.ctx = ctx
        self.path = path
        self.target = target

    def run_script(self, script, target):
        import exec_ida
        args = ["-Oyaco:disable_plugin", "-A"]
        cmd = exec_ida.Exec(os.path.join(self.ctx.ida_dir, "ida64"), os.path.join(self.path, target), *args)
        cmd.set_idle(True)
        fd, fname = tempfile.mkstemp(dir=self.path, prefix="exec_", suffix=".py")
        os.write(fd, ida_start + script + ida_end)
        os.close(fd)
        cmd.with_script(fname, self.ctx.bin_dir, self.ctx.yaco_dir)
        err = cmd.run()
        self.ctx.assertEqual(err, None, "%s" % err)

    def run_with(self, use_yaco, sync_first, *args):
        scripts = ""
        if use_yaco:
            scripts += """
# start
import yaco_plugin
yaco_plugin.start()
ya.enable_testing_mode()
"""
        if sync_first:
            scripts += """
# sync first
idc.save_database("")
"""
        todo = []
        for (script, check) in args:
            if check == None:
                scripts += script
                continue
            fd, fname = tempfile.mkstemp(dir=self.path, prefix="data_%02d_" % self.ctx.idx(), suffix=".xml")
            os.close(fd)
            scripts += """
with open("%s", "wb") as fh:
    fh.write(%s)
""" % (re.sub("\\\\", "/", fname), script)
            todo.append((check, fname))

        target = self.target + ("_local.i64" if use_yaco else ".i64")
        self.run_script(scripts, target)
        for (check, name) in todo:
            check(name)

    def run(self, *args):
        return self.run_with(True, True, *args)

    def run_no_sync(self, *args):
        return self.run_with(True, False, *args)

    def run_bare(self, *args):
        return self.run_with(False, False, *args)

    def check_git(self, added=None, modified=None, deleted=None):
        if not added:
            added = []
        if not modified:
            modified = []
        if not deleted:
            deleted = []
        want_state = {"added":added, "modified":modified, "deleted":deleted}
        output = sysexec(self.path, ["git", "diff", "--name-status", "HEAD~1..HEAD"])
        files = output.split("\n")
        got_added, got_modified, got_deleted = [], [], []
        def add_simple(line):
            state, path = line.split()
            _, otype, name = re.split("[\\\/]", path)
            name = re.sub("\.xml$", "", name) # currently unused
            if state == 'A':
                got_added.append(otype)
            if state == 'M':
                got_modified.append(otype)
            if state == 'D':
                got_deleted.append(otype)
        def add_moved(line):
            _, path_a, path_b = line.split()
            _, otype_a, _ = re.split("[\\\/]", path_a)
            _, otype_b, _ = re.split("[\\\/]", path_b)
            got_deleted.append(otype_a)
            got_added.append(otype_b)
        for line in files:
            if not len(line):
                continue
            try:
                add_simple(line)
            except:
                pass
            try:
                add_moved(line)
            except:
                pass
        for x in [added, modified, deleted, got_added, got_modified, got_deleted]:
            x.sort()
        got_state = {"added":got_added, "modified":got_modified, "deleted":got_deleted}
        self.ctx.assertEqual(want_state, got_state)

ea_defmask = "(~0 & ~(1 << ya.OBJECT_TYPE_STRUCT) & ~(1 << ya.OBJECT_TYPE_ENUM)) & ~(1 << ya.OBJECT_TYPE_SEGMENT_CHUNK)"


class Fixture(unittest.TestCase):
    out_dir = "out"

    def setUp(self):
        args, _ = get_args()
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
        self.enums = {}
        self.strucs = {}
        self.types = {}
        self.local_types = {}
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
        return self.script("""
idc.save_database("")
""")

    def check_diff(self, want_filename, want, filter=None):
        def check(name):
            data = None
            with open(name, "rb") as fh:
                data = fh.read()
                if filter:
                    data = filter(data)
            if data != want:
                self.fail("\n" + "".join(difflib.unified_diff(want.splitlines(1), data.splitlines(1), want_filename, name)))
        return check

    def filter_enum(self, d):
        # enum ordinals are unstable & depend on insertion order
        d = re.sub("address>[A-F0-9]+", "address>", d)
        return d

    def save_enum(self, name):
        script = "ya.export_xml_enum('%s')" % name
        def callback(filename):
            with open(filename, "rb") as fh:
                self.enums[name] = [filename, self.filter_enum(fh.read())]
        return script, callback

    def check_enum(self, name):
        script = "ya.export_xml_enum('%s')" % name
        filename, want = self.enums[name]
        return script, self.check_diff(filename, want, filter=self.filter_enum)

    def filter_struc(self, d):
        # struc ordinals are unstable & depend on insertion order
        d = re.sub("address>[A-F0-9]+", "address>", d)
        return d

    def save_struc(self, name):
        script = "ya.export_xml_struc('%s')" % name
        def callback(filename):
            with open(filename, "rb") as fh:
                self.strucs[name] = [filename, self.filter_struc(fh.read())]
        return script, callback

    def save_strucs(self):
        script = "ya.export_xml_strucs()"
        def callback(filename):
            with open(filename, "rb") as fh:
                self.strucs = [filename, self.filter_struc(fh.read())]
        return script, callback

    def save_local_type(self, name):
        script = "ya.export_xml_local_type('%s')" % name
        def callback(filename):
            with open(filename, "rb") as fh:
                self.local_types[name] = [filename, fh.read()]
        return script, callback

    def save_local_types(self):
        script = "ya.export_xml_local_types()"
        def callback(filename):
            with open(filename, "rb") as fh:
                self.types = [filename, fh.read()]
        return script, callback

    def check_struc(self, name):
        script = "ya.export_xml_struc('%s')" % name
        filename, want = self.strucs[name]
        return script, self.check_diff(filename, want, filter=self.filter_struc)

    def check_strucs(self):
        script = "ya.export_xml_strucs()"
        filename, want = self.strucs
        return script, self.check_diff(filename, want, filter=self.filter_struc)

    def check_local_type(self, name):
        script = "ya.export_xml_local_type('%s')" % name
        filename, want = self.local_types[name]
        return script, self.check_diff(filename, want)

    def check_local_types(self):
        script = "ya.export_xml_local_types()"
        filename, want = self.types
        return script, self.check_diff(filename, want)

    def save_ea(self, ea):
        script = "ya.export_xml(0x%x, %s)" % (ea, ea_defmask)
        def callback(filename):
            with open(filename, "rb") as fh:
                self.eas[ea] = [filename, fh.read()]
        return script, callback

    def save_last_ea(self):
        self.assertIsNotNone(self.last_ea)
        return self.save_ea(self.last_ea)

    def check_last_ea(self):
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

    # set two linked repos
    def setup_repos_with(self, indir, target):
        try:
            os.makedirs(self.out_dir)
        except:
            pass
        work_dir = tempfile.mkdtemp(prefix='repo_', dir=self.out_dir)
        self.dirs.append(work_dir)
        indir = os.path.join(self.tests_dir, "..", "testdata", indir)
        a = os.path.abspath(os.path.join(work_dir, "a"))
        b = os.path.abspath(os.path.join(work_dir, "b"))
        c = os.path.abspath(os.path.join(work_dir, "c"))
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
        ra.run_script("""
import yaco_plugin
yaco_plugin.start()
""", target + ".i64")
        shutil.copytree(a, b)
        sysexec(b, ["git", "config", "user.name", "User B"])
        sysexec(b, ["git", "config", "user.email", "user.b@mail.com"])
        return ra, rb

    def setup_repos(self):
        return self.setup_repos_with("qt54_svg_no_pdb", "Qt5Svgd.dll")

    def setup_cmder(self):
        return self.setup_repos_with("cmder", "Cmder.exe")


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true", default=False, help="list test targets")
    parser.add_argument("-v", "--verbose", type=int, default=2, help="verbosity level")
    parser.add_argument("-f", "--filter", type=str, default="", help="filter tests")
    current_dir = os.path.abspath(os.path.join(__file__, ".."))
    yatools_bin_dir = os.path.abspath(os.path.join(current_dir, "..", "bin", "yaco_x64", "YaTools", "bin"))
    parser.add_argument("-b", "--bindir", type=os.path.abspath, default=yatools_bin_dir, help="binary directory")
    parser.add_argument("-nc", "--no-cleanup", action="store_true", help="do not remove temp folders")
    parser.add_argument("-tf", "--temp_folder", default="out", help="temporary folder for test (default: out)")
    return parser.parse_args(), current_dir


def get_tests(args, cur_dir):
    tests = unittest.TestSuite()
    for s in unittest.defaultTestLoader.discover(os.path.join(cur_dir, "tests")):
        for f in s:
            for test in f:
                if args.list:
                    print test.id()
                if test.id().endswith(args.filter):
                    tests.addTest(test)
    return tests

if __name__ == '__main__':
    args, cur_dir = get_args()
    import runtests
    if args.no_cleanup:
        def nop(_):
            pass
        runtests.remove_dir = nop
    runtests.Fixture.out_dir = args.temp_folder

    tests = get_tests(args, cur_dir)
    if args.list:
        sys.exit(0)
    result = unittest.TextTestRunner(verbosity=args.verbose).run(tests)
    sys.exit(0 if not result.errors and not result.failures else -1)
