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

import inspect
import os
import re
import shutil
import stat
import sys
import tempfile

ida_dir_env = None
try:
    ida_dir_env = os.environ['IDA_DIR']
except KeyError:
    print("error: missing IDA_DIR environment variable")
    sys.exit(-1)
ida_dir = os.path.abspath(ida_dir_env)

test_suites = [
    ('yainit',      'yainit',   'yainit',   ['repo/QtCore4.dll']),
    ('yaexport',    'yaexport', 'yaexport', ['QtCore4_local.i64']),
    ('svginit',     'yainit',   'yainit',   ['qt54_svg/Qt5Svgd.dll', 'qt54_svg/Qt5Svgd.pdb']),
    ('svgtest',     'yasvg',    'yasvg',    ['Qt5Svgd_local.i64']),
]

def import_yaco_path(root_dir):
    for path in ["YaCo", "bin"]:
        sys.path.append(os.path.join(root_dir, path))

def remove_dir(dirname):
    # really remove read-only files
    def del_rw(action, name, exc):
        os.chmod(name, stat.S_IWRITE)
        os.remove(name)
    shutil.rmtree(dirname, onerror=del_rw)

def run_test_suite(work_dir, bin_dir, idaq, target, module, prefix, script):
    print '* running', prefix, 'tests on', target
    import exec_ida
    args = ["-Oyaco:disable_plugin", "-A"]
    cmd = exec_ida.Exec(os.path.join(ida_dir, idaq), os.path.join(work_dir, target), *args)
    cmd.set_idle(True)
    cmd.with_script(script, bin_dir, module, prefix)
    print str(cmd)
    err = cmd.run()
    if not err:
        return 0
    print(err)
    return -1

def main():
    # create temporary work directory
    bin_dir     = os.path.abspath(sys.argv[1])
    cmd         = sys.argv[2]
    test_dir    = os.path.abspath(os.path.dirname(inspect.getsourcefile(lambda:0)))
    out_dir     = os.path.abspath(sys.argv[3])
    idaq        = sys.argv[4]
    work_dir    = os.path.join(out_dir, sys.argv[5]) if len(sys.argv) > 5 else None
    print '* bin_dir', bin_dir
    print '* cmd', cmd
    print '* test_dir', test_dir
    print '* out_dir', out_dir
    print '* idaq', idaq
    print '* ida_dir ', ida_dir if ida_dir else ''

    # import exec_ida
    import_yaco_path(os.path.dirname(bin_dir))
    is64 = idaq.find("64") != -1

    # run all tests
    err = 0
    script = os.path.join(test_dir, 'unittest_ida.py')
    re_match = re.compile('.+' if cmd == 'all' else cmd)
    work_dirs = []
    ext = "i64" if is64 else "idb"
    for (pattern, module, prefix, targets) in test_suites:
        if re_match.match(pattern) == None:
            continue
        if module.find('init') != -1:
            work_dir = tempfile.mkdtemp(prefix='repo_', dir=out_dir)
            print '* work_dir', work_dir
            for f in targets:
                src = os.path.join(test_dir, f)
                dst = os.path.join(work_dir, os.path.basename(f))
                shutil.copyfile(src, dst)
            work_dirs.append(work_dir)
        # overwrite _local idbs
        for f in targets:
            idb = re.sub("\.(:?idb|i64)", "." + ext, f)
            if idb.find("_local." + ext) == -1:
                continue
            dst = os.path.join(work_dir, idb)
            src = os.path.join(work_dir, re.sub("_local\.", ".", idb))
            print '* copying %s to %s' % (os.path.basename(src), os.path.basename(dst))
            shutil.copyfile(src, dst)
        target = os.path.basename(targets[0])
        err = run_test_suite(work_dir, bin_dir, idaq, target, module, prefix, script)
        if err:
            break

    # cleanup & exit
    if cmd == 'all' and not err:
        for w in work_dirs:
            remove_dir(w)
    print '* all tests', 'FAIL' if err else 'OK', hex(err) if err else ''
    sys.exit(err)

if __name__ == '__main__':
    main()
