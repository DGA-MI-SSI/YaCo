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

""" Helper to make a directory of testdata,
    called as subprocess by different tests
"""

import argparse
import logging
import os
import re
import shutil
import sys
import tempfile

def check_fail(err):
    if not err:
        return
    logging.error('error %s' % err)
    sys.exit(-1)

def get_binary_name(name):
    if sys.platform in ["linux", "linux2"]:
        return name
    if sys.platform == "win32":
        return name + ".exe"
    check_fail("unknown platform %s" % sys.platform)

class Ctx:
    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("outdir", type=os.path.abspath, help="output directory")
        parser.add_argument("bindir", type=os.path.abspath, help="binary directory")
        parser.add_argument("srcdir", type=os.path.abspath, help="input binary")
        parser.add_argument("ida", type=str, help="IDA binary name")
        parser.add_argument("--no-pdb", action="store_true", default=False, help="do not analyze with pdb")
        opts = parser.parse_args()
        self.outdir = opts.outdir
        self.bindir = opts.bindir
        self.srcdir = opts.srcdir
        self.yadir  = os.path.abspath(os.path.join(opts.bindir, '..', 'YaCo'))
        self.idaq   = opts.ida
        self.no_pdb = opts.no_pdb

def try_rmtree(path):
    try:
        shutil.rmtree(path)
        shutil.rmtree(path)
    except:
        pass

def main():
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    ctx = Ctx()

    # New directory
    try_rmtree(ctx.outdir)
    indir, dll = os.path.split(ctx.srcdir)
    try:
        shutil.copytree(indir, ctx.outdir)
    except FileExistsError:
        print("Warning make_testdata: file", ctx.outdir, "exists", "Cannot copy from", ctx.srcdir)

    if ctx.no_pdb:
        pdb = re.sub("\.dll", ".pdb", dll)
        os.remove(os.path.join(ctx.outdir, pdb))
    sys.path.append(ctx.yadir)
    import exec_ida
    cmd = exec_ida.Exec(get_binary_name(ctx.idaq), os.path.join(ctx.outdir, dll), '-A')
    cmd.set_idle(True)
    cmd.with_script(os.path.join(ctx.yadir, 'export_all.py'), ctx.bindir)
    logging.debug(' '.join(cmd.get_args()))
    check_fail(cmd.run())
    yadb = os.path.join(ctx.outdir, "database", "database.yadb")
    if not os.path.isfile(yadb):
        check_fail("missing %s" % yadb)

if __name__ == '__main__':
    main()
