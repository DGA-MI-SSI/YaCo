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

import logging
import os
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
        self.outdir = os.path.abspath(os.path.join(sys.argv[1], 'testdata'))
        self.bindir = os.path.abspath(sys.argv[2])
        self.src    = os.path.abspath(sys.argv[3])
        self.yadir  = os.path.abspath(os.path.join(self.bindir, '..', 'YaCo'))
        self.idaq   = sys.argv[4]

def try_rmtree(path):
    try:
        shutil.rmtree(path)
        shutil.rmtree(path)
    except:
        pass

def main():
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    ctx = Ctx()
    indir, dll = os.path.split(ctx.src)
    logging.info('%s (%s)' % (os.path.join('testdata', os.path.basename(indir), dll), ctx.idaq))
    dst = os.path.join(ctx.outdir, os.path.basename(indir))
    try_rmtree(dst)
    shutil.copytree(indir, dst)
    sys.path.append(ctx.yadir)
    import exec_ida
    cmd = exec_ida.Exec(get_binary_name(ctx.idaq), os.path.join(dst, dll), '-A')
    cmd.set_idle(True)
    cmd.with_script(os.path.join(ctx.yadir, 'export_all.py'), ctx.bindir)
    logging.debug(' '.join(cmd.get_args()))
    check_fail(cmd.run())
    yadb = os.path.join(dst, "database", "database.yadb")
    if not os.path.isfile(yadb):
        check_fail("missing %s" % yadb)

if __name__ == '__main__':
    main()
