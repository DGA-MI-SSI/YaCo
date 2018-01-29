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

import os
import platform
import subprocess
import tempfile

IDLE_PRIORITY_CLASS = 0x00000040


class Exec:
    def __init__(self, idaq, database, *args):
        self.idaq = idaq
        self.database = database
        self.args = list(args)
        # options
        self.is_idle = False
        self.cwd = None
        fd, fname = tempfile.mkstemp(dir=os.path.dirname(database), prefix="tmp_", suffix=".log")
        os.close(fd)
        os.remove(fname)
        self.logfile = fname
        self.delete_log = True

    # options
    def set_idle(self, is_idle):
        self.is_idle = is_idle
        return self

    def with_cwd(self, cwd):
        self.cwd = cwd
        return self

    def with_log(self, log):
        self.logfile = log
        self.delete_log = False
        return self

    def with_script(self, script, *args):
        # there can never be enough quotes
        q = '\\\"'
        qargs = ''
        if len(args):
            qargs = ' ' + q + (q + ' ' + q).join(args) + q
        cmd = '-S"%s%s%s%s"' % (q, script, q, qargs)
        self.args.append(cmd)
        return self

    # get all arguments
    def get_args(self):
        return ['"' + self.idaq + '"', '-L"' + self.logfile + '"'] + self.args + ['"' + self.database + '"']

    def __str__(self):
        return ' '.join(self.get_args())

    # start ida in background
    def start(self):
        flags = 0
        is_windows = platform.system() == "Windows"
        if self.is_idle and is_windows:
            flags |= IDLE_PRIORITY_CLASS
        # we MUST give a string & bypass subprocess quoting
        # or subprocess will mangle script arguments
        args = ' '.join(self.get_args())
        # on linux we MUST use shell=True because Popen with string arg expect no arguments
        # and we cannot use an argument array on windows due to invalid script arg escaping...
        self.process = subprocess.Popen(args, cwd=self.cwd, creationflags=flags, shell=not is_windows)

    def join(self):
        code = self.process.wait()
        if code == 0:
            return None
        err = hex(code)
        if not self.delete_log:
            return err
        with open(self.logfile, 'rb') as fh:
            err = fh.read().strip()
        return err

    # start & join
    def run(self):
        self.start()
        return self.join()
