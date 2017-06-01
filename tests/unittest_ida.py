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

import importlib
import inspect
import unittest

debug = False
verbose = False

def import_yaco_path(root_dir):
    for path in ["YaCo", "bin"]:
        sys.path.append(os.path.join(root_dir, path))

def run_tests(filename, module, prefix):
    idc.Wait()
    unittest.defaultTestLoader.testMethodPrefix = prefix + '_'
    mod_dir = os.path.abspath(os.path.dirname(filename))
    test_modules = unittest.defaultTestLoader.discover(mod_dir)
    mod = importlib.import_module(module)
    mod.init(prefix)
    reply = unittest.TextTestRunner(verbosity=2).run(test_modules)
    mod.exit(prefix)
    return len(reply.errors) + len(reply.failures)

def main():
    bin_dir = os.path.abspath(idc.ARGV[1])
    module = idc.ARGV[2]
    prefix = idc.ARGV[3]
    import_yaco_path(os.path.dirname(bin_dir))
    err = run_tests(inspect.getsourcefile(lambda:0), module, prefix)
    idaapi.cvar.database_flags |= idaapi.DBFL_KILL
    if not debug:
        idc.Exit(err)

if __name__ == '__main__':
    main()
