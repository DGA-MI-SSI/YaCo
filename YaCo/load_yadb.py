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
import idaapi
import idc
import logging
import os
import sys

prog = idc.ARGV[0] if len(idc.ARGV) else None
parser = argparse.ArgumentParser(prog=prog, description="Import to IDA database")
parser.add_argument("bin_dir", type=os.path.abspath, help="YaCo bin directory")
parser.add_argument("filename", type=os.path.abspath, help="Input yadb database")
parser.add_argument("--no-exit", action="store_true", help="Do not exit IDA when done")
args = parser.parse_args(idc.ARGV[1:])

root_dir = os.path.abspath(os.path.join(args.bin_dir, '..'))
for path in ['bin', 'YaCo']:
    sys.path.append(os.path.join(root_dir, path))

# import yatools dependencies
if idc.__EA64__:
    import YaToolsPy64 as ya
else:
    import YaToolsPy32 as ya


class YaLogHandler(logging.Handler):
    def __init__(self):
        logging.Handler.__init__(self)
        self.deftype = ya.LOG_LEVEL_ERROR
        self.typemap = {
            logging.DEBUG: ya.LOG_LEVEL_DEBUG,
            logging.INFO: ya.LOG_LEVEL_INFO,
            logging.WARNING: ya.LOG_LEVEL_WARNING,
            logging.ERROR: ya.LOG_LEVEL_ERROR,
        }

    def emit(self, record):
        try:
            level = self.typemap.get(record.levelno, self.deftype)
            ya.yaco_log(level, self.format(record) + '\n')
        except:
            self.handleError(record)


path = idc.GetIdbPath()
name, ext = os.path.splitext(path)
ya.StartYatools(name)

logging.basicConfig()
global logger
logger = logging.getLogger("YaCo")

logger.setLevel(logging.INFO)
logger.propagate = True
for h in logger.handlers:
    h.setLevel(logging.WARN)

handler = YaLogHandler()
handler.setLevel(logging.INFO)
logger.addHandler(handler)

idc.Wait()
hash_provider = ya.MakeHashProvider()
hash_provider.populate_struc_enum_ids()
fbmodel = ya.MakeFlatBufferDatabaseModel(args.filename)
ya.export_to_ida(fbmodel, hash_provider, ya.SkipFrames)

idc.Wait()
idaapi.cvar.database_flags = idaapi.DBFL_COMP
if not args.no_exit:
    idc.Exit(0)
