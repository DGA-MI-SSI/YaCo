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

import idaapi
import idc
import inspect
import logging
import os
import sys
import traceback


def import_yaco_paths():
    root_dir = os.path.abspath(os.path.join(inspect.getsourcefile(lambda: 0), "..", "YaTools"))
    for path in ["YaCo", "bin"]:
        path = os.path.join(root_dir, path)
        print("YaCo: using %s" % path)
        sys.path.append(path)


def is_enabled():
    opts = idaapi.get_plugin_options("yaco")
    return not opts or "disable_plugin" not in opts.split(':')


class YaCoPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "YaCo plugin"
    help = "Yet Another Collaboration tool plugin"
    wanted_name = "YaCo"
    wanted_hotkey = ""

    def init(self, *args, **kwargs):
        if not is_enabled():
            print("YaCo: disabled")
            return idaapi.PLUGIN_SKIP
        try:
            # check if we are in YaCo project
            input_filename = idc.GetIdbPath()
            if input_filename.count("_local.") > 0 and os.path.exists(".git"):
                print("YaCo: initializing")
                import_yaco_paths()
                import YaCo
                YaCo.start()
                return idaapi.PLUGIN_KEEP
            elif "_local." not in input_filename and os.path.exists(".git"):
                print("""
*******************************************************
WARNING : You have opened a database in a git project,
WARNING : but your database doesn't match a YaCo project.
WARNING : YaCo is disabled !
*******************************************************
""")
                return idaapi.PLUGIN_OK
            else:
                return idaapi.PLUGIN_KEEP
        except Exception, e:
            print("YaCo: error during initialization")
            print(traceback.format_exc())
            logger = logging.getLogger("YaCo")
            if logger is not None:
                try:
                    logger.error("YaCo: error during initialization")
                    logger.error(traceback.format_exc())
                except:
                    pass
            raise e

    def run(self, *args, **kwargs):
        try:
            print("YaCo: waiting for auto analysis to finish\n")
            idc.Wait()
            print("YaCo: saving base in current state\n")
            idc.SaveBase("")
            import_yaco_paths()
            import YaCo
            if not YaCo.start():
                idc.Warning("YaCo: already started")
        except Exception, e:
            print("YaCo: error during run")
            print(traceback.format_exc())
            logger = logging.getLogger("YaCo")
            if logger is not None:
                try:
                    logger.error("YaCo: error during run")
                    logger.error(traceback.format_exc())
                except:
                    pass
            raise e

    def term(self, *args, **kwargs):
        print("YaCo: exit")


def PLUGIN_ENTRY():
    return YaCoPlugin()
