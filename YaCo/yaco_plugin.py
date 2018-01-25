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
import os
import sys
import traceback

yaco = None

def start():
    global yaco
    if idc.__EA64__:
        import YaToolsPy64 as ya
    else:
        import YaToolsPy32 as ya
    if not yaco:
        yaco = ya.MakeYaCo(ya.IS_INTERACTIVE)


def close():
    global yaco
    yaco = None


def is_enabled():
    opts = idaapi.get_plugin_options("yaco")
    return not opts or "disable_plugin" not in opts.split(':')


class YaCoPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "YaCo plugin"
    help = "YaCo: Yet Another Collaboration tool plugin"
    wanted_name = "YaCo"
    wanted_hotkey = ""

    def init(self, *args, **kwargs):
        if not is_enabled():
            print("yaco: disabled")
            return idaapi.PLUGIN_SKIP

        root_dir = os.path.abspath(os.path.join(inspect.getsourcefile(lambda: 0), "..", "YaTools"))
        for path in ["YaCo", "bin"]:
            path = os.path.join(root_dir, path)
            print("yaco: using %s" % path)
            sys.path.append(path)

        input_filename = idc.GetIdbPath()
        if input_filename.count("_local.") > 0 and os.path.exists(".git"):
            print("yaco: initializing")
            start()
            return idaapi.PLUGIN_KEEP

        if "_local." not in input_filename and os.path.exists(".git"):
            print("""
*******************************************************
WARNING : You have opened a database in a git project,
WARNING : but your database doesn't match a YaCo project.
WARNING : YaCo is disabled !
*******************************************************
""")
            return idaapi.PLUGIN_OK

        return idaapi.PLUGIN_KEEP

    def run(self, *args, **kwargs):
        print("yaco: waiting for auto analysis...\n")
        idc.Wait()
        print("yaco: saving current base...\n")
        idc.SaveBase("")
        start()

    def term(self, *args, **kwargs):
        print("yaco: exit")
        close()


def PLUGIN_ENTRY():
    return YaCoPlugin()
