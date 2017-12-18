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

import idc
import idaapi
import logging
import time
import traceback
import os
import YaCo

if idc.__EA64__:
    import YaToolsPy64 as ya
else:
    import YaToolsPy32 as ya

logger = logging.getLogger("YaCo")
# logger.setLevel(logging.DEBUG)

hooks = None

class Hooks(object):
    def __init__(self, hash_provider, repo_manager):
        self.ida = ya.MakeHooks(hash_provider, repo_manager)
        self.idb = YaToolIDB_Hooks()
        global hooks
        hooks = self

    def hook(self):
        logger.debug("Hooks:hook")
        self.ida.hook() # native
        self.idb.hook()

    def unhook(self):
        logger.debug("Hooks:unhook")
        self.ida.unhook() # native
        self.idb.unhook()


class YaToolIDB_Hooks(idaapi.IDB_Hooks):
    def __init__(self):
        idaapi.IDB_Hooks.__init__(self)

    def closebase(self, *args):
        logger.debug("closebase")
        YaCo.close()
        return idaapi.IDB_Hooks.closebase(self, *args)
