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
import traceback

from ImportExport import ARMIDAVisitorPlugin
from ImportExport import DefaultIDAVisitorPlugin
from ImportExport import YaToolIDATools
from idaapi import REGVAR_ERROR_OK
from exceptions import Exception

if idc.__EA64__:
    import YaToolsPy64 as ya
else:
    import YaToolsPy32 as ya


logger = logging.getLogger("YaCo")
DEBUG_EXPORTER = False


class YaToolIDAExporter(ya.IObjectVisitorListener):
    def __init__(self, yatools, hash_provider, use_stackframes=True):
        super(YaToolIDAExporter, self).__init__()
        self.native = ya.MakeExporter(hash_provider, ya.ExportFrame if use_stackframes else ya.SkipFrame)

    def object_version_visited(self, id, version):
        self.native.object_version_visited(id, version)
