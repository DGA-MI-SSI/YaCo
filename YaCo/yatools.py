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
import logging
import os

if idc.__EA64__:
    import YaToolsPy64 as ya
else:
    import YaToolsPy32 as ya

logger = logging.getLogger("YaCo")

def ea_to_hex(ea):
    if idc.BADADDR == 0xFFFFFFFF:
        return "0x%08X" % ea
    if idc.BADADDR == 0xFFFFFFFFFFFFFFFF:
        return "0x%016X" % ea
    return hex(ea)


def get_original_idb_name(local_idb_name, suffix=""):
    if suffix == None:
        suffix = ""
    return ya.get_original_idb_name(local_idb_name, suffix)


def get_local_idb_name(original_idb_name, suffix=""):
    if suffix == None:
        suffix = ""
    return ya.get_local_idb_name(original_idb_name, suffix)


def remove_ida_temporary_files(idb_path):
    ya.remove_ida_temporary_files(idb_path)


def copy_idb_to_local_file(suffix=None):
    if suffix == None:
        suffix = ""
    return ya.copy_idb_to_local_file(suffix)


def copy_idb_to_original_file(suffix=None):
    orig_file_name = get_original_idb_name(idc.GetIdbPath(), suffix)
    idc.SaveBase(orig_file_name)
    remove_ida_temporary_files(orig_file_name)
    return orig_file_name
