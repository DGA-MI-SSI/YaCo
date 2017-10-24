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

if idc.__EA64__:
    import YaToolsPy64 as ya
else:
    import YaToolsPy32 as ya

def ea_to_hex(ea):
    return ya.ea_to_hex(ea)


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
    if suffix == None:
        suffix = ""
    return ya.copy_idb_to_original_file(suffix)
