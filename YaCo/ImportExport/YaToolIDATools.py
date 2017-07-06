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

import ctypes
import idc
import logging
import os
import sys

if idc.__EA64__:
    import YaToolsPy64 as ya
else:
    import YaToolsPy32 as ya

logger = logging.getLogger("YaCo")


def get_original_idb_name(local_idb_name, suffix=None):
    idbname = os.path.basename(local_idb_name)
    idbname_prefix = os.path.splitext(idbname)[0]
    idbname_extension = os.path.splitext(idbname)[1]
    if suffix is None:
        suffix = "_local"
    orig_file_name = "%s%s" % (idbname_prefix.replace(suffix, ""), idbname_extension)
    return orig_file_name


def get_local_idb_name(original_idb_name, suffix=None, subdir=None):
    idbname = os.path.basename(original_idb_name)
    idbname_prefix = os.path.splitext(idbname)[0]
    idbname_extension = os.path.splitext(idbname)[1]
    if suffix is None:
        suffix = "_local"
    local_file_name = "%s%s%s" % (idbname_prefix, suffix, idbname_extension)

    if subdir is not None:
        (head, tail) = os.path.split(local_file_name)
        local_file_name = os.path.join(head, subdir, tail)
        # create directory if necessary
        (head, tail) = os.path.split(local_file_name)
        if os.path.exists(head) is False:
            os.mkdir(head)

    return local_file_name


def remove_ida_temporary_files(idb_path):
    dot = idb_path.rfind(".")
    file_name = idb_path[:dot]
    for del_ext in ["id0", "id1", "id2", "nam", "til"]:
        try:
            os.remove(file_name + "." + del_ext)
        except:
            pass


def copy_idb_to_local_file(suffix=None, subdir=None, use_hardlink=False):
    local_file_name = get_local_idb_name(idc.GetIdbPath(), suffix)
    if subdir is not None:
        (head, tail) = os.path.split(local_file_name)
        local_file_name = os.path.join(head, subdir, tail)
        (head, tail) = os.path.split(local_file_name)
        if os.path.exists(head) is False:
            os.mkdir(head)

    if use_hardlink:
        (idb_dir, idb_name) = os.path.split(idc.GetIdbPath())
        original_idb_name = os.path.splitext(idb_name)[0]
        new_idb_name = os.path.splitext(local_file_name)[0]
        (head, tail) = os.path.split(local_file_name)
        logger.info("looking for copy-possible files in %s" % head)
        for f in os.listdir(head):
            (list_file_name, list_file_ext) = os.path.splitext(f)
            logger.info("checking if %s:%s is to be copied to %s as source name" % (
                list_file_name, list_file_ext, original_idb_name))
            if (list_file_name == original_idb_name and
                    (
                        list_file_ext in set([".nam", ".til"]) or
                        (list_file_ext.startswith(".id") and list_file_ext[-1:].isdigit()))):
                new_name = os.path.join(idb_dir, new_idb_name + list_file_ext)
                f = os.path.join(idb_dir, f)
                logger.info("Linking %s to %s" % (f, new_name))

                try:
                    os.remove(new_name)
                except:
                    pass
                os.system("/bin/cp --reflink=auto %s %s" % (f, new_name))
    else:
        idc.SaveBase(local_file_name)
        remove_ida_temporary_files(local_file_name)
    return local_file_name


def copy_idb_to_original_file(suffix=None):
    orig_file_name = get_original_idb_name(idc.GetIdbPath(), suffix)
    idc.SaveBase(orig_file_name)
    remove_ida_temporary_files(orig_file_name)
    return orig_file_name


if sys.platform == "linux2":
    def get_mem_usage():
        status_path = "/proc/%i/status" % os.getpid()
        f_status = open(status_path, 'r')
        lines = f_status.readlines()
        for line in lines:
            if "VmHWM" in line.split(':')[0]:
                s_kmem = line.split(':')[1].split()[0]
                return (int(s_kmem) / 1024)

else:
    from win32.get_process_memory import get_memory_usage

    def get_mem_usage():
        return get_memory_usage() / (1024 * 1024)
