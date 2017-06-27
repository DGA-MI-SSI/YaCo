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
import idaapi
import idc
import logging
import os
import sys

if idc.__EA64__:
    import YaToolsPy64 as ya
else:
    import YaToolsPy32 as ya

logger = logging.getLogger("YaCo")
_yatools_ida = ya.YaToolsIDANativeLib()

OBJECT_WITH_COMMENTS = set([ya.OBJECT_TYPE_BASIC_BLOCK, ya.OBJECT_TYPE_CODE, ya.OBJECT_TYPE_DATA])

STRING_CHAR_SIZE = {
    idc.ASCSTR_TERMCHR: 1,  # Character-terminated ASCII string
    idc.ASCSTR_C: 1,  # C-string, zero terminated
    idc.ASCSTR_PASCAL: 1,  # Pascal-style ASCII string (length byte)
    idc.ASCSTR_LEN2: 2,  # Pascal-style, length is 2 bytes
    idc.ASCSTR_UNICODE: 2,  # Unicode string
    idc.ASCSTR_LEN4: 4,  # Delphi string, length is 4 bytes
    idc.ASCSTR_ULEN2: 2,  # Pascal-style Unicode, length is 2 bytes
    idc.ASCSTR_ULEN4: 4,  # Pascal-style Unicode, length is 4 bytes
}


def get_char_size(str_type):
    return STRING_CHAR_SIZE[str_type]


def get_field_size(field_type, tid=0):
    field_type = field_type & idc.DT_TYPE
    if field_type == idc.FF_BYTE:
        return 1
    if field_type == idc.FF_ASCI:
        return get_char_size(tid)
    elif field_type == idc.FF_WORD:
        return 2
    elif field_type == idc.FF_DWRD:
        return 4
    elif field_type == idc.FF_QWRD:
        return 8
    elif field_type == idc.FF_OWRD:
        return 16
    elif field_type == idc.FF_FLOAT:
        return 4
    elif field_type == idc.FF_DOUBLE:
        return 8
    else:
        return 1


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


def struc_member_list(struc_id, is_union):
    current_idx = 0
    struc = idaapi.get_struc(struc_id)
    if struc is None or struc == idc.BADADDR:
        return []

    offsets = dict()
    for current_idx in xrange(0, struc.memqty):
        offset = _yatools_ida.get_struc_member_by_idx(struc, current_idx)
        if offset not in offsets:
            name = idc.GetMemberName(struc_id, offset)
            if name is not None:
                offsets[offset] = name

    return sorted(offsets.items())


def enum_member_iterate_all(enum_id):
    const_value = idc.GetFirstConst(enum_id, -1)
    while const_value != idc.BADADDR:
        serial = 0
        const_id = idc.GetConstEx(enum_id, const_value, serial, -1)
        while const_id != idc.BADADDR:
            yield (const_id, const_value, idc.BADADDR)

            serial += 1
            const_id = idc.GetConstEx(enum_id, const_value, serial, -1)
        const_value = idc.GetNextConst(enum_id, const_value, -1)

    bmask = idc.GetFirstBmask(enum_id)
    while bmask != idc.BADADDR:
        const_value = idc.GetFirstConst(enum_id, bmask)
        while const_value != idc.BADADDR:
            # TODO must implement serial for bitfield
            const_id = idc.GetConstEx(enum_id, const_value, 0, bmask)
            yield (const_id, const_value, bmask)
            const_value = idc.GetNextConst(enum_id, const_value, bmask)
        bmask = idc.GetNextBmask(enum_id, bmask)


def SetStrucmember(struc_id, member_name, offset, flag, typeid, nitems, member_type=ya.OBJECT_TYPE_STRUCT_MEMBER,
                   name_offset=0):
    if member_name is None:
        member_name = get_default_struc_member_name(member_type, offset, name_offset)

    ret = idc.SetMemberName(struc_id, offset, member_name)
    if not ret:
        logger.debug("Error while naming sub strucmember (struc) : " +
                     "%d (struc=%s, member=%s, offset=0x%08X"
                     % (ret, idc.GetStrucName(struc_id), member_name, offset))
    else:
        ret = idc.SetMemberType(struc_id, offset, flag, typeid, nitems)
        if ret == 0:
            logger.debug("Error while setting sub strucmember type (struc) :" +
                         " %d (struc=%s, member=%s, offset=0x%08X, mflags=%d, nitems=%d, tid=0x%016X" %
                         (ret, idc.GetStrucName(struc_id), member_name, offset, flag, nitems, typeid))


idaname = "ida64" if idc.__EA64__ else "ida"
if sys.platform == "win32":
    dll = ctypes.windll[idaname + ".wll"]
elif sys.platform == "linux2":
    dll = ctypes.cdll["lib" + idaname + ".so"]
elif sys.platform == "darwin":
    dll = ctypes.cdll["lib" + idaname + ".dylib"]

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


def get_default_struc_member_name(object_type, offset, name_offset=0):
    if object_type == ya.OBJECT_TYPE_STRUCT_MEMBER:
        return "field_%X" % (offset - name_offset)
    elif object_type == ya.OBJECT_TYPE_STACKFRAME_MEMBER:
        if offset > name_offset:

            if offset - name_offset < 4:
                name = "var_s%d" % (offset - name_offset)
            else:
                name = "arg_%X" % (offset - (name_offset + 4))
            #             logger.debug("get_default_struc_member_name: offset=0x%08X, name_offset=0x%08X, retval=%s ",
            #                          offset, name_offset, name
            #                          )
            return name
        else:
            #             logger.debug("get_default_struc_member_name: offset=0x%08X, name_offset=0x%08X, retval=%s ",
            #                          offset, name_offset, "var_%X" % (name_offset-offset))
            return "var_%X" % (name_offset - offset)
    else:
        logger.warning("get_default_struc_member_name: bad object_type: %r" % (object_type))
        return None
