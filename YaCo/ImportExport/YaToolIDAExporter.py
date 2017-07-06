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
        self.native = ya.MakeExporter(hash_provider)
        self.yatools = yatools
        self.union_ids = set()
        self.arch_plugin = DefaultIDAVisitorPlugin.DefaultIDAVisitorPlugin()
        if idc.GetCharPrm(idc.INF_PROCNAME) == "ARM":
            self.arch_plugin = ARMIDAVisitorPlugin.ARMIDAVisitorPlugin()
        self.hash_provider = hash_provider
        self.use_stackframes = use_stackframes

    """
    function called when an object passes the "RESOLVED" state
    """

    def object_version_visited(self, obj_id, object_version):
        logger.debug("YaToolIDAExporter.object_version_visited")
        try:
            obj_id_str = self.hash_provider.hash_to_string(obj_id)
            logger.debug("object visited : %s" % obj_id_str)
            obj_type = object_version.get_type()
            address = object_version.get_object_address()
            # create code
            if obj_type == ya.OBJECT_TYPE_STRUCT:
                self.make_struc(object_version, address)
            elif self.use_stackframes and obj_type == ya.OBJECT_TYPE_STACKFRAME:
                self.native.make_stackframe(object_version, address)
            elif obj_type == ya.OBJECT_TYPE_ENUM:
                self.native.make_enum(object_version, address)
            else:

                if DEBUG_EXPORTER:
                    if address == idc.BADADDR:
                        logger.error("Committing object %s (type=%s) : NO ADDRESS" % (obj_id_str, obj_type))
                    else:
                        logger.debug("[0x%08X] Committing object %s (type=%s)" % (address, obj_id_str, obj_type))

                if address == idc.BADADDR:
                    return

                if obj_type == ya.OBJECT_TYPE_CODE:
                    self.native.make_code(object_version, address)

                # create function
                elif obj_type == ya.OBJECT_TYPE_FUNCTION:
                    self.native.make_function(object_version, address)

                # create basic blocks
                elif obj_type == ya.OBJECT_TYPE_BASIC_BLOCK:
                    self.native.make_basic_block(object_version, address)

                elif obj_type == ya.OBJECT_TYPE_STRUCT_MEMBER:
                    self.native.make_struct_member(object_version, address)

                elif obj_type == ya.OBJECT_TYPE_ENUM_MEMBER:
                    self.native.make_enum_member(object_version, address)

                elif self.use_stackframes and obj_type == ya.OBJECT_TYPE_STACKFRAME_MEMBER:
                    self.native.make_struct_member(object_version, address)

                elif obj_type == ya.OBJECT_TYPE_DATA:
                    self.native.make_data(object_version, address)

                elif obj_type == ya.OBJECT_TYPE_SEGMENT:
                    self.native.make_segment(object_version, address)

                elif obj_type == ya.OBJECT_TYPE_SEGMENT_CHUNK:
                    self.native.make_segment_chunk(object_version, address)

                elif obj_type == ya.OBJECT_TYPE_REFERENCE_INFO:
                    self.native.make_reference_info(object_version, address)

                else:
                    pass

            self.native.make_header_comments(object_version, address)

            # add comments
            if obj_type in YaToolIDATools.OBJECT_WITH_COMMENTS:
                self.native.make_comments(object_version, address)
        except Exception as e:
            logger.error("error : %r " % e)
            logger.error(traceback.format_exc())
            traceback.print_exc()
            raise e

    def get_tid(self, id, *args):
        key = self.native.get_tid(id)
        for type in args:
            if key.type == type:
                return key.tid
        return idc.BADADDR

    def make_struc(self, object_version, address):
        name = object_version.get_name()
        object_id = object_version.get_id()
        size = object_version.get_size()

        struc_id = idc.GetStrucIdByName(name)
        if struc_id == idc.BADADDR:
            try:
                is_union = object_version.get_object_flags()
            except KeyError:
                is_union = 0

            struc_id = idc.AddStrucEx(0, name, is_union)
            # add a dummy field.
            # This is necessary to avoid an error is idc.SetType(struc*) is used on another struc
            # member
            # TODO not for empty strucs
            if is_union:
                idc.AddStrucMember(struc_id, "yaco_filler", 0, idc.FF_BYTE, 0, 1)

        else:

            is_union = idc.IsUnion(struc_id)
        if not is_union or is_union == 0:
            self.native.clear_struct_fields(object_version, struc_id)
        else:
            self.union_ids.add(struc_id)

        if DEBUG_EXPORTER:
            logger.debug("adding struc id %s : '0x%.016X' (%s)" %
                         (self.hash_provider.hash_to_string(object_id), struc_id, name))
        self.native.set_tid(object_id, struc_id, ya.OBJECT_TYPE_STRUCT)

        self.hash_provider.put_hash_struc_or_enum(struc_id, object_id, False)

    def sanitize_comment_to_ascii(self, comment):
        try:
            return comment.encode("ascii", "replace")
        except UnicodeDecodeError:
            return comment.decode("ascii", "replace").encode("ascii", "replace")
