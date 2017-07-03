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
                self.make_stackframe(object_version, address)
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
                    self.make_struc_member(object_version, address)

                elif obj_type == ya.OBJECT_TYPE_ENUM_MEMBER:
                    self.native.make_enum_member(object_version, address)

                elif self.use_stackframes and obj_type == ya.OBJECT_TYPE_STACKFRAME_MEMBER:
                    self.make_stackframe_member(object_version, address)

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

    def make_struc_member(self, object_version, address, member_type=ya.OBJECT_TYPE_STRUCT_MEMBER):
        struc_object_id = object_version.get_parent_object_id()

        struc_id = self.get_tid(struc_object_id, ya.OBJECT_TYPE_STRUCT, ya.OBJECT_TYPE_STACKFRAME)
        if struc_id == idc.BADADDR:
            return
        is_union = struc_id in self.union_ids

        offset = address

        if is_union:
            last_offset = idc.GetLastMember(struc_id)
            if last_offset == idc.BADADDR:
                last_offset = -1
            if last_offset < offset:
                for i in xrange(last_offset + 1, offset + 1):
                    idc.AddStrucMember(struc_id, "yaco_filler_%d" % i, 0, idc.FF_BYTE | idc.FF_DATA, -1, 1)
                    # ensure that 'offset' fields are present

        member_size = object_version.get_size()
        member_name = object_version.get_name()

        flags = object_version.get_object_flags()
        if idc.isStruct(flags):
            # if the sub field is a struct, it must have a single Xref field with the struct object id
            try:
                sub_struc_object_id = object_version.getXRefIdsAt(0, 0)[0]
                sub_struc_id = self.get_tid(sub_struc_object_id, ya.OBJECT_TYPE_STRUCT, ya.OBJECT_TYPE_STACKFRAME)

                #                 logger.debug("%20s: adding sub member at offset 0x%08X,
                #                               size=0x%08X (sub=0x%.016X, size=0x%08X) with name %s" %
                #                             (
                #                                 idc.GetStrucName(struc_id), offset, member_size, sub_struc_id,
                #                                               idc.GetStrucSize(sub_struc_id), object_version.get_name()
                #                             ))

                sub_struc_size = idc.GetStrucSize(sub_struc_id)
                if sub_struc_size == 0:
                    logger.error(
                        "%20s: adding sub member at offset 0x%08X, size=0x%08X "
                        "(sub=0x%.016X, size=0x%08X) with name %s : sub struc size is ZERO" %
                        (
                            idc.GetStrucName(struc_id), offset, member_size, sub_struc_id,
                            idc.GetStrucSize(sub_struc_id),
                            object_version.get_name()
                        ))

                else:
                    nitems = member_size / sub_struc_size

                    YaToolIDATools.SetStrucmember(struc_id, member_name, offset, flags, sub_struc_id, nitems)

            except KeyError:
                logger.error("Error while looking for sub struc in struc %s, offset 0x%08X (field name='%s')" %
                             (
                                 self.hash_provider.hash_to_string(
                                     struc_object_id), offset, object_version.get_name()
                             )
                             )
                traceback.print_exc()
        elif idc.isEnum0(flags):
            # an enum is applied here
            sub_enum_object_id = object_version.getXRefIdsAt(0, 0)[0]
            sub_enum_id = self.get_tid(sub_enum_object_id, ya.OBJECT_TYPE_ENUM)
            if sub_enum_id == idc.BADADDR:
                logger.error("Error while looking for sub enum in struc %s, offset 0x%08X (field name='%s')" %
                    (struc_object_id, offset, member_name))
                traceback.print_exc()
            else:
                name_ok = idc.SetMemberName(struc_id, offset, member_name)
                if name_ok is not True:
                    logger.debug(
                        "Error while setting member name (enum) : "
                        "(struc=%s, member=%s, offset=0x%08X, mflags=%d, msize=%d, tid=0x%016X" %
                        (idc.GetStrucName(struc_id), member_name, offset, flags, member_size, sub_enum_id))
                else:
                    sub_enum_size = idc.GetEnumWidth(sub_enum_id)
                    if sub_enum_size == 0:
                        sub_enum_size = member_size

                    nitems = member_size / sub_enum_size
                    ret = idc.SetMemberType(struc_id, offset, flags, sub_enum_id, nitems)
                    if ret == 0:
                        logger.debug(
                            "Error while setting member type (enum) : "
                            "(ret=%d struc=%s, member=%s, offset=0x%08X, mflags=%d, msize=%d, tid=0x%016X" %
                            (ret, idc.GetStrucName(struc_id), member_name, offset, flags, member_size, sub_enum_id))
        else:
            #             logger.debug("%20s: adding member at offset 0x%08X, size=0x%08X with name %s" %
            #                         (
            #                         idc.GetStrucName(struc_id), offset, member_size, object_version.get_name()
            #                         ))
            tid = -1
            if idc.isASCII(flags):
                logger.debug("object: %s : %s" %
                             (self.hash_provider.hash_to_string(object_version.get_id()), object_version.get_name()))
                try:
                    tid = object_version.get_string_type()
                except KeyError:
                    tid = idc.ASCSTR_C

            name_ok = idc.SetMemberName(struc_id, offset, member_name)
            if name_ok is not True:
                logger.debug("Error while setting member name :" +
                             " (struc_id=0x%08X, struc=%s, member=%s, offset=0x%08X, mflags=%d, msize=%d)" %
                             (struc_id, idc.GetStrucName(struc_id), member_name, offset, flags, member_size))
            else:
                item_size = YaToolIDATools.get_field_size(flags, tid)
                nitems = member_size / item_size
                # IDA BUG : 4-byte chars are stored as 2 double words, thus me must
                # multiply nitem by 2!
                ret = idc.SetMemberType(struc_id, offset, flags, tid, nitems)
                if ret == 0:
                    logger.debug("Error while setting member type :" +
                                 " (struc=%s, member=%s, offset=0x%08X, mflags=%d, msize=%d)" %
                                 (idc.GetStrucName(struc_id), member_name, offset, flags, member_size))

        try:
            repeatable_headercomment = self.sanitize_comment_to_ascii(object_version.get_header_comment(True))
            idc.SetMemberComment(struc_id, offset, repeatable_headercomment, 1)
        except KeyError:
            pass

        try:
            nonrepeatable_headercomment = self.sanitize_comment_to_ascii(object_version.get_header_comment(False))
            idc.SetMemberComment(struc_id, offset, nonrepeatable_headercomment, 0)
        except KeyError:
            pass

        member_id = idc.GetMemberId(struc_id, offset)
        self.native.set_struct_member_type(member_id, object_version.get_prototype())
        if object_version.get_type() == ya.OBJECT_TYPE_STRUCT_MEMBER:
            id = object_version.get_id()
            self.native.set_tid(id, member_id, ya.OBJECT_TYPE_STRUCT_MEMBER)

    def make_stackframe(self, object_version, address):
        object_id = object_version.get_id()
        parent_object_id = object_version.get_parent_object_id()
        # association stackframe id to internal struc id
        eaFunc = object_version.get_object_address()
        logger.debug("stackframe[%s] : address of function is 0x%08X" %
                     (self.hash_provider.hash_to_string(object_id), eaFunc))

        attributes = object_version.get_attributes()
        stack_lvars = None
        stack_regvars = None
        stack_args = None
        try:
            stack_lvars = self.yatools.hex_string_to_address(attributes["stack_lvars"])
            stack_regvars = self.yatools.hex_string_to_address(attributes["stack_regvars"])
            stack_args = self.yatools.hex_string_to_address(attributes["stack_args"])
        except KeyError:
            logger.warning("Stackframe at %s has missing attribute" % self.yatools.address_to_hex_string(eaFunc))

        stack_frame = idaapi.get_frame(eaFunc)
        if stack_frame is None:
            logger.error("No function found for stackframe[%s] at 0x%08X" % (
                self.hash_provider.hash_to_string(object_id), eaFunc))
            self.native.analyze_function(eaFunc)
            stack_frame = idaapi.get_frame(eaFunc)

        if stack_frame is None:
            logger.error("No function found for stackframe[%s] at 0x%08X after reanalysis" % (
                self.hash_provider.hash_to_string(object_id), eaFunc))
            idc.SetCharPrm(idc.INF_AUTO, 1)
            idc.Wait()
            idc.SetCharPrm(idc.INF_AUTO, 0)
            stack_frame = idaapi.get_frame(eaFunc)

        if stack_frame is None:
            logger.error("No function found for stackframe[%s] at 0x%08X after full reanalysis" % (
                self.hash_provider.hash_to_string(object_id), eaFunc))
            idc.MakeFrame(eaFunc, stack_lvars, stack_regvars, stack_args)
            stack_frame = idaapi.get_frame(eaFunc)

        if stack_frame is None:
            logger.error("No function found for stackframe[%s] at 0x%08X after idc.MakeFrame" % (
                self.hash_provider.hash_to_string(object_id), eaFunc))
        else:
            self.native.set_tid(object_id, stack_frame.id, ya.OBJECT_TYPE_STACKFRAME)
            stack_lvars = None
            try:
                stack_lvars = self.yatools.hex_string_to_address(object_version.get_attributes()["stack_lvars"])
            except KeyError:
                logger.warning("Stackframe at %s has no stack_lvars attribute" %
                               self.yatools.address_to_hex_string(eaFunc))

            if stack_lvars is not None:
                logger.debug("Clearing everything for stackframe at 0x%08X, with stack_lvars=0x%04X", eaFunc,
                             stack_lvars)
                self.native.clear_struct_fields(object_version, stack_frame.id)

    def make_stackframe_member(self, object_version, address):
        object_id = object_version.get_id()
        self.make_struc_member(object_version, address)
        self.native.set_tid(object_id, object_version.get_parent_object_id(), ya.OBJECT_TYPE_STACKFRAME_MEMBER)

    def sanitize_comment_to_ascii(self, comment):
        try:
            return comment.encode("ascii", "replace")
        except UnicodeDecodeError:
            return comment.decode("ascii", "replace").encode("ascii", "replace")
