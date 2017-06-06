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

from ImportExport import YaToolIDATools
from idaapi import REGVAR_ERROR_OK
from ImportExport.YaToolPrototypeParser import YaToolPrototypeParser
from exceptions import Exception

if idc.__EA64__:
    import YaToolsPy64 as ya
else:
    import YaToolsPy32 as ya

_yatools_ida_exporter = ya.IDANativeExporter()

logger = logging.getLogger("YaCo")
DEBUG_EXPORTER = False


class YaToolIDAExporter(ya.IObjectVisitorListener):
    def __init__(self, yatools, hash_provider, use_stackframes=True):
        super(YaToolIDAExporter, self).__init__()
        self.prototype_parser = YaToolPrototypeParser()
        self.yatools = yatools
        self.struc_ids = {}
        self.union_ids = set()
        self.strucmember_ids = {}
        self.enum_member_ids = {}
        self.stackframes_functions = {}
        self.stackframemembers_stackframes = {}
        self.arch_plugin = yatools.get_arch_plugin().get_ida_visitor_plugin()
        self.enum_ids = {}
        self.reference_infos = {}
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

            if obj_type == ya.OBJECT_TYPE_REFERENCE_INFO:
                self.reference_infos[obj_id] = (object_version.get_object_address(), object_version.get_object_flags())

            address = object_version.get_object_address()
            # create code
            if obj_type == ya.OBJECT_TYPE_STRUCT:
                self.make_struc(object_version, address)
            elif self.use_stackframes and obj_type == ya.OBJECT_TYPE_STACKFRAME:
                self.make_stackframe(object_version, address)
            elif obj_type == ya.OBJECT_TYPE_ENUM:
                self.make_enum(object_version, address)

            else:

                if DEBUG_EXPORTER:
                    if address == idc.BADADDR:
                        logger.error("Committing object %s (type=%s) : NO ADDRESS" % (obj_id_str, obj_type))
                    else:
                        logger.debug("[0x%08X] Committing object %s (type=%s)" % (address, obj_id_str, obj_type))

                if address == idc.BADADDR:
                    return

                if obj_type == ya.OBJECT_TYPE_CODE:
                    _yatools_ida_exporter.make_code(object_version, address)

                # create function
                elif obj_type == ya.OBJECT_TYPE_FUNCTION:
                    self.make_function(object_version, address)

                # create basic blocks
                elif obj_type == ya.OBJECT_TYPE_BASIC_BLOCK:
                    self.make_basic_block(object_version, address)

                elif obj_type == ya.OBJECT_TYPE_STRUCT_MEMBER:
                    self.make_struc_member(object_version, address)

                elif obj_type == ya.OBJECT_TYPE_ENUM_MEMBER:
                    self.make_enum_member(object_version, address)

                elif self.use_stackframes and obj_type == ya.OBJECT_TYPE_STACKFRAME_MEMBER:
                    self.make_stackframe_member(object_version, address)

                elif obj_type == ya.OBJECT_TYPE_DATA:
                    self.make_data(object_version, address)

                elif obj_type == ya.OBJECT_TYPE_SEGMENT:
                    _yatools_ida_exporter.make_segment(object_version, address)

                elif obj_type == ya.OBJECT_TYPE_SEGMENT_CHUNK:
                    _yatools_ida_exporter.make_segment_chunk(object_version, address)

                else:
                    pass

            _yatools_ida_exporter.make_header_comments(object_version, address)

            # add comments
            if obj_type in YaToolIDATools.OBJECT_WITH_COMMENTS:
                _yatools_ida_exporter.make_comments(object_version, address)
        except Exception as e:
            logger.error("error : %r " % e)
            logger.error(traceback.format_exc())
            traceback.print_exc()
            raise e

    def make_data(self, object_version, address):
        size = 0
        try:
            size = object_version.get_size()
        except KeyError:
            pass
        flags = None
        try:
            flags = object_version.get_object_flags()
        except KeyError:
            pass

        if size == 0:
            idc.MakeUnkn(address, idc.DOUNK_EXPAND)
        else:
            if flags is not None:
                if idc.isASCII(flags):
                    try:
                        str_type = object_version.get_string_type()
                        YaToolIDATools.check_and_set_str_type(str_type)
                    except KeyError:
                        pass
                    idc.MakeStr(address, address + size)
                    idc.SetFlags(address, flags)

                if idc.isStruct(flags):
                    found = False
                    for xref_offset_operand, xref_id_attr in object_version.get_xrefed_id_map().iteritems():
                        (xref_offset, xref_operand) = xref_offset_operand
                        for xref_hash, xref_attrs in xref_id_attr:

                            if xref_hash in self.struc_ids:
                                struc_id = self.struc_ids[xref_hash]
                                if DEBUG_EXPORTER:
                                    logger.debug("making unknown from 0x%08X to 0x%08X" % (address, address + size))
                                idaapi.do_unknown_range(address, size, idc.DOUNK_DELNAMES)

                                #   idc.MakeUnkn(address, DOUNK_SIMPLE | idc.DOUNK_DELNAMES)
                                #   for i in xrange(1, size):
                                #       MakeName(address + i, "")
                                #       idc.MakeUnkn(address + i, DOUNK_SIMPLE | idc.DOUNK_DELNAMES)
                                # idc.MakeStructEx uses idaapi.doStruct (but asks for name while
                                # we already have the struc id)
                                if DEBUG_EXPORTER:
                                    logger.debug(
                                        "Making struc at %s : %s (sizeof(%s)=0x%08X, size=0x%08X, flags=0x%08X" %
                                        (
                                            self.yatools.address_to_hex_string(address),
                                            self.yatools.address_to_hex_string(struc_id),
                                            idaapi.get_struc_name(struc_id),
                                            idc.GetStrucSize(struc_id), size,
                                            flags
                                        ))
                                idc.SetCharPrm(idc.INF_AUTO, True)
                                idc.Wait()
                                if idaapi.doStruct(address, size, struc_id) == 0:
                                    if DEBUG_EXPORTER:
                                        logger.warning("Making struc failed")
                                idc.SetCharPrm(idc.INF_AUTO, False)
                                #                                     idc.SetFlags(address, flags)
                                found = True
                    else:
                        logger.error("bad struc flags : idc.isStruct is true but no xref available for object %s" %
                                     self.hash_provider.hash_to_string(object_version.get_id()))
                    if not found:
                        logger.error("bad struc flags : idc.isStruct is true "
                                     "but no struc available for object %s (%s)" %
                                     (self.hash_provider.hash_to_string(object_version.get_id()),
                                      object_version.get_name()))
                else:
                    idc.MakeData(address, flags & (idc.DT_TYPE | idc.MS_0TYPE), size, 0)

            else:
                idc.MakeData(address, idc.FF_BYTE, size, 0)

        _yatools_ida_exporter.make_name(object_version, address, False)
        _yatools_ida_exporter.set_type(address, object_version.get_prototype())

    def make_enum(self, object_version, address):
        enum_name = object_version.get_name()
        object_id = object_version.get_id()

        # build flags
        bitfield = False
        flags = object_version.get_object_flags()
        if flags & 0x1 == 0x1:
            bitfield = True
        flags = flags & ~0x1

        try:
            enum_width = object_version.get_size()
        except KeyError:
            enum_width = None

        # check if enum already exists
        enum_id = idc.GetEnum(enum_name)
        enum_xrefs_ids = object_version.get_xrefed_ids()
        logger.debug("%s:%d : Check here that enum_xrefs_ids is a set(YaToolObjectId) and correctly used" %
                     (__file__, inspect.currentframe().f_lineno))
        if enum_id != idc.BADADDR:
            # enum already exists, deleting all members
            for (const_id, const_value, bmask) in YaToolIDATools.enum_member_iterate_all(enum_id):
                if bmask == idc.BADADDR:
                    bmask = -1
                const_name = idc.GetConstName(const_id)

                if (enum_name, const_name, const_value) not in self.enum_member_ids:
                    idc.DelConstEx(enum_id, const_value, 0, bmask)
                elif self.hash_provider.get_enum_member_id(enum_id, enum_name, const_id, const_name,
                                                           const_value) not in enum_xrefs_ids:
                    logger.debug("deleting not found constant : %s/%s" % (enum_name, const_name))
                    idc.DelConstEx(enum_id, const_value, 0, bmask)

            """
            if the enum "bitfield" state has changed : change it!
            We can't access the functions
            """
            if idc.IsBitfield(enum_id) != bitfield:
                idaapi.set_enum_bf(enum_id, bitfield)
        else:
            # create enum
            # SetEnumFlag return "'module' object has no attribute 'set_enum_flag'".
            enum_id = idc.AddEnum(address, enum_name, flags)

        if enum_width is not None:
            idc.SetEnumWidth(enum_id, enum_width)

        if bitfield:
            idc.SetEnumBf(enum_id, 1)

        # process comment
        try:
            repeatable_headercomment = self.sanitize_comment_to_ascii(object_version.get_header_comment(True))
            idc.SetEnumCmt(enum_id, repeatable_headercomment, 1)
        except KeyError:
            pass
        try:
            nonrepeatable_headercomment = self.sanitize_comment_to_ascii(object_version.get_header_comment(False))
            idc.SetEnumCmt(enum_id, nonrepeatable_headercomment, 0)
        except KeyError:
            pass

        self.enum_ids[object_id] = enum_id

        self.hash_provider.put_hash_struc_or_enum(enum_id, object_id)

        logger.debug("adding enum id %s : '0x%.016X'" % (self.hash_provider.hash_to_string(object_id), enum_id))

    def make_enum_member(self, object_version, value):
        name = object_version.get_name()
        object_id = object_version.get_id()

        enum_object_id = object_version.get_parent_object_id()

        enum_id = 0
        try:
            enum_id = self.enum_ids[enum_object_id]
        except:
            return

        self.hash_provider.put_hash_enum_member(idc.GetEnumName(enum_id), name, value, object_id)

        # create member
        if not idc.IsBitfield(enum_id):
            bmask = -1
        else:
            bmask = object_version.get_object_flags()

        member_id = idc.GetConstEx(enum_id, value, 0, bmask)
        if member_id == idc.BADADDR:
            idc.AddConstEx(enum_id, name, value, bmask)
            member_id = idc.GetConstEx(enum_id, value, 0, bmask)
        else:
            if idc.SetConstName(member_id, name) == 0:
                logger.error("Failed to set const name for enum_id")

        # apply comments
        try:
            repeatable_headercomment = self.sanitize_comment_to_ascii(object_version.get_header_comment(True))
            idc.SetConstCmt(member_id, repeatable_headercomment, 1)
        except KeyError:
            pass

        try:
            nonrepeatable_headercomment = self.sanitize_comment_to_ascii(object_version.get_header_comment(True))
            idc.SetConstCmt(member_id, nonrepeatable_headercomment, 0)
        except KeyError:
            pass

        self.enum_member_ids[(idc.GetEnumName(enum_id), name, value)] = (member_id, object_id)

    def clear_struc_fields(self, struc_id, struc_size, xref_keys, is_union=False,
                           member_type=ya.OBJECT_TYPE_STRUCT_MEMBER, name_offset=0):

        idc.BeginTypeUpdating(idc.UTP_STRUCT)
        last_offset = idc.GetLastMember(struc_id)

        # get existing member offsets
        field_offsets = set()
        for (xref_offset, xref_operand) in xref_keys:
            field_offsets.add(xref_offset)

        new_offsets = set()
        struc = idaapi.get_struc(struc_id)
        # create missing members first (prevent from deleting all members)
        for offset in field_offsets:
            member = idaapi.get_member(struc, offset)
            if member is not None and member.soff < offset:
                # we have a member above this member that is too big and contain this member
                # clear it!
                if DEBUG_EXPORTER:
                    logger.debug("reduce field : set_member_type(0x%08X, 0x%08X), overlapping 0x%08X",
                                 struc_id, member.soff, offset
                                 )
                idaapi.set_member_type(struc, member.soff, idc.FF_BYTE, None, 1)
                member = idaapi.get_member(struc, offset)

            if member is None or idaapi.get_member_name(member.id) is None:
                new_offsets.add(offset)
                member_name = YaToolIDATools.get_default_struc_member_name(member_type, offset, name_offset)
                if offset == last_offset and offset == struc_size:
                    field_size = 0
                else:
                    field_size = 1
                if DEBUG_EXPORTER:
                    logger.debug("AddStrucMember(0x%08X, '%s', 0x%08X, idc.FF_BYTE, -1, 0x%08X), name_offset=%d",
                                 struc_id, member_name, offset, field_size, name_offset
                                 )
                retval = idc.AddStrucMember(struc_id, member_name, offset, idc.FF_BYTE, -1, field_size)
                if retval != 0:
                    logger.error(
                        "Error %d with idc.AddStrucMember(0x%08X, '%s', 0x%08X,"
                        "idc.FF_BYTE, -1, 0x%08X), name_offset=%d",
                        retval, struc_id, member_name, offset, field_size, name_offset
                    )
            elif DEBUG_EXPORTER:
                logger.debug("Member exists : (0x%08X, '%s', 0x%08X, 0x%08X)",
                             struc_id, idc.GetMemberName(struc_id, offset), offset, idc.GetMemberSize(struc_id, offset)
                             )

        kept_offsets = field_offsets - new_offsets
        # clear kept members
        # split the loop since we will modify the structure while iterating
        offsets = set()
        for (offset, member_name) in YaToolIDATools.struc_member_list(struc_id, is_union):
            offsets.add(offset)

        for offset in offsets:
            if offset in kept_offsets:
                # This member already existed and is kept
                if offset == last_offset and offset == struc_size:
                    # this is the last field, and it is a variable sized structure
                    field_size = 0
                else:
                    field_size = 1
                if member_type == ya.OBJECT_TYPE_STRUCT_MEMBER:
                    strucmember_id = self.hash_provider.get_struc_member_id(struc_id, offset)
                elif member_type == ya.OBJECT_TYPE_STACKFRAME_MEMBER:
                    strucmember_id = self.hash_provider.get_stackframe_member_object_id(struc_id, offset)
                else:
                    logger.error("Bad member_type : %d" % member_type)

                if strucmember_id not in self.strucmember_ids:
                    # It is not necessary to clear the member if it is presnet in the resolved_objects
                    if DEBUG_EXPORTER:
                        logger.debug("SetStrucmember(0x%08X, None, 0x%08X, idc.FF_BYTE, -1, 0x%08X, name_offset=%s)",
                                     struc_id, offset, field_size, name_offset
                                     )
                    YaToolIDATools.SetStrucmember(struc_id, None, offset, idc.FF_BYTE, -1, field_size,
                                                  member_type=member_type, name_offset=name_offset)

                    idc.SetMemberComment(struc_id, offset, "", 0)
                    idc.SetMemberComment(struc_id, offset, "", 1)
            elif offset not in new_offsets:
                if (member_type != ya.OBJECT_TYPE_STACKFRAME_MEMBER or not idaapi.is_special_member(
                        idc.GetMemberId(struc_id, offset))):
                    if DEBUG_EXPORTER:
                        logger.debug("DelStrucMember(0x%08X, 0x%08X)  (=%s:%s)",
                                     struc_id, offset, idc.GetStrucName(struc_id), idc.GetMemberName(struc_id, offset)
                                     )
                    idc.DelStrucMember(struc_id, offset)
            else:
                # in new_offsets : just created
                pass
        idc.EndTypeUpdating(idc.UTP_STRUCT)

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
        #             if(is_union):
        #                 pass
        #             else:
        #                 self.clear_struc_fields(struc_id, object_version['xrefs'], is_union)

        if not is_union or is_union == 0:
            self.clear_struc_fields(struc_id, size, object_version.get_xrefed_id_map().iterkeys(), False)
        else:
            self.union_ids.add(struc_id)

        if DEBUG_EXPORTER:
            logger.debug("adding struc id %s : '0x%.016X' (%s)" %
                         (self.hash_provider.hash_to_string(object_id), struc_id, name))
        self.struc_ids[object_id] = struc_id
        _yatools_ida_exporter.set_struct_id(object_id, struc_id)

        self.hash_provider.put_hash_struc_or_enum(struc_id, object_id)

    def make_struc_member(self, object_version, address, member_type=ya.OBJECT_TYPE_STRUCT_MEMBER):
        struc_object_id = object_version.get_parent_object_id()

        struc_id = 0
        try:
            struc_id = self.struc_ids[struc_object_id]
        except:
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
                sub_struc_id = self.struc_ids[sub_struc_object_id]

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
            try:
                sub_enum_object_id = object_version.getXRefIdsAt(0, 0)[0]
                sub_enum_id = self.enum_ids[sub_enum_object_id]

                name_ok = idc.SetMemberName(struc_id, offset, member_name)
                if name_ok is not True:
                    logger.debug(
                        "Error while setting member name (enum) : "
                        "(struc=%s, member=%s, offset=0x%08X, mflags=%d, msize=%d, tid=0x%016X" %
                        (name_ok, idc.GetStrucName(struc_id), member_name, offset, flags, member_size, sub_struc_id))
                else:
                    sub_enum_size = idc.GetEnumWidth(sub_enum_id)
                    if sub_enum_size == 0:
                        sub_enum_size = member_size

                    nitems = member_size / sub_enum_size
                    ret = idc.SetMemberType(struc_id, offset, flags, sub_enum_id, nitems)
                    if ret == 0:
                        logger.debug(
                            "Error while setting member type (enum) : "
                            "(struc=%s, member=%s, offset=0x%08X, mflags=%d, msize=%d, tid=0x%016X" %
                            (ret, idc.GetStrucName(struc_id), member_name, offset, flags, member_size, sub_struc_id))

            except KeyError:
                logger.error("Error while looking for sub enum in struc %s, offset 0x%08X (field name='%s')" %
                             (
                                 struc_object_id, offset, member_name
                             )
                             )
                traceback.print_exc()

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
        _yatools_ida_exporter.set_struct_member_type(member_id, object_version.get_prototype())
        if object_version.get_type() == ya.OBJECT_TYPE_STRUCT_MEMBER:
            self.strucmember_ids[object_version.get_id()] = member_id

    def make_function(self, object_version, address):
        self.arch_plugin.make_function_prehook(object_version, address)
        _yatools_ida_exporter.make_function(object_version, address)
        self.arch_plugin.make_function_posthook(object_version, address)

    def make_stackframe(self, object_version, address):
        object_id = object_version.get_id()
        parent_object_id = object_version.get_parent_object_id()
        # associate stack frame id to function id
        self.stackframes_functions[object_id] = parent_object_id

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
            _yatools_ida_exporter.analyze_function(eaFunc)
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
            self.struc_ids[object_id] = stack_frame.id
            _yatools_ida_exporter.set_struct_id(object_id, stack_frame.id)
            stack_lvars = None
            try:
                stack_lvars = self.yatools.hex_string_to_address(object_version.get_attributes()["stack_lvars"])
            except KeyError:
                logger.warning("Stackframe at %s has no stack_lvars attribute" %
                               self.yatools.address_to_hex_string(eaFunc))

            if stack_lvars is not None:
                logger.debug("Clearing everything for stackframe at 0x%08X, with stack_lvars=0x%04X", eaFunc,
                             stack_lvars)
                self.clear_struc_fields(stack_frame.id, object_version.get_size(), object_version.get_xrefed_id_map()
                                        .iterkeys(), member_type=ya.OBJECT_TYPE_STACKFRAME_MEMBER,
                                        name_offset=stack_lvars)

    def make_stackframe_member(self, object_version, address):
        object_id = object_version.get_id()

        self.make_struc_member(object_version, address)
        # associate stack frame members to stack frame
        self.stackframemembers_stackframes[object_id] = object_version.get_parent_object_id()

    def make_basic_block(self, object_version, address):
        #
        # call the architecture dependent plugin  ###########
        #
        self.arch_plugin.make_basic_block_prehook(object_version, address)

        # create basic block name
        _yatools_ida_exporter.make_name(object_version, address, True)

        # apply view
        _yatools_ida_exporter.make_views(object_version, address)
        _yatools_ida_exporter.make_hiddenareas(object_version, address)

        for ((xref_offset, operand), xref_list) in object_version.get_xrefed_id_map().iteritems():
            struc_path = {}
            struc_off_delta = {}
            for (xref_value, xref_attributes) in xref_list:
                #
                # fetch structure ###################
                #
                # it's a struc (normal case)
                if xref_value in self.struc_ids:
                    struc_id = self.struc_ids[xref_value]
                    path_idx = 0
                    if xref_attributes is not None:
                        try:
                            struc_off_delta[operand] = self.yatools.try_read_hex_value(xref_attributes['delta'])
                        except KeyError:
                            pass
                        try:
                            path_idx = self.yatools.try_read_hex_value(xref_attributes['path_idx'])
                        except KeyError:
                            pass

                    try:
                        struc_path_off = struc_path[operand]
                    except KeyError:
                        struc_path_off = {}
                        struc_path[operand] = struc_path_off

                    struc_path_off[path_idx] = struc_id
                # This is a struc member : it happens when the "struc path" contains unions
                elif xref_value in self.strucmember_ids:
                    member_id = self.strucmember_ids[xref_value]
                    path_idx = 0
                    if xref_attributes is not None:
                        try:
                            struc_off_delta[operand] = self.yatools.try_read_hex_value(xref_attributes['delta'])
                        except KeyError:
                            pass
                        try:
                            path_idx = self.yatools.try_read_hex_value(xref_attributes['path_idx'])
                        except KeyError:
                            pass
                    try:
                        struc_path_off = struc_path[operand]
                    except KeyError:
                        struc_path_off = {}
                        struc_path[operand] = struc_path_off

                    struc_path_off[path_idx] = member_id
                # apply stackframe
                elif xref_value in self.stackframemembers_stackframes:
                    # create operand as stack variable
                    idaapi.op_stkvar(address + xref_offset, operand)

                #
                # apply enums     ###################
                #
                try:
                    enum_id = self.enum_ids[xref_value]
                    idaapi.op_enum(address + xref_offset, operand, enum_id, 0)
                except KeyError:
                    pass

                #
                # apply reference info ##################
                #
                ref_info_valid = False
                try:
                    (reference_info_base, reference_info_flags) = self.reference_infos[xref_value]
                    ref_info_valid = True
                except KeyError:
                    pass

                if ref_info_valid:
                    try:
                        ri = idaapi.refinfo_t()
                        ri.base = reference_info_base
                        ri.flags = reference_info_flags
                        ri.tdelta = 0
                        ri.target = idc.BADADDR
                        idaapi.op_offset_ex(address + xref_offset, operand, ri)
                    except OverflowError:
                        logger.error(
                            "OverflowError while committing address=0x%08X, "
                            "operand=%d, flags=0x%08X, target=0x%08X, value=0x%08X " %
                            (address + xref_offset, operand, reference_info_flags, idc.BADADDR, reference_info_base))
                        traceback.print_exc()

            #
            # now apply structures ##################
            #
            for (operand, struc_path_off) in struc_path.iteritems():
                path_len = len(struc_path_off)
                path = idaapi.tid_array(path_len)
                for i in xrange(0, path_len):
                    path[i] = struc_path_off[i]
                delta = 0
                try:
                    delta = struc_off_delta[operand]
                except KeyError:
                    pass
                if DEBUG_EXPORTER:
                    logger.debug("apply struc : 0x%016X:0x%02X, path_len=%d, delta=%d" %
                                 (address + xref_offset, operand, path_len, delta))
                idaapi.op_stroff(address + xref_offset, operand, path.cast(), path_len, delta)

        #
        # now call the architecture dependent plugin  #########
        #
        self.arch_plugin.make_basic_block_posthook(object_version, address)

    def sanitize_comment_to_ascii(self, comment):
        try:
            return comment.encode("ascii", "replace")
        except UnicodeDecodeError:
            return comment.decode("ascii", "replace").encode("ascii", "replace")
