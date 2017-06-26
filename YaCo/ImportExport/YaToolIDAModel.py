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
import logging


from ImportExport.YaToolObjectVersionElement import YaToolObjectVersionElement
from ImportExport import YaToolIDATools, YaToolPrototypeParser


if idc.__EA64__:
    import YaToolsPy64 as ya
else:
    import YaToolsPy32 as ya


_yatools_ida = ya.YaToolsIDANativeLib()

logger = logging.getLogger("YaCo")

DEBUG_IDA_MODEL_EXPORT = False

MAX_STRUCT_SIZE = 0x01000000

DEFAULT_OPERAND = 0
DEFAULT_NAME_FLAGS = 0

class YaToolIDAModel(YaToolObjectVersionElement):
    def __init__(self, yatools, hash_provider, EquipementDescription="None", OSDescription="None"):
        # self.ea = ea
        self.yatools = yatools
        self.hash_provider = hash_provider
        self.EquipementDescription = EquipementDescription
        self.OSDescription = OSDescription
        self.minXrefAddress = idc.NextSeg(0)
        self.maxXrefAddress = YaToolIDATools.LastSegEnd()
        self.minExportAddress = self.minXrefAddress
        self.maxExportAddress = self.maxXrefAddress
        self.exported_stackframe_addresses = {}
        self.exported_function_ids = {}
        self.exported_segment_ids = {}
        self.exported_segment_chunk_ids = {}
        self.prototype_parser = YaToolPrototypeParser.YaToolPrototypeParser()
        self.arch_plugin = self.yatools.get_arch_plugin().get_ida_model_plugin()
        if self.minXrefAddress == idc.BADADDR:
            self.minXrefAddress = idc.SegStart(0)
            self.maxXrefAddress = idc.SegEnd(0)
        self.native = ya.MakeModelIncremental(self.hash_provider)

    def accept_binary(self, visitor):
        self.native.accept_binary(visitor)

    def accept_deleted_struc(self, visitor, struc_id, struc_type=ya.OBJECT_TYPE_STRUCT):
        object_id = self.hash_provider.get_struc_enum_object_id(struc_id, "", True)
        visitor.visit_start_deleted_object(struc_type)
        visitor.visit_id(object_id)
        visitor.visit_end_deleted_object()

    def accept_enum(self, visitor, enum_id):
        self.native.accept_enum(visitor, enum_id)

    def accept_struc(self, visitor, parent_id, struc_id, struc_type=ya.OBJECT_TYPE_STRUCT,
                     struc_member_type=ya.OBJECT_TYPE_STRUCT_MEMBER, stackframe_func_addr=None):
        ea = stackframe_func_addr if stackframe_func_addr else idc.BADADDR
        self.native.accept_struct(visitor, parent_id, struc_id, ea)

    def accept_struc_member(self, visitor, parent_id, ida_struc, struc_id, is_union, offset, struc_name, name,
                            struc_type=ya.OBJECT_TYPE_STRUCT, struc_member_type=ya.OBJECT_TYPE_STRUCT_MEMBER,
                            default_name_offset=0, stackframe_func_addr=None):
        ida_member = idaapi.get_member(ida_struc, offset)
        if ida_member:
            ea = stackframe_func_addr if stackframe_func_addr else idc.BADADDR
            self.native.accept_struct_member(visitor, parent_id, ea, ida_member.id)

    def accept_deleted_strucmember(self, visitor, struc_id, struc_name, offset, struc_type=ya.OBJECT_TYPE_STRUCT,
                                   strucmember_type=ya.OBJECT_TYPE_STRUCT_MEMBER):
        if struc_type == ya.OBJECT_TYPE_STRUCT:
            member_object_id = self.hash_provider.get_struc_member_id(struc_id, offset, struc_name)
        else:
            member_object_id = self.hash_provider.get_stackframe_member_object_id(struc_id, offset, idc.BADADDR)
        visitor.visit_start_deleted_object(strucmember_type)
        visitor.visit_id(member_object_id)
        visitor.visit_end_deleted_object()

    def accept_ea_list(self, visitor, parent_id, ea_list):
        if len(ea_list) == 0:
            return
        ea_list = sorted(ea_list)
        self.minExportAddress = ea_list[0]
        self.maxExportAddress = ea_list[-1]
        for ea in ea_list:
            self.exported_function_ids.clear()
            self.exported_stackframe_addresses.clear()
            YaToolIDATools.clear_function_basic_block_cache()
            self.minExportAddress = ea
            # handle data/code/function at current_ea
            self.accept_ea(visitor, parent_id, ea, walk_basic_blocks=True, export_segment=False)

    def accept_ea(self, visitor, parent_id, ea, export_segment=True):
        self.native.accept_ea(visitor, parent_id, ea)

    def accept_function(self, visitor, parent_id, eaFunc, func, basic_blocks=None):
        self.native.accept_function(visitor, parent_id, eaFunc)

    def accept_attribute(self, visitor, attr_name, attr_value):
        visitor.visit_attribute(attr_name, attr_value)

    def accept_attributes(self, visitor, attributes):
        for (attr_name, attr_value) in attributes.iteritems():
            self.accept_attribute(visitor, attr_name, str(attr_value))

    def accept_segment(self, visitor, parent_id, seg_ea_start, seg_ea_end=None, export_chunks=False, chunk_eas=None,
                       export_eas=None):
        if seg_ea_start in self.exported_segment_ids:
            return

        if seg_ea_end is None:
            seg_ea_end = idc.SegEnd(seg_ea_start)
        name = idc.SegName(seg_ea_start)

        logger.debug("exporting segment 0x%08X -> 0x%08X : %s" % (seg_ea_start, seg_ea_end, name))

        segment_object_id = self.hash_provider.get_segment_id(name, seg_ea_start)
        self.exported_segment_ids[seg_ea_start] = segment_object_id

        seg_attributes = {}
        for (attr_name, attr_key) in YaToolIDATools.SEGATTR_MAP.iteritems():
            value = idc.GetSegmentAttr(seg_ea_start, attr_key)
            seg_attributes[attr_name] = value

        visitor.visit_start_reference_object(ya.OBJECT_TYPE_SEGMENT)
        # object version id
        visitor.visit_id(segment_object_id)

        visitor.visit_start_object_version()
        visitor.visit_parent_id(parent_id)
        visitor.visit_address(seg_ea_start)

        # size
        visitor.visit_size(seg_ea_end - seg_ea_start)

        visitor.visit_name(name, DEFAULT_NAME_FLAGS)

        visitor.visit_start_xrefs()
        segment_items = YaToolIDATools.segment_get_chunks(seg_ea_start, seg_ea_end)

        for (chunk_start, chunk_end) in segment_items:
            offset = chunk_start - seg_ea_start
            obj_id = self.hash_provider.get_segment_chunk_id(segment_object_id, chunk_start, chunk_end)
            visitor.visit_start_xref(offset, obj_id, DEFAULT_OPERAND)
            visitor.visit_end_xref()
        visitor.visit_end_xrefs()

        visitor.visit_start_matching_systems()
        visitor.visit_start_matching_system(seg_ea_start - idaapi.get_imagebase())
        visitor.visit_matching_system_description("equipement", self.EquipementDescription)
        visitor.visit_matching_system_description("os", self.OSDescription)
        visitor.visit_end_matching_system()
        visitor.visit_end_matching_systems()

        self.accept_attributes(visitor, seg_attributes)

        # TODO: add offsets for all elements inside segment

        visitor.visit_end_object_version()

        visitor.visit_end_reference_object()

        if export_chunks:
            for (chunk_start, chunk_end) in segment_items:
                self.accept_segment_chunk(visitor, chunk_start, chunk_end, segment_object_id, seg_ea_start, seg_ea_end,
                                          export_eas)

        if chunk_eas is not None:
            segment_items = YaToolIDATools.segment_get_chunks_for_eas(seg_ea_start, seg_ea_end, chunk_eas)
            for (chunk_start, chunk_end) in segment_items:
                self.accept_segment_chunk(visitor, chunk_start, chunk_end, segment_object_id, seg_ea_start, seg_ea_end,
                                          export_eas)

        self.accept_binary(visitor)

    def accept_segment_chunk(self, visitor, chunk_start, chunk_end, segment_oid=None, seg_start=None, seg_end=None,
                             export_eas=False):
        if chunk_start in self.exported_segment_chunk_ids:
            return

        if seg_start is None:
            seg_start = idc.SegStart(chunk_start)
        if seg_end is None:
            seg_end = idc.SegEnd(chunk_start)
        if segment_oid is None:
            segment_oid = self.hash_provider.get_segment_id(idc.SegName(seg_start), seg_start)

        segment_chunk_object_id = self.hash_provider.get_segment_chunk_id(segment_oid, chunk_start, chunk_end)

        self.exported_segment_chunk_ids[chunk_start] = segment_chunk_object_id

        logger.debug("exporting segment_chunk 0x%08X -> 0x%08X in segment 0x%08X -> 0x%08X : %s" %
                     (chunk_start, chunk_end, seg_start, seg_end, idc.SegName(seg_start)))

        visitor.visit_start_reference_object(ya.OBJECT_TYPE_SEGMENT_CHUNK)
        # object version id
        visitor.visit_id(segment_chunk_object_id)

        visitor.visit_start_object_version()
        if segment_oid:
            visitor.visit_parent_id(segment_oid)
        visitor.visit_address(chunk_start)

        # size
        visitor.visit_size(chunk_end - chunk_start)

        visitor.visit_start_xrefs()
        segment_items = YaToolIDATools.address_range_get_items(chunk_start, chunk_end)

        for ea in segment_items:
            offset = ea - chunk_start
            obj_id = self.hash_provider.get_hash_for_ea(ea)
            visitor.visit_start_xref(offset, obj_id, DEFAULT_OPERAND)
            visitor.visit_end_xref()
        visitor.visit_end_xrefs()

        visitor.visit_start_matching_systems()
        visitor.visit_start_matching_system(chunk_start - seg_start)
        visitor.visit_matching_system_description("equipement", self.EquipementDescription)
        visitor.visit_matching_system_description("os", self.OSDescription)
        visitor.visit_end_matching_system()
        visitor.visit_end_matching_systems()

        for (blob_addr, blob_content) in sorted(
                YaToolIDATools.address_range_get_blobs(chunk_start, chunk_end).iteritems()):
            while len(blob_content) > ya.MAX_BLOB_TAG_LEN:
                visitor.visit_blob(blob_addr - chunk_start, blob_content[:ya.MAX_BLOB_TAG_LEN])
                blob_content = blob_content[ya.MAX_BLOB_TAG_LEN:]
                blob_addr += ya.MAX_BLOB_TAG_LEN
            visitor.visit_blob(blob_addr - chunk_start, blob_content)

        visitor.visit_end_object_version()

        visitor.visit_end_reference_object()

        self.accept_segment(visitor, 0, seg_start, seg_end)

        if export_eas:
            self.accept_ea_list(visitor, segment_chunk_object_id, segment_items)

    def clear_segment_item_cache(self, ea):
        YaToolIDATools.address_range_items_clear_cache(idc.SegStart(ea), idc.SegEnd(ea))
