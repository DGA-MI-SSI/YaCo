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

        binary_object_id = self.hash_provider.get_binary_id()

        visitor.visit_start_reference_object(ya.OBJECT_TYPE_BINARY)
        # object version id
        visitor.visit_id(binary_object_id)

        visitor.visit_start_object_version()

        # size
        visitor.visit_size(YaToolIDATools.LastSegEnd() - idc.FirstSeg())
        visitor.visit_parent_id(0)

        image_base = idaapi.get_imagebase()
        visitor.visit_address(image_base)
        visitor.visit_name(idc.GetInputFile(), DEFAULT_NAME_FLAGS)

        visitor.visit_start_xrefs()

        seg_ea_start = idc.FirstSeg()

        while seg_ea_start != idc.BADADDR:
            seg_ea_end = idc.SegEnd(seg_ea_start)
            obj_id = self.hash_provider.get_segment_id(idc.SegName(seg_ea_start), seg_ea_start)
            visitor.visit_start_xref(seg_ea_start - image_base, obj_id, DEFAULT_OPERAND)
            visitor.visit_end_xref()

            seg_ea_start = idc.NextSeg(seg_ea_end - 1)
        visitor.visit_end_xrefs()

        visitor.visit_start_matching_systems()
        visitor.visit_start_matching_system(image_base)
        visitor.visit_matching_system_description("equipement", self.EquipementDescription)
        visitor.visit_matching_system_description("os", self.OSDescription)
        visitor.visit_end_matching_system()
        visitor.visit_end_matching_systems()

        # TODO: add offsets for all elements inside segment

        visitor.visit_end_object_version()

        visitor.visit_end_reference_object()

    def accept_enum(self, visitor, enum_id):
        self.native.accept_enum(visitor, enum_id)

    def is_exported(self, enum_id):
        return self.native.is_exported(enum_id) != ya.InvalidId

    def accept_deleted_struc(self, visitor, struc_id, struc_type=ya.OBJECT_TYPE_STRUCT):
        object_id = self.hash_provider.get_struc_enum_object_id(struc_id, "", True)
        visitor.visit_start_deleted_object(struc_type)
        visitor.visit_id(object_id)
        visitor.visit_end_deleted_object()

    def accept_struc(self, visitor, parent_id, struc_id, struc_type=ya.OBJECT_TYPE_STRUCT,
                     struc_member_type=ya.OBJECT_TYPE_STRUCT_MEMBER, stackframe_func_addr=None):
        if struc_type == ya.OBJECT_TYPE_STRUCT:
            if self.is_exported(struc_id):
                return
            elif DEBUG_IDA_MODEL_EXPORT:
                logger.debug(
                    "struc with id 0x%016X not exported : exporting (%s)" % (struc_id, idaapi.get_struc_name(struc_id)))
        else:
            # for a stackframe, ids might be reused, so we store the function addresses
            if stackframe_func_addr in self.exported_stackframe_addresses:
                return

        ida_struc = idaapi.get_struc(struc_id)
        if ida_struc is None:
            logger.error("unable to get struc from id 0x%08X : %s" % (struc_id, idc.GetStrucName(struc_id)))
            return
        struc_name = idc.GetStrucName(struc_id)

        if DEBUG_IDA_MODEL_EXPORT:
            logger.debug("accept_struc : 0x%08X : %s" % (struc_id, struc_name))

        visitor.visit_start_reference_object(struc_type)

        if struc_type == ya.OBJECT_TYPE_STACKFRAME:
            object_id = self.hash_provider.get_stackframe_object_id(struc_id, idc.BADADDR)
        else:
            object_id = self.hash_provider.get_struc_enum_object_id(struc_id, idc.GetStrucName(struc_id), True)

        if struc_type == ya.OBJECT_TYPE_STRUCT:
            self.native.export_id(struc_id, object_id)
        else:
            self.exported_stackframe_addresses[stackframe_func_addr] = object_id

        visitor.visit_id(object_id)

        visitor.visit_start_object_version()
        visitor.visit_parent_id(parent_id)
        if stackframe_func_addr:
            visitor.visit_address(stackframe_func_addr)

        size = idc.GetStrucSize(struc_id)
        if size > MAX_STRUCT_SIZE:
            if struc_type == ya.OBJECT_TYPE_STRUCT:
                Warning("Structure %s is too big : size = 0x%08X" % (struc_name, size))
                raise Exception("Structure %s is too big : size = 0x%08X" % (struc_name, size))
            else:
                func_ea = idaapi.get_func_by_frame(struc_id)
                Warning("[0x%08X:%s] Stackframe %s is too big : size = 0x%08X" %
                        (func_ea, idc.GetFunctionName(func_ea), struc_name, size))
                if idc.AskYN(1, "Do you want to ignore this object and continue export anyway ?") == 1:
                    visitor.visit_end_object_version()
                    visitor.visit_end_reference_object()
                    return
                else:
                    raise Exception("[0x%08X:%s] Stackframe %s is too big : size = 0x%08X" %
                                    (func_ea, idc.GetFunctionName(func_ea), struc_name, size))

        visitor.visit_size(size)

        visitor.visit_name(struc_name, DEFAULT_NAME_FLAGS)

        is_union = ida_struc.is_union()
        if is_union:
            visitor.visit_flags(1)

        #
        # HEADER COMMENT
        #
        RptComt = idc.GetStrucComment(struc_id, 1)
        if RptComt is not None and RptComt != "":
            visitor.visit_header_comment(True, RptComt)
        Cmt = idc.GetStrucComment(struc_id, 0)
        if Cmt is not None and Cmt != "":
            visitor.visit_header_comment(False, Cmt)

        #
        # XREFS TO MEMBERS
        #
        visitor.visit_start_xrefs()
        offset = idaapi.get_struc_first_offset(ida_struc)
        last_offset = idaapi.get_struc_last_offset(ida_struc)
        while offset != idc.BADADDR and (is_union or (offset <= last_offset)):
            ida_member = idaapi.get_member(ida_struc, offset)
            if ida_member:
                mid = ida_member.id
            else:
                mid = -1
            if struc_type != ya.OBJECT_TYPE_STACKFRAME or not idaapi.is_special_member(mid):
                name = idaapi.get_member_name(mid)
                if name is not None:
                    if struc_type == ya.OBJECT_TYPE_STACKFRAME:
                        struc_member_oid = self.hash_provider.get_stackframe_member_object_id(
                            struc_id, offset, idc.BADADDR)
                    else:
                        struc_member_oid = self.hash_provider.get_struc_member_id(struc_id, offset, struc_name)
                    if is_union:
                        use_offset = 0
                    else:
                        use_offset = offset
                    visitor.visit_start_xref(use_offset, struc_member_oid, DEFAULT_OPERAND)
                    visitor.visit_end_xref()

            # next member
            offset = idaapi.get_struc_next_offset(ida_struc, offset)
        visitor.visit_end_xrefs()

        #
        # MATCHING SYSTEMS
        #
        visitor.visit_start_matching_systems()
        visitor.visit_start_matching_system(0)
        visitor.visit_matching_system_description("equipement", self.EquipementDescription)
        visitor.visit_matching_system_description("os", self.OSDescription)
        visitor.visit_end_matching_system()
        visitor.visit_end_matching_systems()

        default_name_offset = 0
        if struc_type == ya.OBJECT_TYPE_STACKFRAME:
            func = idaapi.get_func_by_frame(struc_id)
            lvars_size = idc.GetFrameLvarSize(func)
            regvars_size = idc.GetFrameRegsSize(func)
            args_size = idc.GetFrameArgsSize(func)
            visitor.visit_attribute("stack_lvars", self.yatools.address_to_hex_string(lvars_size))
            visitor.visit_attribute("stack_regvars", self.yatools.address_to_hex_string(regvars_size))
            visitor.visit_attribute("stack_args", self.yatools.address_to_hex_string(args_size))

            default_name_offset = lvars_size

        visitor.visit_end_object_version()

        visitor.visit_end_reference_object()

        self.accept_struc_members(visitor, object_id, ida_struc, struc_id, struc_name, is_union, struc_type,
                                  struc_member_type, default_name_offset, stackframe_func_addr=stackframe_func_addr)

    def accept_struc_members(self, visitor, parent_id, ida_struc, struc_id, struc_name, is_union,
                             struc_type=ya.OBJECT_TYPE_STRUCT, struc_member_type=ya.OBJECT_TYPE_STRUCT_MEMBER,
                             default_name_offset=0, stackframe_func_addr=None):
        for (offset, name) in YaToolIDATools.struc_member_list(struc_id, is_union):
            self.accept_struc_member(visitor, parent_id, ida_struc, struc_id, is_union, offset, struc_name, name,
                                     struc_type, struc_member_type, default_name_offset,
                                     stackframe_func_addr=stackframe_func_addr)

    def accept_struc_member(self, visitor, parent_id, ida_struc, struc_id, is_union, offset, struc_name, name,
                            struc_type=ya.OBJECT_TYPE_STRUCT, struc_member_type=ya.OBJECT_TYPE_STRUCT_MEMBER,
                            default_name_offset=0, stackframe_func_addr=None):
        ida_member = idaapi.get_member(ida_struc, offset)
        if ida_member is None:
            logger.warning("Member is none : %s:0x%08X" % (struc_name, offset))
            return
        mid = ida_member.id

        if self.is_exported(mid):
            return

        if struc_type == ya.OBJECT_TYPE_STACKFRAME and idaapi.is_special_member(mid):
            return

        if struc_type == ya.OBJECT_TYPE_STACKFRAME:
            member_object_id = self.hash_provider.get_stackframe_member_object_id(struc_id, offset, idc.BADADDR)
        else:
            member_object_id = self.hash_provider.get_struc_member_id(struc_id, offset, struc_name)

        self.native.export_id(mid, member_object_id)

        flags = ida_member.flag
        member_size = idaapi.get_member_size(ida_member)
        RptComt = idaapi.get_member_cmt(mid, 1)
        Cmt = idaapi.get_member_cmt(mid, 0)

        default_name = YaToolIDATools.get_default_struc_member_name(struc_member_type, offset, default_name_offset)
        type_dependencies = None

        if is_union:
            YaToolIDATools.register_union_member_object_id(struc_id, mid, member_object_id)

        # is the field is a "default field", don't export it
        if (is_union is False and flags == idc.FF_DATA and member_size == 1 and name == default_name and
                (RptComt is None or RptComt == "") and (Cmt is None or Cmt == "")):
            # this is a default field : delete it
            #             logger.debug("Accepting default strucmember : %s.%s" % (idc.GetStrucName(struc_id), name))
            self.accept_default_strucmember(visitor, struc_id, struc_name, offset, struc_type, struc_member_type)
        else:
            # this is not a default field
            # TODO: type
            member_type = ya.get_type(mid)

            visitor.visit_start_reference_object(struc_member_type)

            visitor.visit_id(member_object_id)

            visitor.visit_start_object_version()

            visitor.visit_parent_id(parent_id)

            visitor.visit_address(offset)

            visitor.visit_size(member_size)

            visitor.visit_name(name, DEFAULT_NAME_FLAGS)

            if len(member_type):
                (member_type, type_dependencies) = self.prototype_parser.update_prototype_with_hashes(
                    member_type, self.hash_provider, name)
                visitor.visit_prototype(member_type)

            visitor.visit_flags(flags)

            if idc.isASCII(flags):
                op = idaapi.opinfo_t()
                idaapi.retrieve_member_info(ida_member, op)
                strtype = op.tid
                if strtype is not None and strtype != -1 and strtype != 0 and strtype != idc.BADADDR:
                    visitor.visit_string_type(strtype)

            if idc.isStruct(flags) or idc.isEnum0(flags):
                xref_dict = None
                if idc.isStruct(flags):
                    cs = idaapi.get_sptr(ida_member)
                    if cs:
                        member_sid = cs.id
                    else:
                        member_sid = -1
                    logger.debug("Getting object id for member : 0x%08X [%s]" % (member_sid, name))
                    object_id = self.hash_provider.get_struc_enum_object_id(member_sid, idc.GetStrucName(member_sid), True)
                else:  # enum
                    op = idaapi.opinfo_t()
                    idaapi.retrieve_member_info(ida_member, op)
                    member_sid = op.ec.tid
                    serial = op.ec.serial
                    if serial != 0:
                        xref_dict = {'serial': self.yatools.address_to_hex_string(serial)}
                        logger.debug("Getting object id for member : 0x%08X" % member_sid)
                    object_id = self.hash_provider.get_struc_enum_object_id(member_sid, idc.GetEnumName(member_sid), True)

                visitor.visit_start_xrefs()
                visitor.visit_start_xref(0, object_id, 0)
                if xref_dict is not None:
                    for (attribute_key, attribute_value) in xref_dict.values():
                        visitor.visit_xref_attribute(attribute_key, attribute_value)
                visitor.visit_end_xref()
                visitor.visit_end_xrefs()

            #
            # HEADER COMMENT
            #
            if RptComt is not None and RptComt != "":
                visitor.visit_header_comment(True, RptComt)
            if Cmt is not None and Cmt != "":
                visitor.visit_header_comment(False, Cmt)

            #
            # MATCHING SYSTEMS
            #
            # matchingsystems
            visitor.visit_start_matching_systems()
            visitor.visit_start_matching_system(offset)
            visitor.visit_matching_system_description("equipement", self.EquipementDescription)
            visitor.visit_matching_system_description("os", self.OSDescription)
            visitor.visit_end_matching_system()
            visitor.visit_end_matching_systems()

            visitor.visit_end_object_version()

            visitor.visit_end_reference_object()

            if idc.isStruct(flags):
                self.accept_struc(visitor, member_object_id, member_sid)
            elif idc.isEnum0(flags):
                self.accept_enum(visitor, member_sid)

        self.accept_struc(visitor, parent_id, struc_id, struc_type, struc_member_type,
                          stackframe_func_addr=stackframe_func_addr)

        if type_dependencies is not None:
            for (dep_object_id, dep_id) in type_dependencies:
                # TODO : check if it is actually a struc!
                self.accept_struc(visitor, parent_id, dep_id, ya.OBJECT_TYPE_STRUCT, ya.OBJECT_TYPE_STRUCT_MEMBER)

    def accept_default_strucmember(self, visitor, struc_id, struc_name, offset, struc_type=ya.OBJECT_TYPE_STRUCT,
                                   strucmember_type=ya.OBJECT_TYPE_STRUCT_MEMBER):
        if struc_type == ya.OBJECT_TYPE_STRUCT:
            member_object_id = self.hash_provider.get_struc_member_id(struc_id, offset, struc_name)
        else:
            member_object_id = self.hash_provider.get_stackframe_member_object_id(struc_id, offset, idc.BADADDR)
        visitor.visit_start_default_object(strucmember_type)
        visitor.visit_id(member_object_id)
        visitor.visit_end_default_object()

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

    def accept_ea(self, visitor, parent_id, ea, walk_basic_blocks=False, export_segment=True):

        previous_item = idc.PrevHead(ea)
        if previous_item != idc.BADADDR:
            previous_item_size = idc.ItemSize(previous_item)
            if previous_item_size > 0 and ea < previous_item + previous_item_size:
                ea = previous_item
        if DEBUG_IDA_MODEL_EXPORT:
            logger.debug("accept_ea : %s" % self.yatools.address_to_hex_string(ea))

        # get flag
        fl = idc.GetFlags(ea)
        # if ea is func
        func = idaapi.get_func(ea)
        if idaapi.isFunc(fl) or (func is not None and idc.isCode(fl)):
            eaFunc = func.startEA
            if walk_basic_blocks:

                basic_blocks = YaToolIDATools.get_function_basic_blocks(ea, func)
                func_object_id = self.hash_provider.get_hash_for_ea(eaFunc)
                for basic_block in basic_blocks:
                    self.accept_basic_block(visitor, func_object_id, basic_block, eaFunc, func, func_object_id)
            else:
                basic_block = YaToolIDATools.get_basic_block_at_ea(ea, eaFunc, func)
                if basic_block is None:
                    logger.error("Function has no basic blocks : %s (eaFunc=%s) " %
                                 (self.yatools.address_to_hex_string(ea), self.yatools.address_to_hex_string(eaFunc)))
                else:
                    func_object_id = self.hash_provider.get_hash_for_ea(eaFunc)
                    self.accept_basic_block(visitor, func_object_id, basic_block, eaFunc, func, func_object_id)

        # if ea is not in a function and it is code
        elif (func is None) and (idaapi.isCode(fl)):
            self.accept_code(visitor, parent_id, ea)
        else:
            self.accept_data(visitor, parent_id, ea)

        if export_segment:
            seg_ea_start = idc.SegStart(ea)
            seg_ea_end = idc.SegEnd(ea)
            if seg_ea_start == idc.BADADDR:
                logger.error("Exported EA [%s] does not belong to a segment : error 1" %
                             self.yatools.address_to_hex_string(ea))
                return
            if seg_ea_end == idc.BADADDR:
                logger.error("Exported EA [%s] does not belong to a segment : error 2" %
                             self.yatools.address_to_hex_string(ea))
                return
            (chunk_start, chunk_end) = YaToolIDATools.get_segment_chunk_for_ea(seg_ea_start, ea)
            self.accept_segment_chunk(visitor, chunk_start, chunk_end, seg_start=seg_ea_start, seg_end=seg_ea_end)

    def accept_code(self, visitor, parent_id, eaCode):
        eaCode = _yatools_ida.get_code_chunk_start_addr(eaCode, idc.SegStart(eaCode))
        if self.is_exported(eaCode):
            return
        eaCodeEnd = _yatools_ida.get_code_chunk_end_addr(eaCode, idc.SegEnd(eaCode))
        
        if DEBUG_IDA_MODEL_EXPORT:
            logger.debug("accept_code : %s" % self.yatools.address_to_hex_string(eaCode))

        visitor.visit_start_reference_object(ya.OBJECT_TYPE_CODE)

        code_id = self.hash_provider.get_hash_for_ea(eaCode)
        # object version id
        visitor.visit_id(code_id)
        self.native.export_id(eaCode, code_id)

        visitor.visit_start_object_version()

        visitor.visit_parent_id(parent_id)
        visitor.visit_address(eaCode)

        visitor.visit_size(eaCodeEnd-eaCode)

        # code label
        name = idc.Name(eaCode)
        if YaToolIDATools.is_userdefined_name(name, eaCode):
            name_flags = YaToolIDATools.GetNameFlags(name, eaCode)
            visitor.visit_name(name, name_flags)
        
        (references, xrefed_struc_ids, xrefed_enum_ids) = self.accept_code_area(visitor, eaCode, eaCodeEnd)

        #
        # MATCHING SYSTEMS
        #
        visitor.visit_start_matching_systems()
        (chunk_start, chunk_end) = YaToolIDATools.get_segment_chunk_for_ea(idc.SegStart(eaCode), eaCode)
        visitor.visit_start_matching_system(eaCode - chunk_start)
        visitor.visit_matching_system_description("equipement", self.EquipementDescription)
        visitor.visit_matching_system_description("os", self.OSDescription)
        visitor.visit_end_matching_system()
        visitor.visit_end_matching_systems()

        visitor.visit_end_object_version()

        visitor.visit_end_reference_object()
        
        # proceed reference values
        for (reference_offset, references_t) in references.iteritems():
            for (operand, reference_dict, reference_value) in references_t:
                self.accept_reference_info(
                    visitor, eaCode, (reference_offset, reference_value, reference_dict['flags']))

        for struc_id in xrefed_struc_ids:
            self.accept_struc(visitor, basic_block_id, struc_id)

        for enum_id in xrefed_enum_ids:
            self.accept_enum(visitor, enum_id)


    def accept_function(self, visitor, parent_id, eaFunc, func, basic_blocks=None):

        if eaFunc in self.exported_function_ids or eaFunc < self.minExportAddress or eaFunc > self.maxExportAddress:
            return

        if DEBUG_IDA_MODEL_EXPORT:
            logger.debug("accept_function : %s" % self.yatools.address_to_hex_string(eaFunc))

        funcId = self.hash_provider.get_hash_for_ea(eaFunc)
        self.exported_function_ids[eaFunc] = funcId

        Comm = idaapi.get_func_cmt(func, 0)
        CommRep = idaapi.get_func_cmt(func, 1)
        if basic_blocks is None:
            basic_blocks = YaToolIDATools.get_function_basic_blocks(eaFunc, func)
        stack_frame = idaapi.get_frame(eaFunc)

        ea_seg = idc.SegStart(eaFunc)

        FunctionSize = 0
        for block in basic_blocks:
            FunctionSize += block['endEA'] - block['startEA']

        # create function sig
        (FirstBytesHash, OpcodesHash) = YaToolIDATools.createSig(basic_blocks)

        #
        # INFOS
        #
        visitor.visit_start_reference_object(ya.OBJECT_TYPE_FUNCTION)

        # id
        visitor.visit_id(funcId)

        visitor.visit_start_object_version()
        visitor.visit_parent_id(parent_id)
        visitor.visit_address(eaFunc)

        # size
        visitor.visit_size(FunctionSize)

        #
        # PROTO
        #
        item_type = ya.get_type(eaFunc)
        type_dependencies = None
        if len(item_type):
            (item_type, type_dependencies) = self.prototype_parser.update_prototype_with_hashes(
                item_type, self.hash_provider, "sub")
            visitor.visit_prototype(item_type)

        flags = idc.GetFunctionFlags(eaFunc)
        visitor.visit_flags(flags)

        #
        # HASHES
        #
        # opcode and operands type signature
        visitor.visit_start_signatures()
        # signature = bytearray(struct.pack("<I", OpcodesHash))
        signature = "%08X" % OpcodesHash
        visitor.visit_signature(ya.SIGNATURE_FIRSTBYTE, ya.SIGNATURE_ALGORITHM_CRC32, signature)
        visitor.visit_end_signatures()

        #
        # HEADER COMMENT
        #
        if Comm is not None and Comm != "":
            # headercomments
            visitor.visit_header_comment(False, Comm)
        if CommRep is not None and CommRep != "":
            # headercomments
            visitor.visit_header_comment(True, CommRep)

        #
        # -- OFFSETS --
        #
        visitor.visit_start_xrefs()

        if stack_frame is not None:
            stackframe_object_id = self.hash_provider.get_stackframe_object_id(stack_frame.id, eaFunc)
            visitor.visit_start_xref(idc.BADADDR, stackframe_object_id, DEFAULT_OPERAND)
            visitor.visit_end_xref()

        # Basic blocks
        for basic_block in basic_blocks:
            basic_block_start_ea = basic_block['startEA']
            bb_oid = self.hash_provider.get_function_basic_block_hash(basic_block['startEA'], basic_block['funcEA'])
            visitor.visit_start_xref((basic_block_start_ea - eaFunc), bb_oid, DEFAULT_OPERAND)
            visitor.visit_xref_attribute(
                "size", self.yatools.address_to_hex_string(basic_block['endEA'] - basic_block['startEA']))
            visitor.visit_end_xref()

        visitor.visit_end_xrefs()

        #
        # MATCHING SYSTEMS
        #
        # matchingsystems
        visitor.visit_start_matching_systems()
        (chunk_start, chunk_end) = YaToolIDATools.get_segment_chunk_for_ea(ea_seg, eaFunc)
        visitor.visit_start_matching_system(eaFunc - chunk_start)
        visitor.visit_matching_system_description("equipement", self.EquipementDescription)
        visitor.visit_matching_system_description("os", self.OSDescription)
        visitor.visit_end_matching_system()
        visitor.visit_end_matching_systems()

        #
        # Call the architecture plugin
        #
        self.arch_plugin.accept_function_hook(visitor, eaFunc, func, basic_blocks)

        #
        # END
        #
        visitor.visit_end_object_version()

        visitor.visit_end_reference_object()

        if stack_frame is not None:
            #             logger.debug("exporting stackframe for function at 0x%08X" % eaFunc)
            self.accept_struc(visitor, funcId, stack_frame.id, ya.OBJECT_TYPE_STACKFRAME,
                              ya.OBJECT_TYPE_STACKFRAME_MEMBER, stackframe_func_addr=eaFunc)

        if type_dependencies is not None:
            for (dep_object_id, dep_id) in type_dependencies:
                # TODO : check if it is actually a struc!
                self.accept_struc(visitor, funcId, dep_id, ya.OBJECT_TYPE_STRUCT, ya.OBJECT_TYPE_STRUCT_MEMBER)

        eas = [eaFunc]
        for basic_block in basic_blocks:
            eas.append(basic_block['startEA'])

        self.accept_segment(visitor, 0, ea_seg, chunk_eas=eas)

    def accept_basic_block(self, visitor, parent_id, basic_block, funcEA, func, parent_function_id):

        startEA = basic_block['startEA']
        endEA = basic_block['endEA']

        if startEA == endEA or self.is_exported(startEA):
            return

        if DEBUG_IDA_MODEL_EXPORT:
            logger.debug("accept_basic_block : %s", self.yatools.address_to_hex_string(startEA))

        basic_block_id = self.hash_provider.get_function_basic_block_hash(startEA, funcEA)
        self.native.export_id(startEA, basic_block_id)

        block_type = basic_block['block_type']

        # create function sig
        (_FirstBytesHash, OpcodesHash) = YaToolIDATools.create_basic_block_sig(basic_block)

        #
        # INFOS
        #
        visitor.visit_start_reference_object(ya.OBJECT_TYPE_BASIC_BLOCK)

        # id
        visitor.visit_id(basic_block_id)

        visitor.visit_start_object_version()

        visitor.visit_parent_id(parent_id)

        visitor.visit_address(startEA)

        # size
        visitor.visit_size(endEA - startEA)

        # function name
        name = idc.GetTrueNameEx(funcEA, startEA)
        if YaToolIDATools.is_userdefined_name(name, startEA):
            name_flags = YaToolIDATools.GetNameFlags(name, startEA)
            visitor.visit_name(name, name_flags)

        # for basic blocks, give the type (see fc_block_type_t enum, gdl.hpp)
        visitor.visit_flags(block_type)

        #
        # HASHES
        #
        # opcode and operands type signature
        visitor.visit_start_signatures()
        # signature = bytearray(struct.pack("<I", OpcodesHash))
        signature = "%08X" % OpcodesHash
        visitor.visit_signature(ya.SIGNATURE_FIRSTBYTE, ya.SIGNATURE_ALGORITHM_CRC32, signature)
        visitor.visit_end_signatures()
        
        (references, xrefed_struc_ids, xrefed_enum_ids) = self.accept_code_area(visitor, startEA, endEA, func)

        #
        # MATCHING SYSTEMS
        #
        visitor.visit_start_matching_systems()
        visitor.visit_start_matching_system(startEA - funcEA)
        visitor.visit_matching_system_description("equipement", self.EquipementDescription)
        visitor.visit_matching_system_description("os", self.OSDescription)
        visitor.visit_end_matching_system()
        visitor.visit_end_matching_systems()

        #
        # Call the architecture plugin
        #
        self.arch_plugin.accept_basic_block_hook(visitor, basic_block, funcEA, func, parent_function_id)

        #
        # END
        #
        visitor.visit_end_object_version()

        visitor.visit_end_reference_object()

        # proceed reference values
        for (reference_offset, references_t) in references.iteritems():
            for (operand, reference_dict, reference_value) in references_t:
                self.accept_reference_info(
                    visitor, startEA, (reference_offset, reference_value, reference_dict['flags']))

        for struc_id in xrefed_struc_ids:
            self.accept_struc(visitor, basic_block_id, struc_id)

        for enum_id in xrefed_enum_ids:
            self.accept_enum(visitor, enum_id)

        self.accept_function(visitor, parent_function_id, funcEA, func)
    
    def accept_code_area(self, visitor, startEA, endEA, func=None):
        # get Xrefs
        xrefsto = YaToolIDATools.createBasicBlockXRefsTo(
            startEA,
            endEA,
            self.minXrefAddress,
            self.maxXrefAddress,
            func
        )
        (
            functionXrefs,
            dataXrefs,
            comments,
            strucs,
            enums,
            operand_view,
            hidden_areas,
            stackframes,
            references
        ) = xrefsto
        xrefed_enum_ids = set()
        xrefed_struc_ids = set()


        if func is not None:
            registers_view = YaToolIDATools.getRegistersView(startEA, endEA, func)
        #
        # HEADER COMMENT
        #
        # Not necessary for basic blocks : they are already in the offsets

        #
        # -- OFFSETS --
        #
        visitor.visit_start_offsets()
        #
        # COMMENTS
        #
        TYPE_COMMENT = 0
        TYPE_VALUE_VIEW = 1
        TYPE_REGISTER_VIEW = 2
        TYPE_HIDDEN_AREA = 3
        offset_elements = {}
        for (offset, comments_set) in comments.iteritems():
            try:
                this_offset = offset_elements[offset]
            except KeyError:
                this_offset = []
                offset_elements[offset] = this_offset

            for (comment_type, comment) in comments_set:
                this_offset.append((TYPE_COMMENT, (comment_type, comment)))
                # visitor.visit_offset_comments(offset, comment_type, comment)
        #
        # OPERAND VIEW
        #
        for (offset, view_set) in operand_view.iteritems():
            try:
                this_offset = offset_elements[offset]
            except KeyError:
                this_offset = []
                offset_elements[offset] = this_offset

            for (view_operand, view_value) in view_set:
                this_offset.append((TYPE_VALUE_VIEW, (view_operand, view_value)))
                # visitor.visit_offset_valueview(view_offset, view_operand, view_value)

        #
        # REGISTERS VIEW
        #
        if func is not None:
            for (offset, registers_set) in registers_view.iteritems():
                try:
                    this_offset = offset_elements[offset]
                except KeyError:
                    this_offset = []
                    offset_elements[offset] = this_offset
    
                for (register_name, end_offset, register_value) in registers_set:
                    this_offset.append((TYPE_REGISTER_VIEW, (end_offset, register_name, register_value)))
                    # visitor.visit_offset_registerview(register_offset, end_offset, register_name, register_value)

        #
        # HIDDEN AREA
        #
        for (offset, hidden_area_set) in hidden_areas.iteritems():
            try:
                this_offset = offset_elements[offset]
            except KeyError:
                this_offset = []
                offset_elements[offset] = this_offset

            for (hidden_areas_size, hidden_areas_value) in hidden_area_set:
                this_offset.append((TYPE_HIDDEN_AREA, (hidden_areas_size, hidden_areas_value)))
                # visitor.visit_offset_hiddenarea(hidden_area_offset, hidden_areas_size, hidden_areas_value)

        for offset in sorted(offset_elements.keys()):
            offset_list = offset_elements[offset]
            for (offset_type, offset_value) in offset_list:
                if offset_type == TYPE_COMMENT:
                    (comment_type, comment) = offset_value
                    visitor.visit_offset_comments(offset, comment_type, comment)
                elif offset_type == TYPE_VALUE_VIEW:
                    (view_operand, view_value) = offset_value
                    visitor.visit_offset_valueview(offset, view_operand, view_value)
                elif offset_type == TYPE_REGISTER_VIEW:
                    (end_offset, register_name, register_value) = offset_value
                    visitor.visit_offset_registerview(offset, end_offset, register_name, register_value)
                elif offset_type == TYPE_HIDDEN_AREA:
                    (hidden_areas_size, hidden_areas_value) = offset_value
                    visitor.visit_offset_hiddenarea(offset, hidden_areas_size, hidden_areas_value)

        visitor.visit_end_offsets()

        visitor.visit_start_xrefs()

        #
        # XREFS
        #
        # we have to order all xrefs, so we create a temp dict to add all xrefs of all types and visit them later
        ordered_xrefs = {}
        for (functionOffset, functionXref) in functionXrefs.iteritems():
            xref_value = self.hash_provider.get_hash_for_ea(functionXref)
            try:
                ll = ordered_xrefs[functionOffset]
            except KeyError:
                ll = list()
                ordered_xrefs[functionOffset] = ll
            ll.append((xref_value, DEFAULT_OPERAND, None))
            # visitor.visit_start_xref(functionOffset, xref_value, DEFAULT_OPERAND)
            # visitor.visit_end_xref()

        for (dataOffset, dataXref) in dataXrefs.iteritems():
            xref_value = self.hash_provider.get_hash_for_ea(dataXref)
            try:
                ll = ordered_xrefs[dataOffset]
            except KeyError:
                ll = list()
                ordered_xrefs[dataOffset] = ll
            ll.append((xref_value, DEFAULT_OPERAND, None))
            # visitor.visit_start_xref(dataOffset, xref_value, DEFAULT_OPERAND)
            # visitor.visit_end_xref()

        #
        # BB XREFS
        #
        # we have to get the xref to the next basic blocks in the Control flow graph
        # get offset of the the jmp or jz instruction ea and get ea of the first cross ref
        if func is not None:
            funcEA = func.startEA
            bbOffset = idc.PrevNotTail(endEA)
            child_ea = idc.Rfirst(bbOffset)
    
            while child_ea != idc.BADADDR:
                # id of the cross ref BB
                child_id = self.hash_provider.get_function_basic_block_hash(child_ea, funcEA)
                try:
                    ll = ordered_xrefs[child_ea]
                except KeyError:
                    ll = list()
                    ordered_xrefs[child_ea] = ll
                ll.append((child_id, DEFAULT_OPERAND, None))  # append to the xRef list
                child_ea = idc.Rnext(bbOffset, child_ea)

        #
        # STRUCTURES
        #
        for (struc_offset, strucs_t) in strucs.iteritems():
            for (operand, struc_dict, path_id) in strucs_t:
                obj_id = None
                path_idx = 0
                if struc_dict is not None:
                    try:
                        path_idx = struc_dict['path_idx']
                        # we know that path_idx > 0 (otherwise the key is not present
                        # this is a member id : we must find its struc_id
                        obj_id = YaToolIDATools.get_object_id_of_union_member_id(self.hash_provider, path_id)
                    except KeyError:
                        pass

                if obj_id is None:
                    if path_idx != 0:
                        # ida bug : we referenced the field itself, not a subfield
                        # We should have shorter path len
                        continue
                    else:
                        struc_name = idc.GetStrucName(path_id)
                        obj_id = self.hash_provider.get_struc_enum_object_id(path_id, struc_name, True)
                        if obj_id is None:
                            logger.error("No object id for struc 0x%08X (name=%s)",
                                         path_id, idaapi.get_struc_name(path_id))

                if path_idx == 0:
                    sid = path_id
                else:
                    sid = YaToolIDATools.get_struc_id_from_member_if(path_id)

                if idaapi.get_struc(sid) is not None:
                    xrefed_struc_ids.add(sid)
                    # visitor.visit_start_xref(struc_offset, obj_id, operand)
                    try:
                        ll = ordered_xrefs[struc_offset]
                    except KeyError:
                        ll = list()
                        ordered_xrefs[struc_offset] = ll
                    ll.append((obj_id, operand, struc_dict))
                    # visitor.visit_end_xref()

        #
        # ENUMS
        #
        for (enum_offset, enums_t) in enums.iteritems():
            for (operand, enum_id, enum_name) in enums_t:
                xrefed_enum_ids.add(enum_id)
                enum_value = self.hash_provider.get_struc_enum_object_id(enum_id, enum_name, True)
                try:
                    ll = ordered_xrefs[enum_offset]
                except KeyError:
                    ll = list()
                    ordered_xrefs[enum_offset] = ll
                ll.append((enum_value, operand, None))
                # visitor.visit_start_xref(enum_offset, enum_value, operand)
                # visitor.visit_end_xref()

        #
        # STACK FRAME
        #
        if func is not None:
            stackframe = idaapi.get_frame(func)
            # lvar_size = idc._IDC_GetAttr(func, idc._FUNCATTRMAP, idc.FUNCATTR_FRSIZE)
            for (stackframe_offset, stackframe_members) in stackframes.iteritems():
                for (operand, ida_member, _sp_delta) in stackframe_members:
                    stackframe_member_value = self.hash_provider.get_stackframe_member_object_id(
                        stackframe.id, ida_member.soff, funcEA)
                    try:
                        ll = ordered_xrefs[stackframe_offset]
                    except KeyError:
                        ll = list()
                        ordered_xrefs[stackframe_offset] = ll
                    ll.append((stackframe_member_value, operand, None))
                    # visitor.visit_start_xref(stackframe_offset, stackframe_member_value, operand)
                    # visitor.visit_end_xref()

        #
        # REFERENCE
        #
        for (reference_offset, references_t) in references.iteritems():
            for (operand, reference_dict, reference_value) in references_t:
                reference_value_hash = self.hash_provider.get_reference_info_hash(
                    startEA + reference_offset, reference_value)
                try:
                    ll = ordered_xrefs[reference_offset]
                except KeyError:
                    ll = list()
                    ordered_xrefs[reference_offset] = ll
                ll.append((reference_value_hash, operand, None))
                # visitor.visit_start_xref(reference_offset, reference_value, operand)
                # visitor.visit_end_xref()

        # we have parsed all xrefs, pass them to visitor in one shot
        for (offset, xref_list) in sorted(ordered_xrefs.iteritems()):

            # TODO : sort xref_list by object id
            for (value, operand, attributes) in xref_list:
                visitor.visit_start_xref(offset, value, operand)
                if attributes is not None:
                    for attribute_key, attribute_value in attributes.iteritems():
                        visitor.visit_xref_attribute(attribute_key, attribute_value)
                visitor.visit_end_xref()

        visitor.visit_end_xrefs()
        
        return (references, xrefed_struc_ids, xrefed_enum_ids)
        
    def accept_reference_info(self, visitor, parent_ea, reference_info):
        (reference_offset, reference_value, reference_flags) = reference_info

        visitor.visit_start_reference_object(ya.OBJECT_TYPE_REFERENCE_INFO)

        # id
        # hash the full ea and value
        visitor.visit_id(self.hash_provider.get_reference_info_hash(parent_ea + reference_offset, reference_value))

        visitor.visit_start_object_version()

        # size
        visitor.visit_size(0)

        # flags
        visitor.visit_flags(reference_flags)

        #
        # MATCHING SYSTEMS
        #
        visitor.visit_start_matching_systems()
        visitor.visit_start_matching_system(reference_value)
        visitor.visit_matching_system_description("equipement", self.EquipementDescription)
        visitor.visit_matching_system_description("os", self.OSDescription)
        visitor.visit_end_matching_system()
        visitor.visit_end_matching_systems()

        #
        # END
        #
        visitor.visit_end_object_version()

        visitor.visit_end_reference_object()

    def accept_data(self, visitor, parent_id, ea):
        if DEBUG_IDA_MODEL_EXPORT:
            logger.debug("accept_data : %s" % self.yatools.address_to_hex_string(ea))

        flags = idc.GetFlags(ea)

        size = idc.ItemSize(ea)
        """
        if(isData(flags) == False):
            # some unknown bytes still have a name : export them
            if(isUnknown(flags) and hasName(flags) is False and size==1):
                if(size == 0):
                    return 1
                else:
                    return size
        """
        object_id = self.hash_provider.get_hash_for_ea(ea)
        if self.is_exported(ea):
            if size == 0:
                return 1
            else:
                return size

        self.native.export_id(ea, object_id)

        visitor.visit_start_reference_object(ya.OBJECT_TYPE_DATA)

        # reference object id
        visitor.visit_id(object_id)

        visitor.visit_start_object_version()

        visitor.visit_parent_id(parent_id)
        visitor.visit_address(ea)

        # size
        visitor.visit_size(size)

        # data name
        name = idc.Name(ea)
        if name is not None and name != "":
            name_flags = YaToolIDATools.GetNameFlags(name, ea)
            visitor.visit_name(name, name_flags)

        item_type = ya.get_type(ea)
        if len(item_type):
            item_type = self.prototype_parser.update_data_prototype_with_hashes(item_type, self.hash_provider)
            visitor.visit_prototype(item_type)

        # flags
        visitor.visit_flags(flags)

        # idc.isASCII ==> is this a String (ASCII, unicode, anything...)
        #             The function name is confusing!!
        if idc.isASCII(flags):
            strtype = idc.GetStringType(ea)
            if strtype != -1 and strtype != 0 and strtype is not None:
                visitor.visit_string_type(strtype)

            #
            # HASHES
            #
            string_at_ea = idc.GetString(ea)
            if string_at_ea is not None:
                # opcode and operands type signature
                visitor.visit_start_signatures()
                string_hash = YaToolIDATools.createStringSig(idc.GetString(ea))

                signature = "%08X" % string_hash
                visitor.visit_signature(ya.SIGNATURE_FIRSTBYTE, ya.SIGNATURE_ALGORITHM_CRC32, signature)
                visitor.visit_end_signatures()

        #
        # -- OFFSETS --
        #
        visitor.visit_start_offsets()
        #
        # COMMENTS
        #
        for (comment_type, comment) in YaToolIDATools.get_comments_at_ea(ea):
            visitor.visit_offset_comments(0, comment_type, comment)

        visitor.visit_end_offsets()

        if idc.isStruct(flags):  # OR HAS_XREFS
            visitor.visit_start_xrefs()

        if idc.isStruct(flags):
            op = idaapi.opinfo_t()
            idaapi.get_opinfo(ea, 0, flags, op)
            strid = op.tid
            str_name = idc.GetStrucName(strid)
            str_object_id = self.hash_provider.get_struc_enum_object_id(strid, str_name, True)
            visitor.visit_start_xref(0, str_object_id, DEFAULT_OPERAND)
            visitor.visit_end_xref()

        # if has_xrefs:
        # export xrefs

        if idc.isStruct(flags):  # OR HAS_XREFS
            visitor.visit_end_xrefs()

        #
        # MATCHING SYSTEMS
        #
        visitor.visit_start_matching_systems()
        (chunk_start, chunk_end) = YaToolIDATools.get_segment_chunk_for_ea(idc.SegStart(ea), ea)
        visitor.visit_start_matching_system(ea - chunk_start)
        visitor.visit_matching_system_description("equipement", self.EquipementDescription)
        visitor.visit_matching_system_description("os", self.OSDescription)
        visitor.visit_end_matching_system()
        visitor.visit_end_matching_systems()

        visitor.visit_end_object_version()

        visitor.visit_end_reference_object()

        if idc.isStruct(flags):
            self.accept_struc(visitor, object_id, strid)

        if size == 0:
            size = 1
        return size

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

    def clear_exported_struc_enum_id(self, struc_id):
        self.native.unexport_id(struc_id)

    def clear_exported_struc_member_id(self, member_id):
        self.native.unexport_id(member_id)

    def clear_exported_function_id(self, ea):
        try:
            del self.exported_function_ids[ea]
        except KeyError:
            pass

    def clear_exported_segment_id(self, ea):
        try:
            del self.exported_segment_ids[ea]
        except KeyError:
            pass

    def clear_exported_ea(self, ea):
        # get flag
        fl = idc.GetFlags(ea)

        # if ea is func
        func = idaapi.get_func(ea)
        if idaapi.isFunc(fl) or func is not None:
            eaFunc = func.startEA
            self.native.unexport_id(eaFunc)
            self.clear_exported_function_id(eaFunc)

            basic_block = YaToolIDATools.get_basic_block_at_ea(ea, eaFunc, func)
            if basic_block is None:
                logger.error("Function has no basic blocks : %s (eaFunc=%s) " %
                             (self.yatools.address_to_hex_string(ea), self.yatools.address_to_hex_string(eaFunc)))
            else:
                self.native.unexport_id(basic_block['startEA'])

        # if ea is not in a function and it is code
        elif (func is None) and (idaapi.isCode(fl)):
            self.native.unexport_id(ea)
        else:
            previous_item = idc.PrevHead(ea)
            if previous_item != idc.BADADDR:
                previous_item_size = idc.ItemSize(previous_item)
                if previous_item_size > 0 and ea < previous_item + previous_item_size:
                    ea = previous_item

            self.native.unexport_id(ea)

        segment_ea = idc.SegStart(ea)
        if segment_ea == ea:
            # ea is a segment start
            self.clear_exported_segment_id(ea)

    def clear_segment_item_cache(self, ea):
        YaToolIDATools.address_range_items_clear_cache(idc.SegStart(ea), idc.SegEnd(ea))
