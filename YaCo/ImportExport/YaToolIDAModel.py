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


if idc.__EA64__:
    import YaToolsPy64 as ya
else:
    import YaToolsPy32 as ya


class YaToolIDAModel(YaToolObjectVersionElement):
    def __init__(self, yatools, hash_provider, EquipementDescription="None", OSDescription="None"):
        self.hash_provider = hash_provider
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

    def accept_ea(self, visitor, parent_id, ea, export_segment=True):
        self.native.accept_ea(visitor, ea)

    def accept_function(self, visitor, parent_id, eaFunc, func, basic_blocks=None):
        self.native.accept_function(visitor, eaFunc)

    def accept_segment(self, visitor, parent_id, seg_ea_start, seg_ea_end=None, export_chunks=False, chunk_eas=None,
                       export_eas=None):
        self.native.accept_segment(visitor, seg_ea_start)
