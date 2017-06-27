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

    def accept_struc(self, visitor, struc_id, func_ea):
        self.native.accept_struct(visitor, struc_id, func_ea)

    def accept_struc_member(self, visitor, struc, offset, func_ea=None):
        member = idaapi.get_member(struc, offset)
        if member:
            ea = func_ea if func_ea else idc.BADADDR
            self.native.accept_struct_member(visitor, ea, member.id)

    def accept_deleted_strucmember(self, visitor, struc_id, struc_name, offset, struc_type=ya.OBJECT_TYPE_STRUCT,
                                   strucmember_type=ya.OBJECT_TYPE_STRUCT_MEMBER):
        if struc_type == ya.OBJECT_TYPE_STRUCT:
            member_object_id = self.hash_provider.get_struc_member_id(struc_id, offset, struc_name)
        else:
            member_object_id = self.hash_provider.get_stackframe_member_object_id(struc_id, offset, idc.BADADDR)
        visitor.visit_start_deleted_object(strucmember_type)
        visitor.visit_id(member_object_id)
        visitor.visit_end_deleted_object()

    def accept_ea(self, visitor, ea):
        self.native.accept_ea(visitor, ea)

    def accept_function(self, visitor, ea):
        self.native.accept_function(visitor, ea)

    def accept_segment(self, visitor, ea):
        self.native.accept_segment(visitor, ea)
