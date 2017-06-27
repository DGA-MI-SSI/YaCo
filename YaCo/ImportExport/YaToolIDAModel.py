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

    def delete_struc(self, visitor, struc_id):
        self.native.delete_struct(visitor, struc_id)

    def accept_enum(self, visitor, enum_id):
        self.native.accept_enum(visitor, enum_id)

    def accept_struc(self, visitor, struc_id, func_ea):
        self.native.accept_struct(visitor, struc_id, func_ea)

    def accept_struc_member(self, visitor, member_id, func_ea):
        self.native.accept_struct_member(visitor, member_id, func_ea)

    def delete_struc_member(self, visitor, struc_id, offset, func_ea):
        self.native.delete_struct_member(visitor, struc_id, offset, func_ea)

    def accept_ea(self, visitor, ea):
        self.native.accept_ea(visitor, ea)

    def accept_function(self, visitor, ea):
        self.native.accept_function(visitor, ea)

    def accept_segment(self, visitor, ea):
        self.native.accept_segment(visitor, ea)
