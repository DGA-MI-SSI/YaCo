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

import idautils
import idc
import logging

from ImportExport.YaToolIDATools import enum_member_iterate_all

if idc.__EA64__:
    import YaToolsPy64 as ya
else:
    import YaToolsPy32 as ya

_yatools_hash_provider = ya.YaToolsHashProvider()
logger = logging.getLogger("YaCo")

DEBUG_HASH_PROVIDER = False

MAX_CACHE_SIZE = 100000


class YaToolHashProvider(object):
    '''
    classdocs
    '''

    def __init__(self):
        _yatools_hash_provider.set_string_start("md5=" + idautils.GetInputFileMD5() + "----")
        self.count = 0
        self.populate_struc_enum_ids()

    def disable_persistent_cache(self):
        _yatools_hash_provider.disable_persistent_cache()

    def get(self):
        return _yatools_hash_provider

    #     def flush_cache(self):
    #         self.cache = dict(self.persistent_cache)

    def hash_to_string(self, hashed):
        return ya.YaToolObjectId_To_String(hashed)

    def string_to_hash(self, hash_str):
        return bytearray.fromhex(hash_str)

    def put_hash_struc_or_enum(self, item_id, hashed, in_persistent_cache=False):
        _yatools_hash_provider.put_hash_struc_or_enum(item_id, hashed, in_persistent_cache)

    def put_hash_enum_member(self, enum_name, const_name, const_value, hashed, in_persistent_cache=False):
        _yatools_hash_provider.put_hash_enum_member(enum_name, const_name, hex(const_value & idc.BADADDR), hashed,
                                                    in_persistent_cache)

    def get_hash_for_ea(self, ea):
        return _yatools_hash_provider.get_hash_for_ea(ea)

    def get_function_chunk_hash(self, chunk_ea, fn_ea):
        return _yatools_hash_provider.hash_local_string('chunk-' + '-' + str(chunk_ea) + "-" + str(fn_ea))

    def get_function_basic_block_hash(self, block_ea, fn_ea):
        return _yatools_hash_provider.hash_local_string('basic_block-' + '-' + str(block_ea) + "-" + str(fn_ea))

    def get_reference_info_hash(self, ea, value):
        return _yatools_hash_provider.hash_local_string('reference_info-' + '-' + str(ea) + "-" + str(value))

    def get_function_id_at_ea(self, ea):
        # get id from model
        return _yatools_hash_provider.get_hash_for_ea(ea)

    def get_data_id_at_ea(self, ea):
        # get id from model
        return _yatools_hash_provider.get_hash_for_ea(ea)

    def get_code_id_at_ea(self, ea):
        # get id from model
        return _yatools_hash_provider.get_hash_for_ea(ea)

    def get_stackframe_object_id(self, sf_id, eaFunc=idc.BADADDR):
        return _yatools_hash_provider.get_stackframe_object_id(sf_id, eaFunc)

    def get_struc_enum_object_id(self, item_id, name=None, use_time=True):
        if name is None:
            name = ""
        return _yatools_hash_provider.get_struc_enum_object_id(item_id, name, use_time)

    def get_struc_enum_id_for_name(self, name):
        item_id = idc.GetStrucIdByName(name)
        if item_id == idc.BADADDR:
            item_id = idc.GetEnum(name)
            if item_id == idc.BADADDR:
                logger.error("no struc or enum id for name : %s", name)
                return None
        return self.get_struc_enum_object_id(item_id, name)

    def get_struc_member_id(self, struc_id, offset, struc_name=None):
        struc_hash = self.get_struc_enum_object_id(struc_id, struc_name)
        # get id from model
        return _yatools_hash_provider.hash_local_string(
            "structmember-" + self.hash_to_string(struc_hash) + "-" + hex(offset))

    def get_struc_member_id_for_name(self, struc_name, offset):
        item_id = idc.GetStrucIdByName(struc_name)
        if item_id == idc.BADADDR:
            logger.error("no struc id for name : %s", struc_name)
            return None
        return self.get_struc_member_id(item_id, offset, struc_name)

    def get_stackframe_member_object_id(self, stackframe_id, offset, eaFunc=idc.BADADDR):
        struc_hash = self.get_stackframe_object_id(stackframe_id, eaFunc)
        hashed = _yatools_hash_provider.hash_local_string(
            "structmember-" + self.hash_to_string(struc_hash) + "-" + hex(offset))
        if DEBUG_HASH_PROVIDER:
            logger.debug("[HASH]:get_stackframe_member_object_id : 0x%08X:0x%04X --> %s",
                         stackframe_id, offset, self.hash_to_string(hashed))
        return hashed

    def get_enum_member_id(self, enum_id, enum_name, const_id, const_name, const_value, bmask=idc.BADADDR,
                           use_time=True):
        return _yatools_hash_provider.get_enum_member_id(enum_id, enum_name, const_id, const_name,
                                                         hex(const_value & idc.BADADDR), bmask, use_time)

    def get_binary_id(self):
        return _yatools_hash_provider.hash_local_string("binary")

    def get_segment_id(self, name, ea_start):
        # get id from model
        return _yatools_hash_provider.hash_local_string("segment-" + str(name) + str(ea_start))

    def get_segment_chunk_id(self, segment_object_id, chunk_start, chunk_end):
        return _yatools_hash_provider.hash_local_string("segment_chunk-" +
                                                        self.hash_to_string(segment_object_id) + "-" +
                                                        str(chunk_start) + "-" +
                                                        str(chunk_end)
                                                        )

    def populate_struc_enum_ids(self):
        logger.debug("Populating hash cache with current values")
        # force hash generation of struc and enums (without use_time)
        idx = idc.GetFirstStrucIdx()
        while idx != idc.BADADDR:
            self.get_struc_enum_object_id(idc.GetStrucId(idx), use_time=False)
            idx = idc.GetNextStrucIdx(idx)

        for idx in xrange(0, idc.GetEnumQty()):
            enum_id = idc.GetnEnum(idx)
            self.get_struc_enum_object_id(enum_id, use_time=False)

            enum_name = idc.GetEnumName(enum_id)
            for (const_id, const_value, bmask) in enum_member_iterate_all(enum_id):
                const_name = idc.GetConstName(const_id)
                self.get_enum_member_id(enum_id, enum_name, const_id, const_name, const_value, bmask, use_time=False)

        _yatools_hash_provider.populate_persistent_cache()
