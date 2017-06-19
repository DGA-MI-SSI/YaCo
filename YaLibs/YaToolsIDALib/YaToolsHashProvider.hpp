//  Copyright (C) 2017 The YaCo Authors
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <YaToolObjectId.hpp>

#include <stdint.h>
#include <unordered_map>


struct YaToolsHashProvider
{
    YaToolsHashProvider();

    std::string     hash_to_string(YaToolObjectId id);
    void            populate_struc_enum_ids();
    void            put_hash_struc_or_enum(ea_t item_id, YaToolObjectId id, bool in_persistent_cache);
    YaToolObjectId  get_hash_for_ea(ea_t ea);
    YaToolObjectId  get_stackframe_object_id(ea_t sf_id, ea_t eaFunc);
    YaToolObjectId  get_struc_enum_object_id(ea_t item_id, const const_string_ref& name, bool use_time);
    YaToolObjectId  get_function_basic_block_hash(ea_t block_ea, ea_t func_ea);
    YaToolObjectId  get_reference_info_hash(ea_t block_ea, uint64_t value);
    YaToolObjectId  get_struc_member_id(ea_t struc_id, ea_t offset, const const_string_ref& name);
    YaToolObjectId  get_stackframe_member_object_id(ea_t stack_id, ea_t offset, ea_t func_ea);
    YaToolObjectId  get_segment_id(const const_string_ref& name, ea_t ea);
    YaToolObjectId  get_segment_chunk_id(YaToolObjectId seg_id, ea_t start, ea_t end);
    YaToolObjectId  get_binary_id();
    YaToolObjectId  get_enum_member_id(ea_t enum_id, const const_string_ref& enum_name, ea_t const_id, const const_string_ref& const_name, const const_string_ref& const_value, bmask_t bmask, bool use_time);
    void            put_hash_enum_member(const const_string_ref& enum_name, const const_string_ref& const_name, uint64_t const_value, YaToolObjectId id, bool in_persistent_cache);

#ifndef SWIG
    YaToolObjectId  hash_local_string(const const_string_ref& key_string, bool in_persistent_cache);

private:
    YaToolObjectId  hash_string(const const_string_ref& key_string, bool in_persistent_cache);
    void            populate_persistent_cache();
    void            check_and_flush_cache_if_needed();
    void            put_hash_cache(const const_string_ref& key_string, YaToolObjectId id, bool in_persistent_cache);
    void            put_hash_cache(ea_t key_string, YaToolObjectId id, bool in_persistent_cache);

    std::string                                     string_start_;
    std::unordered_map<std::string,YaToolObjectId>  cache_by_string_;
    std::unordered_map<std::string,YaToolObjectId>  cache_by_string_persistent_;
#endif
};

