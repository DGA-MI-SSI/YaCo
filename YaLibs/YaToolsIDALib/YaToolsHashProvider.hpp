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

#include "YaTypes.hpp"

#include <memory>

struct IHashProvider
{
    virtual ~IHashProvider() {}

    virtual void            put_hash_struc                  (ea_t item_id, YaToolObjectId id, bool in_persistent_cache) = 0;
    virtual YaToolObjectId  get_hash_for_ea                 (ea_t ea) = 0;
    virtual YaToolObjectId  get_stackframe_object_id        (ea_t sf_id, ea_t eaFunc) = 0;
    virtual YaToolObjectId  get_struc_id                    (ea_t item_id, const const_string_ref& name, bool use_time) = 0;
    virtual YaToolObjectId  get_struc_member_id             (ea_t struc_id, ea_t offset, const const_string_ref& name) = 0;
    virtual YaToolObjectId  get_function_basic_block_hash   (ea_t block_ea, ea_t func_ea) = 0;
    virtual YaToolObjectId  get_reference_info_hash         (ea_t block_ea, uint64_t value) = 0;
    virtual YaToolObjectId  get_stackframe_member_object_id (ea_t stack_id, ea_t offset, ea_t func_ea) = 0;
    virtual YaToolObjectId  get_segment_id                  (const const_string_ref& name, ea_t ea) = 0;
    virtual YaToolObjectId  get_segment_chunk_id            (YaToolObjectId seg_id, ea_t start, ea_t end) = 0;
    virtual YaToolObjectId  get_binary_id                   () = 0;
    virtual YaToolObjectId  get_enum_id                     (const const_string_ref& name) = 0;
    virtual YaToolObjectId  get_enum_member_id              (YaToolObjectId parent, const const_string_ref& name) = 0;
};

std::shared_ptr<IHashProvider> MakeHashProvider();
