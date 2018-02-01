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

    virtual YaToolObjectId  get_binary_id       () = 0;
    virtual YaToolObjectId  get_segment_id      (ea_t ea) = 0;
    virtual YaToolObjectId  get_segment_chunk_id(ea_t ea) = 0;
    virtual YaToolObjectId  get_enum_id         (const const_string_ref& name) = 0;
    virtual YaToolObjectId  get_enum_member_id  (YaToolObjectId parent, const const_string_ref& name) = 0;
    virtual YaToolObjectId  get_struc_id        (const const_string_ref& name) = 0;
    virtual YaToolObjectId  get_stack_id        (ea_t ea) = 0;
    virtual YaToolObjectId  get_member_id       (YaToolObjectId parent, ea_t offset) = 0;
    virtual YaToolObjectId  get_function_id     (ea_t ea) = 0;
    virtual YaToolObjectId  get_ea_id           (ea_t ea) = 0;
    virtual YaToolObjectId  get_reference_id    (ea_t ea, uint64_t base) = 0;
};

std::shared_ptr<IHashProvider> MakeHashProvider();
