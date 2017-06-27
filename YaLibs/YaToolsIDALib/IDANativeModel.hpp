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
#include "IModelAccept.hpp"

namespace std { template<typename T> class shared_ptr; }
struct YaToolsHashProvider;
class IModelAccept;

const int SEGMENT_CHUNK_MAX_SIZE = 0x10000;
const int MAX_BLOB_TAG_LEN = 0x1000;

std::string get_type(ea_t ea);

std::shared_ptr<IModelAccept> MakeModel(YaToolsHashProvider* provider);

struct IModelIncremental
{
    virtual ~IModelIncremental() {}

    // export methods
    virtual void    export_id(YaToolObjectId id) = 0;
    virtual void    unexport_id(YaToolObjectId id) = 0;
    virtual bool    is_exported(YaToolObjectId id) const = 0;

    // accept methods
    virtual void accept_enum(IModelVisitor& v, ea_t enum_id) = 0;
    virtual void accept_struct(IModelVisitor& v, ea_t struc_id, ea_t func_ea) = 0;
    virtual void accept_struct_member(IModelVisitor& v, ea_t func_ea, ea_t member_id) = 0;
    virtual void accept_segment(IModelVisitor& v, ea_t ea) = 0;
    virtual void accept_function(IModelVisitor& v, ea_t ea) = 0;
    virtual void accept_ea(IModelVisitor& v, ea_t ea) = 0;

    // delete methods
    virtual void delete_struct(IModelVisitor& v, ea_t struc_id) = 0;
    virtual void delete_struct_member(IModelVisitor& v, ea_t struc_id, ea_t offset, ea_t func_ea) = 0;
};

std::shared_ptr<IModelIncremental> MakeModelIncremental(YaToolsHashProvider* provider);
