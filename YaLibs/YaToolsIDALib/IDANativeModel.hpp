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

#include <memory>
#include <vector>

struct IHashProvider;
class IModelAccept;

std::string get_type(ea_t ea);

std::shared_ptr<IModelAccept> MakeModel(IHashProvider& provider);
std::vector<ea_t> get_all_items(ea_t start, ea_t end);

struct IModelIncremental
{
    virtual ~IModelIncremental() {}

    // accept methods
    virtual void accept_enum(IModelVisitor& v, ea_t enum_id) = 0;
    virtual void accept_struct(IModelVisitor& v, ea_t func_ea, ea_t struct_id) = 0;
    virtual void accept_struct_member(IModelVisitor& v, ea_t func_ea, ea_t member_id) = 0;
    virtual void accept_segment(IModelVisitor& v, ea_t ea) = 0;
    virtual void accept_function(IModelVisitor& v, ea_t ea) = 0;
    virtual void accept_ea(IModelVisitor& v, ea_t ea) = 0;

    // delete methods
    virtual void delete_enum(IModelVisitor& v, ea_t enum_id) = 0;
    virtual void delete_struct(IModelVisitor& v, ea_t struc_id) = 0;
    virtual void delete_struct_member(IModelVisitor& v, ea_t func_ea, ea_t struct_id, ea_t offset) = 0;
};

std::shared_ptr<IModelIncremental> MakeModelIncremental(IHashProvider& provider);

void export_from_ida(const std::string& filename);
