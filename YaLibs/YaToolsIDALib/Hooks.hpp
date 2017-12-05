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

// Forward declarations
struct IHashProvider;
struct IRepository;
namespace std { template<typename T> class shared_ptr; }

struct IHooks
{
    virtual void rename(ea_t ea, const std::string& new_name, const std::string& type = "", const std::string& old_name = "") = 0;
    virtual void change_comment(ea_t ea) = 0;
    virtual void undefine(ea_t ea) = 0;
    virtual void delete_function(ea_t ea) = 0;
    virtual void make_code(ea_t ea) = 0;
    virtual void make_data(ea_t ea) = 0;
    virtual void add_function(ea_t ea) = 0;
    virtual void update_function(ea_t ea) = 0;
    virtual void update_structure(ea_t struct_id) = 0;
    virtual void update_structure_member(ea_t struct_id, ea_t member_id, ea_t member_offset) = 0;
    virtual void delete_structure_member(ea_t struct_id, ea_t member_id, ea_t offset) = 0;
    virtual void update_enum(ea_t enum_id) = 0;
    virtual void change_operand_type(ea_t ea) = 0;
    virtual void add_segment(ea_t start_ea, ea_t end_ea) = 0;
    virtual void change_type_information(ea_t ea) = 0;

    virtual void hook() = 0;
    virtual void unhook() = 0;

    virtual void save() = 0;
    virtual void save_and_update() = 0;

    virtual void flush() = 0;
};

std::shared_ptr<IHooks> MakeHooks(const std::shared_ptr<IHashProvider>& hash_provider, const std::shared_ptr<IRepository>& repo_manager);
