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


#define MAX_CACHE_SIZE  1000

struct YaToolsHashProvider
{
    YaToolsHashProvider();

    YaToolObjectId hash_string(const std::string& key_string, bool in_persistent_cache=false);
    void set_string_start(const std::string&);
    void populate_persistent_cache();

    void put_hash_struc_or_enum(ea_t item_id, YaToolObjectId id, bool in_persistent_cache=false);
    void put_hash_enum_member(const std::string& enum_name, const std::string& const_name, const std::string& const_value, YaToolObjectId id, bool in_persistent_cache=false);

    YaToolObjectId get_hash_for_ea(ea_t ea);
    YaToolObjectId get_hash_cache(const std::string& key_string);
    YaToolObjectId get_stackframe_object_id(ea_t sf_id, ea_t eaFunc=BADADDR);
    YaToolObjectId get_struc_enum_object_id(ea_t item_id, const std::string& name, bool use_time=true);
    YaToolObjectId get_enum_member_id(ea_t enum_id,
            const std::string& enum_name,
            ea_t const_id,
            const std::string& const_name,
            const std::string& const_value,
            bmask_t bmask,
            bool use_time);

    YaToolObjectId hash_local_string(const std::string& key_string, bool in_persistent_cache=false);

private:
    void put_hash_cache(const std::string& key_string, YaToolObjectId id, bool in_persistent_cache = false);
    void put_hash_cache(ea_t key_string, YaToolObjectId id, bool in_persistent_cache = false);
    void check_and_flush_cache_if_needed();

    std::string                                     string_start_;
    std::unordered_map<std::string,YaToolObjectId>  cache_by_string_;
    std::unordered_map<std::string,YaToolObjectId>  cache_by_string_persistent_;
    bool                                            persistent_cache_enabled_;
};

