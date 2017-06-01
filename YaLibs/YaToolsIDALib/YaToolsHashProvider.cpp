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

#include <YaTypes.hpp>
#include "Ida.h"

#include "YaToolsHashProvider.hpp"

#include <Logger.h>
#include <Yatools.h>
#include "../Helpers.h"


#include <string>
#include <iostream>
#include <set>
#include <chrono>

#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("YaToolsHashProvider", (FMT), ## __VA_ARGS__)

#define YATOOL_OBJECT_ID_NOT_FOUND  ((YaToolObjectId)0)

YaToolsHashProvider::YaToolsHashProvider()
    : persistent_cache_enabled_(true)
{
}

void YaToolsHashProvider::populate_persistent_cache()
{
    cache_by_string_persistent_.clear();
    cache_by_string_persistent_.insert(cache_by_string_.begin(), cache_by_string_.end());
}

void YaToolsHashProvider::set_string_start(const std::string& string_start)
{
    string_start_ = string_start;
}


void YaToolsHashProvider::check_and_flush_cache_if_needed()
{
    if(cache_by_string_.size() - cache_by_string_persistent_.size() > MAX_CACHE_SIZE)
    {
        cache_by_string_.clear();
        cache_by_string_.insert(cache_by_string_persistent_.begin(), cache_by_string_persistent_.end());
    }
}
void YaToolsHashProvider::put_hash_cache(const std::string& key_string, YaToolObjectId id, bool in_persistent_cache)
{
    check_and_flush_cache_if_needed();

    if(persistent_cache_enabled_ || in_persistent_cache)
        cache_by_string_[key_string] = id;

    if(in_persistent_cache)
        cache_by_string_persistent_[key_string] = id;

    LOG(DEBUG, "[HASH]:put_hash_cache : %s --> %s\n", key_string.c_str(),
            YaToolObjectId_To_StdString(id).c_str());
}

std::string ea_to_std_string_key(ea_t id)
{
    char key_string[sizeof(uint64_t)*2+3+1];
    int param = qsnprintf(key_string, sizeof key_string, "ea-%016llX", (uint64_t) id);
    UNUSED(param);
    assert(param + 1 == sizeof key_string);

    return std::string(key_string);
}

std::string get_enum_key_string(const std::string& enum_name, const std::string& const_name, const std::string& const_value)
{
    return std::string("enum-") + enum_name + "----" + const_name + "----" + const_value;
}

YaToolObjectId YaToolsHashProvider::hash_string(const std::string& key_string, bool in_persistent_cache)
{
    auto cache_it = cache_by_string_.find(key_string);
    if(cache_it != cache_by_string_.end())
    {
        return cache_it->second;
    }
    else
    {
        auto hashed = YaToolObjectId_Hash(key_string);
        put_hash_cache(key_string, hashed, in_persistent_cache);
        return hashed;
    }
}

YaToolObjectId YaToolsHashProvider::hash_local_string(const std::string& key_string, bool in_persistent_cache)
{
    std::string local_key_string = string_start_ + "----" + key_string;
    return hash_string(local_key_string, in_persistent_cache);

}

void YaToolsHashProvider::put_hash_cache(ea_t ea, YaToolObjectId id, bool in_persistent_cache)
{
    std::string key_stdstring = ea_to_std_string_key(ea);
    put_hash_cache(key_stdstring, id, in_persistent_cache);
}

YaToolObjectId YaToolsHashProvider::get_hash_cache(const std::string& key_string)
{
    auto cache_it = cache_by_string_.find(key_string);
    if(cache_it != cache_by_string_.end())
    {
        return cache_it->second;
    }
    else
    {
        return YATOOL_OBJECT_ID_NOT_FOUND;
    }
}

YaToolObjectId YaToolsHashProvider::get_hash_for_ea(ea_t ea)
{
    std::string key_stdstring = ea_to_std_string_key(ea);
    return hash_local_string(key_stdstring);
}

YaToolObjectId YaToolsHashProvider::get_stackframe_object_id(ea_t sf_id, ea_t eaFunc)
{
    auto cache_it = cache_by_string_.find(ea_to_std_string_key(sf_id));
    if(cache_it != cache_by_string_.end())
    {
        LOG(DEBUG, "[HASH]:get_stackframe_object_id cache hit : 0x%016llX (%s) --> %s\n",
                (uint64_t)sf_id, get_struc_name(sf_id).c_str(), YaToolObjectId_To_StdString(cache_it->second).c_str());
        return cache_it->second;
    }
    else
    {
        if(eaFunc == BADADDR)
        {
            eaFunc = get_func_by_frame(sf_id);
        }
        std::string key_string = "stackframe-" + ea_to_std_string_key(eaFunc);
        YaToolObjectId id = hash_local_string(key_string);
        put_hash_struc_or_enum(sf_id, id);
        LOG(DEBUG, "[HASH]:get_stackframe_object_id cache miss : 0x%016llX (%s) --> %s\n",
                (uint64_t)sf_id, get_struc_name(sf_id).c_str(), YaToolObjectId_To_StdString(id).c_str());
        return id;
    }
}

void YaToolsHashProvider::put_hash_struc_or_enum(ea_t item_id, YaToolObjectId id, bool in_persistent_cache)
{
    put_hash_cache(item_id, id, in_persistent_cache);
}

void YaToolsHashProvider::put_hash_enum_member(const std::string& enum_name, const std::string& const_name, const std::string& const_value, YaToolObjectId id, bool in_persistent_cache)
{
    std::string key_string = get_enum_key_string(enum_name, const_name, const_value);
    put_hash_cache(key_string, id, in_persistent_cache);
}

int64_t get_clock_ms()
{

    const auto now = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
}

YaToolObjectId YaToolsHashProvider::get_struc_enum_object_id(ea_t item_id, const std::string& name, bool use_time)
{
    std::string used_name = name;
    ea_t eaFunc = get_func_by_frame(item_id);
    if(eaFunc != BADADDR)
    {
        //it is a stackframe : we must only use func's address to genereate the hash
        //(not the timestamp)
        return get_stackframe_object_id(item_id, eaFunc);
    }
    if(name.size() == 0)
        used_name = std::string(get_struc_name(item_id).c_str());

    auto cache_it = cache_by_string_.find(ea_to_std_string_key(item_id));
    if(cache_it != cache_by_string_.end())
    {
        LOG(DEBUG, "[HASH]:get_struc_enum_object_id cache hit : 0x%016llX (%s) --> %s\n",
                (uint64_t)item_id, used_name.c_str(), YaToolObjectId_To_StdString(cache_it->second).c_str());
        return cache_it->second;
    }
    else
    {

        std::string prefix;
        if(use_time)
        {
            std::stringstream ss;
            ss << std::hex << get_clock_ms() << ea_to_std_string_key(item_id);
            prefix = ss.str();
        }
        else
        {
            prefix = std::string("struc_enum-");
        }
        std::string key_string(prefix + "----" + ea_to_std_string_key(item_id));
        YaToolObjectId id = hash_local_string(key_string);
        put_hash_struc_or_enum(item_id, id, use_time);
        LOG(DEBUG, "HASH]:get_struc_enum_object_id cache miss : 0x%016llX (%p) --> %p\n",
                         (uint64_t)item_id, used_name.c_str(), YaToolObjectId_To_StdString(id).c_str());

        return id;
    }
}


YaToolObjectId YaToolsHashProvider::get_enum_member_id(ea_t enum_id, const std::string& enum_name, ea_t const_id, const std::string& const_name, const std::string& const_value, bmask_t bmask, bool use_time)
{
    std::string enum_key_string = get_enum_key_string(enum_name, const_name, const_value);

    auto cache_it = cache_by_string_.find(enum_key_string);
    if(cache_it != cache_by_string_.end())
    {
        LOG(DEBUG, "[HASH]:get_enum_member_id cache hit : 0x%016llX (%s) --> %s\n",
                (uint64_t)const_id, enum_name.c_str(), YaToolObjectId_To_StdString(cache_it->second).c_str());
        return cache_it->second;
    }
    else
    {

        YaToolObjectId enum_object_id = get_struc_enum_object_id(enum_id, enum_name, use_time);

        std::stringstream key_string_stream;
        key_string_stream << "-" << YaToolObjectId_To_StdString(enum_object_id) << "-" << const_name << "-" << std::hex << const_value;

        if(bmask != BADADDR)
        {
            key_string_stream << "-" << std::hex << bmask;
        }
        if(use_time)
        {
            key_string_stream << "-" << std::hex << get_clock_ms();
        }

        std::string key_string(key_string_stream.str());
        YaToolObjectId id = hash_local_string(key_string);
        put_hash_cache(enum_key_string, id, true);
        LOG(DEBUG, "[HASH]:get_enum_member_id cache miss : 0x%016llX (%s) --> %s\n",
                (uint64_t)const_id, (enum_name + "." + const_name).c_str(), YaToolObjectId_To_StdString(id).c_str());
        return id;
    }
}
