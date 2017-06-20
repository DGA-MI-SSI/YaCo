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
#include <Hexa.h>
#include "../Helpers.h"
#include "YaHelpers.hpp"

#include <string>
#include <iostream>
#include <set>
#include <chrono>

#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("hash", (FMT), ## __VA_ARGS__)

#define YATOOL_OBJECT_ID_NOT_FOUND  ((YaToolObjectId)0)

namespace
{
    const bool USE_PERSISTENT_CACHE = true;
    const auto MAX_CACHE_SIZE = 1000;
}

YaToolsHashProvider::YaToolsHashProvider()
{
    uchar hash[16];
    const auto ok = retrieve_input_file_md5(hash);
    if(!ok)
        LOG(ERROR, "unable to retrieve input file MD5\n");

    char hexbuf[sizeof hash * 2 + 1];
    buffer_to_hex(hash, sizeof hash, hexbuf);
    string_start_ = "md5=";
    string_start_ += hexbuf;
    string_start_ += "----";
}

void YaToolsHashProvider::populate_persistent_cache()
{
    cache_by_string_persistent_.clear();
    cache_by_string_persistent_.insert(cache_by_string_.begin(), cache_by_string_.end());
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

    if(USE_PERSISTENT_CACHE || in_persistent_cache)
        cache_by_string_[key_string] = id;

    if(in_persistent_cache)
        cache_by_string_persistent_[key_string] = id;

    LOG(DEBUG, "put_hash_cache: %s --> %s\n", key_string.c_str(),
            YaToolObjectId_To_StdString(id).c_str());
}

std::string ea_to_std_string_key(ea_t id)
{
    char key_string[sizeof(uint64_t)*2+3+1];
    const auto param = qsnprintf(key_string, sizeof key_string, "ea-%016llX", (uint64_t) id);
    UNUSED(param);
    assert(param + 1 == sizeof key_string);

    return key_string;
}

std::string get_enum_key_string(const std::string& enum_name, const std::string& const_name, const std::string& const_value)
{
    return "enum-" + enum_name + "----" + const_name + "----" + const_value;
}

YaToolObjectId YaToolsHashProvider::hash_string(const std::string& key_string, bool in_persistent_cache)
{
    const auto cache_it = cache_by_string_.find(key_string);
    if(cache_it != cache_by_string_.end())
        return cache_it->second;

    const auto hashed = YaToolObjectId_Hash(key_string);
    put_hash_cache(key_string, hashed, in_persistent_cache);
    return hashed;
}

YaToolObjectId YaToolsHashProvider::hash_local_string(const std::string& key_string, bool in_persistent_cache)
{
    return hash_string(string_start_ + "----" + key_string, in_persistent_cache);

}

void YaToolsHashProvider::put_hash_cache(ea_t ea, YaToolObjectId id, bool in_persistent_cache)
{
    put_hash_cache(ea_to_std_string_key(ea), id, in_persistent_cache);
}

YaToolObjectId YaToolsHashProvider::get_hash_for_ea(ea_t ea)
{
    return hash_local_string(ea_to_std_string_key(ea), false);
}

YaToolObjectId YaToolsHashProvider::get_stackframe_object_id(ea_t sf_id, ea_t eaFunc)
{
    const auto cache_it = cache_by_string_.find(ea_to_std_string_key(sf_id));
    if(cache_it != cache_by_string_.end())
    {
        LOG(DEBUG, "get_stackframe_object_id cache hit: 0x%016llX (%s) --> %s\n",
                (uint64_t) sf_id, get_struc_name(sf_id).c_str(), YaToolObjectId_To_StdString(cache_it->second).c_str());
        return cache_it->second;
    }

    if(eaFunc == BADADDR)
        eaFunc = get_func_by_frame(sf_id);
    const auto id = hash_local_string("stackframe-" + ea_to_std_string_key(eaFunc), false);
    put_hash_struc_or_enum(sf_id, id, false);
    LOG(DEBUG, "get_stackframe_object_id cache miss: 0x%016llX (%s) --> %s\n",
            (uint64_t) sf_id, get_struc_name(sf_id).c_str(), YaToolObjectId_To_StdString(id).c_str());
    return id;
}

void YaToolsHashProvider::put_hash_struc_or_enum(ea_t item_id, YaToolObjectId id, bool in_persistent_cache)
{
    put_hash_cache(item_id, id, in_persistent_cache);
}

void YaToolsHashProvider::put_hash_enum_member(const std::string& enum_name, const std::string& const_name, uint64_t const_value, YaToolObjectId id, bool in_persistent_cache)
{
    put_hash_cache(get_enum_key_string(enum_name, const_name, ya::to_py_hex(const_value)), id, in_persistent_cache);
}

static int64_t get_clock_ms()
{
    const auto now = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
}

static qstring get_name(const std::string& value, ea_t item_id)
{
    if(!value.empty())
        return {};
    return get_struc_name(item_id);
}

YaToolObjectId YaToolsHashProvider::get_struc_enum_object_id(ea_t item_id, const std::string& name, bool use_time)
{
    const auto eaFunc = get_func_by_frame(item_id);
    if(eaFunc != BADADDR)
    {
        // if is a stack frame : we must only use function address to generate the hash
        // (not the timestamp)
        return get_stackframe_object_id(item_id, eaFunc);
    }

    const auto item_id_str = ea_to_std_string_key(item_id);
    const auto cache_it = cache_by_string_.find(item_id_str);
    if(cache_it != cache_by_string_.end())
    {
        LOG(DEBUG, "get_struc_enum_object_id cache hit: 0x%016llX (%s) --> %s\n",
                (uint64_t) item_id, get_name(name, item_id).c_str(), YaToolObjectId_To_StdString(cache_it->second).c_str());
        return cache_it->second;
    }

    std::string prefix = "struc_enum-";
    if(use_time)
    {
        std::stringstream ss;
        ss << std::hex << get_clock_ms() << item_id_str;
        prefix = ss.str();
    }

    const auto id = hash_local_string(prefix + "----" + item_id_str, false);
    put_hash_struc_or_enum(item_id, id, use_time);
    LOG(DEBUG, "get_struc_enum_object_id cache miss: 0x%016llX (%p) --> %p\n",
        (uint64_t) item_id, get_name(name, item_id).c_str(), YaToolObjectId_To_StdString(id).c_str());
    return id;
}


YaToolObjectId YaToolsHashProvider::get_enum_member_id(ea_t enum_id, const std::string& enum_name, ea_t const_id, const std::string& const_name, const std::string& const_value, bmask_t bmask, bool use_time)
{
    const auto enum_key_string = get_enum_key_string(enum_name, const_name, const_value);

    const auto cache_it = cache_by_string_.find(enum_key_string);
    if(cache_it != cache_by_string_.end())
    {
        LOG(DEBUG, "get_enum_member_id cache hit: 0x%016llX (%s) --> %s\n",
                (uint64_t) const_id, enum_name.c_str(), YaToolObjectId_To_StdString(cache_it->second).c_str());
        return cache_it->second;
    }

    const auto enum_object_id = get_struc_enum_object_id(enum_id, enum_name, use_time);
    std::stringstream key_string_stream;
    key_string_stream << "-" << YaToolObjectId_To_StdString(enum_object_id) << "-" << const_name << "-" << std::hex << const_value;

    if(bmask != BADADDR)
        key_string_stream << "-" << std::hex << bmask;

    if(use_time)
        key_string_stream << "-" << std::hex << get_clock_ms();

    const auto id = hash_local_string(key_string_stream.str(), false);
    put_hash_cache(enum_key_string, id, true);
    LOG(DEBUG, "get_enum_member_id cache miss: 0x%016llX (%s) --> %s\n",
            (uint64_t) const_id, (enum_name + "." + const_name).c_str(), YaToolObjectId_To_StdString(id).c_str());
    return id;
}

void YaToolsHashProvider::populate_struc_enum_ids()
{
    for(auto idx = get_first_struc_idx(); idx != BADADDR; idx = get_next_struc_idx(idx))
        get_struc_enum_object_id(get_struc_by_idx(idx), {}, false);

    qstring buffer;
    std::string enum_name;
    for(auto idx = 0u, end = get_enum_qty(); idx < end; ++idx)
    {
        const auto enum_id = getn_enum(idx);
        get_enum_name(&buffer, enum_id);
        enum_name.assign(buffer.c_str(), buffer.length());
        get_struc_enum_object_id(enum_id, enum_name, false);
        ya::walk_enum_members(enum_id, [&](const_t const_id, uval_t value, uchar /*serial*/, bmask_t bmask)
        {
            get_enum_member_name(&buffer, const_id);
            get_enum_member_id(enum_id, enum_name, const_id, ya::to_string(buffer), ya::to_py_hex(value), bmask, false);
        });
    }

    populate_persistent_cache();
}

YaToolObjectId YaToolsHashProvider::get_function_basic_block_hash(ea_t block_ea, ea_t func_ea)
{
    return hash_local_string("basic_block--" + std::to_string(block_ea) + "-" + std::to_string(func_ea), false);
}

YaToolObjectId YaToolsHashProvider::get_reference_info_hash(ea_t ea, uint64_t value)
{
    return hash_local_string("reference_info--" + std::to_string(ea) + "-" + std::to_string(value), false);
}

YaToolObjectId YaToolsHashProvider::get_struc_member_id(ea_t struc_id, ea_t offset, const std::string& name)
{
    const auto id = get_struc_enum_object_id(struc_id, name, true);
    return hash_local_string("structmember-" + YaToolObjectId_To_StdString(id) + "-" + ya::to_py_hex(offset), false);
}

YaToolObjectId YaToolsHashProvider::get_stackframe_member_object_id(ea_t stack_id, ea_t offset, ea_t func_ea)
{
    const auto id = get_stackframe_object_id(stack_id, func_ea);
    return hash_local_string("structmember-" + YaToolObjectId_To_StdString(id) + "-" + ya::to_py_hex(offset), false);
}

YaToolObjectId YaToolsHashProvider::get_binary_id()
{
    return hash_local_string("binary", false);
}

YaToolObjectId YaToolsHashProvider::get_segment_id(const std::string& name, ea_t ea)
{
    return hash_local_string("segment-" + name + std::to_string(ea), false);
}

YaToolObjectId YaToolsHashProvider::get_segment_chunk_id(YaToolObjectId seg_id, ea_t start, ea_t end)
{
    return hash_local_string("segment_chunk-" + YaToolObjectId_To_StdString(seg_id) + "-" + std::to_string(start) + "-" + std::to_string(end), false);
}

std::string YaToolsHashProvider::hash_to_string(YaToolObjectId id)
{
    // FIXME remove me when conversion to python is done
    return YaToolObjectId_To_StdString(id);
}
