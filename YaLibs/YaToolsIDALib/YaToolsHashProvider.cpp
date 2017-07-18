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
#include "YaHelpers.hpp"
#include "Pool.hpp"
#include "StringFormat.hpp"
#include "YaToolObjectId.hpp"

#include <chrono>
#include <unordered_map>

#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("hash", (FMT), ## __VA_ARGS__)

// FIXME use integers & binary to generate hashes instead of manipulating strings
// stackframe: type, func ea
// stackframe_member: type, func ea, offset
// binary: type
// segment: type, segment ea
// segment_chunk: type, chunk ea
// struc_enum_object: type, name?, time?
// struc_member: type, parent id, offset
// enum_member: type, parent_id, const_value
// basic_block: type, block ea

namespace std
{
    void pool_item_clear(std::string& item)
    {
        item.clear();
    }
}

namespace
{
    const auto USE_PERSISTENT_CACHE = true;
    const auto MAX_CACHE_SIZE = 1000;

    const std::string separator             = "----";
    const std::string enum_prefix           = "enum-";
    const std::string md5_prefix            = "md5=";
    const std::string stackframe_prefix     = "stackframe-";
    const std::string struc_enum_prefix     = "struc_enum-";
    const std::string basic_block_prefix    = "basic_block--";
    const std::string struct_member_prefix  = "structmember-";
    const std::string reference_info_prefix = "reference_info--";
    const std::string binary_prefix         = "binary";
    const std::string segment_prefix        = "segment-";
    const std::string segment_chunk_prefix  = "segment_chunk-";
    const std::string ea_prefix             = "ea-";
    const std::string ox_prefix             = "0x";

    void append_ea(std::string& dst, ea_t id)
    {
        dst = ea_prefix;
        append_uint64(dst, id);
    }

    std::string& append(std::string& dst, const const_string_ref& ref)
    {
        dst.append(ref.value, ref.size);
        return dst;
    }

    void append_enum(std::string& dst, const const_string_ref& enum_name, const const_string_ref& const_name, const const_string_ref& const_value)
    {
        dst += enum_prefix;
        append(dst, enum_name);
        dst += separator;
        append(dst, const_name);
        dst += separator;
        append(dst, const_value);
    }

    // emulate python behavior
    template<typename T>
    void append_py_hex(std::string& dst, T ea)
    {
        dst += ox_prefix;
        append_uint64<LowerCase, RemovePadding>(dst, ea);
        dst += 'L';
    }

    template<typename T>
    void append_int(std::string& dst, T value)
    {
        char buffer[100];
        const auto param = snprintf(buffer, sizeof buffer, sizeof value == 8 ? "%lld" : "%d", value);
        dst.append(buffer, param);
    }

    struct YaToolsHashProvider
        : public IHashProvider
    {
        YaToolsHashProvider();

        void            put_hash_struc_or_enum          (ea_t item_id, YaToolObjectId id, bool in_persistent_cache) override;
        YaToolObjectId  get_hash_for_ea                 (ea_t ea) override;
        YaToolObjectId  get_stackframe_object_id        (ea_t sf_id, ea_t eaFunc) override;
        YaToolObjectId  get_struc_enum_object_id        (ea_t item_id, const const_string_ref& name, bool use_time) override;
        YaToolObjectId  get_function_basic_block_hash   (ea_t block_ea, ea_t func_ea) override;
        YaToolObjectId  get_reference_info_hash         (ea_t block_ea, uint64_t value) override;
        YaToolObjectId  get_struc_member_id             (ea_t struc_id, ea_t offset, const const_string_ref& name) override;
        YaToolObjectId  get_stackframe_member_object_id (ea_t stack_id, ea_t offset, ea_t func_ea) override;
        YaToolObjectId  get_segment_id                  (const const_string_ref& name, ea_t ea) override;
        YaToolObjectId  get_segment_chunk_id            (YaToolObjectId seg_id, ea_t start, ea_t end) override;
        YaToolObjectId  get_binary_id                   () override;
        YaToolObjectId  get_enum_member_id              (ea_t enum_id, const const_string_ref& enum_name, ea_t const_id, const const_string_ref& const_name, const const_string_ref& const_value, bmask_t bmask, bool use_time) override;
        void            put_hash_enum_member            (const const_string_ref& enum_name, const const_string_ref& const_name, uint64_t const_value, YaToolObjectId id, bool in_persistent_cache) override;

        void            populate_struc_enum_ids();
        YaToolObjectId  hash_local_string(const const_string_ref& key_string, bool in_persistent_cache);
        YaToolObjectId  hash_string(const const_string_ref& key_string, bool in_persistent_cache);
        void            populate_persistent_cache();
        void            check_and_flush_cache_if_needed();
        void            put_hash_cache(const const_string_ref& key_string, YaToolObjectId id, bool in_persistent_cache);
        void            put_hash_cache_ea(ea_t key_string, YaToolObjectId id, bool in_persistent_cache);

        std::shared_ptr<Pool<std::string>>              pool_;
        std::string                                     string_start_;
        std::unordered_map<std::string, YaToolObjectId> cache_by_string_;
        std::unordered_map<std::string, YaToolObjectId> cache_by_string_persistent_;
        std::unordered_map<ea_t, YaToolObjectId>        cache_stackframe_;
        std::unordered_map<ea_t, YaToolObjectId>        cache_block_;
    };
}

std::shared_ptr<IHashProvider> MakeHashProvider()
{
    return std::make_shared<YaToolsHashProvider>();
}

YaToolsHashProvider::YaToolsHashProvider()
    : pool_(std::make_shared<Pool<std::string>>(4))
{
    uchar hash[16];
    const auto ok = retrieve_input_file_md5(hash);
    if(!ok)
        LOG(ERROR, "unable to retrieve input file MD5\n");

    char hexbuf[sizeof hash * 2];
    binhex<UpperCase, IgnorePadding, sizeof hash>(hexbuf, hash);
    string_start_ = md5_prefix;
    string_start_.append(hexbuf, sizeof hash * 2);
    string_start_ += separator;
    string_start_ += separator; // FIXME double
    populate_struc_enum_ids();
}

void YaToolsHashProvider::populate_persistent_cache()
{
    cache_by_string_persistent_ = cache_by_string_;
}

void YaToolsHashProvider::check_and_flush_cache_if_needed()
{
    if(cache_by_string_.size() <= cache_by_string_persistent_.size()  + MAX_CACHE_SIZE)
        return;
    cache_by_string_ = cache_by_string_persistent_;
}

void YaToolsHashProvider::put_hash_cache(const const_string_ref& key_string, YaToolObjectId id, bool in_persistent_cache)
{
    check_and_flush_cache_if_needed();

    const auto key = pool_->acquire();
    append(*key, key_string);
    if(USE_PERSISTENT_CACHE || in_persistent_cache)
        cache_by_string_[*key] = id;
    if(in_persistent_cache)
        cache_by_string_persistent_[*key] = id;

    LOG(DEBUG, "put_hash_cache: %s --> %s\n", key->c_str(),
            YaToolObjectId_To_StdString(id).c_str());
}

YaToolObjectId YaToolsHashProvider::hash_string(const const_string_ref& key_string, bool in_persistent_cache)
{
    const auto cache_it = cache_by_string_.find(append(*pool_->acquire(), key_string));
    if(cache_it != cache_by_string_.end())
        return cache_it->second;

    const auto hashed = YaToolObjectId_Hash(key_string.value, key_string.size);
    put_hash_cache(key_string, hashed, in_persistent_cache);
    return hashed;
}

YaToolObjectId YaToolsHashProvider::hash_local_string(const const_string_ref& key_string, bool in_persistent_cache)
{
    const auto key = pool_->acquire();
    *key = string_start_;
    append(*key, key_string);
    return hash_string(make_string_ref(*key), in_persistent_cache);
}

void YaToolsHashProvider::put_hash_cache_ea(ea_t ea, YaToolObjectId id, bool in_persistent_cache)
{
    const auto key = pool_->acquire();
    append_ea(*key, ea);
    put_hash_cache(make_string_ref(*key), id, in_persistent_cache);
}

YaToolObjectId YaToolsHashProvider::get_hash_for_ea(ea_t ea)
{
    const auto key = pool_->acquire();
    append_ea(*key, ea);
    return hash_local_string(make_string_ref(*key), false);
}

YaToolObjectId YaToolsHashProvider::get_stackframe_object_id(ea_t ea_frame, ea_t ea_func)
{
    const auto it = cache_stackframe_.find(ea_func);
    if(it != cache_stackframe_.end())
        return it->second;

    const auto key = pool_->acquire();
    append_ea(*key, ea_frame);
    const auto cache_it = cache_by_string_.find(*key);
    if(cache_it != cache_by_string_.end())
    {
        LOG(DEBUG, "get_stackframe_object_id cache hit: 0x%016llX (%s) --> %s\n",
                (uint64_t) ea_frame, get_struc_name(ea_frame).c_str(), YaToolObjectId_To_StdString(cache_it->second).c_str());
        return cache_it->second;
    }

    if(ea_func == BADADDR)
        ea_func = get_func_by_frame(ea_frame);
    append_ea(*key, ea_func);
    key->insert(0, stackframe_prefix);
    const auto id = hash_local_string(make_string_ref(*key), false);
    put_hash_struc_or_enum(ea_frame, id, false);
    LOG(DEBUG, "get_stackframe_object_id cache miss: 0x%016llX (%s) --> %s\n",
            (uint64_t) ea_frame, get_struc_name(ea_frame).c_str(), YaToolObjectId_To_StdString(id).c_str());
    cache_stackframe_.emplace(ea_func, id);
    return id;
}

void YaToolsHashProvider::put_hash_struc_or_enum(ea_t item_id, YaToolObjectId id, bool in_persistent_cache)
{
    put_hash_cache_ea(item_id, id, in_persistent_cache);
}

void YaToolsHashProvider::put_hash_enum_member(const const_string_ref& enum_name, const const_string_ref& const_name, uint64_t const_value, YaToolObjectId id, bool in_persistent_cache)
{
    const auto value = pool_->acquire();
    append_py_hex(*value, const_value);
    const auto key = pool_->acquire();
    append_enum(*key, enum_name, const_name, make_string_ref(*value));
    put_hash_cache(make_string_ref(*key), id, in_persistent_cache);
}

namespace
{
    int64_t get_clock_ms()
    {
        const auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    }

    qstring get_name(const const_string_ref& value, ea_t item_id)
    {
        if(value.size)
            return {};
        return get_struc_name(item_id);
    }
}

YaToolObjectId YaToolsHashProvider::get_struc_enum_object_id(ea_t item_id, const const_string_ref& name, bool use_time)
{
    const auto eaFunc = get_func_by_frame(item_id);
    if(eaFunc != BADADDR)
    {
        // if is a stack frame : we must only use function address to generate the hash
        // (not the timestamp)
        return get_stackframe_object_id(item_id, eaFunc);
    }

    const auto key = pool_->acquire();
    append_ea(*key, item_id);
    const auto cache_it = cache_by_string_.find(*key);
    if(cache_it != cache_by_string_.end())
    {
        LOG(DEBUG, "get_struc_enum_object_id cache hit: 0x%016llX (%s) --> %s\n",
                (uint64_t) item_id, get_name(name, item_id).c_str(), YaToolObjectId_To_StdString(cache_it->second).c_str());
        return cache_it->second;
    }

    const auto prefix = pool_->acquire();
    *prefix = struc_enum_prefix;
    if(use_time)
    {
        append_uint64<LowerCase, RemovePadding>(*prefix, get_clock_ms());
        *prefix += *key;
        *prefix += separator;
    }

    *prefix += separator;
    *prefix += *key;
    const auto id = hash_local_string(make_string_ref(*prefix), false);
    put_hash_struc_or_enum(item_id, id, use_time);
    LOG(DEBUG, "get_struc_enum_object_id cache miss: 0x%016llX (%p) --> %p\n",
        (uint64_t) item_id, get_name(name, item_id).c_str(), YaToolObjectId_To_StdString(id).c_str());
    return id;
}

YaToolObjectId YaToolsHashProvider::get_enum_member_id(ea_t enum_id, const const_string_ref& enum_name, ea_t const_id, const const_string_ref& const_name, const const_string_ref& const_value, bmask_t bmask, bool use_time)
{
    const auto key = pool_->acquire();
    append_enum(*key, enum_name, const_name, const_value);
    const auto cache_it = cache_by_string_.find(*key);
    if(cache_it != cache_by_string_.end())
    {
        LOG(DEBUG, "get_enum_member_id cache hit: 0x%016llX (%s) --> %s\n",
                (uint64_t) const_id, enum_name.value, YaToolObjectId_To_StdString(cache_it->second).c_str());
        return cache_it->second;
    }

    const auto enum_object_id = get_struc_enum_object_id(enum_id, enum_name, use_time);
    const auto str = pool_->acquire();
    *str += '-';
    append_uint64(*str, enum_object_id);
    *str += '-';
    str->append(const_name.value, const_name.size);
    *str += "-";
    str->append(const_value.value, const_value.size);

    if(bmask != BADADDR)
    {
        *str += '-';
        append_uint64<LowerCase, RemovePadding>(*str, bmask);
    }

    if(use_time)
    {
        *str += '-';
        append_uint64<LowerCase, RemovePadding>(*str, get_clock_ms());
    }

    const auto id = hash_local_string(make_string_ref(*str), false);
    put_hash_cache(make_string_ref(*key), id, true);
    LOG(DEBUG, "get_enum_member_id cache miss: 0x%016llX (%s) --> %s\n",
            (uint64_t) const_id, (make_string(enum_name) + "." + make_string(const_name)).c_str(), YaToolObjectId_To_StdString(id).c_str());
    return id;
}

void YaToolsHashProvider::populate_struc_enum_ids()
{
    for(auto idx = get_first_struc_idx(); idx != BADADDR; idx = get_next_struc_idx(idx))
        get_struc_enum_object_id(get_struc_by_idx(idx), {}, false);

    qstring enum_name;
    qstring enum_member_name;
    const auto pyhex = pool_->acquire();
    for(auto idx = 0u, end = get_enum_qty(); idx < end; ++idx)
    {
        const auto enum_id = getn_enum(idx);
        get_enum_name(&enum_name, enum_id);
        get_struc_enum_object_id(enum_id, ya::to_string_ref(enum_name), false);
        ya::walk_enum_members(enum_id, [&](const_t const_id, uval_t value, uchar /*serial*/, bmask_t bmask)
        {
            get_enum_member_name(&enum_member_name, const_id);
            pyhex->clear();
            append_py_hex(*pyhex, value);
            get_enum_member_id(enum_id, ya::to_string_ref(enum_name), const_id, ya::to_string_ref(enum_member_name), make_string_ref(*pyhex), bmask, false);
        });
    }

    populate_persistent_cache();
}

YaToolObjectId YaToolsHashProvider::get_function_basic_block_hash(ea_t block_ea, ea_t func_ea)
{
    const auto it = cache_block_.find(block_ea);
    if(it != cache_block_.end())
        return it->second;

    const auto key = pool_->acquire();
    *key = basic_block_prefix;
    append_int(*key, block_ea);
    *key += '-';
    append_int(*key, func_ea);
    const auto id = hash_local_string(make_string_ref(*key), false);
    cache_block_.emplace(block_ea, id);
    return id;
}

YaToolObjectId YaToolsHashProvider::get_reference_info_hash(ea_t ea, uint64_t value)
{
    const auto key = pool_->acquire();
    *key = reference_info_prefix;
    append_int(*key, ea);
    *key += '-';
    append_int(*key, value);
    return hash_local_string(make_string_ref(*key), false);
}

YaToolObjectId YaToolsHashProvider::get_struc_member_id(ea_t struc_id, ea_t offset, const const_string_ref& name)
{
    const auto id = get_struc_enum_object_id(struc_id, name, true);
    const auto key = pool_->acquire();
    *key = struct_member_prefix;
    append_uint64(*key, id);
    *key += '-';
    append_py_hex(*key, offset);
    return hash_local_string(make_string_ref(*key), false);
}

YaToolObjectId YaToolsHashProvider::get_stackframe_member_object_id(ea_t stack_id, ea_t offset, ea_t func_ea)
{
    const auto id = get_stackframe_object_id(stack_id, func_ea);
    const auto key = pool_->acquire();
    *key = struct_member_prefix;
    append_uint64(*key, id);
    *key += '-';
    append_py_hex(*key, offset);
    return hash_local_string(make_string_ref(*key), false);
}

YaToolObjectId YaToolsHashProvider::get_binary_id()
{
    return hash_local_string(make_string_ref(binary_prefix), false);
}

YaToolObjectId YaToolsHashProvider::get_segment_id(const const_string_ref& name, ea_t ea)
{
    const auto key = pool_->acquire();
    *key = segment_prefix;
    append(*key, name);
    append_int(*key, ea);
    return hash_local_string(make_string_ref(*key), false);
}

YaToolObjectId YaToolsHashProvider::get_segment_chunk_id(YaToolObjectId seg_id, ea_t start, ea_t end)
{
    const auto key = pool_->acquire();
    *key = segment_chunk_prefix;
    append_uint64(*key, seg_id);
    *key += '-';
    append_int(*key, start);
    *key += '-';
    append_int(*key, end);
    return hash_local_string(make_string_ref(*key), false);
}