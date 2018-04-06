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

#include "Helpers.h"

#include <algorithm>
#include <vector>
#include <unordered_map>

#ifdef _MSC_VER
#   include <optional.hpp>
using namespace nonstd;
#else
#   include <experimental/optional>
using namespace std::experimental;
#endif

namespace
{
struct XrefTo
{
    HObject_id_t from;
    HObject_id_t to;
};
STATIC_ASSERT_POD(XrefTo);

struct Sig
{
    const_string_ref    key;
    HSignature_id_t     idx;
};
STATIC_ASSERT_POD(Sig);

struct ObjectId
{
    YaToolObjectId  id;
    HObject_id_t    idx;
};
STATIC_ASSERT_POD(ObjectId);

struct ModelIndex
{
    std::vector<XrefTo>     xrefs_to_;
    std::vector<Sig>        sigs_;
    std::vector<Sig>        unique_sigs_;
    std::vector<ObjectId>   object_ids_;
};

inline void reserve(ModelIndex& mi, size_t num_objects, size_t num_versions)
{
    mi.object_ids_.reserve(num_objects);
    mi.sigs_.reserve(num_versions);
    mi.unique_sigs_.reserve(num_versions);
    mi.xrefs_to_.reserve(num_versions); // FIXME
}

bool operator<(const ObjectId& a, const ObjectId& b)
{
    return a.id < b.id;
}

bool operator<(const ObjectId& a, YaToolObjectId b)
{
    return a.id < b;
}

void add_object(ModelIndex& mi, YaToolObjectId id, HObject_id_t idx)
{
    mi.object_ids_.push_back({id, idx});
}

void finish_objects(ModelIndex& mi)
{
    std::sort(mi.object_ids_.begin(), mi.object_ids_.end());
}

optional<HObject_id_t> find_object_id(const ModelIndex& mi, YaToolObjectId id)
{
    const auto& d = mi.object_ids_;
    const auto it = std::lower_bound(d.begin(), d.end(), id);
    if(it == d.end() || it->id != id)
        return nullopt;
    return it->idx;
}

bool operator<(const XrefTo& a, const XrefTo& b)
{
    return std::make_pair(a.to, a.from) < std::make_pair(b.to, b.from);
}

bool operator==(const XrefTo& a, const XrefTo& b)
{
    return std::make_pair(a.to, a.from) == std::make_pair(b.to, b.from);
}

void add_xref_to(ModelIndex& mi, HObject_id_t from, YaToolObjectId to)
{
    if(const auto id = find_object_id(mi, to))
        mi.xrefs_to_.push_back({from, *id});
}

template<typename T>
void finish_xrefs(ModelIndex& mi, const T& operand)
{
    std::sort(mi.xrefs_to_.begin(), mi.xrefs_to_.end());
    mi.xrefs_to_.erase(std::unique(mi.xrefs_to_.begin(), mi.xrefs_to_.end()), mi.xrefs_to_.end());
    uint32_t xref_to_idx = 0;
    for(const auto& xref : mi.xrefs_to_)
        operand(xref.to, xref_to_idx++);
}

template<typename T>
void walk_xrefs(const ModelIndex& mi, HObject_id_t object_idx, uint32_t xref_idx, const T& operand)
{
    const auto end = mi.xrefs_to_.size();
    for(auto i = xref_idx; i < end; ++i)
    {
        const auto& xref = mi.xrefs_to_[i];
        if(object_idx != xref.to)
            return;
        if(operand(xref.from) != WALK_CONTINUE)
            return;
    }
}

bool operator<(const Sig& a, const Sig& b)
{
    return std::less<>()(a.key, b.key);
}

bool operator<(const Sig& a, const const_string_ref& b)
{
    return std::less<>()(a.key, b);
}

bool operator<(const const_string_ref& a, const Sig& b)
{
    return std::less<>()(a, b.key);
}

typedef std::unordered_map<const_string_ref, HSignature_id_t> SigMap;
const HSignature_id_t invalid_sig_id = ~0u;

void add_sig(ModelIndex& mi, SigMap& sigmap, const const_string_ref& key, HSignature_id_t id)
{
    mi.sigs_.push_back({key, id});
    auto it = sigmap.insert({key, id});
    if(!it.second)
        it.first->second = invalid_sig_id;
}

void finish_sigs(ModelIndex& mi, const SigMap& sigmap)
{
    for(const auto& v : sigmap)
        if(v.second != invalid_sig_id)
            mi.unique_sigs_.push_back({v.first, v.second});
    std::sort(mi.unique_sigs_.begin(), mi.unique_sigs_.end());
    std::sort(mi.sigs_.begin(), mi.sigs_.end());
}

template<typename T>
void walk_sigs(const ModelIndex& mi, const const_string_ref& key, const T& operand)
{
    const auto range = std::equal_range(mi.sigs_.begin(), mi.sigs_.end(), key);
    for(auto it = range.first; it != range.second; ++it)
        if(operand(*it) != WALK_CONTINUE)
            return;
}

template<typename T>
void walk_all_unique_sigs(const ModelIndex& mi, const T& operand)
{
    for(const auto& sig : mi.unique_sigs_)
        if(operand(sig) != WALK_CONTINUE)
            return;
}

size_t num_sigs(const ModelIndex& mi, const const_string_ref& key)
{
    const auto range = std::equal_range(mi.sigs_.begin(), mi.sigs_.end(), key);
    return std::distance(range.first, range.second);
}

bool is_unique_sig(const ModelIndex& mi, const const_string_ref& key)
{
    const auto range = std::equal_range(mi.unique_sigs_.begin(), mi.unique_sigs_.end(), key);
    return range.first != range.second;
}
}
