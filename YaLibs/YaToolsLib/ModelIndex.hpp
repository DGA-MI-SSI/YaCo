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
    VersionIndex from;
    VersionIndex to;
};
STATIC_ASSERT_POD(XrefTo);

struct Sig
{
    const_string_ref    key;
    HSignature_id_t     idx;
};
STATIC_ASSERT_POD(Sig);

struct VersionIdToIdx
{
    YaToolObjectId  id;
    VersionIndex    idx;
};
STATIC_ASSERT_POD(VersionIdToIdx);

struct ModelIndex
{
    std::vector<XrefTo>         xrefs_to_;
    std::vector<Sig>            sigs_;
    std::vector<Sig>            uniques_;
    std::vector<VersionIdToIdx> idxs_;
};

inline void reserve(ModelIndex& mi, size_t num_versions)
{
    mi.idxs_.reserve(num_versions);
    mi.sigs_.reserve(num_versions);
    mi.uniques_.reserve(num_versions);
    mi.xrefs_to_.reserve(num_versions); // FIXME
}

bool operator<(const VersionIdToIdx& a, const VersionIdToIdx& b)
{
    return a.id < b.id;
}

bool operator<(const VersionIdToIdx& a, YaToolObjectId b)
{
    return a.id < b;
}

void add_index(ModelIndex& mi, YaToolObjectId id, VersionIndex idx)
{
    mi.idxs_.push_back({id, idx});
}

void finish_indexs(ModelIndex& mi)
{
    std::sort(mi.idxs_.begin(), mi.idxs_.end());
}

optional<VersionIndex> find_index(const ModelIndex& mi, YaToolObjectId id)
{
    const auto& d = mi.idxs_;
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

void add_xref_to(ModelIndex& mi, VersionIndex from, YaToolObjectId to)
{
    if(const auto idx = find_index(mi, to))
        mi.xrefs_to_.push_back({from, *idx});
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
void walk_xrefs(const ModelIndex& mi, VersionIndex idx, uint32_t xref_idx, const T& operand)
{
    const auto end = mi.xrefs_to_.size();
    for(auto i = xref_idx; i < end; ++i)
    {
        const auto& xref = mi.xrefs_to_[i];
        if(idx != xref.to)
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
            mi.uniques_.push_back({v.first, v.second});
    std::sort(mi.uniques_.begin(), mi.uniques_.end());
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
    for(const auto& sig : mi.uniques_)
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
    const auto range = std::equal_range(mi.uniques_.begin(), mi.uniques_.end(), key);
    return range.first != range.second;
}
}
