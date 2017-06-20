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

#include "IModelVisitor.hpp"
#include "YaTypes.hpp"
#include "YaToolsIDANativeLib.hpp"

#include <unordered_set>

namespace std { template<typename T> class shared_ptr; }
class YaToolObjectVersion;
struct YaToolsHashProvider;

struct IDANativeExporter
{
    void make_name(std::shared_ptr<YaToolObjectVersion> object_version, ea_t address, bool is_in_func);

    void make_anterior_comment (ea_t address, const char* comment);
    void make_posterior_comment(ea_t address, const char* comment);

    void make_comments(std::shared_ptr<YaToolObjectVersion> object_version, ea_t address);
    void make_header_comments(std::shared_ptr<YaToolObjectVersion>& object_version, ea_t ea);

    void make_segment(std::shared_ptr<YaToolObjectVersion> object_version, ea_t address);
    void make_segment_chunk(std::shared_ptr<YaToolObjectVersion> object_version, ea_t address);
    bool set_type(ea_t ea, const std::string& prototype);
    bool set_struct_member_type(ea_t ea, const std::string& prototype);

    void        set_tid(YaToolObjectId id, uint64_t tid);
    uint64_t    get_tid(YaToolObjectId id);


    void analyze_function(ea_t ea);
    void make_function(std::shared_ptr<YaToolObjectVersion> version, ea_t ea);

    void make_views(std::shared_ptr<YaToolObjectVersion> version, ea_t ea);

    void make_code(std::shared_ptr<YaToolObjectVersion> version, ea_t ea);
    void make_data(std::shared_ptr<YaToolObjectVersion> version, ea_t ea);

    void make_enum(YaToolsHashProvider* provider, std::shared_ptr<YaToolObjectVersion> version, ea_t ea);
    void make_enum_member(YaToolsHashProvider* provider, std::shared_ptr<YaToolObjectVersion> version, ea_t ea);

#ifndef SWIG
    std::string patch_prototype(const std::string& prototype, ea_t ea);

    using IdMap = std::unordered_map<YaToolObjectId, uint64_t>;
    using EnumMemberMap = std::unordered_map<uint64_t, enum_t>;

private:
    IdMap tids;
    EnumMemberMap enum_members;
    YaToolsIDANativeLib tools;
#endif
};

