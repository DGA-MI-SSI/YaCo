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

namespace std { template<typename T> class shared_ptr; }
class YaToolObjectVersion;
struct YaToolsHashProvider;

struct Tid
{
    ea_t                tid;
    YaToolObjectType_e  type;
};

struct IExporter
{
    virtual bool set_type               (ea_t ea, const std::string& prototype) = 0;
    virtual bool set_struct_member_type (ea_t ea, const std::string& prototype) = 0;
    virtual void set_tid                (YaToolObjectId id, ea_t tid, YaToolObjectType_e type) = 0;
    virtual Tid  get_tid                (YaToolObjectId id) = 0;
    virtual void analyze_function       (ea_t ea) = 0;

    virtual void make_function          (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea) = 0;
    virtual void make_views             (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea) = 0;
    virtual void make_code              (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea) = 0;
    virtual void make_data              (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea) = 0;
    virtual void make_enum              (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea) = 0;
    virtual void make_enum_member       (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea) = 0;
    virtual void make_name              (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea, bool is_in_func) = 0;
    virtual void make_comments          (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea) = 0;
    virtual void make_header_comments   (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea) = 0;
    virtual void make_segment           (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea) = 0;
    virtual void make_segment_chunk     (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea) = 0;
    virtual void make_basic_block       (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea) = 0;
    virtual void make_reference_info    (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea) = 0;
    virtual void clear_struct_fields    (std::shared_ptr<YaToolObjectVersion>& version, ea_t struct_id) = 0;
};

std::shared_ptr<IExporter> MakeExporter(YaToolsHashProvider* provider);
