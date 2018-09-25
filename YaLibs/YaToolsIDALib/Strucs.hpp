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

#include <stddef.h>
#include <memory>

#include "YaTypes.hpp"

struct IModelVisitor;
struct HVersion;

using Tag = std::string;

namespace strucs
{
    YaToolObjectId  hash    (ea_t id);
    Tag             get_tag (ea_t id);
    void            rename  (const char* oldname, const char* newname);
    Tag             remove  (ea_t id);
    void            set_tag (ea_t id, const Tag& tag);
    void            visit   (IModelVisitor& v, const char* name);
    Tag             accept  (const HVersion& version);

    struct IFilter
    {
        virtual ~IFilter() = default;

        virtual YaToolObjectId is_valid(const HVersion& version) = 0;
    };
    std::shared_ptr<IFilter> make_filter();
}

namespace enums
{
    YaToolObjectId  hash    (enum_t id);
    Tag             get_tag (enum_t id);
    void            rename  (const char* oldname, const char* newname);
    Tag             remove  (enum_t id);
    void            set_tag (enum_t id, const Tag& tag);
    void            visit   (IModelVisitor& v, const char* name);
    Tag             accept  (const HVersion& version);
}

namespace local_types
{
    struct Type
    {
        tinfo_t tif;
        qstring name;
        bool    ghost;
    };
    bool identify(Type* type, uint32_t ord);

    YaToolObjectId  hash    (uint32_t ord);
    YaToolObjectId  hash    (const char* name);
    Tag             get_tag (const char* name);
    void            rename  (const char* oldname, const char* newname);
    Tag             remove  (const char* type);
    void            set_tag (const char* type, const Tag& tag);
    void            visit   (IModelVisitor& v, const Type& type);
    Tag             accept  (const HVersion& hver);
}
