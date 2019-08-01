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

#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include <functional>
#include <string>
#include <vector>

#include "YaEnums.hpp"

struct IModelVisitor;
struct IModel;
struct Signature;
struct HVersion;
struct HSignature;
struct HSystem;

typedef uint32_t VersionIndex;

typedef uint32_t HSignature_id_t;
typedef uint32_t VersionRelation_id_t;

typedef uint64_t offset_t;
typedef int32_t  operand_t;
typedef uint32_t flags_t;
typedef uint64_t YaToolObjectId;

YaToolObjectType_e  get_object_type(const char* object_type);
const char*         get_object_type_string(YaToolObjectType_e object_type);

extern const YaToolObjectType_e  ordered_types[OBJECT_TYPE_COUNT];
extern const std::vector<size_t> indexed_types;

typedef struct _Xref
{
    YaToolObjectId  id;
    offset_t        offset;
    operand_t       operand;
    int             path_idx;
} Xref, *PXref;

namespace std
{
    template<>
    struct hash<const YaToolObjectType_e>
    {
        size_t operator()(const YaToolObjectType_e& t) const
        {
            return t;
        }
    };
}

CommentType_e get_comment_type(const char* comment_type);

const char* get_comment_type_string(CommentType_e comment_type);

/*
 * light string reference
 */
struct const_string_ref
{
    const char* value;
    size_t      size;
};

inline std::string make_string(const const_string_ref& ref)
{
    return std::string(ref.value, ref.size);
}

inline const_string_ref make_string_ref(const char* value)
{
    return const_string_ref{value, strlen(value)};
}

inline const_string_ref make_string_ref(const std::string& value)
{
    return const_string_ref{value.data(), value.size()};
}

inline bool operator==(const const_string_ref& a, const const_string_ref& b)
{
    return a.size == b.size && (!a.value || !strcmp(a.value, b.value));
}

inline bool operator!=(const const_string_ref& a, const const_string_ref& b)
{
    return !(a == b);
}

inline bool operator<(const const_string_ref& a, const const_string_ref& b)
{
    return strcmp(a.value, b.value) < 0;
}

namespace std
{
    template<>
    struct hash<const_string_ref>
    {
        size_t operator()(const const_string_ref& v) const;
    };
}
