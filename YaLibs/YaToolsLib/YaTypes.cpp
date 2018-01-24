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

#include "YaTypes.hpp"
#include "Hexa.h"
#include "../Helpers.h"

#include <farmhash.h>

#include <type_traits>
#include <vector>

#ifdef _MSC_VER
#define stricmp _stricmp
#else
#include <strings.h>
#define stricmp strcasecmp
#endif

static const char gObjectTypes[][24] =
{
    "unknown",
    "binary",
    "data",
    "code",
    "function",
    "struc",
    "enum",
    "enum_member",
    "basic_block",
    "segment",
    "segment_chunk",
    "strucmember",
    "stackframe",
    "stackframe_member",
    "reference_info",
};
static_assert(COUNT_OF(gObjectTypes) == OBJECT_TYPE_COUNT, "invalid number of object types");

YaToolObjectType_e get_object_type(const char* object_type)
{
    for(size_t i = 0; i < COUNT_OF(gObjectTypes); ++i)
        if(!stricmp(gObjectTypes[i], object_type))
            return static_cast<YaToolObjectType_e>(i);
    return OBJECT_TYPE_UNKNOWN;
}

const char* get_object_type_string(YaToolObjectType_e object_type)
{
    if(object_type < OBJECT_TYPE_UNKNOWN || object_type >= OBJECT_TYPE_COUNT)
        object_type = OBJECT_TYPE_UNKNOWN;
    return gObjectTypes[object_type];
}

const YaToolObjectType_e ordered_types[] =
{
    OBJECT_TYPE_BINARY,
    OBJECT_TYPE_STRUCT,
    OBJECT_TYPE_STRUCT_MEMBER,
    OBJECT_TYPE_ENUM,
    OBJECT_TYPE_ENUM_MEMBER,
    OBJECT_TYPE_SEGMENT,
    OBJECT_TYPE_SEGMENT_CHUNK,
    OBJECT_TYPE_FUNCTION,
    OBJECT_TYPE_STACKFRAME,
    OBJECT_TYPE_STACKFRAME_MEMBER,
    OBJECT_TYPE_REFERENCE_INFO,
    OBJECT_TYPE_CODE,
    OBJECT_TYPE_DATA,
    OBJECT_TYPE_BASIC_BLOCK,
    OBJECT_TYPE_UNKNOWN,
};
static_assert(COUNT_OF(ordered_types) == OBJECT_TYPE_COUNT, "invalid ordered_types");

const std::vector<size_t> indexed_types = []
{
    std::vector<size_t> indexed;
    indexed.resize(OBJECT_TYPE_COUNT);
    for(size_t i = 0; i < OBJECT_TYPE_COUNT; ++i)
        indexed[ordered_types[i]] = i;
    return indexed;
}();

static const char gComments[][24] =
{
    "unknown",
    "repeatable_comment",
    "nonrepeatable_comment",
    "anterior_comment",
    "posterior_comment",
    "bookmark",
};
static_assert(COUNT_OF(gComments) == COMMENT_COUNT, "invalid comment type strings");

CommentType_e get_comment_type(const char* comment_type)
{
    for(size_t i = 0; i < COUNT_OF(gComments); ++i)
        if(!stricmp(gComments[i], comment_type))
            return static_cast<CommentType_e>(i);
    return COMMENT_UNKNOWN;
}

const char* get_comment_type_string(CommentType_e comment_type)
{
    if(comment_type < 0 || comment_type >= COMMENT_COUNT)
        comment_type = COMMENT_UNKNOWN;
    return gComments[comment_type];
}


STATIC_ASSERT_POD(const_string_ref);

size_t std::hash<const_string_ref>::operator()(const const_string_ref& v) const
{
    return util::Hash(v.value, v.size);
}

YaToolObjectId YaToolObjectId_From_String(const char* input, size_t input_len)
{
    YaToolObjectId id;
    UNUSED(input_len);
    assert(input_len == 16);
    int param = sscanf(input, "%016" PRIX64, &id);
    UNUSED(param);
    assert(param == 1);
    return id;
}