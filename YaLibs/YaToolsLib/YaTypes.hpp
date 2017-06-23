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
#include <string>
#include <memory>
#include <assert.h>
#include <unordered_map>
#include <ostream>
#include <farmhash.h>

class IModelVisitor;
struct IModel;
struct Signature;
struct HVersion;
struct HObject;
struct HSignature;
struct HSystem;

typedef uint32_t HObject_id_t;
typedef uint32_t HVersion_id_t;
typedef uint32_t HSystem_id_t;
typedef uint32_t HSignature_id_t;
typedef uint32_t VersionRelation_id_t;

typedef uint64_t offset_t;
typedef int32_t  operand_t;
typedef uint32_t flags_t;
typedef uint64_t YaToolObjectId;
typedef uint32_t YaToolFlag_T;

#define PRIXOFFSET  PRIX64
#define PRIiOFFSET  PRIi64

#define UNKNOWN_ADDR    static_cast<offset_t>(~0)

static const YaToolObjectId InvalidId = ~0u;

enum ContinueWalking_e
{
    WALK_CONTINUE,
    WALK_STOP,
};

enum YaToolObjectType_e
{
    OBJECT_TYPE_UNKNOWN,
    OBJECT_TYPE_BINARY,
    OBJECT_TYPE_DATA,
    OBJECT_TYPE_CODE,
    OBJECT_TYPE_FUNCTION,
    OBJECT_TYPE_STRUCT,
    OBJECT_TYPE_ENUM,
    OBJECT_TYPE_ENUM_MEMBER,
    OBJECT_TYPE_BASIC_BLOCK,
    OBJECT_TYPE_SEGMENT,
    OBJECT_TYPE_SEGMENT_CHUNK,
    OBJECT_TYPE_STRUCT_MEMBER,
    OBJECT_TYPE_STACKFRAME,
    OBJECT_TYPE_STACKFRAME_MEMBER,
    OBJECT_TYPE_REFERENCE_INFO,
    OBJECT_TYPE_COUNT,
};

enum SignatureMethod_e
{
    SIGNATURE_UNKNOWN,
    SIGNATURE_FIRSTBYTE,
    SIGNATURE_FULL,
    SIGNATURE_INVARIANTS,
    SIGNATURE_OPCODE_HASH,
    SIGNATURE_INTRA_GRAPH_HASH,
    SIGNATURE_STRING_HASH,
    SIGNATURE_METHOD_COUNT,
};

enum SignatureAlgo_e
{
    SIGNATURE_ALGORITHM_UNKNOWN,
    SIGNATURE_ALGORITHM_NONE,
    SIGNATURE_ALGORITHM_CRC32,
    SIGNATURE_ALGORITHM_MD5,
    SIGNATURE_ALGORITHM_COUNT,
};

YaToolObjectType_e get_object_type(const char* object_type);

const char* get_object_type_string(YaToolObjectType_e object_type);
const char* get_object_swig_type_string(YaToolObjectType_e object_type);

#ifndef SWIG
inline std::ostream & operator<<(std::ostream& oss, YaToolObjectType_e type)
{
    return oss << get_object_swig_type_string(type);
}

inline std::string & operator<<(std::string& oss, YaToolObjectType_e type)
{
    return oss.append(get_object_swig_type_string(type));
}

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
#endif//SWIG

/*
 * Type of comments
 * When exporting informations, the order should always be that of the
 * enum members (first, repetable, the non_repeatable, anterior, posterior, bookmark...)
 */
enum CommentType_e
{
    COMMENT_UNKNOWN,
    COMMENT_REPEATABLE,
    COMMENT_NON_REPEATABLE,
    COMMENT_ANTERIOR,
    COMMENT_POSTERIOR,
    COMMENT_BOOKMARK,
    COMMENT_COUNT,
};

CommentType_e get_comment_type(const char* comment_type);

const char* get_comment_type_string(CommentType_e comment_type);

std::string get_uint_hex(uint64_t value);

#ifndef SWIG
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

inline bool operator<(const const_string_ref& a, const const_string_ref& b)
{
    return strcmp(a.value, b.value) < 0;
}

namespace std
{
    template<>
    struct hash<const_string_ref>
    {
        size_t operator()(const const_string_ref& v) const
        {
            return util::Hash(v.value, v.size);
        }
    };
}
#endif //SWIG
