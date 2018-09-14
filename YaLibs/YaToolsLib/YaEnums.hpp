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
    OBJECT_TYPE_LOCAL_TYPE,
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