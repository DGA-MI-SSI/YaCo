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

#include "Hash.hpp"

#include <stddef.h>
#include <farmhash.h>

namespace
{
    struct Hashed
    {
        uint64_t            parent;
        uint64_t            ea;
        YaToolObjectType_e  type;
    };

    inline void wbe16(char* ptr, uint16_t x)
    {
        ptr[0] = static_cast<uint8_t>(x >> 8);
        ptr[1] = static_cast<uint8_t>(x & 0xFF);
    }

    inline void wbe32(char* ptr, uint32_t x)
    {
        wbe16(&ptr[0], static_cast<uint16_t>(x >> 16));
        wbe16(&ptr[2], static_cast<uint16_t>(x & 0xFFFF));
    }

    inline void wbe64(char* ptr, uint64_t x)
    {
        wbe32(&ptr[0], static_cast<uint32_t>(x >> 32));
        wbe32(&ptr[4], static_cast<uint32_t>(x & 0xFFFFFFFF));
    }

    YaToolObjectId process_hash(const Hashed& value)
    {
        char buffer[20];
        static_assert(sizeof buffer == offsetof(Hashed, type) + sizeof value.type, "invalid Hashed layout");
        wbe64(&buffer[0x00], value.parent);
        wbe64(&buffer[0x08], value.ea);
        wbe32(&buffer[0x10], value.type);
        return util::Fingerprint64(buffer, sizeof buffer);
    }
}

YaToolObjectId hash::hash_binary()
{
    return process_hash({0, 0, OBJECT_TYPE_BINARY});
}

YaToolObjectId hash::hash_segment(uint64_t ea)
{
    return process_hash({0, ea, OBJECT_TYPE_SEGMENT});
}

YaToolObjectId hash::hash_segment_chunk(uint64_t ea)
{
    return process_hash({0, ea, OBJECT_TYPE_SEGMENT_CHUNK});
}

YaToolObjectId hash::hash_enum(const const_string_ref& name)
{
    const auto x = util::Fingerprint64(name.value, name.size);
    return process_hash({0, x, OBJECT_TYPE_ENUM});
}

YaToolObjectId hash::hash_enum_member(YaToolObjectId parent, const const_string_ref& name)
{
    const auto x = util::Fingerprint64(name.value, name.size);
    return process_hash({parent, x, OBJECT_TYPE_ENUM_MEMBER});
}

YaToolObjectId hash::hash_struc(const const_string_ref& name)
{
    const auto x = util::Fingerprint64(name.value, name.size);
    return process_hash({0, x, OBJECT_TYPE_STRUCT});
}

YaToolObjectId hash::hash_stack(uint64_t ea)
{
    return process_hash({0, ea, OBJECT_TYPE_STACKFRAME});
}

YaToolObjectId hash::hash_member(YaToolObjectId parent, uint64_t offset)
{
    // either STRUCT_MEMBER or STACKFRAME_MEMBER
    // we choose STRUCT_MEMBER for hash purposes
    return process_hash({parent, offset, OBJECT_TYPE_STRUCT_MEMBER});
}

YaToolObjectId hash::hash_function(uint64_t ea)
{
    return process_hash({0, ea, OBJECT_TYPE_FUNCTION});
}

YaToolObjectId hash::hash_ea(uint64_t ea)
{
    // either CODE, DATA or BASIC_BLOCK
    return process_hash({0, ea, OBJECT_TYPE_BASIC_BLOCK});
}

YaToolObjectId hash::hash_reference(uint64_t ea, uint64_t base)
{
    return process_hash({base, ea, OBJECT_TYPE_REFERENCE_INFO});
}
