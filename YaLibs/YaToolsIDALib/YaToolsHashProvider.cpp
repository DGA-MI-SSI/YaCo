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

#include <YaTypes.hpp>
#include "Ida.h"

#include "YaToolsHashProvider.hpp"

#include <Logger.h>
#include <Yatools.h>
#include "../Helpers.h"
#include "YaHelpers.hpp"

#include <farmhash.h>

#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("hash", (FMT), ## __VA_ARGS__)

namespace
{
    struct YaToolsHashProvider
        : public IHashProvider
    {
        // IHashProvider methods
        YaToolObjectId  get_binary_id       () override;
        YaToolObjectId  get_segment_id      (ea_t ea) override;
        YaToolObjectId  get_segment_chunk_id(ea_t ea) override;
        YaToolObjectId  get_enum_id         (const const_string_ref& name) override;
        YaToolObjectId  get_enum_member_id  (YaToolObjectId parent, const const_string_ref& name) override;
        YaToolObjectId  get_struc_id        (const const_string_ref& name) override;
        YaToolObjectId  get_stack_id        (ea_t ea) override;
        YaToolObjectId  get_member_id       (YaToolObjectId parent, ea_t offset) override;
        YaToolObjectId  get_function_id     (ea_t ea) override;
        YaToolObjectId  get_ea_id           (ea_t ea) override;
        YaToolObjectId  get_reference_id    (ea_t base, uint64_t target) override;
    };

    struct Hashed
    {
        uint64_t            parent;
        uint64_t            ea;
        YaToolObjectType_e  type;
    };

    inline void wbe32(char* ptr, uint32_t x)
    {
        *(uint32_t*) ptr = qhtonl(x);
    }

    inline void wbe64(char* ptr, uint64_t x)
    {
        wbe32(&ptr[0], static_cast<uint32_t>(x >> 32));
        wbe32(&ptr[4], static_cast<uint32_t>(x & 0xFFFFFFFF));
    }

    YaToolObjectId hash(const Hashed& value)
    {
        char buffer[20];
        static_assert(sizeof buffer == offsetof(Hashed, type) + sizeof value.type, "invalid Hashed layout");
        wbe64(&buffer[0x00], value.parent);
        wbe64(&buffer[0x08], value.ea);
        wbe32(&buffer[0x10], value.type);
        return util::Fingerprint64(buffer, sizeof buffer);
    }
}

std::shared_ptr<IHashProvider> MakeHashProvider()
{
    return std::make_shared<YaToolsHashProvider>();
}

YaToolObjectId YaToolsHashProvider::get_binary_id()
{
    return hash({0, 0, OBJECT_TYPE_BINARY});
}

YaToolObjectId YaToolsHashProvider::get_segment_id(ea_t ea)
{
    return hash({0, ea, OBJECT_TYPE_SEGMENT});
}

YaToolObjectId YaToolsHashProvider::get_segment_chunk_id(ea_t ea)
{
    return hash({0, ea, OBJECT_TYPE_SEGMENT_CHUNK});
}

YaToolObjectId YaToolsHashProvider::get_enum_id(const const_string_ref& name)
{
    const auto x = util::Fingerprint64(name.value, name.size);
    return hash({0, x, OBJECT_TYPE_ENUM});
}

YaToolObjectId YaToolsHashProvider::get_enum_member_id(YaToolObjectId parent, const const_string_ref& name)
{
    const auto x = util::Fingerprint64(name.value, name.size);
    return hash({parent, x, OBJECT_TYPE_ENUM_MEMBER});
}

YaToolObjectId YaToolsHashProvider::get_struc_id(const const_string_ref& name)
{
    const auto x = util::Fingerprint64(name.value, name.size);
    return hash({0, x, OBJECT_TYPE_STRUCT});
}

YaToolObjectId YaToolsHashProvider::get_stack_id(ea_t ea)
{
    return hash({0, ea, OBJECT_TYPE_STACKFRAME});
}

YaToolObjectId YaToolsHashProvider::get_member_id(YaToolObjectId parent, ea_t offset)
{
    // either STRUCT_MEMBER or STACKFRAME_MEMBER
    // we choose STRUCT_MEMBER for hash purposes
    return hash({parent, offset, OBJECT_TYPE_STRUCT_MEMBER});
}

YaToolObjectId  YaToolsHashProvider::get_function_id(ea_t ea)
{
    return hash({0, ea, OBJECT_TYPE_FUNCTION});
}

YaToolObjectId YaToolsHashProvider::get_ea_id(ea_t ea)
{
    // either BASIC_BLOCK, DATA or CODE
    // we choose BASIC_BLOCK for hash purposes
    return hash({0, ea, OBJECT_TYPE_BASIC_BLOCK});
}

YaToolObjectId YaToolsHashProvider::get_reference_id(ea_t ea, uint64_t base)
{
    return hash({base, ea, OBJECT_TYPE_REFERENCE_INFO});
}
