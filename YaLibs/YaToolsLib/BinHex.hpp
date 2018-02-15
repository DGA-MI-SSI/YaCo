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

size_t hexbin(void* vdst, size_t szdst, const char* src, size_t szsrc);

namespace
{

    const char hexchars_upper[] = "0123456789ABCDEF";
    const char hexchars_lower[] = "0123456789abcdef";

    enum BinHexFlags
    {
        LowerCase           = 1 << 0,   // use lower-case instead of upper-case
        RemovePadding       = 1 << 1,   // do not pad with '0'
        NullTerminate       = 1 << 2,   // ensure output is null terminated
        HexaPrefix          = 1 << 3,   // add 0x prefix
    };

    template<size_t szhex>
    void binhex(char* dst, const char (&hexchars)[szhex], const void* vsrc, size_t size)
    {
        const uint8_t* src = static_cast<const uint8_t*>(vsrc);
        for(size_t i = 0; i < size; ++i)
        {
            dst[i*2 + 0] = hexchars[src[i] >> 4];
            dst[i*2 + 1] = hexchars[src[i] & 0x0F];
        }
    }

    template<size_t size, uint32_t flags = 0, size_t szdst>
    const_string_ref binhex(char (&dst)[szdst], const void* src)
    {
        static_assert(szdst == !!(flags & HexaPrefix) * 2  + size * 2 + !!(flags & NullTerminate), "invalid destination size");
        const auto& hexchars = flags &  LowerCase ? hexchars_lower : hexchars_upper;
        const auto prefix = flags & HexaPrefix ? 2 : 0;
        if(flags & HexaPrefix)
        {
            dst[0] = '0';
            dst[1] = 'x';
        }
        binhex(&dst[prefix], hexchars, src, size);
        if(flags & NullTerminate)
            dst[prefix + size * 2] = 0;
        if(!(flags & RemovePadding))
            return {dst, prefix + size * 2};

        size_t skip = 0;
        // we need at least one 0
        while(skip + 1 < size * 2  && dst[prefix + skip] == '0')
            skip++;
        if(flags & HexaPrefix)
        {
            dst[prefix + skip - 2] = '0';
            dst[prefix + skip - 1] = 'x';
        }
        return {&dst[skip], prefix + size * 2 - skip};
    }

    inline uint8_t swap(uint8_t x)
    {
        return x;
    }

    inline uint16_t swap(uint16_t x)
    {
        return (x >> 8) | (x << 8);
    }

    inline uint32_t swap(uint32_t x)
    {
        return swap(uint16_t(x >> 16)) | (uint32_t(swap(uint16_t(x & 0xFFFF))) << 16);
    }

    inline uint64_t swap(uint64_t x)
    {
        return swap(uint32_t(x >> 32)) | (uint64_t(swap(uint32_t(x & 0xFFFFFFFF))) << 32);
    }

    template<uint32_t flags = 0, size_t szdst, typename T>
    const_string_ref to_hex(char (&dst)[szdst], T x)
    {
        x = swap(x);
        return binhex<sizeof x, flags>(dst, &x);
    }
}