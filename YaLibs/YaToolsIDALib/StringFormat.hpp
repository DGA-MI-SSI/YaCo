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

namespace
{
    const char hexchars_upper[] = "0123456789ABCDEF";
    const char hexchars_lower[] = "0123456789abcdef";

    enum CasePolicy
    {
        UpperCase,
        LowerCase,
    };

    enum PadPolicy
    {
        IgnorePadding,
        RemovePadding,
    };

    template<CasePolicy casep, PadPolicy padp, size_t size, size_t szdst>
    const_string_ref binhex(char (&dst)[szdst], const void* vsrc)
    {
        static_assert(szdst == size * 2, "invalid destination size");
        const uint8_t* src = static_cast<const uint8_t*>(vsrc);
        const auto& hexchars = casep == UpperCase ? hexchars_upper : hexchars_lower;
        for(size_t i = 0; i < size; ++i)
        {
            dst[i*2 + 0] = hexchars[src[i] >> 4];
            dst[i*2 + 1] = hexchars[src[i] & 0x0F];
        }
        if(padp == IgnorePadding)
            return {dst, size * 2};
        
        size_t skip = 0;
        // we need at least one 0
        while(skip + 1 < size * 2  && dst[skip] == '0')
            skip++;
        return {&dst[skip], size * 2 - skip};
    }

    inline uint8 swap(uint8_t x)
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

    template<CasePolicy casep = UpperCase, PadPolicy padp = IgnorePadding, size_t szdst, typename T>
    const_string_ref to_hex(char (&dst)[szdst], T x)
    {
        x = swap(x);
        return binhex<casep, padp, sizeof x>(dst, &x);
    }

    template<CasePolicy casep = UpperCase, PadPolicy padp = IgnorePadding, typename T>
    void append_uint64(T& dst, uint64_t x)
    {
        char buf[sizeof x * 2];
        const auto str = to_hex<casep, padp>(buf, x);
        dst.append(str.value, str.size);
    }

    // duplicate hex function behavior from python
    template<typename T, typename U>
    void to_py_hex(T& dst, U value)
    {
        dst = "0x";
        append_uint64<LowerCase, RemovePadding>(dst, value);
        dst += 'L';
    }
}