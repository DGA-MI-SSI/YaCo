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
#include "BinHex.hpp"

#include <algorithm>

namespace
{
    const uint8_t charhexs[] =
    {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, // '0' 0x30 to '9' 0x39
        0, 0, 0, 0, 0, 0,             // 0x3A to 0x3F
        0,                            // 0x40
        0xA, 0xB, 0xC, 0xD, 0xE, 0xF, // 'A' 0x41 to 'F' 0x46
        0, 0, 0,                      // 0x47 to 0x49
        0, 0, 0, 0, 0, 0,             // 0x4A to 0x4F
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x50 to 0x59
        0, 0, 0, 0, 0, 0,             // 0x5A to 0x5F
        0,                            // 0x60
        0xA, 0xB, 0xC, 0xD, 0xE, 0xF, // 'a' 0x61 to 'f' 0x66
    };

    uint8_t cliphex(char x)
    {
        return charhexs[std::max('0', std::min('f', x)) - '0'];
    }
}

size_t hexbin(void* vdst, size_t szdst, const char* src, size_t szsrc)
{
    uint8_t* dst = static_cast<uint8_t*>(vdst);
    const auto min = std::min(szdst, szsrc >> 1);
    for(size_t i = 0; i < min; ++i)
    {
        const auto high = cliphex(src[i*2 + 0]);
        const auto low  = cliphex(src[i*2 + 1]);
        dst[i] = (high << 4) | low;
    }
    return min;
}
