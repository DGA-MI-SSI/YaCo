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

#include "YaToolObjectId.hpp"

#include "../Helpers.h"

YaToolObjectId YaToolObjectId_Hash(const std::string& s)
{
    return util::Fingerprint64(s);
}

YaToolObjectId YaToolObjectId_Hash(const char* s, size_t len)
{
    return util::Fingerprint64(s, len);
}

void YaToolObjectId_To_String(char* output, size_t output_len, YaToolObjectId id)
{
    assert(output_len >= (sizeof(YaToolObjectId)*2+1));
    int param = snprintf(output, output_len, "%016" PRIX64, id);
    UNUSED(param);
    assert(param == sizeof(YaToolObjectId)*2);
}

std::string YaToolObjectId_To_StdString(YaToolObjectId id)
{
    char id_str[YATOOL_OBJECT_ID_STR_LEN+1];
    YaToolObjectId_To_String(id_str, YATOOL_OBJECT_ID_STR_LEN+1, id);
    return std::string(id_str, YATOOL_OBJECT_ID_STR_LEN);
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

YaToolObjectId YaToolObjectId_From_StdString(const std::string& str)
{
    return YaToolObjectId_From_String(str.c_str(), str.length());
}
