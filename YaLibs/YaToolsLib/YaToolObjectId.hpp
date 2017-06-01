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
#include <string>

#define YATOOL_OBJECT_ID_LENGTH 8
#define YATOOL_OBJECT_ID_STR_LEN (sizeof(YaToolObjectId)*2)

YaToolObjectId  YaToolObjectId_Hash             (const std::string& s);
YaToolObjectId  YaToolObjectId_Hash             (const char* s, size_t len);
std::string     YaToolObjectId_To_StdString     (YaToolObjectId id);
void            YaToolObjectId_To_String        (char* output, size_t output_len, YaToolObjectId id);
YaToolObjectId  YaToolObjectId_From_String      (const char* input, size_t input_len);
YaToolObjectId  YaToolObjectId_From_StdString   (const std::string& str);
