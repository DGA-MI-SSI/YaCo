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

namespace std { template<typename T> class shared_ptr; }
struct YaToolsHashProvider;
class IModelAccept;

const int SEGMENT_CHUNK_MAX_SIZE = 0x10000;
const int MAX_BLOB_TAG_LEN = 0x1000;

std::string get_type(ea_t ea);

std::shared_ptr<IModelAccept> MakeIdaModel(YaToolsHashProvider* provider);
