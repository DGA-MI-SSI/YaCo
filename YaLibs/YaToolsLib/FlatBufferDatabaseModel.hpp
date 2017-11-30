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

#include <memory>
#include <string>
#include <vector>

struct IModel;

struct Mmap_ABC;

std::shared_ptr<IModel> MakeFlatBufferDatabaseModel(const std::shared_ptr<Mmap_ABC>& mmap);
std::shared_ptr<IModel> MakeFlatBufferDatabaseModel(const std::string& filename);

std::shared_ptr<IModel> MakeMultiFlatBufferDatabaseModel(const std::vector<std::string>& filenames);

std::shared_ptr<IModel> MakeFlatBufferDatabaseModel(const std::string& filename);
std::shared_ptr<IModel> MakeMultiFlatBufferDatabaseModel(const std::vector<std::string>& filenames);

