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

#include "IModelVisitor.hpp"

#include <memory>
#include <vector>
#include <string>

struct ExportedBuffer
{
    const void* value;
    size_t size;
};

struct IFlatBufferVisitor
    : public IModelVisitor
{
    ~IFlatBufferVisitor() override {}

    virtual ExportedBuffer GetBuffer() const = 0;
};

std::shared_ptr<IFlatBufferVisitor> MakeFlatBufferVisitor();

bool merge_yadbs_to_yadb(const std::string& dest, const std::vector<std::string>& sources);
bool merge_xmls_to_yadb(const std::string& dest, const std::vector<std::string>& sources);
