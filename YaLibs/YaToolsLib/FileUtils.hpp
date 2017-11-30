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

#ifndef FILEUTILS_H__
#define FILEUTILS_H__

#include <stddef.h>

#include <memory>
#include <string>

struct Mmap_ABC
{
    virtual ~Mmap_ABC() {}
    virtual const void* Get() const = 0;
    virtual size_t      GetSize() const = 0;
};
std::shared_ptr<Mmap_ABC> MmapFile(const char* pPath);

std::string CreateTemporaryDirectory(const std::string& base);

#endif
