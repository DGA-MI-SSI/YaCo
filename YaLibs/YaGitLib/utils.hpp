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

#ifndef UTILS_H__
#define UTILS_H__

#include <memory>
#include <string>

struct File_ABC
{
    virtual ~File_ABC() {}

    virtual const std::string& GetPath() const = 0;
    virtual void Write(const char* line) const = 0;
    virtual void Flush() const = 0;
    virtual void Close() const = 0;
};
std::shared_ptr<File_ABC> CreateTempFile();

#endif
