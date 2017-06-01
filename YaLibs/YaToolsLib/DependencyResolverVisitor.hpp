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

#include <vector>

struct IObjectVisitorListener;

struct IDeleter
{
    virtual ~IDeleter() {}

    virtual void delete_objects    (const std::vector<YaToolObjectId>& objects) = 0;
    virtual void invalidate_objects(const std::vector<YaToolObjectId>& objects, bool set_to_null) = 0;
};

// We need both a validator & a deleter, but cannot derive from
// IModelVisitor in IDeleter due to diamond inheritance...
struct DependencyResolver
{
    std::shared_ptr<IModelVisitor>  visitor;
    std::shared_ptr<IDeleter>       deleter;
};

DependencyResolver MakeDependencyResolverVisitor(const std::shared_ptr<IModelVisitor>& visitor);
DependencyResolver MakeDependencyResolverVisitor(IObjectVisitorListener& listener, bool validate, const std::string& name);
