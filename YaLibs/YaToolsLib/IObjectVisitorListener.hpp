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

class YaToolObjectVersion;

struct IObjectVisitorListener
{
    virtual ~IObjectVisitorListener() {}

    virtual void object_version_visited         (YaToolObjectId object_id, const std::shared_ptr<YaToolObjectVersion>& object) = 0;
    virtual void deleted_object_version_visited (YaToolObjectId object_id) = 0;
    virtual void default_object_version_visited (YaToolObjectId object_id) = 0;
};

std::shared_ptr<IModelVisitor> MakeSingleObjectVisitor(IObjectVisitorListener& listener);
