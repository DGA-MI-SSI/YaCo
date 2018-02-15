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

#include "HObject.hpp"

#include "Helpers.h"

STATIC_ASSERT_POD(HObject);

void HObject::walk_versions(const IObjects::OnVersionFn& fnWalk) const
{
    model_->walk_versions(id_, fnWalk);
}

YaToolObjectType_e HObject::type() const
{
    return model_->type(id_);
}

YaToolObjectId HObject::id() const
{
    return model_->id(id_);
}

bool HObject::match(const HObject& object) const
{
    return model_->match(id_, object);
}

void HObject::walk_xrefs_from(const IObjects::OnXrefFromFn& fnWalk) const
{
    model_->walk_xrefs_from(id_, fnWalk);
}

void HObject::walk_xrefs_to(const IObjects::OnObjectFn& fnWalk) const
{
    model_->walk_xrefs_to(id_, fnWalk);
}

void HObject::accept(IModelVisitor& visitor)const
{
    return model_->accept(id_, visitor);
}

bool HObject::has_signature() const
{
    return model_->has_signature(id_);
}
