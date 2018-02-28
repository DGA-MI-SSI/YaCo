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
#include "IModel.hpp"

struct HObject
{
    bool                is_valid        () const { return !!model_; }

    void                accept          (IModelVisitor& visitor) const;

    YaToolObjectType_e  type            () const;
    YaToolObjectId      id              () const;
    bool                has_signature   () const;

    void                walk_versions   (const IObjects::OnVersionFn& fnWalk) const;
    void                walk_xrefs_from (const IObjects::OnXrefFromFn& fnWalk) const;
    void                walk_xrefs_to   (const IObjects::OnObjectFn& fnWalk) const;

    bool                match           (const HObject& remote) const;

    const IObjects* model_;
    HObject_id_t    id_;
};

namespace std
{
  template<>
  struct hash<HObject>
  {
      size_t operator()(const HObject& v) const
      {
          return static_cast<size_t>(v.id());
      }
  };
}
