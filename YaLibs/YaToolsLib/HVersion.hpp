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

#include <memory>

struct HVersion
{
    bool                is_valid() const { return !!model_; }

    void                accept(IModelVisitor& visitor) const;

    YaToolObjectId      id                  () const;
    YaToolObjectId      parent_id           () const;
    offset_t            size                () const;
    YaToolObjectType_e  type                () const;
    offset_t            address             () const;
    const_string_ref    username            () const;
    bool                has_username        () const;
    int                 username_flags      () const;
    const_string_ref    prototype           () const;
    bool                has_prototype       () const;
    YaToolFlag_T        flags               () const;
    int                 string_type         () const;
    const_string_ref    header_comment      (bool repeatable) const;
    bool                has_header_comment  (bool repeatable) const;

    void                walk_signatures         (const IVersions::OnSignatureFn& fnWalk) const;
    bool                has_signatures          () const;
    void                walk_xrefs_from         (const IVersions::OnXrefFromFn& fnWalk) const;
    void                walk_xrefs_to           (const IVersions::OnObjectFn& fnWalk) const;
    void                walk_blobs              (const IVersions::OnBlobFn& fnWalk) const;
    bool                has_blobs               () const;
    void                walk_comments           (const IVersions::OnCommentFn& fnWalk) const;
    bool                has_comments            () const;
    void                walk_value_views        (const IVersions::OnValueViewFn& fnWalk) const;
    bool                has_value_views         () const;
    void                walk_register_views     (const IVersions::OnRegisterViewFn& fnWalk) const;
    bool                has_register_views      () const;
    void                walk_hidden_areas       (const IVersions::OnHiddenAreaFn& fnWalk) const;
    bool                has_hidden_areas        () const;
    void                walk_xrefs              (const IVersions::OnXrefFn& fnWalk) const;
    bool                has_xrefs               () const;
    void                walk_xref_attributes    (const XrefAttributes* hattr, const IVersions::OnAttributeFn& fnWalk) const;
    void                walk_attributes         (const IVersions::OnAttributeFn& fnWalk) const;
    bool                has_attributes          () const;

    bool                is_different_from   (const HVersion& object_version_diff) const;
    bool                match               (const HVersion& version) const;

#ifndef SWIG
    friend bool operator==(const HVersion& t1, const HVersion& t2)
    {
        return t1.id() == t2.id();
    }

    friend bool operator!=(const HVersion& t1, const HVersion& t2)
    {
        return t1.id() != t2.id();
    }

    friend bool operator<(const HVersion& t1, const HVersion& t2)
    {
        return t1.id() < t2.id();
    }

    friend bool operator>(const HVersion& t1, const HVersion& t2)
    {
        return t1.id() > t2.id();
    }
#endif //SWIG

    const IVersions*    model_;
    HVersion_id_t       id_;
};

#ifndef SWIG
namespace std
{
    template<>
    struct hash<HVersion>
    {
        size_t operator()(const HVersion& v) const
        {
            return static_cast<size_t>(v.id());
        }
    };
}
#endif //SWIG
