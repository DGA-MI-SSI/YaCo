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
#include "HSignature.hpp"

#include <functional>
#include <memory>


struct XrefAttributes;

struct IVersions
{
    virtual ~IVersions() = default;

    typedef std::function<ContinueWalking_e(const HSignature&)> OnSignatureFn;
    typedef std::function<ContinueWalking_e(offset_t, operand_t, const HVersion&)> OnXrefFromFn;
    typedef std::function<ContinueWalking_e(const HVersion&)> OnVersionFn;
    typedef std::function<ContinueWalking_e(offset_t, const void*, size_t)> OnBlobFn;
    typedef std::function<ContinueWalking_e(offset_t, CommentType_e, const const_string_ref&)> OnCommentFn;
    typedef std::function<ContinueWalking_e(offset_t, operand_t, const const_string_ref&)> OnValueViewFn;
    typedef std::function<ContinueWalking_e(offset_t, offset_t, const const_string_ref&, const const_string_ref&)> OnRegisterViewFn;
    typedef std::function<ContinueWalking_e(offset_t, offset_t, const const_string_ref&)> OnHiddenAreaFn;
    typedef std::function<ContinueWalking_e(offset_t, operand_t, YaToolObjectId, const XrefAttributes*)> OnXrefFn;
    typedef std::function<ContinueWalking_e(const const_string_ref&, const const_string_ref&)> OnAttributeFn;

    virtual void                accept(VersionIndex idx, IModelVisitor& visitor) const = 0;

    virtual YaToolObjectId      id              (VersionIndex idx) const = 0;
    virtual YaToolObjectId      parent_id       (VersionIndex idx) const = 0;
    virtual offset_t            size            (VersionIndex idx) const = 0;
    virtual YaToolObjectType_e  type            (VersionIndex idx) const = 0;
    virtual offset_t            address         (VersionIndex idx) const = 0;
    virtual const_string_ref    username        (VersionIndex idx) const = 0;
    virtual int                 username_flags  (VersionIndex idx) const = 0;
    virtual const_string_ref    prototype       (VersionIndex idx) const = 0;
    virtual YaToolFlag_T        flags           (VersionIndex idx) const = 0;
    virtual int                 string_type     (VersionIndex idx) const = 0;
    virtual const_string_ref    header_comment  (VersionIndex idx, bool repeatable) const = 0;
    virtual bool                has_signature   (VersionIndex idx) const = 0;

    virtual void                walk_signatures         (VersionIndex idx, const OnSignatureFn& fnWalk) const = 0;
    virtual void                walk_xrefs_from         (VersionIndex idx, const OnXrefFromFn& fnWalk) const = 0;
    virtual void                walk_xrefs_to           (VersionIndex idx, const OnVersionFn& fnWalk) const = 0;
    virtual void                walk_blobs              (VersionIndex idx, const OnBlobFn& fnWalk) const = 0;
    virtual void                walk_comments           (VersionIndex idx, const OnCommentFn& fnWalk) const = 0;
    virtual void                walk_value_views        (VersionIndex idx, const OnValueViewFn& fnWalk) const = 0;
    virtual void                walk_register_views     (VersionIndex idx, const OnRegisterViewFn& fnWalk) const = 0;
    virtual void                walk_hidden_areas       (VersionIndex idx, const OnHiddenAreaFn& fnWalk) const = 0;
    virtual void                walk_xrefs              (VersionIndex idx, const OnXrefFn& fnWalk) const = 0;
    virtual void                walk_xref_attributes    (VersionIndex idx, const XrefAttributes* hattr, const OnAttributeFn& fnWalk) const = 0;
    virtual void                walk_attributes         (VersionIndex idx, const OnAttributeFn& fnWalk) const = 0;
};

struct ISignatures
{
    virtual ~ISignatures() = default;

    virtual Signature get(HSignature_id_t id) const = 0;
};

struct IModel
{
    virtual ~IModel() = default;

    virtual void                accept(IModelVisitor& visitor) = 0;

    // private methods
    typedef std::function<ContinueWalking_e(const HVersion&)> OnVersionFn;
    typedef std::function<ContinueWalking_e(const HVersion&, const HSignature&)> OnSignatureFn;

    virtual void                walk            (const OnVersionFn& fnWalk) const = 0;
    virtual size_t              size            () const = 0;
    virtual HVersion            get             (YaToolObjectId id) const = 0;
    virtual bool                has             (YaToolObjectId id) const = 0;
    virtual size_t              size_matching   (const HSignature& sig) const = 0;
    virtual void                walk_matching   (const HSignature& sig, const OnVersionFn& fnWalk) const = 0;
    virtual void                walk_uniques    (const OnSignatureFn& fnWalk) const = 0;

    /**
     * Return all the versions from this object that match a version of another object
     * If the signature has collisions, the local version is checked for its size, and the match is ignored
     * if the size is < min_size
     * Thus small functions that have many collisions are avoided
     */
    virtual void walk_matching(const HVersion& version, size_t min_size, const OnVersionFn& fnWalk) const = 0;
};
