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

#include "IModelAccept.hpp"
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

    virtual void                accept(HVersion_id_t version_id, IModelVisitor& visitor) const = 0;

    virtual YaToolObjectId      id              (HVersion_id_t version_id) const = 0;
    virtual YaToolObjectId      parent_id       (HVersion_id_t version_id) const = 0;
    virtual offset_t            size            (HVersion_id_t version_id) const = 0;
    virtual YaToolObjectType_e  type            (HVersion_id_t version_id) const = 0;
    virtual offset_t            address         (HVersion_id_t version_id) const = 0;
    virtual const_string_ref    username        (HVersion_id_t version_id) const = 0;
    virtual int                 username_flags  (HVersion_id_t version_id) const = 0;
    virtual const_string_ref    prototype       (HVersion_id_t version_id) const = 0;
    virtual YaToolFlag_T        flags           (HVersion_id_t version_id) const = 0;
    virtual int                 string_type     (HVersion_id_t version_id) const = 0;
    virtual const_string_ref    header_comment  (HVersion_id_t version_id, bool repeatable) const = 0;
    virtual bool                has_signature   (HVersion_id_t version_id) const = 0;

    virtual void                walk_signatures         (HVersion_id_t version_id, const OnSignatureFn& fnWalk) const = 0;
    virtual void                walk_xrefs_from         (HVersion_id_t version_id, const OnXrefFromFn& fnWalk) const = 0;
    virtual void                walk_xrefs_to           (HVersion_id_t version_id, const OnVersionFn& fnWalk) const = 0;
    virtual void                walk_blobs              (HVersion_id_t version_id, const OnBlobFn& fnWalk) const = 0;
    virtual void                walk_comments           (HVersion_id_t version_id, const OnCommentFn& fnWalk) const = 0;
    virtual void                walk_value_views        (HVersion_id_t version_id, const OnValueViewFn& fnWalk) const = 0;
    virtual void                walk_register_views     (HVersion_id_t version_id, const OnRegisterViewFn& fnWalk) const = 0;
    virtual void                walk_hidden_areas       (HVersion_id_t version_id, const OnHiddenAreaFn& fnWalk) const = 0;
    virtual void                walk_xrefs              (HVersion_id_t version_id, const OnXrefFn& fnWalk) const = 0;
    virtual void                walk_xref_attributes    (HVersion_id_t version_id, const XrefAttributes* hattr, const OnAttributeFn& fnWalk) const = 0;
    virtual void                walk_attributes         (HVersion_id_t version_id, const OnAttributeFn& fnWalk) const = 0;
};

struct ISignatures
{
    virtual ~ISignatures() = default;

    virtual Signature get(HSignature_id_t id) const = 0;
};

struct IModel
    : public IModelAccept
{
    ~IModel() override = default;

    // IModelAccept methods
    virtual void                accept(IModelVisitor& visitor) = 0;

    // private methods
    typedef std::function<ContinueWalking_e(YaToolObjectId, const HVersion&)> OnVersionAndIdFn;
    typedef std::function<ContinueWalking_e(const HVersion&)> OnVersionFn;
    typedef std::function<ContinueWalking_e(const HSignature&, const HVersion&)> OnSigAndVersionFn;
    typedef std::function<ContinueWalking_e(const HVersion&, const HVersion&)> OnVersionPairFn;

    virtual void                walk_objects                    (const OnVersionAndIdFn& fnWalk) const = 0;
    virtual size_t              num_objects                     () const = 0;
    virtual HVersion            get_object                      (YaToolObjectId id) const = 0;
    virtual bool                has_object                      (YaToolObjectId id) const = 0;
    virtual size_t              num_objects_with_signature      (const HSignature& hash) const = 0;
    virtual void                walk_versions_with_signature    (const HSignature& hash, const OnVersionFn& fnWalk) const = 0;
    virtual void                walk_versions_without_collision (const OnSigAndVersionFn& fnWalk) const = 0;

    /**
     * Return all the versions from this object that match a version of another object
     * This returns pairs of <va,vb> with matches
     * If the signature has collisions, the local version is checked for its size, and the match is ignored
     * if the size is < min_size
     * Thus, small functions that have many collisions will be avoided
     */
    virtual void walk_matching_versions(const HVersion& object, size_t min_size, const OnVersionPairFn& fnWalk) const = 0;
};
