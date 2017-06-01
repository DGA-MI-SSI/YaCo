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

#include "HVersion.hpp"

#include "../Helpers.h"

#include <functional>

STATIC_ASSERT_POD(HVersion);

void HVersion::walk_signatures(const IVersions::OnSignatureFn& fnWalk) const
{
    model_->walk_signatures(id_, fnWalk);
}

void HVersion::walk_xrefs_from(const IVersions::OnXrefFromFn& fnWalk) const
{
    model_->walk_xrefs_from(id_, fnWalk);
}

void HVersion::walk_xrefs_to(const IVersions::OnObjectFn& fnWalk) const
{
    model_->walk_xrefs_to(id_, fnWalk);
}

offset_t HVersion::size() const
{
    return model_->size(id_);
}

YaToolObjectType_e HVersion::type() const
{
    return model_->type(id_);
}

YaToolObjectId HVersion::id() const
{
    return model_->id(id_);
}

YaToolObjectId HVersion::parent_id() const
{
    return model_->parent_id(id_);
}

offset_t HVersion::address() const
{
    return model_->address(id_);
}

const_string_ref HVersion::username() const
{
    return model_->username(id_);
}

int HVersion::username_flags() const
{
    return model_->username_flags(id_);
}

const_string_ref HVersion::prototype() const
{
    return model_->prototype(id_);
}

YaToolFlag_T HVersion::flags()const
{
    return model_->flags(id_);
}

int HVersion::string_type()const
{
    return model_->string_type(id_);
}

void HVersion::walk_blobs(const IVersions::OnBlobFn& fnWalk)const
{
    model_->walk_blobs(id_, fnWalk);
}

const_string_ref HVersion::header_comment(bool repeatable)const
{
    return model_->header_comment(id_, repeatable);
}

void HVersion::walk_comments(const IVersions::OnCommentFn& fnWalk)const
{
    model_->walk_comments(id_, fnWalk);
}

void HVersion::walk_value_views(const IVersions::OnValueViewFn& fnWalk)const
{
    model_->walk_value_views(id_, fnWalk);
}

void HVersion::walk_register_views(const IVersions::OnRegisterViewFn& fnWalk)const
{
    model_->walk_register_views(id_, fnWalk);
}

void HVersion::walk_hidden_areas(const IVersions::OnHiddenAreaFn& fnWalk)const
{
    model_->walk_hidden_areas(id_, fnWalk);
}

void HVersion::walk_xrefs(const IVersions::OnXrefFn& fnWalk)const
{
    model_->walk_xrefs(id_, fnWalk);
}

void HVersion::walk_xref_attributes(const XrefAttributes* hattr, const IVersions::OnAttributeFn& fnWalk)const
{
    model_->walk_xref_attributes(id_, hattr, fnWalk);
}

void HVersion::walk_systems(const IVersions::OnSystemFn& fnWalk)const
{
    model_->walk_systems(id_, fnWalk);
}

void HVersion::walk_system_attributes(HSystem_id_t system, const IVersions::OnAttributeFn& fnWalk)const
{
    model_->walk_system_attributes(id_, system, fnWalk);
}

void HVersion::walk_attributes(const IVersions::OnAttributeFn& fnWalk)const
{
    model_->walk_attributes(id_, fnWalk);
}

bool HVersion::match(const HVersion& version) const
{
    ContinueWalking_e stop = WALK_CONTINUE;
    walk_signatures([&](const HSignature& signature)
    {
        version.walk_signatures([&](const HSignature& re_signature)
        {
            if(std::equal_to<>()(signature, re_signature))
                stop = WALK_STOP;
            return stop;
        });
        return stop;
    });
    return stop == WALK_STOP;
}

bool HVersion::is_different_from(const HVersion& object_version_diff) const
{
    /* Check type */
    if (type() != object_version_diff.type())
    {
        return true;
    }

    /* Check name */
    if (!std::equal_to<>()(username(), object_version_diff.username()))
    {
        return true;
    }

    /* Check size */
    if (size() != object_version_diff.size())
    {
        return true;
    }

    /* Check non repeatable header */
    if (!std::equal_to<>()(header_comment(false), object_version_diff.header_comment(false)))
    {
        return true;
    }

    /* Check repeatable header */
    if (!std::equal_to<>()(header_comment(true), object_version_diff.header_comment(true)))
    {
        return true;
    }

    /* Check prototype */
    if (!std::equal_to<>()(prototype(), object_version_diff.prototype()))
    {
        return true;
    }

    /* Check comments */
    bool found = true;
    if(this->has_comments() != object_version_diff.has_comments())
    {
        return true;
    }

    walk_comments([&](offset_t this_offset, CommentType_e this_type, const const_string_ref& this_comment)
    {
        found = false;
        object_version_diff.walk_comments([&](offset_t diff_offset, CommentType_e diff_type, const const_string_ref& diff_comment)
        {
            if (this_offset == diff_offset && this_type == diff_type && std::equal_to<>()(this_comment, diff_comment))
            {
                found = true;
                return WALK_STOP;
            }
            return WALK_CONTINUE;
        });
        if (!found)
        {
            return WALK_STOP;
        }
        return WALK_CONTINUE;
    });
    if (!found)
    {
        return true;
    }

    /* Check attributes */
    found = true;
    if(this->has_attributes() != object_version_diff.has_attributes())
    {
        return true;
    }

    walk_attributes([&](const const_string_ref& this_key, const const_string_ref& this_value)
    {
        found = false;
        object_version_diff.walk_attributes([&](const const_string_ref& diff_key, const const_string_ref& diff_value)
        {
            if (std::equal_to<>()(this_key, diff_key) && std::equal_to<>()(this_value, diff_value))
            {
                found = true;
                return WALK_STOP;
            }
            return WALK_CONTINUE;
        });
        if (!found)
        {
            return WALK_STOP;
        }
        return WALK_CONTINUE;
    });
    if (!found)
    {
        return true;
    }

    /* Check Xref */
    found = true;
    if(this->has_xrefs() != object_version_diff.has_xrefs())
    {
        return true;
    }

    walk_xrefs([&](offset_t this_offset, operand_t this_operand, YaToolObjectId, const void*)
    {
        found = false;
        object_version_diff.walk_xrefs([&](offset_t diff_offset, operand_t diff_operand, YaToolObjectId, const void*)
        {
            /* TODO: we have to handle in the case of this_value == diff_value, so we need to know if both Xrefs are equals */
            if (this_offset == diff_offset && this_operand == diff_operand)
            {
                found = true;
                return WALK_STOP;
            }
            return WALK_CONTINUE;
            /* TODO: Xref attributes */
        });
        if (!found)
        {
            return WALK_STOP;
        }
        return WALK_CONTINUE;
    });
    if (!found)
    {
        return true;
    }

    return false;
}

void HVersion::accept(IModelVisitor& visitor) const
{
    return model_->accept(id_, visitor);
}

bool HVersion::has_comments() const
{
    bool found = false;
    model_->walk_comments(id_, [&](offset_t, CommentType_e, const const_string_ref&)
    {
        found = true;
        return WALK_STOP;
    });
    return found;
}

bool HVersion::has_attributes() const
{
    bool found = false;
    model_->walk_attributes(id_, [&](const const_string_ref&, const const_string_ref&)
    {
        found = true;
        return WALK_STOP;
    });
    return found;
}

bool HVersion::has_blobs() const
{
    bool found = false;
    model_->walk_blobs(id_, [&](offset_t, const void*, size_t)
    {
        found = true;
        return WALK_STOP;
    });
    return found;
}

bool HVersion::has_signatures() const
{
    bool found = false;
    model_->walk_signatures(id_, [&](const HSignature&)
    {
        found = true;
        return WALK_STOP;
    });
    return found;
}

bool HVersion::has_systems() const
{
    bool found = false;
    model_->walk_systems(id_, [&](offset_t, HSystem_id_t)
    {
        found = true;
        return WALK_STOP;
    });
    return found;
}

bool HVersion::has_value_views() const
{
    bool found = false;
    model_->walk_value_views(id_, [&](offset_t, operand_t, const const_string_ref&)
    {
        found = true;
        return WALK_STOP;
    });
    return found;
}

bool HVersion::has_register_views() const
{
    bool found = false;
    model_->walk_register_views(id_, [&](offset_t, offset_t, const const_string_ref&, const const_string_ref&)
    {
        found = true;
        return WALK_STOP;
    });
    return found;
}

bool HVersion::has_hidden_areas() const
{
    bool found = false;
    model_->walk_hidden_areas(id_, [&](offset_t, offset_t, const const_string_ref&)
    {
        found = true;
        return WALK_STOP;
    });
    return found;
}

bool HVersion::has_xrefs() const
{
    bool found = false;
    model_->walk_xrefs(id_, [&](offset_t, operand_t, YaToolObjectId, const void*)
    {
        found = true;
        return WALK_STOP;
    });
    return found;
}

bool HVersion::has_prototype() const
{
    return !!model_->prototype(id_).size;
}

bool HVersion::has_username() const
{
    return !!model_->username(id_).size;
}

bool HVersion::has_header_comment(bool repeatable) const
{
    return !!model_->header_comment(id_, repeatable).size;
}
