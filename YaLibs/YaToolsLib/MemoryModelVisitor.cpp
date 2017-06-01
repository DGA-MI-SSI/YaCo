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

#include "MemoryModelVisitor.hpp"

#include "Signature.hpp"
#include "MatchingSystem.hpp"
#include "YaToolObjectVersion.hpp"
#include "YaToolReferencedObject.hpp"
#include "Logger.h"
#include "Yatools.h"

#include <iostream>


MemoryModelVisitor::MemoryModelVisitor()
    : object_type_                      (OBJECT_TYPE_UNKNOWN)
    , current_referenced_object_id_     (0)
    , current_xref_offset_              (0)
    , current_xref_offset_value_        (0)
    , current_xref_operand_             (0)
    , current_matching_system_address_  (0)
{

}

std::shared_ptr<MatchingSystem> MemoryModelVisitor::get_matching_system_for_attributes(const std::map<const std::string, const std::string>& attributes)
{
    auto sys = matching_systems_by_attrs_.find(attributes);
    if (sys == matching_systems_by_attrs_.end())
    {
        std::shared_ptr<MatchingSystem> new_sys = std::make_shared<MatchingSystem>(attributes);
        matching_systems_by_attrs_[attributes] = new_sys;
        matching_systems_by_id_.push_back(new_sys);
        return new_sys;
    }
    return (*sys).second;
}

//============= HEADER ==============
void MemoryModelVisitor::visit_start()
{
}

void MemoryModelVisitor::visit_end()
{
}

//============= REFERENCE OBJECT ==============
void MemoryModelVisitor::visit_start_object(YaToolObjectType_e object_type)
{
    object_type_ = object_type;
}

void MemoryModelVisitor::visit_start_reference_object(YaToolObjectType_e object_type)
{
    visit_start_object(object_type);
    current_referenced_object_ = std::make_shared<YaToolReferencedObject>(object_type);
}

void MemoryModelVisitor::visit_start_deleted_object(YaToolObjectType_e object_type)
{
    visit_start_object(object_type);
    current_referenced_object_ = std::make_shared<YaToolReferencedObject>(object_type);
}

void MemoryModelVisitor::visit_start_default_object(YaToolObjectType_e object_type)
{
    visit_start_object(object_type);
    current_referenced_object_ = std::make_shared<YaToolReferencedObject>(object_type);
}

//#============= REFERENCE OBJECT ID ==============
void MemoryModelVisitor::visit_id(YaToolObjectId object_id)
{
    current_referenced_object_id_ = object_id;
    current_referenced_object_->setId(object_id);
}
//#============= OBJECT VERSION ==============
void MemoryModelVisitor::visit_start_object_version()
{
    current_object_version_ = std::make_shared<YaToolObjectVersion>();
    current_object_version_->set_id(current_referenced_object_->getId());
    current_object_version_->set_type(object_type_);
}
//#============= REFERENCE OBJECT ID ==============
void MemoryModelVisitor::visit_parent_id(YaToolObjectId object_id)
{
    current_object_version_->set_parent_object_id(object_id);
}

void MemoryModelVisitor::visit_address(offset_t address)
{
    current_object_version_->set_absolute_object_address(address);
}

//#============= OBJECT VERSION name ==============
void MemoryModelVisitor::visit_name(const const_string_ref& name, int flags)
{
    current_object_version_->set_name(make_string(name));
    if (flags != 0)
    {
        current_object_version_->set_name_flags(flags);
    }
}

void MemoryModelVisitor::visit_size(offset_t size)
{
    current_object_version_->set_size(size);
}

// #============= OBJECT VERSION HASHES ==============
void MemoryModelVisitor::visit_start_signatures()
{

}
void MemoryModelVisitor::visit_signature(SignatureMethod_e method, SignatureAlgo_e algo, const const_string_ref& hex)
{
    switch(algo)
    {
        case SIGNATURE_ALGORITHM_CRC32:
        case SIGNATURE_ALGORITHM_MD5:
            current_object_version_->add_signature(MakeSignature(algo, method, hex));
            return;

        case SIGNATURE_ALGORITHM_UNKNOWN:
        case SIGNATURE_ALGORITHM_NONE:
        case SIGNATURE_ALGORITHM_COUNT:
            break;
    }

    YALOG_ERROR(nullptr, "unknown signature algo %x\n", algo);
}

void MemoryModelVisitor::visit_end_signatures()
{

}

void MemoryModelVisitor::visit_prototype(const const_string_ref& prototype)
{
    current_object_version_->set_prototype(make_string(prototype));
}

void MemoryModelVisitor::visit_string_type(int str_type)
{
    current_object_version_->set_string_type(str_type);
}

void MemoryModelVisitor::visit_header_comment(bool repeatable, const const_string_ref& comment)
{
    current_object_version_->set_header_comment(repeatable, make_string(comment));
}

void MemoryModelVisitor::visit_start_offsets()
{

}

void MemoryModelVisitor::visit_end_offsets()
{

}

void MemoryModelVisitor::visit_offset_comments(offset_t offset, CommentType_e comment_type, const const_string_ref& comment)
{
    current_object_version_->add_offset_comment(offset, comment_type, make_string(comment));
}

void MemoryModelVisitor::visit_offset_valueview(offset_t offset, operand_t operand, const const_string_ref& view_value)
{
    current_object_version_->add_offset_valueview(offset, operand, make_string(view_value));
}

void MemoryModelVisitor::visit_offset_registerview(offset_t offset, offset_t end_offset, const const_string_ref& register_name,
        const const_string_ref& register_new_name)
{
    current_object_version_->add_offset_registerview(offset, end_offset, make_string(register_name), make_string(register_new_name));
}

void MemoryModelVisitor::visit_offset_hiddenarea(offset_t offset, offset_t area_size, const const_string_ref& hidden_area_value)
{
    current_object_version_->add_offset_hidden_area(std::make_pair(offset, offset + area_size),
            make_string(hidden_area_value));
}

void MemoryModelVisitor::visit_start_xrefs()
{

}

void MemoryModelVisitor::visit_end_xrefs()
{

}

void MemoryModelVisitor::visit_start_xref(offset_t offset, YaToolObjectId offset_value, operand_t operand)
{
    current_xref_offset_ = offset;
    current_xref_offset_value_ = offset_value;
    current_xref_operand_ = operand;
    current_xref_attributes_.clear();
}

void MemoryModelVisitor::visit_xref_attribute(const const_string_ref& attribute_key, const const_string_ref& attribute_value)
{
    current_xref_attributes_.insert(make_pair(make_string(attribute_key), make_string(attribute_value)));
}

void MemoryModelVisitor::visit_end_xref()
{
    current_object_version_->addXRefId(current_xref_offset_, current_xref_operand_,
            current_xref_offset_value_, current_xref_attributes_);
}

void MemoryModelVisitor::visit_start_matching_systems()
{

}

void MemoryModelVisitor::visit_start_matching_system(offset_t address)
{
    current_matching_system_address_ = address;
    current_matching_system_description_.clear();
}

void MemoryModelVisitor::visit_matching_system_description(const const_string_ref& description_key, const const_string_ref& description_value)
{
    current_matching_system_description_.insert(make_pair(make_string(description_key), make_string(description_value)));
}

void MemoryModelVisitor::visit_end_matching_system()
{
    std::shared_ptr<MatchingSystem> sys = get_matching_system_for_attributes(current_matching_system_description_);
    current_object_version_->add_matching_system(sys, current_matching_system_address_);
}

void MemoryModelVisitor::visit_end_matching_systems()
{

}

void MemoryModelVisitor::visit_segments_start()
{

}

void MemoryModelVisitor::visit_segments_end()
{

}

void MemoryModelVisitor::visit_attribute(const const_string_ref& attr_name, const const_string_ref& attr_value)
{
    current_object_version_->add_attribute(make_string(attr_name), make_string(attr_value));
}

void MemoryModelVisitor::visit_blob(offset_t offset, const void* vblob, size_t len)
{
    const uint8_t* blob = reinterpret_cast<const uint8_t*>(vblob);
    assert(current_referenced_object_ != nullptr);
    assert(current_referenced_object_->hasId());
    std::vector<unsigned char> v(&blob[0], &blob[len]);

    current_object_version_->add_blob(offset, v);
}

void MemoryModelVisitor::visit_flags(flags_t flags)
{
    current_object_version_->set_object_flags(flags);
}

