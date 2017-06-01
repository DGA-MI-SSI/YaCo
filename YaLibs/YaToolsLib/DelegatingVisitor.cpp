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

#include "DelegatingVisitor.hpp"

DelegatingVisitor::DelegatingVisitor()
{
}

DelegatingVisitor::~DelegatingVisitor()
{
}

void DelegatingVisitor::add_delegate(const std::shared_ptr<IModelVisitor>& delegate)
{
    delegates_.push_back(delegate);
}

void DelegatingVisitor::visit_start()
{
    for(const auto& delegate : delegates_)
        delegate->visit_start();
}

void DelegatingVisitor::visit_end()
{
    for(const auto& delegate : delegates_)
        delegate->visit_end();
}

void DelegatingVisitor::visit_start_object(
        YaToolObjectType_e object_type)
{
    for(const auto& delegate : delegates_)
        delegate->visit_start_object(object_type);
}

void DelegatingVisitor::visit_start_reference_object(
        YaToolObjectType_e object_type)
{
    for(const auto& delegate : delegates_)
        delegate->visit_start_reference_object(object_type);
}

void DelegatingVisitor::visit_start_deleted_object(YaToolObjectType_e object_type)
{
    for(const auto& delegate : delegates_)
        delegate->visit_start_deleted_object(object_type);
}

void DelegatingVisitor::visit_start_default_object(YaToolObjectType_e object_type)
{
    for(const auto& delegate : delegates_)
        delegate->visit_start_default_object(object_type);
}

void DelegatingVisitor::visit_end_reference_object()
{
    for(const auto& delegate : delegates_)
        delegate->visit_end_reference_object();
}

void DelegatingVisitor::visit_end_deleted_object()
{
    for(const auto& delegate : delegates_)
        delegate->visit_end_deleted_object();
}

void DelegatingVisitor::visit_end_default_object()
{
    for(const auto& delegate : delegates_)
        delegate->visit_end_default_object();
}

void DelegatingVisitor::visit_id(YaToolObjectId id)
{
    for(const auto& delegate : delegates_)
        delegate->visit_id(id);
}

void DelegatingVisitor::visit_parent_id(YaToolObjectId parent_object_id)
{
    for(const auto& delegate : delegates_)
        delegate->visit_parent_id(parent_object_id);
}

void DelegatingVisitor::visit_address(offset_t address)
{
    for(const auto& delegate : delegates_)
        delegate->visit_address(address);
}

void DelegatingVisitor::visit_start_object_version()
{
    for(const auto& delegate : delegates_)
        delegate->visit_start_object_version();
}

void DelegatingVisitor::visit_end_object_version()
{
    for(const auto& delegate : delegates_)
        delegate->visit_end_object_version();
}

void DelegatingVisitor::visit_name(const const_string_ref& name, int flags)
{
    for(const auto& delegate : delegates_)
        delegate->visit_name(name, flags);
}

void DelegatingVisitor::visit_size(offset_t size)
{
    for(const auto& delegate : delegates_)
        delegate->visit_size(size);
}

void DelegatingVisitor::visit_start_signatures()
{
    for(const auto& delegate : delegates_)
        delegate->visit_start_signatures();
}

void DelegatingVisitor::visit_signature(SignatureMethod_e method, SignatureAlgo_e algo, const const_string_ref& hex)
{
    for(const auto& delegate : delegates_)
        delegate->visit_signature(method, algo, hex);
}

void DelegatingVisitor::visit_end_signatures()
{
    for(const auto& delegate : delegates_)
        delegate->visit_end_signatures();

}

void DelegatingVisitor::visit_prototype(const const_string_ref& prototype)
{
    for(const auto& delegate : delegates_)
        delegate->visit_prototype(prototype);
}

void DelegatingVisitor::visit_string_type(int str_type)
{
    for(const auto& delegate : delegates_)
        delegate->visit_string_type(str_type);
}

void DelegatingVisitor::visit_header_comment(bool repeatable, const const_string_ref& comment)
{
    for(const auto& delegate : delegates_)
        delegate->visit_header_comment(repeatable, comment);
}

void DelegatingVisitor::visit_start_offsets()
{
    for(const auto& delegate : delegates_)
        delegate->visit_start_offsets();
}

void DelegatingVisitor::visit_offset_comments(offset_t offset,
        CommentType_e comment_type, const const_string_ref& comment)
{
    for(const auto& delegate : delegates_)
        delegate->visit_offset_comments(offset, comment_type, comment);
}

void DelegatingVisitor::visit_offset_valueview(offset_t offset, operand_t operand,
        const const_string_ref& view_value)
{
    for(const auto& delegate : delegates_)
        delegate->visit_offset_valueview(offset, operand, view_value);
}

void DelegatingVisitor::visit_offset_registerview(offset_t offset, offset_t end_offset,
        const const_string_ref& register_name, const const_string_ref& register_new_name)
{
    for(const auto& delegate : delegates_)
        delegate->visit_offset_registerview(offset, end_offset, register_name, register_new_name);
}

void DelegatingVisitor::visit_offset_hiddenarea(offset_t offset, offset_t area_size,
        const const_string_ref& hidden_area_value)
{
    for(const auto& delegate : delegates_)
        delegate->visit_offset_hiddenarea(offset, area_size, hidden_area_value);
}

void DelegatingVisitor::visit_end_offsets()
{
    for(const auto& delegate : delegates_)
        delegate->visit_end_offsets();
}

void DelegatingVisitor::visit_start_xrefs()
{
    for(const auto& delegate : delegates_)
        delegate->visit_start_xrefs();
}

void DelegatingVisitor::visit_start_xref(offset_t offset,
        YaToolObjectId offset_value, operand_t operand)
{
    for(const auto& delegate : delegates_)
        delegate->visit_start_xref(offset, offset_value, operand);
}

void DelegatingVisitor::visit_xref_attribute(const const_string_ref& attribute_key,
        const const_string_ref& attribute_value)
{
    for(const auto& delegate : delegates_)
        delegate->visit_xref_attribute(attribute_key, attribute_value);
}

void DelegatingVisitor::visit_end_xref()
{
    for(const auto& delegate : delegates_)
        delegate->visit_end_xref();
}

void DelegatingVisitor::visit_end_xrefs()
{
    for(const auto& delegate : delegates_)
        delegate->visit_end_xrefs();
}

void DelegatingVisitor::visit_start_matching_systems()
{
    for(const auto& delegate : delegates_)
        delegate->visit_start_matching_systems();
}

void DelegatingVisitor::visit_start_matching_system(offset_t address)
{
    for(const auto& delegate : delegates_)
        delegate->visit_start_matching_system(address);
}

void DelegatingVisitor::visit_matching_system_description(
        const const_string_ref& description_key, const const_string_ref& description_value)
{
    for(const auto& delegate : delegates_)
        delegate->visit_matching_system_description(description_key, description_value);
}

void DelegatingVisitor::visit_end_matching_system()
{
    for(const auto& delegate : delegates_)
        delegate->visit_end_matching_system();
}

void DelegatingVisitor::visit_end_matching_systems()
{
    for(const auto& delegate : delegates_)
        delegate->visit_end_matching_systems();
}

void DelegatingVisitor::visit_segments_start()
{
    for(const auto& delegate : delegates_)
        delegate->visit_segments_start();
}

void DelegatingVisitor::visit_segments_end()
{
    for(const auto& delegate : delegates_)
        delegate->visit_segments_end();
}

void DelegatingVisitor::visit_attribute(const const_string_ref& attr_name, const const_string_ref& attr_value)
{
    for(const auto& delegate : delegates_)
        delegate->visit_attribute(attr_name, attr_value);
}

void DelegatingVisitor::visit_flags(flags_t flags)
{
    for(const auto& delegate : delegates_)
        delegate->visit_flags(flags);
}

void DelegatingVisitor::visit_blob(offset_t offset, const void* blob, size_t len)
{
    for(const auto& delegate : delegates_)
        delegate->visit_blob(offset, blob, len);
}
