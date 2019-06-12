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

struct IModelVisitor
{
    virtual ~IModelVisitor() = default;

    virtual void visit_start() = 0;
    virtual void visit_end() = 0;
    virtual void visit_deleted(YaToolObjectType_e type, YaToolObjectId id) = 0;
    virtual void visit_start_version(YaToolObjectType_e type, YaToolObjectId id) = 0;
    virtual void visit_end_version() = 0;
    virtual void visit_parent_id(YaToolObjectId parent_id) = 0;
    virtual void visit_address(offset_t address) = 0;
    virtual void visit_name(const const_string_ref& name, int flags) = 0;
    virtual void visit_size(offset_t size) = 0;
    virtual void visit_start_signatures() = 0;
    virtual void visit_signature(SignatureMethod_e method, SignatureAlgo_e algo,  const const_string_ref& hex) = 0;
    virtual void visit_end_signatures() = 0;
    virtual void visit_prototype(const const_string_ref& prototype) = 0;
    virtual void visit_string_type(int str_type) = 0;
    virtual void visit_header_comment(bool repeatable, const const_string_ref& comment) = 0;
    virtual void visit_start_offsets() = 0;
    virtual void visit_end_offsets() = 0;
    virtual void visit_offset_comments(offset_t offset, CommentType_e comment_type, const const_string_ref& comment) = 0;
    virtual void visit_offset_valueview(offset_t offset, operand_t operand, const const_string_ref& view_value) = 0;
    virtual void visit_offset_registerview(offset_t offset, offset_t end_offset, const const_string_ref& register_name, const const_string_ref& register_new_name) = 0;
    virtual void visit_offset_hiddenarea(offset_t offset, offset_t area_size, const const_string_ref& hidden_area_value) = 0;
    virtual void visit_start_xrefs() = 0;
    virtual void visit_end_xrefs() = 0;
    virtual void visit_start_xref(offset_t offset, YaToolObjectId offset_value, operand_t operand) = 0;
    virtual void visit_end_xref() = 0;
    virtual void visit_xref_attribute(const const_string_ref& key_attribute, const const_string_ref& value_attribute) = 0;
    virtual void visit_segments_start() = 0;
    virtual void visit_segments_end() = 0;
    virtual void visit_attribute(const const_string_ref& attr_name, const const_string_ref& attr_value) = 0;
    virtual void visit_blob(offset_t offset, const void* blob, size_t len) = 0;
    virtual void visit_flags(flags_t flags) = 0;
};

/* Macro to keep method declaration in one place (the interface) 
 *     and not decalre them everywhere before the implementation 
 *     XmlVisitor, flatVisitor, ExporterValidatorVisitor, test_common.hpp ...
 *     Anyway, grempe and you will see
 */
#define DECLARE_VISITOR_INTERFACE_METHODS \
    void visit_start() override; \
    void visit_end() override; \
    void visit_start_version(YaToolObjectType_e type, YaToolObjectId id) override; \
    void visit_deleted(YaToolObjectType_e type, YaToolObjectId id) override; \
    void visit_end_version() override; \
    void visit_parent_id(YaToolObjectId object_id) override; \
    void visit_address(offset_t address) override; \
    void visit_name(const const_string_ref& name, int flags) override; \
    void visit_size(offset_t size) override; \
    void visit_start_signatures() override; \
    void visit_signature(SignatureMethod_e method, SignatureAlgo_e algo, const const_string_ref& hex) override; \
    void visit_end_signatures() override; \
    void visit_prototype(const const_string_ref& prototype) override; \
    void visit_string_type(int str_type) override; \
    void visit_header_comment(bool repeatable, const const_string_ref& comment) override; \
    void visit_start_offsets() override; \
    void visit_end_offsets() override; \
    void visit_offset_comments(offset_t offset, CommentType_e comment_type, const const_string_ref& comment) override; \
    void visit_offset_valueview(offset_t offset, operand_t operand, const const_string_ref& view_value) override; \
    void visit_offset_registerview(offset_t offset, offset_t end_offset, const const_string_ref& register_name, const const_string_ref& register_new_name) override; \
    void visit_offset_hiddenarea(offset_t offset, offset_t area_size, const const_string_ref& hidden_area_value) override; \
    void visit_start_xrefs() override; \
    void visit_end_xrefs() override; \
    void visit_start_xref(offset_t offset, YaToolObjectId offset_value, operand_t operand) override; \
    void visit_end_xref() override; \
    void visit_xref_attribute(const const_string_ref& attribute_key, const const_string_ref& attribute_value) override; \
    void visit_segments_start() override; \
    void visit_segments_end() override; \
    void visit_attribute(const const_string_ref& attr_name, const const_string_ref& attr_value) override; \
    void visit_blob(offset_t offset, const void* blob, size_t len) override; \
    void visit_flags(flags_t flags) override;
