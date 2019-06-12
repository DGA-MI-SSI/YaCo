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


#include "IModelVisitor.hpp"
#include "Yatools.hpp"
#include "Helpers.h"

#include <stdint.h>
#include <memory>

#include "ExporterValidatorVisitor.hpp"

std::shared_ptr<IModelVisitor> MakeExporterValidatorVisitor()
{
    return std::make_shared<ExporterValidatorVisitor>();
}

ExporterValidatorVisitor::ExporterValidatorVisitor()
    : current_state_depth(-1)
    , last_offset_ea(UNKNOWN_ADDR)
{
    memset(state, -1, sizeof(state));
}

ExporterValidatorVisitor::~ExporterValidatorVisitor()
{
    validator_assert(current_state_depth == -1, "Bad state in destructor");
}

//============= HEADER ==============
void ExporterValidatorVisitor::visit_start()
{
    validator_assert(current_state_depth < 0, "Bad state depth : %d", current_state_depth);
    state[++current_state_depth] = VISIT_STARTED;
}

void ExporterValidatorVisitor::visit_end()
{
    validator_assert(current_state_depth == 0, "Bad state depth : %d", current_state_depth);
    validator_assert(state[current_state_depth] == VISIT_STARTED, "Bad state");
    current_state_depth--;
}

//============= REFERENCE OBJECT ==============
void ExporterValidatorVisitor::visit_start_version(YaToolObjectType_e type, YaToolObjectId id)
{
    UNUSED(type);
    UNUSED(id);
    validator_assert(state[current_state_depth] == VISIT_STARTED, "Bad state");
    state[++current_state_depth] = VISIT_OBJECT_VERSION;
}

void ExporterValidatorVisitor::visit_deleted(YaToolObjectType_e type, YaToolObjectId id)
{
    UNUSED(type);
    UNUSED(id);
    validator_assert(state[current_state_depth] == VISIT_STARTED, "Bad state");
}

void ExporterValidatorVisitor::visit_end_version()
{
    validator_assert(state[current_state_depth] == VISIT_OBJECT_VERSION, "Bad state");
    current_state_depth--;
    validator_assert(state[current_state_depth] == VISIT_STARTED, "Bad state");
}

//#============= REFERENCE OBJECT ID ==============
void ExporterValidatorVisitor::visit_parent_id(YaToolObjectId object_id)
{
    UNUSED(object_id);
    validator_assert(state[current_state_depth] == VISIT_OBJECT_VERSION, "Bad state");
}

void ExporterValidatorVisitor::visit_address(offset_t address)
{
    UNUSED(address);
    validator_assert(state[current_state_depth] == VISIT_OBJECT_VERSION, "Bad state");
}

//#============= OBJECT VERSION name ==============
void ExporterValidatorVisitor::visit_name(const const_string_ref& name, int flags)
{
    UNUSED(name);
    UNUSED(flags);
    validator_assert(state[current_state_depth] == VISIT_OBJECT_VERSION, "Bad state");
}

void ExporterValidatorVisitor::visit_size(offset_t size)
{
    UNUSED(size);
    validator_assert(state[current_state_depth] == VISIT_OBJECT_VERSION, "Bad state");
}

// #============= OBJECT VERSION HASHES ==============
void ExporterValidatorVisitor::visit_start_signatures()
{
    validator_assert(state[current_state_depth] == VISIT_OBJECT_VERSION, "Bad state");
    state[++current_state_depth] = VISIT_SIGNATURES;
}

void ExporterValidatorVisitor::visit_signature(SignatureMethod_e method, SignatureAlgo_e algo, const const_string_ref& hex)
{
    UNUSED(method);
    UNUSED(algo);
    UNUSED(hex);
    validator_assert(state[current_state_depth] == VISIT_SIGNATURES, "Bad state");
}

void ExporterValidatorVisitor::visit_end_signatures()
{
    validator_assert(state[current_state_depth] == VISIT_SIGNATURES, "Bad state");
    current_state_depth--;
    validator_assert(state[current_state_depth] == VISIT_OBJECT_VERSION, "Bad state");
}

void ExporterValidatorVisitor::visit_prototype(const const_string_ref& prototype)
{
    UNUSED(prototype);
    validator_assert(state[current_state_depth] == VISIT_OBJECT_VERSION, "Bad state");
}

void ExporterValidatorVisitor::visit_string_type(int str_type)
{
    UNUSED(str_type);
    validator_assert(state[current_state_depth] == VISIT_OBJECT_VERSION, "Bad state");
}

void ExporterValidatorVisitor::visit_header_comment(bool repeatable, const const_string_ref& comment)
{
    UNUSED(repeatable);
    UNUSED(comment);
    validator_assert(state[current_state_depth] == VISIT_OBJECT_VERSION, "Bad state");
}

void ExporterValidatorVisitor::visit_start_offsets()
{
    validator_assert(state[current_state_depth] == VISIT_OBJECT_VERSION, "Bad state");
    state[++current_state_depth] = VISIT_OFFSETS;
    last_offset_ea = UNKNOWN_ADDR;
}

void ExporterValidatorVisitor::visit_end_offsets()
{
    validator_assert(state[current_state_depth] == VISIT_OFFSETS, "Bad state");
    current_state_depth--;
    validator_assert(state[current_state_depth] == VISIT_OBJECT_VERSION, "Bad state");
}

void ExporterValidatorVisitor::visit_offset_comments(offset_t offset, CommentType_e comment_type, const const_string_ref& comment)
{
    UNUSED(comment_type);
    validator_assert(state[current_state_depth] == VISIT_OFFSETS, "Bad state");
	static_assert(sizeof(offset) == sizeof(uint64_t), "bad static assert");
    validator_assert(last_offset_ea==UNKNOWN_ADDR || offset >= last_offset_ea, "Bad offset : 0x%" PRIX64 " < 0x%" PRIX64 " (comment='%s')", offset, last_offset_ea, comment.value);
    last_offset_ea = offset;
}

void ExporterValidatorVisitor::visit_offset_valueview(offset_t offset, operand_t operand, const const_string_ref& view_value)
{
    UNUSED(operand);
    UNUSED(view_value);
    validator_assert(state[current_state_depth] == VISIT_OFFSETS, "Bad state");
    validator_assert(last_offset_ea==UNKNOWN_ADDR || offset >= last_offset_ea, "Bad offset : 0x%" PRIX64 " < 0x%" PRIX64 "", offset, last_offset_ea);
    last_offset_ea = offset;
}

void ExporterValidatorVisitor::visit_offset_registerview(offset_t offset, offset_t end_offset, const const_string_ref& register_name,
        const const_string_ref& register_new_name)
{
    UNUSED(end_offset);
    UNUSED(register_name);
    UNUSED(register_new_name);
    validator_assert(state[current_state_depth] == VISIT_OFFSETS, "Bad state");
    validator_assert(last_offset_ea==UNKNOWN_ADDR || offset >= last_offset_ea, "Bad offset : 0x%" PRIX64 " < 0x%" PRIX64 "", offset, last_offset_ea);
    last_offset_ea = offset;
}

void ExporterValidatorVisitor::visit_offset_hiddenarea(offset_t offset, offset_t area_size, const const_string_ref& hidden_area_value)
{
    UNUSED(area_size);
    UNUSED(hidden_area_value);
    validator_assert(state[current_state_depth] == VISIT_OFFSETS, "Bad state");
    validator_assert(last_offset_ea==UNKNOWN_ADDR || offset >= last_offset_ea, "Bad offset : 0x%" PRIX64 " < 0x%" PRIX64 "", offset, last_offset_ea);
    last_offset_ea = offset;
}

void ExporterValidatorVisitor::visit_start_xrefs()
{
    validator_assert(state[current_state_depth] == VISIT_OBJECT_VERSION, "Bad state");
    state[++current_state_depth] = VISIT_XREFS;
}

void ExporterValidatorVisitor::visit_end_xrefs()
{
    validator_assert(state[current_state_depth] == VISIT_XREFS, "Bad state");
    current_state_depth--;
    validator_assert(state[current_state_depth] == VISIT_OBJECT_VERSION, "Bad state");
}

void ExporterValidatorVisitor::visit_start_xref(offset_t offset, YaToolObjectId offset_value, operand_t operand)
{
    UNUSED(offset);
    UNUSED(offset_value);
    UNUSED(operand);
    validator_assert(state[current_state_depth] == VISIT_XREFS, "Bad state");
    state[++current_state_depth] = VISIT_XREF;
}

void ExporterValidatorVisitor::visit_xref_attribute(const const_string_ref& attribute_key, const const_string_ref& attribute_value)
{
    UNUSED(attribute_key);
    UNUSED(attribute_value);
    validator_assert(state[current_state_depth] == VISIT_XREF, "Bad state");
}

void ExporterValidatorVisitor::visit_end_xref()
{
    validator_assert(state[current_state_depth] == VISIT_XREF, "Bad state");
    current_state_depth--;
    validator_assert(state[current_state_depth] == VISIT_XREFS, "Bad state");
}

void ExporterValidatorVisitor::visit_segments_start()
{
    //TODO update this check
    validator_assert(state[current_state_depth] == VISIT_STARTED, "Bad state");
}

void ExporterValidatorVisitor::visit_segments_end()
{
    //TODO update this check
    validator_assert(state[current_state_depth] == VISIT_STARTED, "Bad state");
}

void ExporterValidatorVisitor::visit_attribute(const const_string_ref& attr_name, const const_string_ref& attr_value)
{
    UNUSED(attr_name);
    UNUSED(attr_value);
    validator_assert(state[current_state_depth] == VISIT_OBJECT_VERSION, "Bad state");
}

void ExporterValidatorVisitor::visit_blob(offset_t offset, const void* blob, size_t len)
{
    UNUSED(offset);
    UNUSED(blob);
    UNUSED(len);
    validator_assert(state[current_state_depth] == VISIT_OBJECT_VERSION, "Bad state");
}

void ExporterValidatorVisitor::visit_flags(flags_t flags)
{
    UNUSED(flags);
    validator_assert(state[current_state_depth] == VISIT_OBJECT_VERSION, "Bad state");
}

