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

#include <stdint.h>
#include "ExporterValidatorVisitor.hpp"

#include "IModelVisitor.hpp"
#include "Yatools.hpp"
#include "Helpers.h"

#include <memory>

#define validator_assert(CONDITION, FMT, ...) do {\
    if(CONDITION) break;\
    YALOG_ERROR(nullptr, " " FMT, ## __VA_ARGS__);\
    exit(-1);\
} while(0)

namespace
{
enum VisitorState_e
{
    VISIT_STARTED = 0,
    VISIT_START_OBJECT = 1,
    VISIT_START_REFERENCED_OBJECT = 2,
    VISIT_START_DEFAULT_OBJECT = 3,
    VISIT_START_DELETED_OBJECT = 4,
    VISIT_OBJECT_VERSION = 5,
    VISIT_SIGNATURES = 6,
    VISIT_OFFSETS = 7,
    VISIT_XREFS = 8,
    VISIT_XREF = 9,
    VISIT_MATCHING_SYSTEMS = 10,
    VISIT_MATCHING_SYSTEM = 11,
};

const int MAX_VISIT_DEPTH = 256;

class ExporterValidatorVisitor
    : public IModelVisitor
{
public:
    ExporterValidatorVisitor();
    ~ExporterValidatorVisitor() override;
    void visit_start() override;
    void visit_end() override;
    void visit_start_reference_object(YaToolObjectType_e object_type) override;
    void visit_start_deleted_object(YaToolObjectType_e object_type) override;
    void visit_end_deleted_object() override;
    void visit_end_reference_object() override;
    void visit_id(YaToolObjectId object_id) override;
    void visit_start_object_version() override;
    void visit_parent_id(YaToolObjectId object_id) override;
    void visit_address(offset_t address) override;
    void visit_end_object_version() override;
    void visit_name(const const_string_ref& name, int flags) override;
    void visit_size(offset_t size) override;
    void visit_start_signatures() override;
    void visit_signature(SignatureMethod_e method, SignatureAlgo_e algo, const const_string_ref& hex) override;
    void visit_end_signatures() override;
    void visit_prototype(const const_string_ref& prototype) override;
    void visit_string_type(int str_type) override;
    void visit_header_comment(bool repeatable, const const_string_ref& comment) override;
    void visit_start_offsets() override;
    void visit_end_offsets() override;
    void visit_offset_comments(offset_t offset, CommentType_e comment_type, const const_string_ref& comment) override;
    void visit_offset_valueview(offset_t offset, operand_t operand, const const_string_ref& view_value) override;
    void visit_offset_registerview(offset_t offset, offset_t end_offset, const const_string_ref& register_name, const const_string_ref& register_new_name) override;
    void visit_offset_hiddenarea(offset_t offset, offset_t area_size, const const_string_ref& hidden_area_value) override;
    void visit_start_xrefs() override;
    void visit_end_xrefs() override;
    void visit_start_xref(offset_t offset, YaToolObjectId offset_value, operand_t operand) override;
    void visit_end_xref() override;
    void visit_xref_attribute(const const_string_ref& attribute_key, const const_string_ref& attribute_value) override;
    void visit_segments_start() override;
    void visit_segments_end() override;
    void visit_attribute(const const_string_ref& attr_name, const const_string_ref& attr_value) override;
    void visit_blob(offset_t offset, const void* blob, size_t len) override;
    void visit_flags(flags_t flags) override;

private:
    VisitorState_e state[MAX_VISIT_DEPTH];
    int current_state_depth;
    offset_t last_offset_ea;
    bool id_visited;
};
}

std::shared_ptr<IModelVisitor> MakeExporterValidatorVisitor()
{
    return std::make_shared<ExporterValidatorVisitor>();
}

ExporterValidatorVisitor::ExporterValidatorVisitor() :
        current_state_depth(-1),
        last_offset_ea(UNKNOWN_ADDR),
        id_visited(false)
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
void ExporterValidatorVisitor::visit_start_reference_object(YaToolObjectType_e object_type)
{
    UNUSED(object_type);
    validator_assert(state[current_state_depth] == VISIT_STARTED, "Bad state");
    state[++current_state_depth] = VISIT_START_REFERENCED_OBJECT;
    id_visited = false;
}

void ExporterValidatorVisitor::visit_start_deleted_object(YaToolObjectType_e object_type)
{
    UNUSED(object_type);
    validator_assert(state[current_state_depth] == VISIT_STARTED, "Bad state");
    state[++current_state_depth] = VISIT_START_DELETED_OBJECT;
    id_visited = false;
}

void ExporterValidatorVisitor::visit_end_deleted_object()
{
    validator_assert(id_visited, "Id not visited");
    validator_assert(state[current_state_depth] == VISIT_START_DELETED_OBJECT, "Bad state");
    current_state_depth--;
    validator_assert(state[current_state_depth] == VISIT_STARTED, "Bad state");
}

void ExporterValidatorVisitor::visit_end_reference_object()
{
    validator_assert(id_visited, "Id not visited");
    validator_assert(state[current_state_depth] == VISIT_START_REFERENCED_OBJECT, "Bad state");
    current_state_depth--;
    validator_assert(state[current_state_depth] == VISIT_STARTED, "Bad state");
}

//#============= REFERENCE OBJECT ID ==============
void ExporterValidatorVisitor::visit_id(YaToolObjectId object_id)
{
    UNUSED(object_id);
    validator_assert(
            state[current_state_depth] == VISIT_START_OBJECT
                    || state[current_state_depth] == VISIT_START_REFERENCED_OBJECT
                    || state[current_state_depth] == VISIT_START_DELETED_OBJECT
                    || state[current_state_depth] == VISIT_START_DEFAULT_OBJECT, "Bad state");
    id_visited = true;
}
//#============= OBJECT VERSION ==============
void ExporterValidatorVisitor::visit_start_object_version()
{
    validator_assert(
            state[current_state_depth] == VISIT_START_OBJECT
                    || state[current_state_depth] == VISIT_START_REFERENCED_OBJECT
                    || state[current_state_depth] == VISIT_START_DELETED_OBJECT
                    || state[current_state_depth] == VISIT_START_DEFAULT_OBJECT, "Bad state");
    state[++current_state_depth] = VISIT_OBJECT_VERSION;
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

void ExporterValidatorVisitor::visit_end_object_version()
{
    validator_assert(state[current_state_depth] == VISIT_OBJECT_VERSION, "Bad state");
    current_state_depth--;
    validator_assert(
            state[current_state_depth] == VISIT_START_OBJECT
                    || state[current_state_depth] == VISIT_START_REFERENCED_OBJECT
                    || state[current_state_depth] == VISIT_START_DELETED_OBJECT
                    || state[current_state_depth] == VISIT_START_DEFAULT_OBJECT, "Bad state");
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

