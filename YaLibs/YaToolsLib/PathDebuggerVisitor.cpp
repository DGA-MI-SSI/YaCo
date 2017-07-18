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

#include "PathDebuggerVisitor.hpp"

#include "DelegatingVisitor.hpp"
#include "Yatools.h"
#include "Logger.h"

#include <memory>

#define LOG(FMT, ...) YALOG_INFO("path_debugger", (FMT), ## __VA_ARGS__)

namespace
{
int path_debugger_id = 0;

class PathDebuggerVisitor : public DelegatingVisitor
{
public:
    PathDebuggerVisitor(const std::string& name, const std::shared_ptr<IModelVisitor>& delegate, PrintValues_e eprint);
    ~PathDebuggerVisitor() override;

    void visit_start() override;
    void visit_end() override;
    void visit_start_object(YaToolObjectType_e object_type) override;
    void visit_start_reference_object(YaToolObjectType_e object_type) override;
    void visit_start_deleted_object(YaToolObjectType_e object_type) override;
    void visit_start_default_object(YaToolObjectType_e object_type) override;
    void visit_end_deleted_object() override;
    void visit_end_default_object() override;
    void visit_end_reference_object() override;
    void visit_id(YaToolObjectId object_id) override;
    void visit_start_object_version() override;
    void visit_parent_id(YaToolObjectId object_idobject_id) override;
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
    void visit_xref_attribute(const const_string_ref& key_attribute, const const_string_ref& value_attribute) override;
    void visit_start_matching_systems() override;
    void visit_end_matching_systems() override;
    void visit_start_matching_system(offset_t address) override;
    void visit_matching_system_description(const const_string_ref& description_key, const const_string_ref& description_value) override;
    void visit_end_matching_system() override;
    void visit_segments_start() override;
    void visit_segments_end() override;
    void visit_attribute(const const_string_ref& attr_name, const const_string_ref& attr_value) override;
    void visit_blob(offset_t offset, const void* blob, size_t len) override;
    void visit_flags(flags_t flags) override;

private:
    bool    print_values_;
    int     id_;
};
}

std::shared_ptr<IModelVisitor> MakePathDebuggerVisitor(const std::string& name, const std::shared_ptr<IModelVisitor>& delegate, PrintValues_e eprint)
{
    return std::make_shared<PathDebuggerVisitor>(name, delegate, eprint);
}

#define LOG_IN()  LOG("PathDebuggerVisitor:%x: in  " "\n", id_)
#define LOG_OUT() LOG("PathDebuggerVisitor:%x: out " "\n", id_)

PathDebuggerVisitor::PathDebuggerVisitor(const std::string& name, const std::shared_ptr<IModelVisitor>& delegate, PrintValues_e eprint)
    : print_values_ (eprint == PrintValues)
    , id_           (path_debugger_id++)
{
    add_delegate(delegate);
    LOG("PathDebuggerVisitorA:%x: in "  " print_values=%s name=%s\n", id_, TO_STRING(print_values_), name.data());
    LOG("PathDebuggerVisitorA:%x: out "  "\n", id_);
    LOG("toto");
}

PathDebuggerVisitor::~PathDebuggerVisitor()
{
    LOG_IN();
    LOG_OUT();
}

void PathDebuggerVisitor::visit_start()
{
    LOG_IN();
    DelegatingVisitor::visit_start();
    LOG_OUT();
}

void PathDebuggerVisitor::visit_end()
{
    LOG_IN();
    DelegatingVisitor::visit_end();
    LOG_OUT();
}

void PathDebuggerVisitor::visit_start_object(YaToolObjectType_e object_type)
{
    LOG("PathDebuggerVisitor:%x: in "  " -- object_type=%x\n", id_, object_type);
    DelegatingVisitor::visit_start_object(object_type);
    LOG_OUT();
}

void PathDebuggerVisitor::visit_start_reference_object(
        YaToolObjectType_e object_type)
{
    LOG("PathDebuggerVisitor:%x: in "  " -- object_type=%x\n", id_, object_type);
    DelegatingVisitor::visit_start_reference_object(object_type);
    LOG_OUT();
}

void PathDebuggerVisitor::visit_start_deleted_object(
        YaToolObjectType_e object_type)
{
    LOG("PathDebuggerVisitor:%x: in "  " -- object_type=%x\n", id_, object_type);
    DelegatingVisitor::visit_start_deleted_object(object_type);
    LOG_OUT();
}

void PathDebuggerVisitor::visit_start_default_object(
        YaToolObjectType_e object_type)
{
    LOG("PathDebuggerVisitor:%x: in "  " -- object_type=%x\n", id_, object_type);
    DelegatingVisitor::visit_start_default_object(object_type);
    LOG_OUT();
}

void PathDebuggerVisitor::visit_end_reference_object()
{
    LOG_IN();
    DelegatingVisitor::visit_end_reference_object();
    LOG_OUT();
}

void PathDebuggerVisitor::visit_end_deleted_object()
{
    LOG_IN();
    DelegatingVisitor::visit_end_deleted_object();
    LOG_OUT();
}

void PathDebuggerVisitor::visit_end_default_object()
{
    LOG_IN();
    DelegatingVisitor::visit_end_default_object();
    LOG_OUT();
}

void PathDebuggerVisitor::visit_id(YaToolObjectId id)
{
    LOG("PathDebuggerVisitor:%x: in "  " -- id=%llx\n", id_, id);
    DelegatingVisitor::visit_id(id);
    LOG_OUT();
}

void PathDebuggerVisitor::visit_parent_id(YaToolObjectId parent_object_id)
{
    LOG_IN();
    DelegatingVisitor::visit_parent_id(parent_object_id);
    LOG_OUT();
}

void PathDebuggerVisitor::visit_address(offset_t address)
{
    LOG_IN();
    DelegatingVisitor::visit_address(address);
    LOG_OUT();
}

void PathDebuggerVisitor::visit_start_object_version()
{
    LOG_IN();
    DelegatingVisitor::visit_start_object_version();
    LOG_OUT();
}

void PathDebuggerVisitor::visit_end_object_version()
{
    LOG_IN();
    DelegatingVisitor::visit_end_object_version();
    LOG_OUT();
}

void PathDebuggerVisitor::visit_name(const const_string_ref& name, int flags)
{
    LOG("PathDebuggerVisitor:%x: in "  " -- name=%s\n", id_, name.value);
    DelegatingVisitor::visit_name(name, flags);
    LOG_OUT();
}

void PathDebuggerVisitor::visit_size(offset_t size)
{
    LOG_IN();
    DelegatingVisitor::visit_size(size);
    LOG_OUT();
}

void PathDebuggerVisitor::visit_start_signatures()
{
    LOG_IN();
    DelegatingVisitor::visit_start_signatures();
    LOG_OUT();
}

void PathDebuggerVisitor::visit_signature(SignatureMethod_e method, SignatureAlgo_e algo, const const_string_ref& hex)
{
    if(print_values_)
    {
        LOG("PathDebuggerVisitor:%x: in "  " signature=%s\n", id_, hex.value);
    }
    else
    {
        LOG_IN();
    }
    DelegatingVisitor::visit_signature(method, algo, hex);
    LOG_OUT();
}

void PathDebuggerVisitor::visit_end_signatures()
{
    LOG_IN();
    DelegatingVisitor::visit_end_signatures();
    LOG_OUT();
}

void PathDebuggerVisitor::visit_prototype(const const_string_ref& prototype)
{
    LOG_IN();
    DelegatingVisitor::visit_prototype(prototype);
    LOG_OUT();
}

void PathDebuggerVisitor::visit_string_type(int str_type)
{
    LOG_IN();
    DelegatingVisitor::visit_string_type(str_type);
    LOG_OUT();
}

void PathDebuggerVisitor::visit_header_comment(bool repeatable, const const_string_ref& comment)
{
    LOG_IN();
    DelegatingVisitor::visit_header_comment(repeatable, comment);
    LOG_OUT();
}

void PathDebuggerVisitor::visit_start_offsets()
{
    LOG_IN();
    DelegatingVisitor::visit_start_offsets();
    LOG_OUT();
}

void PathDebuggerVisitor::visit_offset_comments(offset_t offset,
        CommentType_e comment_type, const const_string_ref& comment)
{
    LOG_IN();
    if(print_values_)
    {
        LOG(" : %" PRIXOFFSET ":%x\"%s\"\n", offset, comment_type, comment.value);
    }
    DelegatingVisitor::visit_offset_comments(offset, comment_type, comment);
    LOG_OUT();
}

void PathDebuggerVisitor::visit_offset_valueview(offset_t offset, operand_t operand,
        const const_string_ref& view_value)
{
    LOG_IN();
    if(print_values_)
    {
        LOG(" : %" PRIXOFFSET ":%x\n", offset, operand);
    }
    DelegatingVisitor::visit_offset_valueview(offset, operand, view_value);
    LOG_OUT();
}

void PathDebuggerVisitor::visit_offset_registerview(offset_t offset,
        offset_t end_offset, const const_string_ref& register_name, const const_string_ref& register_new_name)
{
    LOG_IN();
    DelegatingVisitor::visit_offset_registerview(offset, end_offset,
            register_name, register_new_name);
    LOG_OUT();
}

void PathDebuggerVisitor::visit_offset_hiddenarea(offset_t offset, offset_t area_size,
        const const_string_ref& hidden_area_value)
{
    LOG_IN();
    DelegatingVisitor::visit_offset_hiddenarea(offset, area_size,
            hidden_area_value);
    LOG_OUT();
}

void PathDebuggerVisitor::visit_end_offsets()
{
    LOG_IN();
    DelegatingVisitor::visit_end_offsets();
    LOG_OUT();
}

void PathDebuggerVisitor::visit_start_xrefs()
{
    LOG_IN();
    DelegatingVisitor::visit_start_xrefs();
    LOG_OUT();
}

void PathDebuggerVisitor::visit_start_xref(offset_t offset,
        YaToolObjectId offset_value, operand_t operand)
{
    LOG("PathDebuggerVisitor:%x: in "  " -- offset=%" PRIXOFFSET ":%x, offset_value=%llx\n", id_, offset, operand, offset_value);
    DelegatingVisitor::visit_start_xref(offset, offset_value, operand);
    LOG_OUT();
}

void PathDebuggerVisitor::visit_xref_attribute(const const_string_ref& attribute_key,
        const const_string_ref& attribute_value)
{
    LOG_IN();
    DelegatingVisitor::visit_xref_attribute(attribute_key, attribute_value);
    LOG_OUT();
}

void PathDebuggerVisitor::visit_end_xref()
{
    LOG_IN();
    DelegatingVisitor::visit_end_xref();
    LOG_OUT();
}

void PathDebuggerVisitor::visit_end_xrefs()
{
    LOG_IN();
    DelegatingVisitor::visit_end_xrefs();
    LOG_OUT();
}

void PathDebuggerVisitor::visit_start_matching_systems()
{
    LOG_IN();
    DelegatingVisitor::visit_start_matching_systems();
    LOG_OUT();
}

void PathDebuggerVisitor::visit_start_matching_system(offset_t address)
{
    LOG_IN();
    DelegatingVisitor::visit_start_matching_system(address);
    LOG_OUT();
}

void PathDebuggerVisitor::visit_matching_system_description(
        const const_string_ref& description_key, const const_string_ref& description_value)
{
    LOG_IN();
    DelegatingVisitor::visit_matching_system_description(description_key,
            description_value);
    LOG_OUT();
}

void PathDebuggerVisitor::visit_end_matching_system()
{
    LOG_IN();
    DelegatingVisitor::visit_end_matching_system();
    LOG_OUT();
}

void PathDebuggerVisitor::visit_end_matching_systems()
{
    LOG_IN();
    DelegatingVisitor::visit_end_matching_systems();
    LOG_OUT();
}

void PathDebuggerVisitor::visit_segments_start()
{
    LOG_IN();
    DelegatingVisitor::visit_segments_start();
    LOG_OUT();
}

void PathDebuggerVisitor::visit_segments_end()
{
    LOG_IN();
    DelegatingVisitor::visit_segments_end();
    LOG_OUT();
}

void PathDebuggerVisitor::visit_attribute(const const_string_ref& attr_name, const const_string_ref& attr_value)
{
    LOG_IN();
    DelegatingVisitor::visit_attribute(attr_name, attr_value);
    LOG_OUT();
}

void PathDebuggerVisitor::visit_flags(flags_t flags)
{
    LOG_IN();
    DelegatingVisitor::visit_flags(flags);
    LOG_OUT();
}

void PathDebuggerVisitor::visit_blob(offset_t offset, const void* blob,
        size_t len)
{
    LOG_IN();
    DelegatingVisitor::visit_blob(offset, blob, len);
    LOG_OUT();
}
