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

#ifndef MEMORYDATABASEVISITOR_H_
#define MEMORYDATABASEVISITOR_H_

#include "IModelVisitor.hpp"
#include <vector>
#include <map>

#ifdef SWIG
#error swig MUST NOT include this header
#endif

class YaToolObjectVersion;
class YaToolReferencedObject;
class MatchingSystem;

class MemoryModelVisitor: public IModelVisitor
{
    public:
                 MemoryModelVisitor();
        ~MemoryModelVisitor() override {}

        void visit_end_deleted_object() = 0;
        void visit_end_default_object() = 0;
        void visit_end_reference_object() = 0;
        void visit_end_object_version() = 0;

        void visit_start() override;
        void visit_end() override;
        void visit_start_object(YaToolObjectType_e object_type) override;
        void visit_start_reference_object(YaToolObjectType_e object_type) override;
        void visit_start_deleted_object(YaToolObjectType_e object_type) override;
        void visit_start_default_object(YaToolObjectType_e object_type) override;
        void visit_id(YaToolObjectId object_id) override;
        void visit_start_object_version() override;
        void visit_parent_id(YaToolObjectId object_id) override;
        void visit_address(offset_t address) override;
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

        YaToolObjectType_e                      object_type_;
        std::shared_ptr<YaToolObjectVersion>    current_object_version_;
        std::shared_ptr<YaToolReferencedObject> current_referenced_object_;
        YaToolObjectId                          current_referenced_object_id_;
        offset_t                                current_xref_offset_;

#ifndef SWIG
        std::shared_ptr<MatchingSystem> get_matching_system_for_attributes(const std::map<const std::string,const std::string>& attributes);
        std::map<const std::map<const std::string,const std::string>, std::shared_ptr<MatchingSystem>>  matching_systems_by_attrs_;
        std::vector<std::shared_ptr<MatchingSystem>>                                                    matching_systems_by_id_;
#endif
    private:
        YaToolObjectId                                      current_xref_offset_value_;
        operand_t                                           current_xref_operand_;
        std::map<std::string,std::string>                   current_xref_attributes_;
        offset_t                                            current_matching_system_address_;
        std::map<const std::string, const std::string>      current_matching_system_description_;

};

#endif /* MEMORYDATABASEVISITOR_H_ */
