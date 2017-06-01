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

#include <gtest/gtest.h>

#include <string>
#include <queue>
#include <stdio.h>

#ifdef _MSC_VER
#   include <filesystem>
#   define tempnam _tempnam
#   define chdir _chdir
#else
#   include <experimental/filesystem>
#endif

namespace fs = std::experimental::filesystem;

class TestInTempFolder : public testing::Test
{
protected:
    virtual void SetUp()
    {
        char tmp[32];
        snprintf(tmp, 32, "tmp_%x", ++index);
        current_dir = fs::current_path() / "temp_folder_unittest" / tmp;
        fs::create_directories(current_dir);
        chdir(current_dir.string().data());
    }

    virtual void TearDown()
    {
        chdir(orig_dir.string().data());
        std::error_code ec;
        fs::remove_all(current_dir, ec);
    }

    TestInTempFolder()
        : orig_dir(testing::internal::FilePath::GetCurrentDir().string())
    {
    }

    fs::path current_dir;
    fs::path orig_dir;

public:
    static int index;
};

#ifdef YALIB_TEST
#include "IModelVisitor.hpp"
class TestDatabaseModelVisitor : public IModelVisitor {
public:
        virtual void visit_start(){
            call_trace_q->push("visit_start()");
        };
        virtual void visit_end(){
            call_trace_q->push("visit_end()");
        };
        virtual void visit_start_object(YaToolObjectType_e){
            call_trace_q->push("visit_start_object()");
        };
        virtual void visit_start_reference_object(YaToolObjectType_e){
            call_trace_q->push("visit_start_reference_object()");
        };
        virtual void visit_start_deleted_object(YaToolObjectType_e){
            call_trace_q->push("visit_start_deleted_object()");
        };
        virtual void visit_start_default_object(YaToolObjectType_e){
            call_trace_q->push("visit_start_default_object()");
        };
        virtual void visit_end_deleted_object(){
            call_trace_q->push("visit_end_deleted_object()");
        };
        virtual void visit_end_default_object(){
            call_trace_q->push("visit_end_default_object()");
        };
        virtual void visit_end_reference_object(){
            call_trace_q->push("visit_end_reference_object()");
        };
        virtual void visit_id(YaToolObjectId){
            call_trace_q->push("visit_id()");
        };
        virtual void visit_start_object_version(){
            call_trace_q->push("visit_start_object_version()");
        };
        virtual void visit_parent_id(YaToolObjectId){
            call_trace_q->push("visit_parent_id()");
        };
        virtual void visit_address(offset_t){
            call_trace_q->push("visit_address()");
        };
        virtual void visit_end_object_version(){
            call_trace_q->push("visit_end_object_version()");
        };
        virtual void visit_name(const const_string_ref&, int){
            call_trace_q->push("visit_name()");
        };
        virtual void visit_size(offset_t){
            call_trace_q->push("visit_size()");
        };
        virtual void visit_start_signatures(){
            call_trace_q->push("visit_start_signatures()");
        };
        virtual void visit_signature(SignatureMethod_e, SignatureAlgo_e, const const_string_ref&){
            call_trace_q->push("visit_signature()");
        };
        virtual void visit_end_signatures(){
            call_trace_q->push("visit_end_signatures()");
        };
        virtual void visit_prototype(const const_string_ref&){
            call_trace_q->push("visit_prototype()");
        };
        virtual void visit_string_type(int){
            call_trace_q->push("visit_string_type()");
        };
        virtual void visit_header_comment(bool, const const_string_ref&){
            call_trace_q->push("visit_header_comment()");
        };
        virtual void visit_start_offsets(){
            call_trace_q->push("visit_start_offsets()");
        };
        virtual void visit_end_offsets(){
            call_trace_q->push("visit_end_offsets()");
        };
        virtual void visit_offset_comments(offset_t, CommentType_e, const const_string_ref&){
            call_trace_q->push("visit_offset_comments()");
        };
        virtual void visit_offset_valueview(offset_t, int32_t, const const_string_ref&){
            call_trace_q->push("visit_offset_valueview()");
        };
        virtual void visit_offset_registerview(offset_t, offset_t, const const_string_ref&, const const_string_ref&){
            call_trace_q->push("visit_offset_registerview()");
        };
        virtual void visit_offset_hiddenarea(offset_t, offset_t, const const_string_ref&){
            call_trace_q->push("visit_offset_hiddenarea()");
        };
        virtual void visit_start_xrefs(){
            call_trace_q->push("visit_start_xrefs()");
        };
        virtual void visit_end_xrefs(){
            call_trace_q->push("visit_end_xrefs()");
        };
        virtual void visit_start_xref(offset_t, YaToolObjectId, operand_t){
            call_trace_q->push("visit_start_xref()");
        };
        virtual void visit_end_xref(){
            call_trace_q->push("visit_end_xref()");
        };
        virtual void visit_xref_attribute(const const_string_ref&, const const_string_ref&){
            call_trace_q->push("visit_xref_attribute()");
        };
        virtual void visit_start_matching_systems(){
            call_trace_q->push("visit_start_matching_systems()");
        };
        virtual void visit_end_matching_systems(){
            call_trace_q->push("visit_end_matching_systems()");
        };
        virtual void visit_start_matching_system(offset_t){
            call_trace_q->push("visit_start_matching_system()");
        };
        virtual void visit_matching_system_description(const const_string_ref&, const const_string_ref&){
            call_trace_q->push("visit_matching_system_description()");
        };
        virtual void visit_end_matching_system(){
            call_trace_q->push("visit_end_matching_system()");
        };
        virtual void visit_segments_start(){
            call_trace_q->push("visit_segments_start()");
        };
        virtual void visit_segments_end(){
            call_trace_q->push("visit_segments_end()");
        };
        virtual void visit_attribute(const const_string_ref&, const const_string_ref&){
            call_trace_q->push("visit_attribute()");
        };

        virtual void visit_blob(offset_t, const void*, size_t){
            call_trace_q->push("visit_blob()");
        };
        virtual void visit_flags(flags_t){
            call_trace_q->push("visit_flags()");
        };

        std::shared_ptr<std::queue<std::string>> call_trace_q;
        TestDatabaseModelVisitor(std::shared_ptr<std::queue<std::string>> call_trace_q) {
            this->call_trace_q = call_trace_q;
        }
};
#endif
