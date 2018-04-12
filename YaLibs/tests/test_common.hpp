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
        ASSERT_EQ(chdir(current_dir.string().data()), 0);
    }

    virtual void TearDown()
    {
        ASSERT_EQ(chdir(orig_dir.string().data()), 0);
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
        void visit_start() override
        {
            call_trace_q->push("visit_start()");
        };
        void visit_end() override
        {
            call_trace_q->push("visit_end()");
        };
        void visit_start_version(YaToolObjectType_e, YaToolObjectId) override
        {
            call_trace_q->push("visit_start_version()");
        };
        void visit_deleted(YaToolObjectType_e, YaToolObjectId) override
        {
            call_trace_q->push("visit_deleted()");
        };
        void visit_end_version() override
        {
            call_trace_q->push("visit_end_version()");
        };
        void visit_parent_id(YaToolObjectId) override
        {
            call_trace_q->push("visit_parent_id()");
        };
        void visit_address(offset_t) override
        {
            call_trace_q->push("visit_address()");
        };
        void visit_name(const const_string_ref&, int) override
        {
            call_trace_q->push("visit_name()");
        };
        void visit_size(offset_t) override
        {
            call_trace_q->push("visit_size()");
        };
        void visit_start_signatures() override
        {
            call_trace_q->push("visit_start_signatures()");
        };
        void visit_signature(SignatureMethod_e, SignatureAlgo_e, const const_string_ref&) override
        {
            call_trace_q->push("visit_signature()");
        };
        void visit_end_signatures() override
        {
            call_trace_q->push("visit_end_signatures()");
        };
        void visit_prototype(const const_string_ref&) override
        {
            call_trace_q->push("visit_prototype()");
        };
        void visit_string_type(int) override
        {
            call_trace_q->push("visit_string_type()");
        };
        void visit_header_comment(bool, const const_string_ref&) override
        {
            call_trace_q->push("visit_header_comment()");
        };
        void visit_start_offsets() override
        {
            call_trace_q->push("visit_start_offsets()");
        };
        void visit_end_offsets() override{
            call_trace_q->push("visit_end_offsets()");
        };
        void visit_offset_comments(offset_t, CommentType_e, const const_string_ref&) override
        {
            call_trace_q->push("visit_offset_comments()");
        };
        void visit_offset_valueview(offset_t, int32_t, const const_string_ref&) override
        {
            call_trace_q->push("visit_offset_valueview()");
        };
        void visit_offset_registerview(offset_t, offset_t, const const_string_ref&, const const_string_ref&) override
        {
            call_trace_q->push("visit_offset_registerview()");
        };
        void visit_offset_hiddenarea(offset_t, offset_t, const const_string_ref&) override
        {
            call_trace_q->push("visit_offset_hiddenarea()");
        };
        void visit_start_xrefs() override
        {
            call_trace_q->push("visit_start_xrefs()");
        };
        void visit_end_xrefs() override
        {
            call_trace_q->push("visit_end_xrefs()");
        };
        void visit_start_xref(offset_t, YaToolObjectId, operand_t) override
        {
            call_trace_q->push("visit_start_xref()");
        };
        void visit_end_xref() override
        {
            call_trace_q->push("visit_end_xref()");
        };
        void visit_xref_attribute(const const_string_ref&, const const_string_ref&) override
        {
            call_trace_q->push("visit_xref_attribute()");
        };
        void visit_segments_start() override
        {
            call_trace_q->push("visit_segments_start()");
        };
        void visit_segments_end() override
        {
            call_trace_q->push("visit_segments_end()");
        };
        void visit_attribute(const const_string_ref&, const const_string_ref&) override
        {
            call_trace_q->push("visit_attribute()");
        };
        void visit_blob(offset_t, const void*, size_t) override
        {
            call_trace_q->push("visit_blob()");
        };
        void visit_flags(flags_t) override
        {
            call_trace_q->push("visit_flags()");
        };

        std::shared_ptr<std::queue<std::string>> call_trace_q;
        TestDatabaseModelVisitor(std::shared_ptr<std::queue<std::string>> call_trace_q) {
            this->call_trace_q = call_trace_q;
        }
};
#endif
