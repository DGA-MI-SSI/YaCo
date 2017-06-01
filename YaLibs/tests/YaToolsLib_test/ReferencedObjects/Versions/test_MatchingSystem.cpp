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

#include <iostream>
#include "MatchingSystem.hpp"
#include "YaToolObjectVersion.hpp"
#include "YaToolObjectId.hpp"

#include "gtest/gtest.h"


#ifndef YALIB_TEST
#   define YALIB_TEST
#endif

#include "test_common.hpp"
#include "../Helpers.h"

using namespace std;

class TestMatchingSystem : public testing::Test {
protected:
    virtual void SetUp() {
    }

    virtual void TearDown() {

    }

};


class TestMatchingSystemVisitor: public TestDatabaseModelVisitor{
public:
    virtual void visit_start_matching_systems(){
        call_trace_q->push("visit_start_matching_systems()");
    };
    virtual void visit_end_matching_systems(){
        call_trace_q->push("visit_end_matching_systems()");
    };
    virtual void visit_start_matching_system(offset_t address){
        UNUSED(address);
        call_trace_q->push("visit_start_matching_system()");
    };
    virtual void visit_matching_system_description(const const_string_ref& description_key, const const_string_ref& description_value){
        call_trace_q->push(std::string("visit_matching_system_description(") + description_key.value + ", " + description_value.value + ")");
    };
    virtual void visit_end_matching_system(){
        call_trace_q->push("visit_end_matching_system()");
    }

    TestMatchingSystemVisitor(std::shared_ptr<std::queue<std::string>> queue) : TestDatabaseModelVisitor(queue) {
    }
};

TEST_F(TestMatchingSystem, Init) {
    int id = 1234;
    std::map<const std::string,const std::string> attributes;
    MatchingSystem test(id, attributes);
}

TEST_F(TestMatchingSystem, accept) {

    int id = 1234;
    std::map<const std::string,const std::string> attributes;
    attributes.insert(std::make_pair<const std::string, const std::string>("attr1", "value1"));
    attributes.insert(std::make_pair<const std::string, const std::string>("attr2", "value2"));
    attributes.insert(std::make_pair<const std::string, const std::string>("attr3", "value3"));
    MatchingSystem test_sys(id, attributes);

    auto call_queue = make_shared<std::queue<std::string>>();
    TestMatchingSystemVisitor visitor(call_queue);
//  visitor->visit_start();
    test_sys.accept(visitor);
//  visitor->visit_end();
    EXPECT_FALSE(call_queue->empty());
//  EXPECT_STREQ(call_queue->front().c_str(), "visit_start()");
//  EXPECT_NO_THROW(call_queue->pop());
    EXPECT_STREQ(call_queue->front().c_str(), "visit_matching_system_description(attr1, value1)");
    EXPECT_NO_THROW(call_queue->pop());
    EXPECT_STREQ(call_queue->front().c_str(), "visit_matching_system_description(attr2, value2)");
    EXPECT_NO_THROW(call_queue->pop());
    EXPECT_STREQ(call_queue->front().c_str(), "visit_matching_system_description(attr3, value3)");
//  EXPECT_NO_THROW(call_queue->pop());
//  EXPECT_STREQ(call_queue->front().c_str(), "visit_end()");
}

