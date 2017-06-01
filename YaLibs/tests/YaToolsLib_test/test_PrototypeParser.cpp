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
#include <list>
#include <string>
#include <vector>
#include <functional>


#include "gtest/gtest.h"


#ifndef YALIB_TEST
#   define YALIB_TEST
#endif

#include "test_common.hpp"

#include "PrototypeParser.hpp"
#include "YaToolObjectId.hpp"

using namespace std;

static std::vector<std::pair<std::string, YaToolObjectId>> parse_proto_for_hashes(const std::string& prototype)
{
    std::vector<std::pair<std::string, YaToolObjectId>> v;
    ParseProtoFromHashes(prototype, [&](const std::string& name, YaToolObjectId id)
    {
        v.push_back(std::make_pair(name, id));
        return WALK_CONTINUE;
    });
    return v;
}

class TestPrototypeParser : public testing::Test {
protected:
    virtual void SetUp() {
    }

    virtual void TearDown() {
    }
};

TEST_F(TestPrototypeParser, TestEmpty) {
    std::vector<std::pair<std::string,YaToolObjectId>> result;
    EXPECT_EQ(parse_proto_for_hashes(""), result);
}

TEST_F(TestPrototypeParser, TestOneProto) {
    string prototype("__int64 __fastcall tioto(struc_1 /*%struc_1#123456789ABCDEF0%*/ *mystruc)");
    std::vector<std::pair<std::string,YaToolObjectId>> result({
        std::pair<std::string, YaToolObjectId>("struc_1", YaToolObjectId_From_StdString(std::string("123456789ABCDEF0")))
    });
    EXPECT_EQ(parse_proto_for_hashes(prototype), result);
}

TEST_F(TestPrototypeParser, TestTwoProto) {
    string prototype("__int64 __fastcall tioto(struc_1 /*%struc_1#123456789ABCDEF0%*/ *mystruc, struc_2 /*%struc_2#FEDCBA9876543210%*/ *mystruc2)");
    std::vector<std::pair<std::string,YaToolObjectId>> result({
        std::pair<std::string, YaToolObjectId>("struc_1", YaToolObjectId_From_StdString(std::string("123456789ABCDEF0"))),
        std::pair<std::string, YaToolObjectId>("struc_2", YaToolObjectId_From_StdString(std::string("FEDCBA9876543210")))
    });
    EXPECT_EQ(parse_proto_for_hashes(prototype), result);
}

TEST_F(TestPrototypeParser, TestBadProto) {
    string prototype("__int64 __fastcall tioto(struc_1 /*%struc_1123456789ABCDEF0%*/ *mystruc)");
    std::vector<std::pair<std::string,YaToolObjectId>> result;
    EXPECT_EQ(parse_proto_for_hashes(prototype), result);
}

TEST_F(TestPrototypeParser, TestBadProto2) {
    string prototype("__int64 __fastcall tioto(struc_1 /*%struc_1#123456789AB#CDEF0%*/ *mystruc)");
    std::vector<std::pair<std::string,YaToolObjectId>> result;
    EXPECT_EQ(parse_proto_for_hashes(prototype), result);
}


