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

#include "gtest/gtest.h"


#ifndef YALIB_TEST
#   define YALIB_TEST
#endif

#include "test_common.hpp"

#include "YaToolReferencedObject.hpp"
#include "../../YaToolsLib/YaTypes.hpp"
#include "YaToolObjectId.hpp"

using namespace std;

class TestYaToolReferencedObject : public TestInTempFolder {
protected:
    virtual void SetUp() {
        TestInTempFolder::SetUp();
    }

    virtual void TearDown() {
        TestInTempFolder::TearDown();

    }
};

TEST_F(TestYaToolReferencedObject, init) {
    YaToolReferencedObject obj(OBJECT_TYPE_UNKNOWN);
    EXPECT_EQ(obj.hasId(), false);
}

TEST_F(TestYaToolReferencedObject, eq_no_id) {
    auto pobj1 = make_shared<YaToolReferencedObject>(OBJECT_TYPE_UNKNOWN);
    auto pobj2 = make_shared<YaToolReferencedObject>(OBJECT_TYPE_UNKNOWN);
    EXPECT_EQ(pobj1, pobj2);
}

TEST_F(TestYaToolReferencedObject, eq_id) {
    auto pobj1 = make_shared<YaToolReferencedObject>(OBJECT_TYPE_UNKNOWN);
    auto pobj2 = make_shared<YaToolReferencedObject>(OBJECT_TYPE_UNKNOWN);
    std::string hash("123456789ABCDEF0");
    auto id1 = YaToolObjectId_From_StdString(hash);
    auto id2 = YaToolObjectId_From_StdString(hash);
    pobj1->setId(id1);
    pobj2->setId(id2);
    EXPECT_EQ(pobj1, pobj2);
}

TEST_F(TestYaToolReferencedObject, gt_id) {
    auto pobj1 = make_shared<YaToolReferencedObject>(OBJECT_TYPE_UNKNOWN);
    auto pobj2 = make_shared<YaToolReferencedObject>(OBJECT_TYPE_UNKNOWN);
    std::string hash("123456789ABCDEF1");
    std::string hash2("123456789ABCDEF0");
    auto id1 = YaToolObjectId_From_StdString(hash);
    auto id2 = YaToolObjectId_From_StdString(hash2);
    pobj1->setId(id1);
    pobj2->setId(id2);
    EXPECT_GT(pobj1, pobj2);
}

TEST_F(TestYaToolReferencedObject, gt2_id) {
    auto pobj1 = make_shared<YaToolReferencedObject>(OBJECT_TYPE_UNKNOWN);
    auto pobj2 = make_shared<YaToolReferencedObject>(OBJECT_TYPE_CODE);
    std::string hash("123456789ABCDEF0");
    std::string hash2("123456789ABCDEF1");
    auto id1 = YaToolObjectId_From_StdString(hash);
    auto id2 = YaToolObjectId_From_StdString(hash2);
    pobj1->setId(id1);
    pobj2->setId(id2);
    EXPECT_LT(pobj1, pobj2);
}

TEST_F(TestYaToolReferencedObject, list_same_type) {
    std::list<std::shared_ptr<YaToolReferencedObject>> objects;
    auto pobj1 = make_shared<YaToolReferencedObject>(OBJECT_TYPE_UNKNOWN);
    auto pobj2 = make_shared<YaToolReferencedObject>(OBJECT_TYPE_UNKNOWN);
    auto pobj3 = make_shared<YaToolReferencedObject>(OBJECT_TYPE_UNKNOWN);
    auto pobj4 = make_shared<YaToolReferencedObject>(OBJECT_TYPE_UNKNOWN);
    auto pobj5 = make_shared<YaToolReferencedObject>(OBJECT_TYPE_UNKNOWN);
    auto pobj6 = make_shared<YaToolReferencedObject>(OBJECT_TYPE_UNKNOWN);
    std::string hash("0123456789ABCDEF");
    std::string hash2("1123456789ABCDEF");
    std::string hash3("2123456789ABCDEF");
    std::string hash4("3123456789ABCDEF");
    std::string hash5("4123456789ABCDEF");
    std::string hash6("5123456789ABCDEF");
    auto id1 = YaToolObjectId_From_StdString(hash);
    auto id2 = YaToolObjectId_From_StdString(hash2);
    auto id3 = YaToolObjectId_From_StdString(hash3);
    auto id4 = YaToolObjectId_From_StdString(hash4);
    auto id5 = YaToolObjectId_From_StdString(hash5);
    auto id6 = YaToolObjectId_From_StdString(hash6);
    pobj1->setId(id1);
    pobj2->setId(id2);
    pobj3->setId(id3);
    pobj4->setId(id4);
    pobj5->setId(id5);
    pobj6->setId(id6);
    objects.push_back(pobj1);
    objects.push_back(pobj5);
    objects.push_back(pobj3);
    objects.push_back(pobj2);
    objects.push_back(pobj6);
    objects.push_back(pobj4);
    objects.sort();
    EXPECT_EQ(objects.front(), pobj1);
    objects.pop_front();
    EXPECT_EQ(objects.front(), pobj2);
    objects.pop_front();
    EXPECT_EQ(objects.front(), pobj3);
    objects.pop_front();
    EXPECT_EQ(objects.front(), pobj4);
    objects.pop_front();
    EXPECT_EQ(objects.front(), pobj5);
    objects.pop_front();
    EXPECT_EQ(objects.front(), pobj6);
    objects.pop_front();
}

TEST_F(TestYaToolReferencedObject, list_several_types) {
    std::list<std::shared_ptr<YaToolReferencedObject>> objects;
    auto pobj1 = make_shared<YaToolReferencedObject>(OBJECT_TYPE_UNKNOWN);
    auto pobj2 = make_shared<YaToolReferencedObject>(OBJECT_TYPE_DATA);
    auto pobj3 = make_shared<YaToolReferencedObject>(OBJECT_TYPE_CODE);
    auto pobj4 = make_shared<YaToolReferencedObject>(OBJECT_TYPE_FUNCTION);
    auto pobj5 = make_shared<YaToolReferencedObject>(OBJECT_TYPE_FUNCTION);
    auto pobj6 = make_shared<YaToolReferencedObject>(OBJECT_TYPE_FUNCTION);
    std::string hash1("0123456789ABCDEF");
    std::string hash2("1123456789ABCDEF");
    std::string hash3("2123456789ABCDEF");
    std::string hash4("3123456789ABCDEF");
    std::string hash5("4123456789ABCDEF");
    std::string hash6("5123456789ABCDEF");
    auto id1 = YaToolObjectId_From_StdString(hash1);
    auto id2 = YaToolObjectId_From_StdString(hash2);
    auto id3 = YaToolObjectId_From_StdString(hash3);
    auto id4 = YaToolObjectId_From_StdString(hash4);
    auto id5 = YaToolObjectId_From_StdString(hash5);
    auto id6 = YaToolObjectId_From_StdString(hash6);
    pobj1->setId(id1);
    pobj2->setId(id2);
    pobj3->setId(id3);
    pobj4->setId(id4);
    pobj5->setId(id5);
    pobj6->setId(id6);
    objects.push_back(pobj1);
    objects.push_back(pobj5);
    objects.push_back(pobj3);
    objects.push_back(pobj2);
    objects.push_back(pobj6);
    objects.push_back(pobj4);
    objects.sort();
    EXPECT_EQ(objects.front(), pobj1);
    objects.pop_front();
    EXPECT_EQ(objects.front(), pobj2);
    objects.pop_front();
    EXPECT_EQ(objects.front(), pobj3);
    objects.pop_front();
    EXPECT_EQ(objects.front(), pobj4);
    objects.pop_front();
    EXPECT_EQ(objects.front(), pobj5);
    objects.pop_front();
    EXPECT_EQ(objects.front(), pobj6);
    objects.pop_front();
}


