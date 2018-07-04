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
#include "VersionRelation.hpp"

#include "gtest/gtest.h"


#ifndef YALIB_TEST
#   define YALIB_TEST
#endif

#define DEFAULT_CONFIDENCE  12
#define DEFAULT_TYPE RELATION_TYPE_NONE
#define DEFAULT_FOREIGN 1


class TestVersionRelation : public testing::Test {
protected:
    void SetUp() override
    {
        HVersion object_version{nullptr, 0x01234567};
        pRelation = std::make_shared<VersionRelation>(object_version, default_type, default_confidence, default_direction);
    }

    std::shared_ptr<VersionRelation> pRelation;
    RelationType_e default_type = DEFAULT_TYPE;
    RelationConfidence_T default_confidence = DEFAULT_CONFIDENCE;
    RelationDirection_e default_direction = RELATION_DIRECTION_LOCAL_TO_REMOTE;
};

TEST_F(TestVersionRelation, Init) {
    EXPECT_EQ(pRelation->getType(), DEFAULT_TYPE);
    EXPECT_EQ(pRelation->getConfidence(), DEFAULT_CONFIDENCE);
}

TEST_F(TestVersionRelation, IncreaseConfidence) {
    EXPECT_NO_THROW(pRelation->increaseConfidence(1));
    EXPECT_EQ(pRelation->getConfidence(), DEFAULT_CONFIDENCE + 1);
}