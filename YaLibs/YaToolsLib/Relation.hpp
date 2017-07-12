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

#pragma once

#include "YaTypes.hpp"
#include "HVersion.hpp"

// TODO: make bit mask for RelationType_e
enum RelationType_e
{
    /**
     * The functions has no link
     */
    RELATION_TYPE_NONE,
    /**
     * The functions match exactly
     */
    RELATION_TYPE_EXACT_MATCH,
};

enum RelationDirection_e
{
    RELATION_DIRECTION_NONE = 0,
    RELATION_DIRECTION_LOCAL_TO_REMOTE,
    RELATION_DIRECTION_REMOTE_TO_LOCAL,
    RELATION_DIRECTION_BOTH,
};

typedef int RelationConfidence_T;
#define RELATION_CONFIDENCE_MAX     65536
#define RELATION_CONFIDENCE_MIN     0
#define RELATION_CONFIDENCE_BAD     1
#define RELATION_CONFIDENCE_GOOD    4

struct Relation
{
    HVersion                version1_;
    HVersion                version2_;
    RelationType_e          type_;
    RelationConfidence_T    confidence_;
    RelationDirection_e     direction_;
    uint32_t                flags_;
};