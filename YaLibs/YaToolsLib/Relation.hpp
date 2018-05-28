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
    /**
     * The function are different
     */
    RELATION_TYPE_DIFF,
    /**
     * The function are different, but the difference doesn't impact the signature : one of the call changed
     * This means that one of the call changed to a function that has an exact match in the local base, different to that of
     * the initially called function
     */
    RELATION_TYPE_DIFF_CALL,
    /**
     * The current described function corresponds to one in N other functions
     */
    RELATION_TYPE_ALTERNATIVE_TO_N,
    /**
     * This function is one of several possible function that correspond to the pointed function
     */
    RELATION_TYPE_ALTERNATIVE_FROM_N,
    /**
     * Function have many parameters in common (basic block number, in/out call number, ret number ..)
     * Matched with the Algo "VectorSign"
     */
    RELATION_TYPE_VECTOR_SIGN,
    /**
    * Function control flow graph (including the calls) matches with each other within 24 blocks in a horizontal walk
    * Matched with the Algo "Patas"
    */
    RELATION_TYPE_PATAS,

    /**
     * Objects with this relation conflicts a lot with other object version, so don't trust relations.
     */
    RELATION_TYPE_UNTRUSTABLE,
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