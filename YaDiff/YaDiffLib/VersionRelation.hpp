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

#include "Relation.hpp"

class VersionRelation
{
public:
    VersionRelation(HVersion version, RelationType_e type, RelationConfidence_T confidence, RelationDirection_e RelationDirection);

    void increaseConfidence(RelationConfidence_T confidence);

    RelationType_e          getType() const;
    void                    setType(RelationType_e type);
    RelationConfidence_T    getConfidence() const;
    HVersion                getMatchingObject() const;
    RelationDirection_e     getDirection() const;

private:
    HVersion                matching_;
    RelationType_e          type_;
    RelationConfidence_T    confidence_;
    RelationDirection_e     direction_;
};
