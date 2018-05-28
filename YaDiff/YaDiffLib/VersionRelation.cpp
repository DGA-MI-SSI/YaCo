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

#include "VersionRelation.hpp"

VersionRelation::VersionRelation(HVersion version, RelationType_e type, RelationConfidence_T confidence, RelationDirection_e RelationDirection)
    : matching_(version)
    , type_(type)
    , confidence_(confidence)
    , direction_(RelationDirection)
{
}

void VersionRelation::increaseConfidence(RelationConfidence_T confidence)
{
    confidence_ += confidence;
    if(confidence_ > RELATION_CONFIDENCE_MAX)
    {
        confidence_ = RELATION_CONFIDENCE_MAX;
    }
}

RelationType_e VersionRelation::getType() const
{
    return type_;
}

void VersionRelation::setType(RelationType_e type)
{
    type_ = type;
}

RelationConfidence_T VersionRelation::getConfidence() const
{
    return confidence_;
}

HVersion VersionRelation::getMatchingObject() const
{
    return matching_;
}

RelationDirection_e VersionRelation::getDirection() const
{
    return direction_;
}