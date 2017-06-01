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

#include <string.h>

#include "MatchingSystem.hpp"
#include "IModelVisitor.hpp"
#include "../Helpers.h"

#include <type_traits>

MatchingSystem::MatchingSystem(int id, const std::map<const std::string, const std::string>& attributes)
    : system_attributes(attributes)
{
    UNUSED(id);
}

MatchingSystem::MatchingSystem(const std::map<const std::string, const std::string>& attributes)
    : system_attributes(attributes)
{
}

MatchingSystem::~MatchingSystem()
{
}

void MatchingSystem::buildHashCode() const
{
    for(const auto& attr : system_attributes)
    {
        hashUpdate(attr.first + " ### " + attr.second);
    }
}

void MatchingSystem::accept(IModelVisitor& visitor)
{
    for(const auto& desc : system_attributes)
        visitor.visit_matching_system_description(make_string_ref(desc.first), make_string_ref(desc.second));
}

const std::map<const std::string, const std::string> MatchingSystem::getAttributes() const
{
    return system_attributes;
}
