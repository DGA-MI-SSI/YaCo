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

#include "PrototypeParser.hpp"

#include "YaToolObjectId.hpp"
#include <regex>
#include <functional>

void ParseProtoFromHashes(const std::string& prototype, const std::function<ContinueWalking_e(const std::string&, YaToolObjectId)>& fnWalk)
{
    if(prototype.empty())
        return;

    std::regex pattern(R"regex(/*%([^#]+)#([0-9a-fA-F]{16,17})%*)regex");
    for(auto it = std::sregex_iterator(prototype.begin(), prototype.end(), pattern); it != std::sregex_iterator(); it++)
    {
        const auto match = *it;
        const auto struct_name = match[1].str();
        const auto struct_id = match[2].str();
        const auto code = fnWalk(struct_name, YaToolObjectId_From_String(struct_id.data(), struct_id.size()));
        if(code != WALK_CONTINUE)
            return;
    }
}
