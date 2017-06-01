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

#include <string>
#include <sstream>
#include <ctype.h>
#include <stdint.h>

#include "common.hpp"

#include "../../Helpers.h"

std::string xml_escape(const std::string& input){

    std::ostringstream buffer;
    for(const auto& c : input) {
        if ((uint8_t)c >= 128 || (uint8_t)c < 0x09 || ((uint8_t)c > 0x0D && (uint8_t)c <0x20)) {
            buffer << "?";
        }
        else {
            buffer << c;
        }
    }
    return buffer.str();
}

std::string xml_unescape(const std::string& input)
{
    UNUSED(input);
    throw "not implemented yet";
}
