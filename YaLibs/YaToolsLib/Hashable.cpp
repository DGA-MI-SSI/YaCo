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

#include "Hashable.hpp"

#include <farmhash.h>
#include <string>


Hashable::Hashable()
    : hashcode  (0)
    , hash_built(false)
{
}

void Hashable::hashString(const char* str) const
{
    hashcode = util::Hash32WithSeed(str, strlen(str), hashcode);
}

void Hashable::hashString(const std::string& str) const
{
    hashcode = util::Hash32WithSeed(str, hashcode);
}

void Hashable::hashUpdate(const char* str) const
{
    hashcode = util::Hash32WithSeed(str, strlen(str), hashcode);
}

void Hashable::hashUpdate(const std::string& str) const
{
    hashcode = util::Hash32WithSeed(str, hashcode);
}

void Hashable::hashUpdate(uint32_t i) const
{
    hashcode = util::Hash32WithSeed((char*)&i, sizeof(i), hashcode);
}

void Hashable::hashUpdate(uint64_t i) const
{
    hashcode = util::Hash32WithSeed((char*)&i, sizeof(i), hashcode);
}

hashcode_t Hashable::getHashcode() const
{
    if (hash_built == false)
    {
        buildHashCode();
        hash_built = true;
    }
    return hashcode;
}
