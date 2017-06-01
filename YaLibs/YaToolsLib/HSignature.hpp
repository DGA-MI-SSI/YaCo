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
#include "Signature.hpp"

struct ISignatures;

struct HSignature
{
    const ISignatures* model;
    HSignature_id_t id;
    Signature get() const;
};

#ifndef SWIG
inline bool operator==(const HSignature& a, const HSignature& b)
{
    return a.get() == b.get();
}

inline bool operator<(const HSignature& a, const HSignature& b)
{
    return a.get() < b.get();
}

namespace std
{
    template<>
    struct hash<HSignature>
    {
        size_t operator()(const HSignature& v) const
        {
            return hash<Signature>()(v.get());
        }
    };
}
#endif //SWIG
