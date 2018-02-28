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

struct IModel;

const char*         get_signature_algo_string(SignatureAlgo_e algo);
SignatureAlgo_e     get_signature_algo(const char* algo);
const char*         get_signature_method_string(SignatureMethod_e method);
SignatureMethod_e   get_signature_method(const char* method);

struct Signature
{
    char                buffer[32];
    size_t              size;
    size_t              hash;
    SignatureAlgo_e     algo;
    SignatureMethod_e   method;
};

std::string ToString(const Signature& sign);
Signature MakeSignature(SignatureAlgo_e algo, SignatureMethod_e method, const const_string_ref& value);

inline const_string_ref make_string_ref(const Signature& sign)
{
    return {sign.buffer, sign.size};
}

inline bool operator==(const Signature& a, const Signature& b)
{
    return !strcmp(a.buffer, b.buffer);
}

inline bool operator<(const Signature& a, const Signature& b)
{
    return strcmp(a.buffer, b.buffer) < 0;
}

namespace std
{
    template<>
    struct hash<Signature>
    {
        size_t operator()(const Signature& obj) const
        {
            return obj.hash;
        }
    };
}
