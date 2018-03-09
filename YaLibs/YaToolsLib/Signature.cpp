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

#include "Signature.hpp"

#include "IModel.hpp"
#include "Helpers.h"

#include <farmhash.h>
#include <sstream>
#include <type_traits>

#ifdef _MSC_VER
#define stricmp _stricmp
#else
#include <strings.h>
#define stricmp strcasecmp
#endif

STATIC_ASSERT_POD(Signature);
STATIC_ASSERT_POD(HSignature);

static const char g_algos[][8] =
{
    "unknown",
    "none",
    "crc32",
    "md5",
};
static_assert(COUNT_OF(g_algos) == SIGNATURE_ALGORITHM_COUNT, "invalid number of algorithm strings");

const char* get_signature_algo_string(SignatureAlgo_e value)
{
    if(value < 0 || value >= SIGNATURE_ALGORITHM_COUNT)
        value = SIGNATURE_ALGORITHM_UNKNOWN;
    static_assert(SIGNATURE_ALGORITHM_UNKNOWN == 0, "invalid signature algorithm unknown value");
    return g_algos[value];
}

SignatureAlgo_e get_signature_algo(const char* value)
{
    for(size_t i = 0; i < COUNT_OF(g_algos); ++i)
        if(!stricmp(g_algos[i], value))
            return static_cast<SignatureAlgo_e>(i);
    return SIGNATURE_ALGORITHM_UNKNOWN;
}

static const char g_methods[][20] =
{
    "unknown",
    "firstbyte",
    "full",
    "invariants",
    "opcode_hash",
    "intra_graph_hash",
    "string_hash",
};
static_assert(COUNT_OF(g_methods) == SIGNATURE_METHOD_COUNT, "invalid number of method strings");

const char* get_signature_method_string(SignatureMethod_e value)
{
    if(value < 0 || value >= SIGNATURE_METHOD_COUNT)
        value = SIGNATURE_UNKNOWN;
    static_assert(SIGNATURE_UNKNOWN == 0, "invalid signature method unknown value");
    return g_methods[value];
}

SignatureMethod_e get_signature_method(const char* value)
{
    for(size_t i = 0; i < COUNT_OF(g_methods); ++i)
        if(!stricmp(g_methods[i], value))
            return static_cast<SignatureMethod_e>(i);
    return SIGNATURE_UNKNOWN;
}

Signature MakeSignature(SignatureAlgo_e algo, SignatureMethod_e method, const const_string_ref& value)
{
    Signature sign{{}, value.size, util::Hash(value.value, value.size), algo, method};
    assert(value.size + 1 <= sizeof sign.buffer);
    memcpy(sign.buffer, value.value, value.size);
    sign.buffer[value.size] = 0;
    return sign;
}