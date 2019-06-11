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

#define UNUSED(X) ((void)(X))

#define COUNT_OF(X) (sizeof(X)/sizeof*(X))

#define ALIGN(X) alignas(X)

#define CONCAT_(A, B) A ## B
#define CONCAT(A, B) CONCAT_(A, B)

#define STATIC_ASSERT_POD(X) static_assert(std::is_pod<X>::value, # X " must be a POD structure")
#define STATIC_ASSERT_SIZEOF(X,Y) static_assert(sizeof(X) == (Y), # X " must have sizeof " # Y)

// TODO add log in a file
#if 1
#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("yadiff", (FMT), ## __VA_ARGS__)
#else
#define LOG(...) do {} while(0)
#endif

// "value" -> s_value
#define DECLARE_REF(name, value)\
    const char name ## _txt[] = value;\
    const const_string_ref name = {name ## _txt, sizeof name ## _txt - 1};


// Convert : s_ascii -> s_formatted_stringed
#define DECLARE_STRINGER(NAME, FMT, VALUE_TYPE)\
const_string_ref NAME(char* buf, size_t szbuf, VALUE_TYPE value)\
{\
    const auto n = snprintf(buf, szbuf, (FMT), value);\
    if(n <= 0) {\
        return {nullptr, 0};\
    }\
    return {buf, static_cast<size_t>(n)};\
}


#define DECL_CC_NAME(VALUE, NAME) {VALUE, {NAME, sizeof NAME - 1}},

// Ignore gcc -Wunused-function
#ifdef __GNUC__
#define UNUSED_VARIABLE __attribute__((unused))
#else
#define UNUSED_VARIABLE
#endif
