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
