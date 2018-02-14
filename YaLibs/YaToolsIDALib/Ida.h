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

#ifdef _MSC_VER
#pragma warning(push, 0)
#else
// disable warnings from external headers
#pragma GCC system_header
#endif

#define BYTES_SOURCE        // access byte flags
#define NO_OBSOLETE_FUNCS   // disable obsolete functions
#include <auto.hpp>
#include <bytes.hpp>
#include <enum.hpp>
#include <frame.hpp>
#include <funcs.hpp>
#include <gdl.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <lines.hpp>
#include <loader.hpp>
#include <moves.hpp>
#include <name.hpp>
#include <offset.hpp>
#include <segment.hpp>
#include <segregs.hpp>
#include <struct.hpp>
#include <typeinf.hpp>
#include <pro.h>
#include <idp.hpp>
#include <expr.hpp>
#include <tryblks.hpp>
#include <dbg.hpp>
#undef snprintf // ida disable this...

#ifdef _MSC_VER
#pragma warning(pop)
#endif
