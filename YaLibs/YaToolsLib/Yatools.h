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

#include <stdint.h>
#include "../Helpers.h"
#include <string>
#include <sstream>


// forward declarations
struct LOG_Ctx;

#ifdef ARCH_X86
    #define YATOOLS_ALIGN       (0x4)
    #define YATOOLS_CTX_SIZE    (0x108)
#else
    #define YATOOLS_ALIGN       (0x8)
    #define YATOOLS_CTX_SIZE    (0x210)
#endif

struct ALIGN(YATOOLS_ALIGN) YATOOLS_Ctx
{
    char Buffer[YATOOLS_CTX_SIZE];
};

bool        YATOOLS_Init       (YATOOLS_Ctx* pCtx);
void        YATOOLS_Exit       (YATOOLS_Ctx* pCtx);
LOG_Ctx*    YATOOLS_GetLogger  (YATOOLS_Ctx* pCtx);

// use a global variable for now
YATOOLS_Ctx* YATOOLS_Get();

// default loggers
#define YALOG_ERROR(MOD, FMT, ...)   LOG_ERROR  (YATOOLS_GetLogger(YATOOLS_Get()), (MOD), (FMT), ## __VA_ARGS__)
#define YALOG_WARNING(MOD, FMT, ...) LOG_WARNING(YATOOLS_GetLogger(YATOOLS_Get()), (MOD), (FMT), ## __VA_ARGS__)
#define YALOG_INFO(MOD, FMT, ...)    LOG_INFO   (YATOOLS_GetLogger(YATOOLS_Get()), (MOD), (FMT), ## __VA_ARGS__)
#define YALOG_DEBUG(MOD, FMT, ...)   LOG_DEBUG  (YATOOLS_GetLogger(YATOOLS_Get()), (MOD), (FMT), ## __VA_ARGS__)


// helper for objects using operator<<
template<typename T>
inline std::string ToString(const T& Value)
{
    std::stringstream Stream;
    Stream << Value;
    return Stream.str();
}

template<>
inline std::string ToString(const bool& Value)
{
    return Value ? "true" : "false";
}

#define TO_STRING(X) ToString(X).data()
