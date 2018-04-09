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

#include <stdio.h>
#include <stdint.h>

#include <functional>
#include <memory>
#include <vector>

namespace logger
{
// levels are sorted in decreasing severity order
enum ELevel
{
    LOG_LEVEL_ERROR,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_LAST,
};

const ELevel eMaxLevel = LOG_LEVEL_INFO;

using delegate_fn_t = std::function<void(size_t time_prefix, const char* message)>;

struct ILogger
{
    virtual ~ILogger() = default;

    virtual void FilterOut  (const char* pModule) = 0;
    virtual void FilterIn   (const char* pModule) = 0;
    virtual void Delegate   (const delegate_fn_t& delegate) = 0;
    virtual void Print      (const char* pModule, ELevel eLevel, const char* pFmt, ...) = 0;
};

std::shared_ptr<ILogger> MakeLogger();

// ex: LOG_(pCtx, "memory", INFO, "%s %d %p\n", "something", 0x60, some_pointer);
#define LOG_(CTX, MOD, LEVEL, FMT, ...) do {\
        if((logger::LOG_LEVEL_ ## LEVEL) <= logger::eMaxLevel) {\
            (CTX)->Print((MOD), (logger::LOG_LEVEL_ ## LEVEL), (FMT), ## __VA_ARGS__); }\
        /* visual studio can validate format string on regular printf calls*/\
        /* this code is never called but always compiled & validated*/\
        if(false) { printf((FMT), ## __VA_ARGS__); }\
    } while(0)

#define LOG_ERROR(  CTX, MOD, FMT, ...) LOG_((CTX), (MOD), ERROR,    (FMT), ## __VA_ARGS__)
#define LOG_WARNING(CTX, MOD, FMT, ...) LOG_((CTX), (MOD), WARNING,  (FMT), ## __VA_ARGS__)
#define LOG_INFO(   CTX, MOD, FMT, ...) LOG_((CTX), (MOD), INFO,     (FMT), ## __VA_ARGS__)
#define LOG_DEBUG(  CTX, MOD, FMT, ...) LOG_((CTX), (MOD), DEBUG,    (FMT), ## __VA_ARGS__)
}
