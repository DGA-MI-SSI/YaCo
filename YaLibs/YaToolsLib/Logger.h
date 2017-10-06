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
#include "../Helpers.h"

// levels are sorted in decreasing severity order
enum LOG_ELevel
{
    LOG_LEVEL_ERROR,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_LAST,
};

static const LOG_ELevel LOG_eMaxLevel = LOG_LEVEL_INFO;

enum LOG_EOutput
{
    LOG_OUTPUT_NONE,
    LOG_OUTPUT_FILE_HANDLE,
    LOG_OUTPUT_FILENAME_TRUNCATE,
    LOG_OUTPUT_FILENAME_APPEND,
    LOG_OUTPUT_LAST,
};

#ifndef SWIG

struct LOG_Output
{
    LOG_EOutput eOutput;
    FILE*       hFile;
    const char* pFilename;
};

struct LOG_Cfg
{
    LOG_Output  Outputs[16];
    const char* ModulesIn[16];
    const char* ModulesOut[16];
};

#ifdef ARCH_X86
    #define LOG_ALIGN    (0x4)
    #define LOG_CTX_SIZE (0x104)
#else
    #define LOG_ALIGN    (0x8)
    #define LOG_CTX_SIZE (0x208)
#endif

struct ALIGN(LOG_ALIGN) LOG_Ctx
{
    char Buffer[LOG_CTX_SIZE];
};

bool    LOG_Init    (LOG_Ctx* pCtx, const LOG_Cfg* pCfg);
bool    LOG_Exit    (LOG_Ctx* pCtx);
bool    LOG_Print   (LOG_Ctx* pCtx, const char* pModule, LOG_ELevel eLevel, const char* pFmt, ...);

// ex: LOG_(pCtx, "memory", INFO, "%s %d %p\n", "something", 0x60, some_pointer);
#define LOG_(CTX, MOD, LEVEL, FMT, ...) do {\
        if((LOG_LEVEL_ ## LEVEL) <= LOG_eMaxLevel)\
            LOG_Print((CTX), (MOD), (LOG_LEVEL_ ## LEVEL), (FMT), ## __VA_ARGS__);\
        /* visual studio can validate format string on regular printf calls*/\
        /* this code is never called but always compiled & validated*/\
        if(false) printf((FMT), ## __VA_ARGS__);\
    } while(0)

#define LOG_ERROR(  CTX, MOD, FMT, ...) LOG_((CTX), (MOD), ERROR,    (FMT), ## __VA_ARGS__)
#define LOG_WARNING(CTX, MOD, FMT, ...) LOG_((CTX), (MOD), WARNING,  (FMT), ## __VA_ARGS__)
#define LOG_INFO(   CTX, MOD, FMT, ...) LOG_((CTX), (MOD), INFO,     (FMT), ## __VA_ARGS__)
#define LOG_DEBUG(  CTX, MOD, FMT, ...) LOG_((CTX), (MOD), DEBUG,    (FMT), ## __VA_ARGS__)

#endif
