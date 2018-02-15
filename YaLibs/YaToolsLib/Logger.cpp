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

#include "Logger.h"

#include <stdint.h>
#include <memory.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>

#if defined(_MSC_VER) && defined(_DEBUG)
#include <windows.h>
#include <vector>
#endif

static const uint32_t Magic = 0x2EB4BA7F;

struct LOG_PrivCtx
{
    const char* ModulesIn[16];
    const char* ModulesOut[16];
    FILE*       hFiles[16];
    FILE*       hOwners[16];
    uint32_t    uMagic;
};

static LOG_PrivCtx* GetCtx(LOG_Ctx* pvCtx)
{
    LOG_PrivCtx* pCtx = reinterpret_cast<LOG_PrivCtx*>(pvCtx);
    return pCtx && pCtx->uMagic == Magic ? pCtx : nullptr;
}

static bool InitOutput(LOG_PrivCtx* pCtx, size_t i, const LOG_Output* pOutput)
{
    switch(pOutput->eOutput)
    {
        case LOG_OUTPUT_LAST:
            return false;

        case LOG_OUTPUT_NONE:
            return true;

        case LOG_OUTPUT_FILE_HANDLE:
            pCtx->hFiles[i] = pOutput->hFile;
            return true;

        case LOG_OUTPUT_FILENAME_APPEND:
            pCtx->hOwners[i] = fopen(pOutput->pFilename, "ab");
            return !!pCtx->hOwners[i];

        case LOG_OUTPUT_FILENAME_TRUNCATE:
            pCtx->hOwners[i] = fopen(pOutput->pFilename, "wb");
            return !!pCtx->hOwners[i];
    }

    return false;
}

bool LOG_Init(LOG_Ctx* pvCtx, const LOG_Cfg* pCfg)
{
    LOG_PrivCtx*    pCtx    = reinterpret_cast<LOG_PrivCtx*>(pvCtx);
    bool            ok      = true;
    
    static_assert(alignof(LOG_Ctx) == alignof(LOG_PrivCtx), "invalid logger context alignment");
    static_assert(sizeof(*pvCtx) == sizeof(*pCtx), "invalid logger context size");
    static_assert(COUNT_OF(pCtx->hFiles)  == COUNT_OF(pCfg->Outputs), "invalid logger files size");
    static_assert(COUNT_OF(pCtx->hOwners) == COUNT_OF(pCfg->Outputs), "invalid logger owners size");
    static_assert(sizeof(pCtx->ModulesIn) == sizeof(pCfg->ModulesIn), "invalid logger module in list size");
    static_assert(sizeof(pCtx->ModulesOut) == sizeof(pCfg->ModulesOut), "invalid logger module out list size");
    
    memset(pCtx, 0, sizeof *pCtx);
    pCtx->uMagic = Magic;

    // try to initialize every outputs
    for(size_t i = 0 ; i < COUNT_OF(pCfg->Outputs); ++i)
        ok &= InitOutput(pCtx, i, &pCfg->Outputs[i]);

    // finish initialization or release open file handles
    for(size_t i = 0; i < COUNT_OF(pCfg->Outputs); ++i)
    {
        if(!pCtx->hOwners[i])
            continue;
        if(ok)
            pCtx->hFiles[i] = pCtx->hOwners[i];
        else
            fclose(pCtx->hOwners[i]);
    }

    memcpy(pCtx->ModulesIn,  pCfg->ModulesIn,  sizeof pCtx->ModulesIn);
    memcpy(pCtx->ModulesOut, pCfg->ModulesOut, sizeof pCtx->ModulesOut);
    return ok;
}

bool LOG_Exit(LOG_Ctx* pvCtx)
{
    LOG_PrivCtx* pCtx = GetCtx(pvCtx);
    if(!pCtx)
        return false;
    for(size_t i = 0; i < COUNT_OF(pCtx->hOwners); ++i)
        if(pCtx->hOwners[i])
            fclose(pCtx->hOwners[i]);
    return true;
}

static const char LogLevels[][10] =
{
    "error ",
    "warning ",
    "",
    "debug",
};
static_assert(COUNT_OF(LogLevels) == LOG_LEVEL_LAST, "missing log levels");

static bool AcceptModule(LOG_PrivCtx* pCtx, const char* pModule)
{
    // filter in
    for(size_t i = 0; i < COUNT_OF(pCtx->ModulesIn); ++i)
        if(!pCtx->ModulesIn[i])
            break;
        else if(!strcmp(pCtx->ModulesIn[i], pModule))
            return true;

    // filter out
    for(size_t i = 0; i < COUNT_OF(pCtx->ModulesOut); ++i)
        if(!pCtx->ModulesOut[i])
            break;
        else if(!strcmp(pCtx->ModulesOut[i], pModule))
            return false;

    return !pCtx->ModulesIn[0];
}

bool LOG_Print(LOG_Ctx* pvCtx, const char* pModule, LOG_ELevel eLevel, const char* pFmt, ...)
{
    LOG_PrivCtx*    pCtx    = GetCtx(pvCtx);
    tm*             pNow    = nullptr;
    size_t          szChars = 0;
    int             nChars  = 0;
    bool            ok      = true;
    char            Fmt[1024];
    char            TxtTime[64];
    time_t          Now;

    if(eLevel > LOG_eMaxLevel)
        return true;

    if(!pCtx)
        return false;

    if(eLevel < 0 || eLevel >= LOG_LEVEL_LAST)
        return false;

    if(pModule && !AcceptModule(pCtx, pModule))
        return true;

    time(&Now);
    if(Now == -1)
        return false;

    pNow = localtime(&Now);
    if(!pNow)
        return false;

    szChars = strftime(TxtTime, sizeof TxtTime, "%Y-%m-%d %H:%M:%S", pNow);
    if(!szChars)
        return false;

    nChars = snprintf(Fmt, sizeof Fmt - 1,
                      "%s%s%s: %s%s",
                      TxtTime,
                      pModule ? " " : "",
                      pModule ? pModule : "",
                      LogLevels[eLevel], pFmt);
    Fmt[sizeof Fmt - 1] = 0;
    if(nChars < 0)
        return false;

#if defined(_MSC_VER) && defined(_DEBUG)
    {
        va_list args;
        va_start(args, pFmt);
        const auto size = _vscprintf(Fmt, args);
        va_end(args);

        std::vector<char> buffer(size + 1);
        va_start(args, pFmt);
        vsnprintf(&buffer[0], buffer.size(), Fmt, args);
        va_end(pFmt);

        OutputDebugString(&buffer[0]);
    }
#endif

    // try hard to do one print only to destination
    for(size_t i = 0; i < COUNT_OF(pCtx->hFiles); ++i)
        if(pCtx->hFiles[i])
        {
            va_list args;
            va_start(args, pFmt);
            ok &= -1 != vfprintf(pCtx->hFiles[i], Fmt, args);
            va_end(args);
            fflush(pCtx->hFiles[i]);
        }
    return ok;
}
