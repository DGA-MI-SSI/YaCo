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

#include "Yatools.h"

#include "Logger.h"

#include <string.h>
#include <string>
#include <memory>

static const uint32_t Magic = 0x65DB5952;

namespace
{
    // use a global variable for now...
    YATOOLS_Ctx gCtx;
}

struct YATOOLS_PrivateCtx
{
    LOG_Ctx     Logger;
    uint32_t    uMagic;
};

static YATOOLS_PrivateCtx* GetCtx(YATOOLS_Ctx* pvCtx)
{
    YATOOLS_PrivateCtx* pCtx = reinterpret_cast<YATOOLS_PrivateCtx*>(pvCtx);
    return pCtx && pCtx->uMagic == Magic ? pCtx : nullptr;
}

YATOOLS_Ctx* YATOOLS_Get()
{
    return &gCtx;
}

bool YATOOLS_Init(YATOOLS_Ctx* pvCtx)
{
    YATOOLS_PrivateCtx* pCtx = reinterpret_cast<YATOOLS_PrivateCtx*>(pvCtx);

    static_assert(alignof(YATOOLS_PrivateCtx) == alignof(YATOOLS_Ctx), "invalid yaco context aligment");
    static_assert(sizeof(*pCtx) == sizeof(*pvCtx), "invalid yaco context size");

    memset(pCtx, 0, sizeof *pCtx);
    pCtx->uMagic = Magic;
    return true;
}

void YATOOLS_Exit(YATOOLS_Ctx* pvCtx)
{
    YATOOLS_PrivateCtx* pCtx = GetCtx(pvCtx);
    if(!pCtx)
        return;
    LOG_Exit(&pCtx->Logger);
}

LOG_Ctx* YATOOLS_GetLogger(YATOOLS_Ctx* pvCtx)
{
    YATOOLS_PrivateCtx* pCtx = GetCtx(pvCtx);
    if(!pCtx)
        return nullptr;
    return &pCtx->Logger;
}

void StartYatools(const char* base)
{
    auto pCtx = YATOOLS_Get();
    YATOOLS_Init(pCtx);

    const auto strbase = std::string(base);
    const auto session = strbase + ".log";
    const auto all     = strbase + ".all.log";

    LOG_Cfg Cfg;
    memset(&Cfg, 0, sizeof Cfg);
    Cfg.Outputs[0] = {LOG_OUTPUT_FILENAME_TRUNCATE, nullptr, session.data()};
    Cfg.Outputs[1] = {LOG_OUTPUT_FILENAME_APPEND,   nullptr, all.data()};
    LOG_Init(YATOOLS_GetLogger(pCtx), &Cfg);
    LOG_Print(YATOOLS_GetLogger(YATOOLS_Get()), "yaco", static_cast<LOG_ELevel>(LOG_LEVEL_DEBUG), "Yatools Created\n");
}

void StopYatools()
{
    LOG_Print(YATOOLS_GetLogger(YATOOLS_Get()), "yaco", static_cast<LOG_ELevel>(LOG_LEVEL_DEBUG), "~Yatools\n");
    YATOOLS_Exit(YATOOLS_Get());
}
