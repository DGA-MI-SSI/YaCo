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

#include "Logger.hpp"

#include "Helpers.h"

#include <stdarg.h>
#include <time.h>

#if defined(_MSC_VER) && defined(_DEBUG)
#include <windows.h>
#endif

namespace
{
    struct Logger
        : public logger::ILogger
    {
        Logger();

        // ILogger methods
        void FilterOut  (const char* module) override;
        void FilterIn   (const char* module) override;
        void Delegate   (const logger::delegate_fn_t& delegate) override;
        void Print      (const char* module, logger::ELevel eLevel, const char* pFmt, ...) override;

        std::vector<std::string>            modin;
        std::vector<std::string>            modout;
        std::vector<logger::delegate_fn_t>  delegates;
        std::vector<char>                   buffmt;
        std::vector<char>                   bufline;
    };
}

std::shared_ptr<logger::ILogger> logger::MakeLogger()
{
    return std::make_shared<Logger>();
}

Logger::Logger()
    : buffmt(4096)
    , bufline(4096)
{
}

void Logger::FilterOut(const char* module)
{
    modin.push_back(module);
}

void Logger::FilterIn(const char* module)
{
    modout.push_back(module);
}

void Logger::Delegate(const logger::delegate_fn_t& delegate)
{
    delegates.push_back(delegate);
}

namespace
{
    const char LogLevels[][10] =
    {
        "error ",
        "warning ",
        "",
        "debug ",
    };
    static_assert(COUNT_OF(LogLevels) == logger::LOG_LEVEL_LAST, "missing log levels");

    bool accept_module(const Logger& logger, const char* module)
    {
        for(const auto& in : logger.modin)
            if(in == module)
                return true;

        for(const auto& out : logger.modout)
            if(out == module)
                return false;

        return logger.modin.empty();
    }
}

void Logger::Print(const char* pModule, logger::ELevel eLevel, const char* pFmt, ...)
{
    if(eLevel > logger::eMaxLevel)
        return;

    if(eLevel < 0 || eLevel >= logger::LOG_LEVEL_LAST)
        return;

    if(pModule && !accept_module(*this, pModule))
        return;

    time_t Now;
    time(&Now);
    if(Now == -1)
        return;

    const auto pNow = localtime(&Now);
    if(!pNow)
        return;

    char TxtTime[64];
    const auto sz = strftime(TxtTime, sizeof TxtTime, "%Y-%m-%d %H:%M:%S", pNow);
    if(!sz)
        return;

    auto n = snprintf(&buffmt[0], buffmt.size() - 1,
                      "%s%s%s: %s%s",
                      TxtTime,
                      pModule ? " " : "",
                      pModule ? pModule : "",
                      LogLevels[eLevel], pFmt);
    if(n < 0)
        return;

    // try hard to do one print only to destination
    buffmt[n] = 0;
    va_list args;
    va_start(args, pFmt);
    n = vsnprintf(&bufline[0], bufline.size() - 1, &buffmt[0], args);
    va_end(args);
    if(n < 0)
        return;

    bufline[n] = 0;
#if defined(_MSC_VER) && defined(_DEBUG)
    OutputDebugString(&bufline[0]);
#endif
    for(const auto& d : delegates)
        d(sz, &bufline[0]);
}
