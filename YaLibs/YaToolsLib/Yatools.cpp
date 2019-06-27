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

#include "Yatools.hpp"

namespace
{
    globals::Yatools g_yatools;
}

globals::Yatools::Yatools()
    : logger(logger::MakeLogger())
{
}

globals::Yatools& globals::Get()
{
    return g_yatools;
}

bool globals::InitIdbLogger(logger::ILogger& logger, const char* basename)
{
    const std::string strname = basename;
    const auto make_file_delegate = [](const std::string& filename, const char* mode) -> logger::delegate_fn_t
    {
        const auto hfile = fopen(filename.data(), mode);
        if (!hfile) {
            return logger::delegate_fn_t{};
        }

        // Capture file handle by copy into the delegate
        const auto smart = std::shared_ptr<FILE>(hfile, &fclose);
        return [=](size_t /*prefix*/, const char* message)
        {
            fprintf(smart.get(), "%s", message);
            fflush(smart.get());
        };
    };
    const auto current = make_file_delegate(strname + ".log", "wb");
    if (!current) {
        return false;
    }

    const auto all = make_file_delegate(strname + ".all.log", "ab");
    if (!all) {
        return false;
    }

    logger.Delegate(current);
    logger.Delegate(all);
    return true;
}

bool globals::InitFileLogger(logger::ILogger& logger, FILE* handle)
{
    logger.Delegate([=](size_t /*prefix*/, const char* message)
    {
        fprintf(handle, "%s", message);
        fflush(handle);
    });
    return true;
}

// String of executable launching me (YaDiff, YaCo)
std::string globals::s_command;
