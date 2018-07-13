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

//#define BENCHMARK

#ifdef BENCHMARK
#include <chrono>
#include <string>
#endif

namespace bench
{
    struct Log
    {
#ifndef BENCHMARK
         Log(const char* /*name*/) {}
        ~Log() {}
#else
        using timestamp_t = decltype(std::chrono::high_resolution_clock::now());

        Log(const char* name)
            : begin(std::chrono::high_resolution_clock::now())
            , name(name)
        {
        }

        ~Log()
        {
            const auto end = std::chrono::high_resolution_clock::now();
            const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
            LOG(INFO, "%s: %zd ms\n", name.data(), duration);
        }

        const timestamp_t begin;
        const std::string name;
#endif

    };
}
