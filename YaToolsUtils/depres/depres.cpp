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

#include <FlatBufferModel.hpp>
#include <FlatBufferVisitor.hpp>
#include <IModel.hpp>
#include <IObjectListener.hpp>
#include <Yatools.h>
#include <Logger.h>

#include "../Helpers.h"

#include <chrono>
#include <memory>

#ifdef _MSC_VER
#include <windows.h>
#include <psapi.h>
#endif

#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("depres", (FMT), ## __VA_ARGS__)

namespace
{
struct Listener : public IObjectListener
{
    virtual void on_object(const HObject&)
    {
    }

    virtual void on_deleted(YaToolObjectId)
    {
    }

    virtual void on_default(YaToolObjectId)
    {
    }
};

#ifdef _MSC_VER
void dump_mem_stats()
{
    PROCESS_MEMORY_COUNTERS_EX counters;
    GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PPROCESS_MEMORY_COUNTERS>(&counters), sizeof counters);
    LOG(INFO, "peak mem %zd kb mem %zd kb\n", counters.PeakWorkingSetSize / 1000, counters.WorkingSetSize / 1000);
}
#else
#define dump_mem_stats()
#endif

template<typename T>
void Benchmark(const char* name, const T& lambda)
{
    const auto a = std::chrono::high_resolution_clock::now();
    lambda();
    const auto b = std::chrono::high_resolution_clock::now();
    LOG(WARNING, "%s done in %u ms\n", name, (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count());
    dump_mem_stats();
}
}

int main(int argc, const char* argv[])
{
    UNUSED(argc);

    auto pCtx = YATOOLS_Get();
    YATOOLS_Init(pCtx);
    LOG_Cfg Cfg;
    memset(&Cfg, 0, sizeof Cfg);
    Cfg.Outputs[0] = {LOG_OUTPUT_FILE_HANDLE, stdout, nullptr};
    LOG_Init(YATOOLS_GetLogger(pCtx), &Cfg);

    LOG(INFO, "create flat buffer exporter\n");
    const auto output = MakeFlatBufferVisitor();

    LOG(INFO, "create address solver\n");
    Listener listener;

    LOG(INFO, "load flat buffer model\n");
    std::shared_ptr<IModel> input;
    Benchmark("load flatbuffer", [&]
    {
        input = MakeFlatBufferModel(argv[1]);
    });

    LOG(INFO, "transfer model\n");
    Benchmark("accept", [&]{
        input->accept(*MakeVisitorFromListener(listener));
    });

    LOG(INFO, "exit\n");
    return 0;
}
