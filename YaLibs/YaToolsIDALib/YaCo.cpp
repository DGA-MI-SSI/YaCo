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

#include "Ida.h"
#include "YaCo.hpp"

#include "YaToolsHashProvider.hpp"
#include "IDANativeExporter.hpp"
#include "XML/XMLDatabaseModel.hpp"

#define MODULE_NAME "yaco"
#include "IDAUtils.hpp"

#include <chrono>

namespace
{
    struct YaCo
        : public IYaCo
    {
        YaCo(IHashProvider& hash_provider);

        // IYaCo
        void initial_load() override;

        // Variables
        IHashProvider&   hash_provider_;
    };
}

YaCo::YaCo(IHashProvider& hash_provider)
    : hash_provider_(hash_provider)
{
}

void YaCo::initial_load()
{
    const auto time_start = std::chrono::system_clock::now();
    IDA_LOG_INFO("Initial load started");

    export_to_ida(MakeXmlAllDatabaseModel("cache/").get(), &hash_provider_);

    const auto time_end = std::chrono::system_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(time_end - time_start);
    IDA_LOG_INFO("Cache loaded in %d seconds", static_cast<int>(elapsed.count()));
}


std::shared_ptr<IYaCo> MakeYaCo(const std::shared_ptr<IHashProvider>& hash_provider)
{
    return std::make_shared<YaCo>(*hash_provider);
}
