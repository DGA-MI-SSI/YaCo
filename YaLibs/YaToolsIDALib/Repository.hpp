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

#include "YaTypes.hpp"

#include <string>
#include <vector>
#include <memory>

struct State
{
    std::vector<std::string> deleted;
    std::vector<std::string> updated;
};

struct IRepository
{
    virtual ~IRepository() = default;

    virtual void add_comment(const std::string& msg) = 0;

    virtual void check_valid_cache_startup() = 0;

    virtual State update_cache() = 0;

    virtual bool commit_cache() = 0;

    virtual void toggle_repo_auto_sync() = 0;

    virtual void sync_and_push_original_idb() = 0;

    virtual void discard_and_pull_idb() = 0;
};

std::shared_ptr<IRepository> MakeRepository(const std::string& path);
