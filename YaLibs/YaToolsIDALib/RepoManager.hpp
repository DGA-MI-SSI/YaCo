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

#include <string>

// Forward declarations
class GitRepo;
namespace std { template<typename T> class shared_ptr; }


struct IRepoManager
{
    virtual ~IRepoManager() = default;

    virtual std::string get_master_commit(GitRepo& repo) = 0;
    virtual std::string get_origin_master_commit(GitRepo& repo) = 0;

    virtual void fetch_origin(GitRepo& repo) = 0;
    virtual void fetch(GitRepo& repo, const std::string& origin) = 0;

    virtual void push_origin_master(GitRepo& repo) = 0;

    virtual void checkout_master(GitRepo& repo) = 0;
};


std::shared_ptr<IRepoManager> MakeRepoManager();
