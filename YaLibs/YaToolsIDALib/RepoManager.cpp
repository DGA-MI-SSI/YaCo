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

#include "RepoManager.hpp"

#include "../YaGitLib/YaGitLib.hpp"

#include <memory>

namespace
{
    struct RepoManager
        : public IRepoManager
    {
        RepoManager() = default;

        void fetch_origin(GitRepo& repo) override;
        void fetch(GitRepo& repo, const std::string& origin) override;

        void checkout_master(GitRepo& repo) override;
    };
}

void RepoManager::fetch_origin(GitRepo& repo)
{
    repo.fetch();
}

void RepoManager::fetch(GitRepo& repo, const std::string& origin)
{
    repo.fetch(origin);
}

void RepoManager::checkout_master(GitRepo& repo)
{
    repo.checkout("master");
}

std::shared_ptr<IRepoManager> MakeRepoManager()
{
    return std::shared_ptr<RepoManager>();
}
