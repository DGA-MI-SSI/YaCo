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
#include "Ida.h"

#include <memory>

#define GITREPO_TRY(call, msg) \
try { \
    call; \
} \
catch (const std::runtime_error& error) \
{ \
    warning(msg "\n\n%s", error.what()); \
}

namespace
{
    struct RepoManager
        : public IRepoManager
    {
        RepoManager() = default;

        std::string get_master_commit(GitRepo& repo) override;
        std::string get_origin_master_commit(GitRepo& repo) override;

        void fetch_origin(GitRepo& repo) override;
        void fetch(GitRepo& repo, const std::string& origin) override;

        void push_origin_master(GitRepo& repo) override;

        void checkout_master(GitRepo& repo) override;
    };
}

std::string RepoManager::get_master_commit(GitRepo& repo)
{
    std::string result;
    GITREPO_TRY(result = repo.get_commit("master"), "Couldn't get commit from master.");
    return result;
}

std::string RepoManager::get_origin_master_commit(GitRepo& repo)
{
    std::string result;
    GITREPO_TRY(result = repo.get_commit("origin/master"), "Couldn't get commit from origin/master.");
    return result;
}

void RepoManager::fetch_origin(GitRepo& repo)
{
    GITREPO_TRY(repo.fetch(), "Couldn't fetch remote origin.");
}

void RepoManager::fetch(GitRepo& repo, const std::string& origin)
{
    GITREPO_TRY(repo.fetch(origin), "Couldn't fetch remote.");
}

void RepoManager::push_origin_master(GitRepo& repo)
{
    const std::map<std::string, std::string> remotes{ repo.get_remotes() };
    if (remotes.find(std::string("origin")) != remotes.end())
    {
        GITREPO_TRY(repo.push("master", "master"), "Couldn't push to remote origin.");
    }
}

void RepoManager::checkout_master(GitRepo& repo)
{
    GITREPO_TRY(repo.checkout("master"), "Couldn't checkout master.");
}

std::shared_ptr<IRepoManager> MakeRepoManager()
{
    return std::make_shared<RepoManager>();
}
