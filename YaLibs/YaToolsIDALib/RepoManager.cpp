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

        void ensure_git_globals(GitRepo& repo) override;

        void repo_open(GitRepo& repo, const std::string path) override;

        std::tuple<std::set<std::string>, std::set<std::string>, std::set<std::string>> repo_get_cache_files_status(GitRepo& repo) override;

        std::string get_master_commit(GitRepo& repo) override;
        std::string get_origin_master_commit(GitRepo& repo) override;

        void fetch_origin(GitRepo& repo) override;
        void fetch(GitRepo& repo, const std::string& origin) override;

        void push_origin_master(GitRepo& repo) override;

        void checkout_master(GitRepo& repo) override;
    };
}

void RepoManager::ensure_git_globals(GitRepo& repo)
{
    std::string userName{ repo.config_get_string("user.name") };
    if (userName.empty())
    {
        do
        {
            const char* tmp = askstr(0, "username", "Entrer git user.name");
            userName = tmp != nullptr ? tmp : "";
        }
        while (userName.empty());
        GITREPO_TRY(repo.config_set_string("user.name", userName), "Couldn't set git user name.");
    }

    std::string userEmail{ repo.config_get_string("user.email") };
    if (userEmail.empty())
    {
        do
        {
            const char* tmp = askstr(0, "username@localdomain", "Entrer git user.email");
            userEmail = tmp != nullptr ? tmp : "";
        }
        while (userEmail.empty());
        GITREPO_TRY(repo.config_set_string("user.email", userEmail), "Couldn't set git user email.");
    }
}

void RepoManager::repo_open(GitRepo& repo, const std::string path)
{
    //repo = GitRepo(path); // still in Python
    GITREPO_TRY(repo.init(), "Couldn't init repository.");
    ensure_git_globals(repo);
}

std::tuple<std::set<std::string>, std::set<std::string>, std::set<std::string>> RepoManager::repo_get_cache_files_status(GitRepo & repo)
{
    return std::make_tuple(
        repo.get_untracked_objects_in_path("cache/"),
        repo.get_deleted_objects_in_path("cache/"),
        repo.get_modified_objects_in_path("cache/")
    );
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
