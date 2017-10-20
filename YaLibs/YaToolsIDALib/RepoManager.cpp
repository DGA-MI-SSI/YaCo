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
#include <sstream>
#include <ctime>

#ifdef _MSC_VER
#   include <filesystem>
#else
#   include <experimental/filesystem>
#endif

namespace fs = std::experimental::filesystem;

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

        bool ask_to_checkout_modified_files(GitRepo& repo, bool repo_auto_sync) override;

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

// TODO: move repo_auto_sync from python to RepoManager
bool RepoManager::ask_to_checkout_modified_files(GitRepo& repo, bool repo_auto_sync)
{
    std::string modified_objects;
    bool checkout_head{ false };

    std::string original_idb = get_original_idb_name(database_idb);
    for (std::string modified_object : repo.get_modified_objects())
    {
        if (modified_object == original_idb)
        {
            std::string new_idb{ original_idb };
            new_idb += "_bkp_";
            std::time_t now{ std::time(nullptr) };
            std::string date{ std::ctime(&now) };
            std::replace(date.begin(), date.end(), ' ', '_');
            std::replace(date.begin(), date.end(), ':', '_');
            new_idb += date;
            try
            {
                fs::copy_file(original_idb, new_idb);
            }
            catch (fs::filesystem_error error)
            {
                warning("Couldn't create backup idb file.\n\n%s", error.what());
                throw std::runtime_error(error);
            }
            checkout_head = true;
        }
        else
        {
            modified_objects += modified_object;
            modified_objects += '\n';
        }
    }

    if (!modified_objects.empty())
    {
        // modified_objects is now the message
        modified_objects += "\nhas been modified, this is not normal, do you want to checkout these files ? (Rebasing will be disabled if you answer no)";
        if (askyn_c(true, modified_objects.c_str()) != ASKBTN_NO)
        {
            repo.checkout_head();
        }
        else
        {
            //repo_auto_sync = false;
            return false;
        }
    }

    if (checkout_head)
    {
        // checkout silently
        repo.checkout_head();
    }

    return repo_auto_sync;
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

std::string get_original_idb_name(const std::string& local_idb_name, const std::string& suffix)
{
    std::string orig_file_name{ fs::path{ local_idb_name }.filename().string() };

    if (suffix.empty())
        orig_file_name.erase(orig_file_name.rfind("_local"), 6);
    else
        orig_file_name.erase(orig_file_name.rfind(suffix), suffix.size());

    return orig_file_name;
}

std::string get_local_idb_name(const std::string& original_idb_name, const std::string& suffix)
{
    fs::path idb_path{ original_idb_name };
    std::string idb_name{ idb_path.filename().string() };
    std::string idb_extension{ idb_path.extension().string() };
    idb_name.erase(idb_name.rfind(idb_extension), idb_extension.size());

    std::string local_idb_name{ idb_name };
    if (suffix.empty())
        local_idb_name += "_local";
    else
        local_idb_name += suffix;
    local_idb_name += idb_extension;

    return local_idb_name;
}

void remove_ida_temporary_files(const std::string& idb_path)
{
    std::string idb_no_ext{ idb_path };
    std::string idb_extension{ fs::path{ idb_path }.extension().string() };
    idb_no_ext.erase(idb_no_ext.rfind(idb_extension), idb_extension.size());

    const char* extentions_to_delete[] = { ".id0", ".id1", ".id2", ".nam", ".til" };
    for (const char* ext : extentions_to_delete)
    {
        try
        {
            fs::remove(fs::path{ idb_no_ext + ext });
        }
        catch (fs::filesystem_error){}
    }
}
