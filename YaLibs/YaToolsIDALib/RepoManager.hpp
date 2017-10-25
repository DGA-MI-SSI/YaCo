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
#include <tuple>
#include <set>

#include <pro.h>

// Forward declarations
class GitRepo;
namespace std { template<typename T> class shared_ptr; }


struct IRepoManager
{
    virtual ~IRepoManager() = default;

    virtual bool ask_to_checkout_modified_files(bool repo_auto_sync) = 0;

    virtual void ensure_git_globals() = 0;

    virtual void add_auto_comment(ea_t ea, const std::string& text) = 0;

    virtual bool repo_exists() = 0;

    virtual void repo_init(const std::string& idb_filename, bool ask_for_remote = true) = 0;

    virtual void repo_open(const std::string path = ".") = 0;

    virtual std::tuple<std::set<std::string>, std::set<std::string>, std::set<std::string>> repo_get_cache_files_status() = 0;

    virtual std::string get_master_commit() = 0;
    virtual std::string get_origin_master_commit() = 0;

    virtual void fetch_origin() = 0;
    virtual void fetch(const std::string& origin) = 0;

    virtual void push_origin_master() = 0;

    virtual void checkout_master() = 0;

    virtual bool repo_commit(std::string commit_msg = "") = 0;

    //tmp
    virtual GitRepo& get_repo() = 0;
    virtual void new_repo(const std::string& path) = 0;
};


std::shared_ptr<IRepoManager> MakeRepoManager(bool ida_is_interactive);

std::string ea_to_hex(ea_t ea);

std::string get_original_idb_name(const std::string& local_idb_name, const std::string& suffix = "");

std::string get_local_idb_name(const std::string& original_idb_name, const std::string& suffix = "");

void remove_ida_temporary_files(const std::string& idb_path);

std::string copy_idb_to_local_file(const std::string& suffix = "");

std::string copy_idb_to_original_file(const std::string& suffix = "");
