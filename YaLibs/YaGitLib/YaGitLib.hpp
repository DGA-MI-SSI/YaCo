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

#include <iostream>
#include <memory>
#include <vector>
#include <string>
#include <set>
#include <map>
#include <tuple>
#include <functional>

class ResolveFileConflictCallback;

struct git_repository;
struct git_remote;
struct git_signature;
struct git_remote_callbacks;
struct git_index;
struct git_cred;
struct git_rebase;
struct git_tree;
struct git_diff;
struct git_oid;

class GitRepo
{
public:
    GitRepo(const GitRepo&) = delete;
    GitRepo(const std::string& path);
    ~GitRepo();
    void open();
    void init();
    void init_bare();
    void clone(const std::string& url);
    void clone(const std::string& url, const std::string& branch);
    void load_remote(const std::string& remote_name);
    void remove_remote(const std::string& remote_name);
    void create_remote(const std::string& name, const std::string& url);
    void fetch();
    void fetch(const std::string& remote_name);
    void add_file(const std::string& file_path);
    void add_files(const std::vector<std::string>& file_paths);
    void remove_file(const std::string& file_path);
    void remove_files(const std::vector<std::string>& file_paths);
    void add_all();

    typedef std::function<int(const char* path, bool added, const void* data, size_t szdata)> on_blob_fn;
    void diff_index(const std::string& from, const on_blob_fn& on_blob) const;

    //void rebase();
    void rebase(const std::string& upstreal, const std::string& dst, ResolveFileConflictCallback& callback);
    std::set<std::string> get_modified_objects(const std::string& reference);
    std::set<std::string> get_modified_objects(const std::string& reference_from, const std::string& reference_to);
    std::set<std::string> get_new_objects(const std::string& reference);
    std::set<std::string> get_new_objects(const std::string& reference_from, const std::string& reference_to);
    std::set<std::string> get_deleted_objects(const std::string& reference);
    std::set<std::string> get_deleted_objects(const std::string& reference_from, const std::string& reference_to);
    std::set<std::string> get_conflicted_objects(const std::string& reference);
    std::set<std::string> get_conflicted_objects(const std::string& reference_from, const std::string& reference_to);
    void commit(const std::string& message);
    void commit(const std::string& message, const std::string& reference);
    void merge(const std::string& t1, const std::string& t2);
    void merge_fastforward(const std::string& onto, const std::string& from);
    void merge();

    void create_tag(const std::string& target, const std::string& tag_name, const std::string& message);
    std::set<std::string> get_tags(const std::string& pattern);
    std::set<std::string> get_tags();
    void remove_tag(const std::string& tag_name);

    void checkout(const std::string& branch);
    void checkout_head();
    std::set<std::string> get_untracked_objects();
    std::set<std::string> get_modified_objects();
    std::set<std::string> get_deleted_objects();
    std::set<std::string> get_conflicted_objects();
    std::set<std::string> get_untracked_objects_in_path(const std::string& path);
    std::set<std::string> get_modified_objects_in_path(const std::string& path);
    std::set<std::string> get_deleted_objects_in_path(const std::string& path);
#ifndef SWIGPYTHON
    std::set<std::tuple<std::string, bool, bool, bool>> get_status();
    std::set<std::tuple<std::string, bool, bool, bool>> get_status_in_path(const std::string& path);
#endif //SWIGPYTHON

    std::string get_commit(const std::string& name);
    void push(const std::string& src_ref, const std::string& dst_ref);

    void reload_index();

    std::string config_get_string(const std::string& name);
    void config_set_string(const std::string& name, const std::string& value);

    std::map<std::string, std::string> get_remotes();

    GitRepo& operator=(const GitRepo&) = delete;

private:
    std::string repo_path;
    git_repository* repository;
    git_remote* current_remote;
    git_index*  idx;
    git_remote_callbacks*   remote_callbacks;


    void init(bool bare);
    void load_index();
    void _get_diff_from_index(git_diff** ppGitDiff, const std::string& reference);
    void _get_diff_tree_to_tree(git_diff** ppGitDiff, const std::string& reference_from, const std::string& reference_to);
    void get_tree_from_reference(std::shared_ptr<git_tree> *out_tree, const std::string& reference);
    std::set<std::string> foreach_object_invoke_diff(git_diff* pGitDiff, int diff_delta);
    std::shared_ptr<const git_signature> make_signature();
    std::shared_ptr<git_tree> get_tree_from_oid(const git_oid* oid);
};

int git_cred_acquire_callback(git_cred **cred, const char *url, const char *username_from_url, unsigned int allowed_types, void* payload);
