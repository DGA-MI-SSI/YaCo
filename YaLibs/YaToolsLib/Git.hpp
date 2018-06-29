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

#include <memory>
#include <string>
#include <functional>

struct IGit
{
    virtual ~IGit() = default;

    struct Status
    {
        bool conflicted;
        bool deleted;
        bool modified;
        bool untracked;
    };

    enum ECloneMode
    {
        CLONE_FULL,
        CLONE_BARE,
    };

    typedef std::function<int(const char* path, bool added, const void* data, size_t szdata)>           on_blob_fn;
    typedef std::function<void(const char* src, const char* dst)>                                       on_remote_fn;
    typedef std::function<void(const char* name)>                                                       on_path_fn;
    typedef std::function<void(const char* name, const Status& status)>                                 on_status_fn;
    typedef std::function<bool(const std::string& a, const std::string& b, const std::string& path)>    on_conflict_fn;

    virtual bool        add_remote          (const std::string& name, const std::string& url) = 0;
    virtual bool        fetch               (const std::string& name) = 0;
    virtual bool        clone               (const std::string& path, ECloneMode emode) = 0;
    virtual bool        add_file            (const std::string& name) = 0;
    virtual bool        remove_file         (const std::string& name) = 0;
    virtual std::string config_get_string   (const std::string& name) = 0;
    virtual bool        config_set_string   (const std::string& name, const std::string& value) = 0;
    virtual bool        diff_index          (const std::string& from, const on_blob_fn& on_blob) const = 0;
    virtual bool        rebase              (const std::string& upstreal, const std::string& dst, const on_conflict_fn& on_conflict) = 0;
    virtual bool        commit              (const std::string& message) = 0;
    virtual bool        checkout_head       () = 0;
    virtual bool        is_tracked          (const std::string& name) = 0;
    virtual std::string get_commit          (const std::string& name) = 0;
    virtual bool        push                (const std::string& src, const std::string& dst) = 0;
    virtual bool        remotes             (const on_remote_fn& on_remote) = 0;
    virtual bool        status              (const std::string& path, const on_status_fn& on_path) = 0;
};

std::shared_ptr<IGit> MakeGit       (const std::string& path);
std::shared_ptr<IGit> MakeGitBare   (const std::string& path);