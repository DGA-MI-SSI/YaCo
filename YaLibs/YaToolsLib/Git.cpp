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

#include "Git.hpp"
#include "LibGit.h"
#include "Helpers.h"
#include "Yatools.hpp"

#include <fstream>

#ifdef _MSC_VER
#   include <filesystem>
#else
#   include <experimental/filesystem>
#endif

namespace fs = std::experimental::filesystem;

#if 1
#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("git", (FMT), ## __VA_ARGS__)
#else
#define LOG(...) do {} while(0)
#endif

#include "Bench.h"

#define UNUSED(X) ((void)(X))

// custom deleters
namespace std
{
    template<> struct default_delete<git_annotated_commit>        { static const bool marker = true; void operator()(git_annotated_commit*        ptr) { git_annotated_commit_free(ptr); } };
    template<> struct default_delete<git_blob>                    { static const bool marker = true; void operator()(git_blob*                    ptr) { git_blob_free(ptr); } };
    template<> struct default_delete<git_buf>                     { static const bool marker = true; void operator()(git_buf*                     ptr) { git_buf_free(ptr); } };
    template<> struct default_delete<git_commit>                  { static const bool marker = true; void operator()(git_commit*                  ptr) { git_commit_free(ptr); } };
    template<> struct default_delete<git_config>                  { static const bool marker = true; void operator()(git_config*                  ptr) { git_config_free(ptr); } };
    template<> struct default_delete<git_diff>                    { static const bool marker = true; void operator()(git_diff*                    ptr) { git_diff_free(ptr); } };
    template<> struct default_delete<git_index_conflict_iterator> { static const bool marker = true; void operator()(git_index_conflict_iterator* ptr) { git_index_conflict_iterator_free(ptr); } };
    template<> struct default_delete<git_index>                   { static const bool marker = true; void operator()(git_index*                   ptr) { git_index_free(ptr); } };
    template<> struct default_delete<git_merge_file_result>       { static const bool marker = true; void operator()(git_merge_file_result*       ptr) { git_merge_file_result_free(ptr); } };
    template<> struct default_delete<git_object>                  { static const bool marker = true; void operator()(git_object*                  ptr) { git_object_free(ptr); } };
    template<> struct default_delete<git_patch>                   { static const bool marker = true; void operator()(git_patch*                   ptr) { git_patch_free(ptr); } };
    template<> struct default_delete<git_rebase>                  { static const bool marker = true; void operator()(git_rebase*                  ptr) { git_rebase_free(ptr); } };
    template<> struct default_delete<git_reference>               { static const bool marker = true; void operator()(git_reference*               ptr) { git_reference_free(ptr); } };
    template<> struct default_delete<git_remote>                  { static const bool marker = true; void operator()(git_remote*                  ptr) { git_remote_free(ptr); } };
    template<> struct default_delete<git_repository>              { static const bool marker = true; void operator()(git_repository*              ptr) { git_repository_free(ptr); } };
    template<> struct default_delete<git_signature>               { static const bool marker = true; void operator()(git_signature*               ptr) { git_signature_free(ptr); } };
    template<> struct default_delete<git_strarray>                { static const bool marker = true; void operator()(git_strarray*                ptr) { git_strarray_free(ptr); } };
    template<> struct default_delete<git_tree>                    { static const bool marker = true; void operator()(git_tree*                    ptr) { git_tree_free(ptr); } };
}

namespace
{
    template<typename T>
    std::unique_ptr<T> make_unique(T* ptr)
    {
        // check whether we correctly defined a custom deleter
        static_assert(std::default_delete<T>::marker == true, "missing custom marker");
        return std::unique_ptr<T>(ptr);
    }

    struct Git
        : public IGit
    {
        Git(const std::string& path, std::unique_ptr<git_repository>&& repo);

        // IGit methods
        bool        add_remote          (const std::string& name, const std::string& url) override;
        bool        fetch               (const std::string& name) override;
        bool        clone               (const std::string& path, ECloneMode emode) override;
        bool        add_file            (const std::string& name) override;
        bool        remove_file         (const std::string& name) override;
        std::string config_get_string   (const std::string& name) override;
        bool        config_set_string   (const std::string& name, const std::string& value) override;
        bool        diff_index          (const std::string& from, const on_blob_fn& on_blob) override;
        bool        rebase              (const std::string& upstream, const std::string& dst, IPatcher& patcher, const on_fixup_fn& on_fixup, const on_conflict_fn& on_conflict) override;
        bool        commit              (const std::string& message) override;
        bool        checkout_head       () override;
        bool        is_tracked          (const std::string& name) override;
        std::string get_commit          (const std::string& name) override;
        bool        push                (const std::string& src, const std::string& remote, const std::string& dst) override;
        bool        remotes             (const on_remote_fn& on_remote) override;
        bool        status              (const std::string& path, const on_status_fn& on_path) override;
        void        flush               () override;

        const std::string               path_;
        std::unique_ptr<git_repository> repo_;
        std::unique_ptr<git_index>      index_;
        std::vector<std::string>        errors_;
    };

    #define PUSH_GIT_ERROR(DST, FMT, ...) do {\
        const auto err_ = giterr_last();\
        const auto size_ = std::snprintf(nullptr, 0, FMT "%s%s", ## __VA_ARGS__, err_ ? ": " : "", err_ ? err_->message : "");\
        std::vector<char> buf_(size_ + 1);\
        std::snprintf(&buf_[0], size_ + 1, FMT "%s%s", ## __VA_ARGS__, err_ ? ": " : "", err_ ? err_->message : "");\
        (DST).push_back(std::string(&buf_[0], &buf_[size_]));\
    } while(0)

    #define FAIL_WITH(X, GIT, FMT, ...) do {\
        PUSH_GIT_ERROR((GIT).errors_, FMT, ## __VA_ARGS__);\
        return (X);\
    } while(0)

    std::unique_ptr<git_signature> make_signature(Git& git)
    {
        git_signature* ptr_sig = nullptr;
        const auto err = git_signature_default(&ptr_sig, &*git.repo_);
        if(err != GIT_OK)
            FAIL_WITH(std::nullptr_t(), git, "unable to create default signature");

        return make_unique(ptr_sig);
    }

    std::unique_ptr<git_config> get_config(Git& git, int (*getter)(git_config**, git_repository*))
    {
        git_config* ptr_config = nullptr;
        auto err = getter(&ptr_config, &*git.repo_);
        if(err != GIT_OK)
            FAIL_WITH(std::nullptr_t(), git, "unable to snapshot config");

        return make_unique(ptr_config);
    }

    std::string config_get_string(Git& git, git_config* cfg, const std::string& name)
    {
        const char* buffer = nullptr;
        const auto err = git_config_get_string(&buffer, cfg, name.data());
        if(err != GIT_OK)
            FAIL_WITH(std::string(), git, "unable to read config string %s", name.data());

        return std::string(buffer);
    }

    bool config_set_string(Git& git, git_config* cfg, const std::string& name, const std::string& value)
    {
        const auto err = git_config_set_string(cfg, name.data(), value.data());
        if (err != GIT_OK)
            FAIL_WITH(false, git, "unable to set config string %s to %s", name.data(), value.data());

        return true;
    }

    std::shared_ptr<IGit> init(const std::string& path, Git::ECloneMode emode)
    {
        const auto fullpath = fs::absolute(path);
        git_repository* ptr_repo = nullptr;
        auto err = git_repository_init(&ptr_repo, fullpath.generic_string().data(), emode == Git::CLONE_BARE);
        if(err != GIT_OK)
            err = git_repository_open(&ptr_repo, fullpath.string().data());
        if(err != GIT_OK)
        {
            std::vector<std::string> errors;
            PUSH_GIT_ERROR(errors, "unable to open/init git repository at %s", fullpath.generic_string().data());
            LOG(ERROR, "%s\n", errors.front().data());
            return std::nullptr_t();
        }

        return std::make_shared<Git>(path, std::move(make_unique(ptr_repo)));
    }
}

std::shared_ptr<IGit> MakeGit(const std::string& path)
{
    return init(path, Git::CLONE_FULL);
}

std::shared_ptr<IGit> MakeGitBare(const std::string& path)
{
    return init(path, Git::CLONE_BARE);
}

bool is_git_directory(const std::string& path)
{
    const auto fullpath = fs::absolute(path);
    git_repository* ptr_repo = nullptr;
    const auto err = git_repository_open(&ptr_repo, fullpath.generic_string().data());
    const auto repo = make_unique(ptr_repo);
    return err == GIT_OK;
}

Git::Git(const std::string& path, std::unique_ptr<git_repository>&& repo)
    : path_(path)
    , repo_(std::move(repo))
{
    const auto cfg = get_config(*this, &git_repository_config);
    ::config_set_string(*this, &*cfg, "core.eol", "lf");
    ::config_set_string(*this, &*cfg, "core.autocrlf", "input");
}

bool Git::add_remote(const std::string& name, const std::string& url)
{
    git_remote* ptr_remote = nullptr;
    const auto err = git_remote_create(&ptr_remote, &*repo_, name.data(), url.data());
    if(err != GIT_OK)
        FAIL_WITH(false, *this, "unable to create remote %s at %s", name.data(), url.data());

    const auto remote = make_unique(ptr_remote);
    return true;
}

namespace
{
    int default_credentials(git_cred** cred, const char* /*url*/, const char* username_from_url, unsigned int /*allowed_types*/, void* /*payload*/)
    {
        return git_cred_ssh_key_from_agent(cred, username_from_url);
    };

    std::unique_ptr<git_remote> load_remote(Git& git, const char* name)
    {
        git_remote* ptr_remote = nullptr;
        auto err = git_remote_lookup(&ptr_remote, &*git.repo_, name);
        if(err != GIT_OK)
            FAIL_WITH(std::nullptr_t(), git, "unable to lookup remote %s", name);

        return make_unique(ptr_remote);
    }
}

bool Git::fetch(const std::string& name)
{
    const auto remote = load_remote(*this, name.data());
    if(!remote)
        return false;

    git_fetch_options options;
    git_fetch_init_options(&options, GIT_FETCH_OPTIONS_VERSION);
    options.callbacks.credentials = &default_credentials;
    const auto err = git_remote_fetch(&*remote, nullptr, &options, "");
    if(err != GIT_OK)
        FAIL_WITH(false, *this, "unable to fetch remote %s", name.data());

    return true;
}

namespace
{
    bool load_index(Git& git)
    {
        if(git.index_)
            return true;

        git_index* ptr_index = nullptr;
        auto err = git_repository_index(&ptr_index, &*git.repo_);
        if(err != GIT_OK)
            FAIL_WITH(false, git, "unable to get index");

        auto index = make_unique(ptr_index);
        err = git_index_read(ptr_index, true);
        if(err != GIT_OK)
            FAIL_WITH(false, git, "unable to read index");

        git.index_ = std::move(index);
        return true;
    }
}

bool Git::add_file(const std::string& name)
{
    if(!load_index(*this))
        return false;

    auto err = git_index_add_bypath(&*index_, name.data());
    if(err != GIT_OK)
        FAIL_WITH(false, *this, "unable to add %s to index", name.data());

    return true;
}

bool Git::remove_file(const std::string& name)
{
    if(!load_index(*this))
        return false;

    auto err = git_index_remove_bypath(&*index_, name.data());
    if(err != GIT_OK)
        FAIL_WITH(false, *this, "unable to remove %s from index", name.data());

    return true;
}

std::string Git::config_get_string(const std::string& name)
{
    const auto cfg = get_config(*this, &git_repository_config_snapshot);
    return ::config_get_string(*this, &*cfg, name);
}

bool Git::config_set_string(const std::string& name, const std::string& value)
{
    const auto cfg = get_config(*this, &git_repository_config);
    return ::config_set_string(*this, &*cfg, name, value);
}

namespace
{
    std::unique_ptr<git_reference> get_reference_from(git_repository* repo, const char* name)
    {
        git_reference* ptr_ref = nullptr;
        const auto err = git_reference_dwim(&ptr_ref, repo, name);
        if(err != GIT_OK)
            return std::nullptr_t();

        return make_unique(ptr_ref);
    }

    git_oid get_oid_from(git_repository* repo, const char* name)
    {
        git_oid empty;
        memset(&empty, 0, sizeof empty);
        const auto ref = get_reference_from(repo, name);
        if(!ref)
            return empty;

        git_oid reply;
        const auto err = git_reference_name_to_id(&reply, repo, git_reference_name(&*ref));
        if(err != GIT_OK)
            return empty;

        return reply;
    }

    bool is_equal_oid(git_repository* repo, const char* a, const char* b)
    {
        const auto oida = get_oid_from(repo, a);
        const auto oidb = get_oid_from(repo, b);
        return !git_oid_cmp(&oida, &oidb);
    }

    std::unique_ptr<git_commit> get_commit_from_oid(Git& git, const git_oid& oid)
    {
        git_commit* ptr_commit = nullptr;
        const auto err = git_commit_lookup(&ptr_commit, &*git.repo_, &oid);
        if(err != GIT_OK)
            FAIL_WITH(std::nullptr_t(), git, "unable to lookup commit");

        return make_unique(ptr_commit);
    }

    std::unique_ptr<git_tree> get_tree_from_oid(Git& git, const git_oid& oid)
    {
        const auto commit = get_commit_from_oid(git, oid);
        if(!commit)
            return std::nullptr_t();

        git_tree* ptr_tree = nullptr;
        const auto err = git_commit_tree(&ptr_tree, &*commit);
        if(err != GIT_OK)
            FAIL_WITH(std::nullptr_t(), git, "unable to get commit tree");

        return make_unique(ptr_tree);
    }

    std::unique_ptr<git_tree> get_tree(Git& git, const std::string& target)
    {
        git_oid oid;
        auto err = git_oid_fromstr(&oid, target.data());
        if(err != GIT_OK)
            err = git_reference_name_to_id(&oid, &*git.repo_, target.data());
        if(err != GIT_OK)
            FAIL_WITH(std::nullptr_t(), git, "unknown target %s", target.data());

        auto tree = get_tree_from_oid(git, oid);
        if(!tree)
            FAIL_WITH(std::nullptr_t(), git, "unable to get tree from %s", target.data());

        return tree;
    }

    std::unique_ptr<git_blob> get_blob(git_repository* repo, const git_oid& oid)
    {
        git_blob* ptr_blob = nullptr;
        const auto err = git_blob_lookup(&ptr_blob, repo, &oid);
        if(err != GIT_OK)
            return std::nullptr_t();

        return make_unique(ptr_blob);
    }

    template<typename T>
    bool diff_foreach(Git& git, git_diff* diff, const T& on_blob)
    {
        using Payload = struct
        {
            git_repository* repo;
            T               on_blob;
        };
        const auto file_cb = [](const git_diff_delta* delta, float /*progress*/, void* vpayload) -> int
        {
            if(delta->status == GIT_DELTA_CONFLICTED)
                return GIT_OK;

            const auto& payload = *static_cast<Payload*>(vpayload);
            const auto  deleted = delta->status == GIT_DELTA_DELETED;
            const auto& file    = deleted ? delta->old_file : delta->new_file;
            return payload.on_blob(file.path, !deleted, file.id);
        };
        Payload payload{&*git.repo_, on_blob};
        const auto err = git_diff_foreach(diff, file_cb, nullptr, nullptr, nullptr, &payload);
        if(err != GIT_OK)
            FAIL_WITH(false, git, "unable to iterate diff");

        return true;
    }
}

bool Git::diff_index(const std::string& from, const Git::on_blob_fn& on_blob)
{
    const auto from_tree = get_tree(*this, from);
    if(!from_tree)
        return false;

    git_diff* ptr_diff = nullptr;
    const auto err = git_diff_tree_to_index(&ptr_diff, &*repo_, &*from_tree, nullptr, nullptr);
    if(err != GIT_OK)
        FAIL_WITH(false, *this, "unable to diff tree to index");

    const auto diff = make_unique(ptr_diff);
    return diff_foreach(*this, ptr_diff, [&](const char* path, bool added, const git_oid& oid)
    {
        const auto blob = get_blob(&*repo_, oid);
        return on_blob(path, added, git_blob_rawcontent(&*blob), git_blob_rawsize(&*blob));
    });
}

namespace
{
    std::string get_entry_data(git_repository* repo, const git_index_entry* entry, bool& found)
    {
        found = false;
        if(!entry)
            return std::string();

        const auto blob = get_blob(repo, entry->id);
        if(!blob)
            return std::string();

        const auto data = static_cast<const char*>(git_blob_rawcontent(&*blob));
        const auto size = git_blob_rawsize(&*blob);
        found = true;
        return std::string(data, size);
    }

    enum EConflict
    {
        GIT_ADD,
        GIT_DEL,
        GIT_ABORT,
    };

    EConflict handle_conflict(git_repository* repo, const git_index_entry* our, const git_index_entry* their, const fs::path& path, const Git::on_conflict_fn& on_conflict)
    {
        bool has_local = false;
        const auto local = get_entry_data(repo, our, has_local);
        if(!has_local)
            return GIT_DEL;

        bool has_remote = false;
        const auto remote = get_entry_data(repo, their, has_remote);
        if(!has_remote)
            return GIT_DEL;

        const auto ok = on_conflict(local, remote, path.generic_string());
        if(!ok)
            return GIT_ABORT;

        return GIT_ADD;
    }

    std::unique_ptr<git_annotated_commit> get_annotated_commit(Git& git, const std::string& name)
    {
        const auto ref = get_reference_from(&*git.repo_, name.data());
        if(!ref)
            FAIL_WITH(std::nullptr_t(), git, "unable to resolve reference %s", name.data());

        git_annotated_commit* ptr_commit = nullptr;
        const auto err = git_annotated_commit_from_ref(&ptr_commit, &*git.repo_, &*ref);
        if(err != GIT_OK)
            FAIL_WITH(std::nullptr_t(), git, "unable to get annotated commit from %s", name.data());

        return make_unique(ptr_commit);
    }

    std::unique_ptr<git_rebase> init_rebase(Git& git, const std::string& dst, const std::string& upstream)
    {
        git_rebase* ptr_rebase = nullptr;
        git_rebase_options options;
        git_rebase_init_options(&options, GIT_REBASE_OPTIONS_VERSION);
        auto err = git_rebase_open(&ptr_rebase, &*git.repo_, &options);
        if(err == GIT_OK)
            return make_unique(ptr_rebase);

        const auto commit_dst = get_annotated_commit(git, dst);
        if(!commit_dst)
            FAIL_WITH(std::nullptr_t(), git, "unable to get annotated commit from %s", dst.data());

        const auto commit_upstream = get_annotated_commit(git, upstream);
        if(!commit_upstream)
            FAIL_WITH(std::nullptr_t(), git, "unable to get annotated commit from %s", upstream.data());

        err = git_rebase_init(&ptr_rebase, &*git.repo_, &*commit_dst, &*commit_upstream, nullptr, &options);
        if(err != GIT_OK)
            FAIL_WITH(std::nullptr_t(), git, "unable to initialize rebase");

        return make_unique(ptr_rebase);
    }

    bool resolve_conflicts(Git& git, const Git::on_conflict_fn& on_conflict)
    {
        git_index_conflict_iterator* ptr_iterator = nullptr;
        auto err = git_index_conflict_iterator_new(&ptr_iterator, &*git.index_);
        if(err != GIT_OK)
            FAIL_WITH(false, git, "unable to create conflict iterator");

        const auto iterator = make_unique(ptr_iterator);
        const auto root = fs::path(git.path_);
        while(true)
        {
            const git_index_entry* ancestor = nullptr;
            const git_index_entry* our      = nullptr;
            const git_index_entry* their    = nullptr;
            err = git_index_conflict_next(&ancestor, &our, &their, ptr_iterator);
            if(err == GIT_ITEROVER)
                return true;

            const auto path = our ? our->path : their ? their->path : nullptr;
            if(!path)
                return false;

            std::error_code ec;
            const auto eop = handle_conflict(&*git.repo_, our, their, root / path, on_conflict);
            switch(eop)
            {
                case GIT_ADD:
                    git.add_file(path);
                    break;

                case GIT_DEL:
                    fs::remove(root / path, ec);
                    // remove or add_file discard index!
                    git.remove_file(path);
                    break;

                case GIT_ABORT:
                    return false;
            }
        }
    }

    bool fixup_blobs(Git& git, git_diff* ptr_diff, IPatcher& patcher, const on_fixup_fn& on_fixup)
    {
        const auto ok = diff_foreach(git, ptr_diff, [&](const char* path, bool added, const git_oid& oid)
        {
            if(!added)
                return GIT_OK;

            const auto blob = get_blob(&*git.repo_, oid);
            if(!blob)
                added = added;
            const auto ptr  = reinterpret_cast<const char*>(git_blob_rawcontent(&*blob));
            const auto size = git_blob_rawsize(&*blob);
            patcher.add(path, ptr, size);
            return GIT_OK;
        });
        if(!ok)
            FAIL_WITH(false, git, "unable to iterate diff");

        patcher.finish(on_fixup);
        return true;
    }

    bool replay_remote_first(Git& git, git_oid& oid, git_rebase* ptr_rebase, IPatcher& patcher, const on_fixup_fn& on_fixup)
    {
        if(!on_fixup)
            return true;

        const auto op = git_rebase_operation_byindex(ptr_rebase, 0);
        if(!op)
            return true;

        // find ancestor commit & lookup local & remote trees
        const auto commit = get_commit_from_oid(git, op->id);
        git_oid_cpy(&oid, git_commit_parent_id(&*commit, 0));
        const auto remote = get_oid_from(&*git.repo_, "origin/master");
        if(!git_oid_cmp(&oid, &remote))
            return true;

        git_diff* ptr_diff = nullptr;
        const auto local_tree = get_tree_from_oid(git, oid);
        git_oid_cpy(&oid, &remote);
        const auto remote_tree = get_tree_from_oid(git, remote);
        const auto err = git_diff_tree_to_tree(&ptr_diff, &*git.repo_, &*local_tree, &*remote_tree, nullptr);
        if(err != GIT_OK)
            FAIL_WITH(false, git, "unable to diff tree to tree");

        const auto diff = make_unique(ptr_diff);
        const auto ok = fixup_blobs(git, ptr_diff, patcher, on_fixup);
        if(!ok)
            FAIL_WITH(false, git, "unable to fixup patch during replay");

        return true;
    }

    std::string read_file(const fs::path& path)
    {
        std::ifstream ifs(path);
        std::string line;
        std::string data;
        while(std::getline(ifs, line))
            data += line + "\n";
        return data;
    }

    bool fixup_rebase(Git& git, const git_oid& prev_oid, IPatcher& patcher, const on_fixup_fn& on_fixup, const Git::on_conflict_fn& on_conflict)
    {
        if(!on_fixup)
            return true;

        const auto prev = get_tree_from_oid(git, prev_oid);
        if(!prev)
            FAIL_WITH(false, git, "unable to get tree from oid");

        const auto root = fs::path(git.path_);
        git_diff* ptr_diff = nullptr;
        const auto err = git_diff_tree_to_index(&ptr_diff, &*git.repo_, &*prev, nullptr, nullptr);
        if(err != GIT_OK)
            FAIL_WITH(false, git, "unable to diff tree to index");

        const auto diff = make_unique(ptr_diff);
        const auto ok = fixup_blobs(git, ptr_diff, patcher, [&](const std::string& path, const char* ptr, size_t size)
        {
            auto newpath = path;
            const auto fixup = on_fixup(newpath, ptr, size);
            if(!fixup)
                return false;

            const auto their = read_file(root / newpath);
            on_conflict(std::string(ptr, size), their, newpath);
            git.add_file(newpath);

            std::error_code ec;
            fs::remove(root / path, ec);
            git.remove_file(path);
            return true;
        });
        if(!ok)
            FAIL_WITH(false, git, "unable to fixup blobs");

        return true;
    }

    bool rebase(Git& git, git_rebase* ptr_rebase, IPatcher& patcher, const on_fixup_fn& on_fixup, const Git::on_conflict_fn& on_conflict)
    {
        // initialize previous oid
        git_oid prev;
        replay_remote_first(git, prev, ptr_rebase, patcher, on_fixup);

        while(true)
        {
            git_rebase_operation* op = nullptr;
            auto err = git_rebase_next(&op, ptr_rebase);
            if(err == GIT_ITEROVER)
                return true;

            if(err != GIT_OK)
                FAIL_WITH(false, git, "unable to rebase");

            if(op->type != GIT_REBASE_OPERATION_PICK)
                continue;

            if(!load_index(git))
                FAIL_WITH(false, git, "unable to load index");

            auto ok = fixup_rebase(git, prev, patcher, on_fixup, on_conflict);
            if(!ok)
                FAIL_WITH(false, git, "error during rebase fixup");

            ok = resolve_conflicts(git, on_conflict);
            if(!ok)
                return false;

            err = git_index_write(&*git.index_);
            if(err != GIT_OK)
                FAIL_WITH(false, git, "unable to write index");

            git_oid oid;
            memset(&oid, 0, sizeof oid);
            err = git_rebase_commit(&oid, ptr_rebase, nullptr, make_signature(git).get(), nullptr, nullptr);
            // skip commit if there is nothing to apply
            // can happen when rebasing yaco.version changes
            if(err == GIT_EAPPLIED)
                continue;

            if(err != GIT_OK)
                FAIL_WITH(false, git, "unable to pick rebase commit");

            if(!git_oid_iszero(&oid))
                git_oid_cpy(&prev, &oid);
        }
    }
}

bool Git::rebase(const std::string& upstream, const std::string& dst, IPatcher& patcher, const on_fixup_fn& on_fixup, const on_conflict_fn& on_conflict)
{
    if(is_equal_oid(&*repo_, upstream.data(), dst.data()))
        return true;

    const auto rebase = init_rebase(*this, dst, upstream);
    if(!rebase)
        return false;

    const auto ok = ::rebase(*this, &*rebase, patcher, on_fixup, on_conflict);
    if(!ok)
    {
        const auto err = git_rebase_abort(&*rebase);
        if(err != GIT_OK)
            FAIL_WITH(false, *this, "unable to abort rebase");
        return false;
    }

    const auto err = git_rebase_finish(&*rebase, make_signature(*this).get());
    if(err != GIT_OK)
        FAIL_WITH(false, *this, "unable to finish rebase");

    return true;
}

namespace
{
    bool commit(Git& git, const std::string& message, const std::string& reference)
    {
        if(!load_index(git))
            return false;

        auto err = git_index_write(&*git.index_);
        if(err != GIT_OK)
            FAIL_WITH(false, git, "unable to write index");

        const auto sig = make_signature(git);
        git_oid tree_id;
        memset(&tree_id, 0, sizeof tree_id);
        err = git_index_write_tree(&tree_id, &*git.index_);
        if(err != GIT_OK)
            FAIL_WITH(false, git, "unable to write index tree");

        git_tree* ptr_tree = nullptr;
        err = git_tree_lookup(&ptr_tree, &*git.repo_, &tree_id);
        if(err != GIT_OK)
            FAIL_WITH(false, git, "unable to lookup tree");

        const auto tree = make_unique(ptr_tree);
        git_oid parent_id;
        memset(&parent_id, 0, sizeof parent_id);
        err = git_reference_name_to_id(&parent_id, &*git.repo_, reference.data());
        if(err != GIT_OK)
        {
            // no parent commit
            git_oid commit_id;
            err = git_commit_create_v(&commit_id, &*git.repo_, reference.data(), &*sig, &*sig, nullptr, message.data(), ptr_tree, 0);
            if(err != GIT_OK)
                FAIL_WITH(false, git, "unable to create first commit");

            return true;
        }

        git_commit* ptr_commit = nullptr;
        err = git_commit_lookup(&ptr_commit, &*git.repo_, &parent_id);
        if(err != GIT_OK)
            FAIL_WITH(false, git, "unable to lookup commit");

        const auto commit = make_unique(ptr_commit);
        const git_commit* parents[] = { ptr_commit };
        git_oid commit_id;
        memset(&commit_id, 0, sizeof commit_id);
        err = git_commit_create(&commit_id, &*git.repo_, reference.data(), &*sig, &*sig, nullptr, message.data(), ptr_tree, 1, parents);
        if(err != GIT_OK)
            FAIL_WITH(false, git, "unable to create commit");

        return true;
    }
}

bool Git::commit(const std::string& message)
{
    return ::commit(*this, message, "HEAD");
}

bool Git::checkout_head()
{
    git_checkout_options opts;
    git_checkout_init_options(&opts, GIT_CHECKOUT_OPTIONS_VERSION);
    opts.checkout_strategy = GIT_CHECKOUT_FORCE;
    const auto err = git_checkout_head(&*repo_, &opts);
    if(err != GIT_OK)
        FAIL_WITH(false, *this, "unable to checkout head");

    return true;
}

bool Git::is_tracked(const std::string& name)
{
    unsigned int flags = 0;
    const auto err = git_status_file(&flags, &*repo_, name.data());
    return err == GIT_OK && !(flags & (GIT_STATUS_WT_NEW | GIT_STATUS_IGNORED));
}

std::string Git::get_commit(const std::string& name)
{
    const auto oid = get_oid_from(&*repo_, name.data());
    if(git_oid_iszero(&oid))
        FAIL_WITH(std::string(), *this, "unable to get reference from %s", name.data());

    char oidstr[GIT_OID_HEXSZ+1];
    git_oid_nfmt(oidstr, sizeof oidstr, &oid);
    return std::string(oidstr, sizeof oidstr);
}

bool Git::push(const std::string& src, const std::string& remotename, const std::string& dst)
{
    // skip push if there is nothing to do
    if(is_equal_oid(&*repo_, src.data(), (remotename + "/" + dst).data()))
        return true;

    const auto remote = load_remote(*this, remotename.data());
    if(!remote)
        return false;

    const auto target = "refs/heads/" + src + ":refs/heads/" + dst;
    std::vector<char> targets(target.begin(), target.end());
    targets.push_back(0);
    char* begin = &targets[0];
    const git_strarray refspecs = { &begin, 1 };

    git_push_options opts;
    git_push_init_options(&opts, GIT_PUSH_OPTIONS_VERSION);
    opts.callbacks.credentials = &default_credentials;
    opts.pb_parallelism = 0;
    auto err = git_remote_push(&*remote, &refspecs, &opts);
    if(err != GIT_OK)
        FAIL_WITH(false, *this, "unable to upload %s to %s:%s", src.data(), remotename.data(), dst.data());

    return true;
}

bool Git::remotes(const on_remote_fn& on_remote)
{
    git_strarray remotes;
    auto err = git_remote_list(&remotes, &*repo_);
    if(err != GIT_OK)
        FAIL_WITH(false, *this, "unable to list remotes");

    const auto free_remotes = make_unique(&remotes);
    for(size_t i = 0; i < remotes.count; ++i)
    {
        git_remote* ptr_remote = nullptr;
        err = git_remote_lookup(&ptr_remote, &*repo_, remotes.strings[i]);
        if(err != GIT_OK)
            continue;

        const auto remote = make_unique(ptr_remote);
        on_remote(git_remote_name(ptr_remote), git_remote_url(ptr_remote));
    }
    return true;
}

bool Git::status(const std::string& path, const on_status_fn& on_status)
{
    using Payload = struct
    {
        const on_status_fn& on_status;
    };
    const auto callback = [](const char* path, unsigned int flags, void* payload)
    {
        Payload& p = *static_cast<Payload*>(payload);
        Git::Status status;
        status.deleted      = flags & GIT_STATUS_WT_DELETED;
        status.modified     = flags & GIT_STATUS_WT_MODIFIED;
        status.untracked    = flags & (GIT_STATUS_WT_NEW | GIT_STATUS_IGNORED);
        p.on_status(path, status);
        return 0;
    };
    git_status_options opts;
    git_status_init_options(&opts, GIT_STATUS_OPTIONS_VERSION);
    opts.flags |= GIT_STATUS_OPT_DEFAULTS
               |  GIT_STATUS_OPT_DISABLE_PATHSPEC_MATCH;
    opts.show = GIT_STATUS_SHOW_WORKDIR_ONLY;
    std::vector<char> buffer(path.begin(), path.end());
    buffer.push_back(0);
    char* begin = nullptr;
    if(!path.empty())
    {
        begin = &buffer[0];
        opts.pathspec.strings = &begin;
        opts.pathspec.count = 1;
    }

    Payload payload{on_status};
    const auto err = git_status_foreach_ext(&*repo_, &opts, callback, &payload);
    if(err != GIT_OK)
        FAIL_WITH(false, *this, "unable to iterate git status");

    return true;
}

bool Git::clone(const std::string& path, ECloneMode emode)
{
    git_clone_options opts;
    auto err = git_clone_init_options(&opts, GIT_CLONE_OPTIONS_VERSION);
    if(err != GIT_OK)
        FAIL_WITH(false, *this, "unable to initialize git clone options");

    opts.bare = emode == CLONE_BARE;
    git_repository* ptr_repo = nullptr;
    err = git_clone(&ptr_repo, path_.data(), path.data(), &opts);
    if(err != GIT_OK)
        FAIL_WITH(false, *this, "unable to clone %s to %s", path_.data(), path.data());

    const auto repo = make_unique(ptr_repo);
    UNUSED(repo); // will delete repo
    return true;
}

void Git::flush()
{
    for(const auto& err : errors_)
        LOG(ERROR, "%s\n", err.data());
    errors_.clear();
}

std::string diff_strings(const const_string_ref& left, const char* leftname, const const_string_ref& right, const char* rightname)
{
    git_patch* ptr_patch = nullptr;
    git_diff_options opts;
    git_diff_init_options(&opts, GIT_DIFF_OPTIONS_VERSION);
    opts.flags |= GIT_DIFF_INDENT_HEURISTIC;
    opts.context_lines = 3;
    auto err = git_patch_from_buffers(&ptr_patch, left.value, left.size, leftname, right.value, right.size, rightname, &opts);
    if(err != GIT_OK)
        return std::string();

    const auto patch = make_unique(ptr_patch);
    git_buf buf;
    memset(&buf, 0, sizeof buf);
    err = git_patch_to_buf(&buf, ptr_patch);
    if(err != GIT_OK)
        return std::string();

    const auto free_buf = make_unique(&buf);
    return std::string(buf.ptr, buf.size);
}

namespace
{
    git_merge_file_input make_merge_input(const char* name, const const_string_ref& value)
    {
        git_merge_file_input input;
        git_merge_file_init_input(&input, GIT_MERGE_FILE_INPUT_VERSION);
        input.path = name;
        input.ptr = value.value;
        input.size = value.size;
        return input;
    }
}

std::string merge_strings(const const_string_ref& left, const char* leftname, const const_string_ref& right, const char* rightname)
{
    const auto local  = make_merge_input(leftname, left);
    const auto remote = make_merge_input(rightname, right);
    git_merge_file_result result;
    memset(&result, 0, sizeof result);
    git_merge_file_options opts;
    git_merge_file_init_options(&opts, GIT_MERGE_FILE_OPTIONS_VERSION);
    opts.flags = static_cast<git_merge_file_flag_t>(opts.flags | GIT_MERGE_FILE_DIFF_MINIMAL);
    const auto err = git_merge_file(&result, nullptr, &local, &remote, &opts);
    if(err != GIT_OK)
        return std::string();

    const auto free_result = make_unique(&result);
    return std::string(result.ptr, result.len);
}
