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
#include "FileUtils.hpp"
#include "Helpers.h"
#include "Yatools.hpp"

#include <fstream>
#include <sstream>
#include <string.h>
#include <vector>

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
    template<> struct default_delete<git_buf>                     { static const bool marker = true; void operator()(git_buf*                     ptr) { git_buf_free(ptr); } };
    template<> struct default_delete<git_commit>                  { static const bool marker = true; void operator()(git_commit*                  ptr) { git_commit_free(ptr); } };
    template<> struct default_delete<git_config>                  { static const bool marker = true; void operator()(git_config*                  ptr) { git_config_free(ptr); } };
    template<> struct default_delete<git_diff>                    { static const bool marker = true; void operator()(git_diff*                    ptr) { git_diff_free(ptr); } };
    template<> struct default_delete<git_index_conflict_iterator> { static const bool marker = true; void operator()(git_index_conflict_iterator* ptr) { git_index_conflict_iterator_free(ptr); } };
    template<> struct default_delete<git_index>                   { static const bool marker = true; void operator()(git_index*                   ptr) { git_index_free(ptr); } };
    template<> struct default_delete<git_merge_file_result>       { static const bool marker = true; void operator()(git_merge_file_result*       ptr) { git_merge_file_result_free(ptr); } };
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
    struct LibGit
    {
        LibGit()
        {
            git_libgit2_init();
        }

        ~LibGit()
        {
            git_libgit2_shutdown();
        }
    };
    static const LibGit libgit;

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
        bool        rebase              (const std::string& upstream, const std::string& dst, const on_conflict_fn& on_conflict) override;
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

    err = git_index_write(&*index_);
    if(err != GIT_OK)
        FAIL_WITH(false, *this, "unable to write index");

    return true;
}

bool Git::remove_file(const std::string& name)
{
    if(!load_index(*this))
        return false;

    auto err = git_index_remove_bypath(&*index_, name.data());
    if(err != GIT_OK)
        FAIL_WITH(false, *this, "unable to remove %s from index", name.data());

    err = git_index_write(&*index_);
    if(err != GIT_OK)
        FAIL_WITH(false, *this, "unable to write index");

    return true;
}

namespace
{
    std::unique_ptr<git_config> get_config(Git& git)
    {
        git_config* ptr_config = nullptr;
        auto err = git_repository_config_snapshot(&ptr_config, &*git.repo_);
        if(err != GIT_OK)
            FAIL_WITH(std::nullptr_t(), git, "unable to snapshot config");

        return make_unique(ptr_config);
    }
}

std::string Git::config_get_string(const std::string& name)
{
    const auto config = get_config(*this);
    if(!config)
        return std::string();

    const char* buffer = nullptr;
    const auto err = git_config_get_string(&buffer, &*config, name.data());
    if(err != GIT_OK)
        FAIL_WITH(std::string(), *this, "unable to read config string %s", name.data());

    return std::string(buffer);
}

bool Git::config_set_string(const std::string& name, const std::string& value)
{
    const auto config = get_config(*this);
    if(!config)
        return false;

    const auto err = git_config_set_string(&*config, name.data(), value.data());
    if (err != GIT_OK)
        FAIL_WITH(false, *this, "unable to set config string %s to %s", name.data(), value.data());

    return true;
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

    std::unique_ptr<git_tree> get_tree(Git& git, const std::string& target)
    {
        git_oid oid;
        auto err = git_oid_fromstr(&oid, target.data());
        if(err != GIT_OK)
            err = git_reference_name_to_id(&oid, &*git.repo_, target.data());
        if(err != GIT_OK)
            FAIL_WITH(std::nullptr_t(), git, "unknown target %s", target.data());

        git_commit* ptr_commit = nullptr;
        err = git_commit_lookup(&ptr_commit, &*git.repo_, &oid);
        if(err != GIT_OK)
            FAIL_WITH(std::nullptr_t(), git, "unable to lookup commit from %s", target.data());

        auto commit = make_unique(ptr_commit);
        git_tree* ptr_tree = nullptr;
        err = git_commit_tree(&ptr_tree, ptr_commit);
        if(err != GIT_OK)
            FAIL_WITH(std::nullptr_t(), git, "unable to get commit tree from %s", target.data());

        return make_unique(ptr_tree);
    }
}

bool Git::diff_index(const std::string& from, const Git::on_blob_fn& on_blob)
{
    const auto from_tree = get_tree(*this, from);
    if(!from_tree)
        return false;

    git_diff* ptr_diff = nullptr;
    auto err = git_diff_tree_to_index(&ptr_diff, &*repo_, &*from_tree, nullptr, nullptr);
    if(err != GIT_OK)
        FAIL_WITH(false, *this, "unable to diff tree to index");

    const auto diff = make_unique(ptr_diff);
    using Payload = struct
    {
        git_repository* repo;
        on_blob_fn      on_blob;
    };
    const auto file_cb = [](const git_diff_delta* delta, float /*progress*/, void* vpayload)
    {
        const auto& payload = *static_cast<Payload*>(vpayload);
        const auto  deleted = delta->status == GIT_DELTA_DELETED;
        const auto& file    = deleted ? delta->old_file : delta->new_file;

        git_blob* blob = nullptr;
        const auto err = git_blob_lookup(&blob, payload.repo, &file.id);
        if(err != GIT_OK)
            return 0;

        const auto ptr = git_blob_rawcontent(blob);
        const auto size = git_blob_rawsize(blob);
        const auto rpy = payload.on_blob(file.path, !deleted, ptr, size);
        git_blob_free(blob);
        return rpy;
    };
    Payload payload{&*repo_, on_blob};
    err = git_diff_foreach(ptr_diff, file_cb, nullptr, nullptr, nullptr, &payload);
    if(err != GIT_OK)
        FAIL_WITH(false, *this, "unable to iterate diff index");

    return true;
}

namespace
{
    bool handle_conflict(const fs::path& path, const Git::on_conflict_fn& on_conflict)
    {
/*
<<<<<<< refs/remotes/origin/master
plop.txt content line 0
plop.txt content line 1b
=======
plop.txt content line 1
plop.txt content line 2
>>>>>>> update plop.txt line 2
*/
        std::stringstream first;
        std::stringstream second;
        {
            std::string line;
            bool has_first = true;
            bool has_second = true;
            std::ifstream input(path);
            while(std::getline(input, line))
            {
                if(line.find("<<<<<<<") == 0)
                {
                    has_first = true;
                    has_second = false;
                    continue;
                }
                else if(line.find("=======") == 0)
                {
                    has_first = false;
                    has_second = true;
                    continue;
                }
                else if(line.find(">>>>>>>") == 0)
                {
                    has_first = true;
                    has_second = true;
                    continue;
                }
                else if(line.empty())
                    continue;
                if(has_first)
                    first << line << std::endl;
                if(has_second)
                    second << line << std::endl;
            }
        }

        return on_conflict(first.str(), second.str(), path.string());
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
        if(!load_index(git))
            return false;

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

            const auto aborted = !handle_conflict(root / our->path, on_conflict);
            if(aborted)
                return false;

            git.add_file(our->path);
        }
    }

    bool rebase(Git& git, git_rebase* ptr_rebase, const Git::on_conflict_fn& on_conflict)
    {
        git_rebase_operation* operation = nullptr;
        while(true)
        {
            auto err = git_rebase_next(&operation, ptr_rebase);
            if(err == GIT_ITEROVER)
                return true;

            if(err != GIT_OK)
                FAIL_WITH(false, git, "unable to rebase");

            if(operation->type != GIT_REBASE_OPERATION_PICK)
                continue;

            const auto ok = resolve_conflicts(git, on_conflict);
            if(!ok)
                return false;

            git_oid oid;
            memset(&oid, 0, sizeof oid);
            err = git_rebase_commit(&oid, ptr_rebase, nullptr, make_signature(git).get(), nullptr, nullptr);
            if(err != GIT_OK)
                FAIL_WITH(false, git, "unable to pick rebase commit");
        }
    }
}

bool Git::rebase(const std::string& upstream, const std::string& dst, const on_conflict_fn& on_conflict)
{
    if(is_equal_oid(&*repo_, upstream.data(), dst.data()))
        return true;

    const auto rebase = init_rebase(*this, dst, upstream);
    if(!rebase)
        return false;

    const auto ok = ::rebase(*this, &*rebase, on_conflict);
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

        const auto sig = make_signature(git);
        git_oid tree_id;
        memset(&tree_id, 0, sizeof tree_id);
        auto err = git_index_write_tree(&tree_id, &*git.index_);
        if(err != GIT_OK)
            FAIL_WITH(false, git, "unable to write index");

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
    memset(oidstr, 0, sizeof oidstr);
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
