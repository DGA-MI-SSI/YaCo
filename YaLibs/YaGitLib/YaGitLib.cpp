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

#include "YaGitLib.hpp"

#include "utils.hpp"
#include "YaGit.h"

#include <string.h>

#ifdef _MSC_VER
#   include <io.h>
#   include <stdio.h>
#   define mktemp  _mktemp
#else
#   include <unistd.h>
#endif

#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <vector>
#include <sstream>

#ifdef _MSC_VER
#   include <filesystem>
#else
#   include <experimental/filesystem>
#endif

#include "YaGitLib.hpp"
#include "ResolveFileConflictCallback.hpp"
#include "../Helpers.h"

using namespace std;
using namespace std::experimental;

#define DEFAULT_NAME "git_default_name"
#define DEFAULT_EMAIL "git_default@mail.com"

static void check_git_error(int result)
{
    {
        if (result != 0)
        {
            const git_error* error = giterr_last();
            throw std::runtime_error(error->message);
        }
    }
}

template<typename T, typename Init_T, typename Exit_T>
static std::shared_ptr<T> MakeAutoFree(const Init_T& Init, const Exit_T& Exit)
{
    T* pPtr = nullptr;
    check_git_error(Init(&pPtr));
    return std::shared_ptr<T>(pPtr, Exit);
}

template<typename T, typename Init_T, typename Exit_T>
static std::shared_ptr<T> MakeAutoFree_unchecked(const Init_T& Init, const Exit_T& Exit, int& result)
{
    T* pPtr = nullptr;
    result = Init(&pPtr);
    return std::shared_ptr<T>(pPtr, Exit);
}

GitRepo::GitRepo(const std::string& path)
    : repo_path         (path)
    , repository        (nullptr)
    , current_remote    (nullptr)
    , idx               (nullptr)
    , remote_callbacks  (nullptr)
{
    git_libgit2_init();
    remote_callbacks = new(git_remote_callbacks);

}

GitRepo::~GitRepo()
{
    if (repository != nullptr)
    {
        git_repository_free(repository);
        repository = nullptr;
    }
    if (idx != nullptr)
    {
        git_index_free(idx);
        idx = nullptr;
    }
    if (remote_callbacks != nullptr)
    {
        delete remote_callbacks;
    }
    git_libgit2_shutdown();
}

int git_cred_acquire_callback(git_cred **cred, const char *url, const char *username_from_url, unsigned int allowed_types, void* payload)
{
    UNUSED(url);
    UNUSED(allowed_types);
    UNUSED(payload);
    return git_cred_ssh_key_from_agent(cred, username_from_url);
}

std::shared_ptr<const git_signature> GitRepo::make_signature()
{
    if (repository == nullptr)
    {
        throw std::runtime_error("could not get signature, no repository configured");
    }
    const auto signature = MakeAutoFree<git_signature>([&](git_signature** sign){
        return git_signature_default(sign, repository);
    },
        &git_signature_free);
    return signature;
}

void GitRepo::open()
{
    check_git_error(git_repository_open(&repository, repo_path.c_str()));
}

void GitRepo::init(bool bare)
{
    if (repository != nullptr)
    {
        throw std::runtime_error("already open or init repository");
    }
    check_git_error(git_repository_init(&repository, repo_path.c_str(), static_cast<unsigned int>(bare)));
    git_signature* sig = nullptr;
    git_signature_default(&sig, repository);
}

void GitRepo::init()
{
    init(false);
}

void GitRepo::init_bare()
{
    init(true);
}

void GitRepo::clone(const std::string& url)
{
    clone(url, "");
}

void GitRepo::create_remote(const std::string& name, const std::string& url)
{
    check_git_error(git_remote_create(&current_remote, repository, name.c_str(), url.c_str()));
}

void GitRepo::remove_remote(const std::string& remote_name)
{
    check_git_error(git_remote_delete(repository, remote_name.c_str()));
}

void GitRepo::clone(const std::string &url, const std::string &branch)
{
    git_clone_options options = make_git_clone_options();
    options.fetch_opts.callbacks.credentials = git_cred_acquire_callback;

    if (branch.length() == 0)
    {
        check_git_error(git_clone(&repository, url.c_str(), repo_path.c_str(), &options ));
    }
    else
    {
        options.checkout_branch = branch.c_str();
        check_git_error(git_clone(&repository, url.c_str(), repo_path.c_str(), &options ));
    }
}



void GitRepo::load_index()
{
    if (repository == nullptr)
    {
        throw std::runtime_error("repository must be opened/inited before loading index");
    }
    if (idx == nullptr)
    {
        check_git_error(git_repository_index(&idx, repository));
        check_git_error(git_index_read(idx, true));
    }
}

void GitRepo::reload_index()
{
    if (repository == nullptr)
    {
        throw std::runtime_error("repository must be opened/inited before reloading index");
    }
    if (idx == nullptr)
    {
        load_index();
    }
    check_git_error(git_index_read(idx, true));

}



void GitRepo::fetch()
{
    fetch("origin");
}

void GitRepo::fetch(const std::string& remote_name)
{
    if (repository == nullptr)
    {
        throw std::runtime_error("repository must be opened/inited before fetching it");
    }
    if(current_remote != nullptr)
    {
        git_remote_free(current_remote);
        current_remote = nullptr;
    }
    check_git_error(git_remote_lookup(&current_remote, repository, remote_name.c_str()));
    git_fetch_options options = make_git_fetch_options();
    options.callbacks.credentials = git_cred_acquire_callback;
    check_git_error(git_remote_fetch(current_remote, nullptr, &options, ""));
}

void GitRepo::load_remote(const std::string& remote_name)
{
    if (current_remote != nullptr)
    {
        git_remote_free(current_remote);
        current_remote = nullptr;
    }
    check_git_error(git_remote_lookup(&current_remote, repository, remote_name.c_str()));

    // set authentication callback
    check_git_error(git_remote_init_callbacks(remote_callbacks, GIT_REMOTE_CALLBACKS_VERSION));
    remote_callbacks->credentials = git_cred_acquire_callback;
}

void GitRepo::remove_file(const std::string& file_path)
{
    if (repository == nullptr)
    {
        throw std::runtime_error("repository must be opened/inited using it");
    }
    if (idx == nullptr)
    {
        load_index();
    }
    check_git_error(git_index_remove_bypath(idx, file_path.c_str()));
    check_git_error(git_index_write(idx));
}

void GitRepo::remove_files(const std::vector<std::string>& file_paths)
{
    if (repository == nullptr)
    {
        throw std::runtime_error("repository must be opened/inited before using it");
    }

    for (string file_path : file_paths)
    {
        remove_file(file_path);
    }
}

void GitRepo::add_file(const std::string& file_path)
{
    if (repository == nullptr)
    {
        throw std::runtime_error("repository must be opened/inited before using it");
    }
    if (idx == nullptr)
    {
        load_index();
    }
    check_git_error(git_index_add_bypath(idx, file_path.c_str()));
    check_git_error(git_index_write(idx));
}

void GitRepo::add_files(const std::vector<std::string>& file_paths)
{
    if (repository == nullptr)
    {
        throw std::runtime_error("repository must be opened/inited before using it");
    }
    for (const std::string& file_path : file_paths)
    {
        add_file(file_path);
    }
}

void GitRepo::add_all()
{
    if (repository == nullptr)
    {
        throw std::runtime_error("repository must be opened/inited before using it");
    }
    if (idx == nullptr)
    {
        load_index();
    }
    throw std::runtime_error("not implemented yet");
}



void GitRepo::_get_diff_from_index(git_diff** ppGitDiff, const std::string& reference)
{
    std::shared_ptr<git_tree> tree;
    get_tree_from_reference(&tree, reference);
    check_git_error(git_diff_tree_to_index(ppGitDiff, repository, tree.get(), NULL, NULL));
}

std::shared_ptr<git_tree> GitRepo::get_tree_from_oid(const git_oid* oid)
{
    //get commit of reference
    auto commit = MakeAutoFree<git_commit>(
        [&](git_commit **commit){
        return git_commit_lookup(commit, repository, oid);
    }, git_commit_free);

    //get tree of commit
    auto tree = MakeAutoFree<git_tree>(
        [&](git_tree **tree){
        return git_commit_tree(tree, commit.get());
    }, git_tree_free);
    return tree;
}

void GitRepo::get_tree_from_reference(std::shared_ptr<git_tree> *out_tree, const std::string& reference)
{
    git_oid oid;
    memset(&oid, 0, sizeof oid);

    //try to convert reference as oid string
    if(git_oid_fromstr(&oid, reference.c_str()) == 0)
    {
        auto tree = get_tree_from_oid(&oid);
        if(tree != nullptr) {
            *out_tree = tree;
            return;
        }
    }
    //get oid of a reference
    try
    {
        auto ref = MakeAutoFree<git_reference>(
            [&](git_reference** ref){
            return git_reference_dwim(ref, repository, reference.c_str());
        },
            git_reference_free
            );
        check_git_error(git_reference_name_to_id(&oid, repository, git_reference_name(ref.get())));
        auto tree = get_tree_from_oid(&oid);
        *out_tree = tree;
        return;
    }
    catch (const std::runtime_error& exc)
    {
        UNUSED(exc);
        check_git_error(git_reference_name_to_id(&oid, repository, reference.c_str()));
    }

    return;
}

void GitRepo::_get_diff_tree_to_tree(git_diff** ppGitDiff, const std::string& reference_from, const std::string& reference_to)
{
    std::shared_ptr<git_tree> tree_from;
    std::shared_ptr<git_tree> tree_to;

    get_tree_from_reference(&tree_from, reference_from);
    get_tree_from_reference(&tree_to, reference_to);

    //get diff
    check_git_error(git_diff_tree_to_tree(ppGitDiff, repository, tree_from.get(), tree_to.get(), NULL));

    return;
}

extern "C" int invoke_git_diff_file_cb(const git_diff_delta *delta, float progress, void* func)
{
    return (*static_cast<std::function<int(const git_diff_delta *, float)>*>(func))(delta, progress);
}

std::set<std::string> GitRepo::foreach_object_invoke_diff(git_diff* pGitDiff, int diff_delta)
{
    std::set<std::string>           objects;

    //parse trees
    auto callback = std::make_shared<std::function<int(const git_diff_delta*, float)>>([&](const git_diff_delta* delta, float progress)
    {
        UNUSED(progress);
        if (delta->status == diff_delta)
        {
            objects.insert(std::string(delta->new_file.path));
        }
        return 0;
    });
    check_git_error(git_diff_foreach(pGitDiff, &invoke_git_diff_file_cb, nullptr, nullptr, nullptr, callback.get()));
    return objects;
}

std::set<std::string> GitRepo::get_modified_objects(const std::string& reference)
{
    git_diff*                       pGitDiff;

    //get diff
    _get_diff_from_index(&pGitDiff, reference);

    //build objects
    return foreach_object_invoke_diff(pGitDiff, GIT_DELTA_MODIFIED);

}

std::set<std::string> GitRepo::get_modified_objects(const std::string& reference_from, const std::string& reference_to)
{
    git_diff*                       pGitDiff;

    //get diff
    _get_diff_tree_to_tree(&pGitDiff, reference_from, reference_to);

    //build objects
    return foreach_object_invoke_diff(pGitDiff, GIT_DELTA_MODIFIED);

}

std::set<std::string> GitRepo::get_conflicted_objects(const std::string& reference)
{
    git_diff*                       pGitDiff;

    //get diff
    _get_diff_from_index(&pGitDiff, reference);

    //build objects
    return foreach_object_invoke_diff(pGitDiff, GIT_DELTA_CONFLICTED);
}

std::set<std::string> GitRepo::get_conflicted_objects(const std::string& reference_from, const std::string& reference_to)
{
    git_diff*                       pGitDiff;

    //get diff
    _get_diff_tree_to_tree(&pGitDiff, reference_from, reference_to);

    //build objects
    return foreach_object_invoke_diff(pGitDiff, GIT_DELTA_CONFLICTED);

}

std::set<std::string> GitRepo::get_new_objects(const std::string& reference)
{
    git_diff*                       pGitDiff;

    //get diff
    _get_diff_from_index(&pGitDiff, reference);

    //build objects
    return foreach_object_invoke_diff(pGitDiff, GIT_DELTA_ADDED);
}

std::set<std::string> GitRepo::get_new_objects(const std::string& reference_from, const std::string& reference_to)
{
    git_diff*                       pGitDiff;

    //get diff
    _get_diff_tree_to_tree(&pGitDiff, reference_from, reference_to);

    //build objects
    return foreach_object_invoke_diff(pGitDiff, GIT_DELTA_ADDED);

}

std::set<std::string> GitRepo::get_deleted_objects(const std::string& reference)
{
    git_diff*                       pGitDiff;

    //get diff
    _get_diff_from_index(&pGitDiff, reference);

    //build objects
    return foreach_object_invoke_diff(pGitDiff, GIT_DELTA_DELETED);
}

std::set<std::string> GitRepo::get_deleted_objects(const std::string& reference_from, const std::string& reference_to)
{
    git_diff*                       pGitDiff;

    //get diff
    _get_diff_tree_to_tree(&pGitDiff, reference_from, reference_to);

    //build objects
    return foreach_object_invoke_diff(pGitDiff, GIT_DELTA_DELETED);

}

extern "C" int invoke_git_status_cb(const char *path, unsigned int status_flags, void* func)
{
    return (*static_cast<std::function<int(const char *, unsigned int)>*>(func))(path, status_flags);
}

std::set<std::string> GitRepo::get_untracked_objects()
{
    std::set<std::string>   objects;
    auto callback = std::make_shared<std::function<int(const char *, unsigned int)>>([&](const char *path, unsigned int status_flags)
    {
        if (status_flags & GIT_STATUS_WT_NEW)
        {
            objects.insert(std::string(path));
        }
        return 0;
    });
    check_git_error(git_status_foreach(repository, &invoke_git_status_cb, callback.get()));
    return objects;
}

std::set<std::string> GitRepo::get_conflicted_objects()
{
    std::set<std::string>   objects;
    auto callback = std::make_shared<std::function<int(const char *, unsigned int)>>([&](const char *path, unsigned int status_flags)
    {
        if ((status_flags & GIT_STATUS_CONFLICTED))// || (status_flags & GIT_STATUS_INDEX_MODIFIED))
        {
            objects.insert(std::string(path));
        }
        return 0;
    });
    check_git_error(git_status_foreach(repository, &invoke_git_status_cb, callback.get()));
    return objects;
}

std::set<std::string> GitRepo::get_modified_objects()
{
    std::set<std::string>   objects;
    auto callback = std::make_shared<std::function<int(const char *, unsigned int)>>([&](const char *path, unsigned int status_flags)
    {
        if (status_flags & GIT_STATUS_WT_MODIFIED)
        {
            objects.insert(std::string(path));
        }
        return 0;
    });
    check_git_error(git_status_foreach(repository, &invoke_git_status_cb, callback.get()));
    return objects;
}

std::set<std::string> GitRepo::get_deleted_objects()
{
    std::set<std::string>   objects;
    auto callback = std::make_shared<std::function<int(const char *, unsigned int)>>([&](const char *path, unsigned int status_flags)
    {
        if (status_flags == GIT_STATUS_WT_DELETED)
        {
            objects.insert(std::string(path));
        }
        return 0;
    });
    check_git_error(git_status_foreach(repository, &invoke_git_status_cb, callback.get()));
    return objects;
}

std::set<std::tuple<std::string, bool, bool, bool>> GitRepo::get_status()
{
    std::set<std::tuple<std::string, bool, bool, bool>> files;

    auto callback = std::make_shared<std::function<int(const char *, unsigned int)>>([&](const char *path, unsigned int status_flags)
    {
        bool modified = false;
        bool untracked = false;
        bool deleted = false;

        if (status_flags == GIT_STATUS_WT_DELETED)
        {
            deleted = true;
        }

        if (status_flags == GIT_STATUS_WT_MODIFIED)
        {
            modified = true;
        }

        if (status_flags == GIT_STATUS_WT_NEW)
        {
            untracked = true;
        }
        files.insert(make_tuple(std::string(path), modified, deleted, untracked));
        return 0;
    });
    check_git_error(git_status_foreach(repository, &invoke_git_status_cb, callback.get()));
    return files;
}

std::set<std::tuple<std::string, bool, bool, bool>> GitRepo::get_status_in_path(const std::string& path)
{
    std::set<std::tuple<std::string, bool, bool, bool>> files;
    for (auto status : get_status())
    {
        if (path == "." || get<0>(status).compare(0, path.size(), path) == 0)
        {
            files.insert(status);
        }
    }
    return files;
}


std::set<std::string> GitRepo::get_untracked_objects_in_path(const std::string& path)
{
    std::set<std::string> files;
    for (auto status : get_status_in_path(path))
    {
        if (get<3>(status) == true)
        {
            files.insert(get<0>(status));
        }
    }
    return files;
}
std::set<std::string> GitRepo::get_modified_objects_in_path(const std::string& path)
{
    std::set<std::string> files;
    for (auto status : get_status_in_path(path))
    {
        if (get<1>(status) == true)
        {
            files.insert(get<0>(status));
        }
    }
    return files;
}
std::set<std::string> GitRepo::get_deleted_objects_in_path(const std::string& path)
{
    std::set<std::string> files;
    for (std::tuple<std::string, bool, bool, bool> status : get_status_in_path(path))
    {
        if (get<2>(status) == true)
        {
            files.insert(get<0>(status));
        }
    }
    return files;
}


void GitRepo::commit(const std::string& message)
{
    const std::string ref = "HEAD";
    commit(message, ref);
}




void GitRepo::commit(const std::string& message, const std::string& reference)
{
    if(idx == nullptr){
        load_index();
    }
    auto signature = make_signature();
    git_oid tree_id, commit_id, parent_id;
    memset(&parent_id, 0, sizeof parent_id);

    check_git_error(git_index_write_tree(&tree_id, idx));

    const auto tree = MakeAutoFree<git_tree>([&](git_tree** pTree)
    {
        return git_tree_lookup(pTree, repository, &tree_id);
    },
        &git_tree_free);

    if (git_reference_name_to_id(&parent_id, repository, reference.c_str()) < 0)
    {
        check_git_error(git_commit_create_v(&commit_id,
            repository, reference.c_str(), signature.get(), signature.get(), NULL, message.c_str(),
            tree.get(), 0));

    }
    else
    {
        auto commit = MakeAutoFree<git_commit>([&](git_commit** commit)
        {
            return git_commit_lookup(commit, repository, &parent_id);
        },
            &git_commit_free);
        const git_commit* parents[] = { commit.get() };
        check_git_error(git_commit_create(&commit_id,
            repository, reference.c_str(), signature.get(), signature.get(), NULL, message.c_str(),
            tree.get(), 1, parents));

    }
}

void GitRepo::checkout(const std::string& branch)
{

    git_oid target_oid;
    memset(&target_oid, 0, sizeof target_oid);
    auto signature = make_signature();
    git_checkout_options opts = make_git_checkout_options();
    opts.checkout_strategy = GIT_CHECKOUT_FORCE;


    int result = 0;
    std::shared_ptr<git_reference> branch_ref;
    std::shared_ptr<git_commit> target;
    std::shared_ptr<git_object> treeish;

    /************ lookup for asked branch reference **********************************/
    branch_ref = MakeAutoFree_unchecked<git_reference>([&](git_reference** ref)
    {
        return git_branch_lookup(ref, repository, branch.c_str(), GIT_BRANCH_LOCAL);
    }, &git_reference_free, result);
    /**********************************************************************************/

    switch (result)
    {
        case GIT_ENOTFOUND:
            // branch not found, create a new one

            /******************** get head reference **************************************/
            check_git_error(git_reference_name_to_id(&target_oid, repository, "HEAD"));
            target = MakeAutoFree<git_commit>([&](git_commit** commit)
            {
                return git_commit_lookup(commit, repository, &target_oid);
            }, &git_commit_free);
            /********************************************************************************/

            /********************************** create new branch ***************************/
            branch_ref = MakeAutoFree<git_reference>([&](git_reference** ref)
            {
                return git_branch_create(ref, repository, branch.c_str(), target.get(), 1);
            }, &git_reference_free);
            /*********************************************************************************/

            // avoid gcc warning with -Wimplicit-fallthrough
            /* FALLTHRU */

        case 0:
            //jump to new branch
            // branch found, change current branch
            /********************** set HEAD to asked branch ***************************/
            check_git_error(git_repository_set_head(repository, git_reference_name(branch_ref.get())));
            /***************************************************************************/

            treeish = MakeAutoFree<git_object>([&](git_object** tree)
            {
                return git_revparse_single(tree, repository, branch.c_str());
            },
                git_object_free);

            /********************* get asked branch files *****************************/
            check_git_error(git_checkout_tree(repository, treeish.get(), &opts));
            /**************************************************************************/

            break;
        default:
            throw std::runtime_error("could not get asked branch");
            break;
    }
}

void GitRepo::checkout_head()
{
    git_checkout_options opts;

    git_checkout_init_options(&opts, GIT_CHECKOUT_OPTIONS_VERSION);

    opts.checkout_strategy = GIT_CHECKOUT_FORCE;
    git_checkout_head(repository, &opts);

}

std::string GitRepo::get_commit(const std::string& name)
{
    git_oid reference_oid;
    memset(&reference_oid, 0, sizeof reference_oid);
    char oidstr[41];
    memset(oidstr, 0, sizeof oidstr);
    auto reference = MakeAutoFree<git_reference>(
        [&](git_reference** ref){
            return git_reference_dwim(ref, repository, name.c_str());
        },
        git_reference_free
    );
    check_git_error(git_reference_name_to_id(&reference_oid, repository, git_reference_name(reference.get())));
    git_oid_fmt(oidstr, &reference_oid);
    return std::string(oidstr);
}


void GitRepo::push(const std::string& src, const std::string& dst)
{
    if (current_remote == nullptr)
    {
        git_remote_lookup(&current_remote, repository, "origin");
    }

    git_push_options options;
    memset(&options, 0, sizeof options);
    git_push_init_options(&options, GIT_PUSH_OPTIONS_VERSION);
    options.callbacks.credentials = git_cred_acquire_callback;

    std::string sref = "refs/heads/" + src + ":refs/heads/" + dst;
    char* ref_ = const_cast<char*>(sref.data());
    const git_strarray refspecs = {
            &ref_,
            1,
    };
    check_git_error(git_remote_push(current_remote, &refspecs, &options));
}

void GitRepo::merge_fastforward(const std::string& onto, const std::string& from)
{
    git_annotated_commit* onto_;
    git_reference *onto_ref = nullptr;
    check_git_error(git_reference_dwim(&onto_ref, repository, onto.c_str()));//, GIT_BRANCH_ALL));
    check_git_error(git_annotated_commit_from_ref(&onto_, repository, onto_ref));

    git_annotated_commit* from_;
    git_reference *from_ref = nullptr;
    check_git_error(git_reference_dwim(&from_ref, repository, from.c_str()));//, GIT_BRANCH_ALL));
    check_git_error(git_annotated_commit_from_ref(&from_, repository, from_ref));


    //checkout tree
    git_checkout_options co_opts = make_git_checkout_options();
    co_opts.checkout_strategy = GIT_CHECKOUT_FORCE;
    auto tree = MakeAutoFree<git_object>([&](git_object** tree)
                {
                    return git_revparse_single(tree, repository, from.c_str());
                },
                    git_object_free);

    git_oid from_oid;
    memset(&from_oid, 0, sizeof from_oid);
    check_git_error(git_reference_name_to_id(&from_oid, repository, git_reference_name(from_ref)));


    check_git_error(git_checkout_tree(repository, tree.get(), &co_opts));
    git_reference *ref_curr =  nullptr;
    git_reference* plop;
    check_git_error(git_reference_dwim(&plop, repository, onto.c_str()));
    check_git_error(git_reference_set_target(&plop, plop, &from_oid, "merge fastforward"));
    git_reference_free(onto_ref);
    git_reference_free(ref_curr);
    git_reference_free(from_ref);
    return;
}


void GitRepo::merge(const std::string& onto, const std::string& from)
{
    checkout(onto);
    git_annotated_commit *heads[2];
    git_annotated_commit* onto_;
    git_reference *onto_ref = nullptr;
    check_git_error(git_reference_dwim(&onto_ref, repository, onto.c_str()));//, GIT_BRANCH_ALL));
    check_git_error(git_annotated_commit_from_ref(&onto_, repository, onto_ref));
    git_reference_free(onto_ref);

    git_annotated_commit* from_;
    git_reference *from_ref = nullptr;
    check_git_error(git_reference_dwim(&from_ref, repository, from.c_str()));//, GIT_BRANCH_ALL));
    check_git_error(git_annotated_commit_from_ref(&from_, repository, from_ref));
    git_reference_free(from_ref);

    heads[0] = from_;

    git_checkout_options opts = make_git_checkout_options();
    opts.checkout_strategy = GIT_CHECKOUT_FORCE | GIT_CHECKOUT_ALLOW_CONFLICTS | GIT_CHECKOUT_SAFE;
    git_merge_options merge_option = make_git_merge_options();

    check_git_error(git_merge(repository, (const git_annotated_commit**)heads, 1, &merge_option, &opts));

    commit("merge");

}

void GitRepo::merge()
{
    merge("master", "origin/master");
}

std::string GitRepo::config_get_string(const std::string& name)
{
    if(repository == nullptr) {
        throw std::runtime_error("repository must be init first");
    }
    auto config = MakeAutoFree<git_config>(
            [&](git_config** config){
                return git_repository_config_snapshot(config, repository);
            },
            git_config_free
        );

    const char* buffer = nullptr;

    if(git_config_get_string(&buffer, config.get(), name.c_str()) < 0) {
        return "";
    }
    return buffer;
}

void GitRepo::config_set_string(const std::string& name, const std::string& value)
{
    if(repository == nullptr) {
        throw std::runtime_error("repository must be init first");
    }
    auto config = MakeAutoFree<git_config>(
                [&](git_config** config){
                    return git_repository_config(config, repository);
                },
                git_config_free
            );
    check_git_error(git_config_set_string(config.get(), name.c_str(), value.c_str()));
}

std::map<std::string, std::string> GitRepo::get_remotes()
{
    auto remotes = std::map<std::string, std::string>();
    git_strarray remote_array;
    memset(&remote_array, 0, sizeof remote_array);
    check_git_error(git_remote_list(&remote_array, repository));

    for(size_t i = 0; i < remote_array.count; i++)
    {
        auto remote = MakeAutoFree<git_remote>(
                            [&](git_remote** remote){
                                return git_remote_lookup(remote, repository, remote_array.strings[i]);
                            },
                            git_remote_free
                        );
        remotes.insert(std::make_pair(git_remote_name(remote.get()), git_remote_url(remote.get())));
    }
    git_strarray_free(&remote_array);
    return remotes;
}

static bool handle_conflict(const filesystem::path& file_path, ResolveFileConflictCallback& ResolveFileConflict)
{
    /*
     *
<<<<<<< refs/remotes/origin/master
plop.txt content line 0
plop.txt content line 1b
=======
plop.txt content line 1
plop.txt content line 2
>>>>>>> update plop.txt line 2
     *
     */

    const auto f1 = CreateTempFile();
    if(!f1)
        throw std::runtime_error("unable to create temp2 file");

    const auto f2 = CreateTempFile();
    if(!f2)
        throw std::runtime_error("unable to create temp2 file");

    typedef std::function<void(const std::string& line)> Writer;
    const Writer write_input1 = [&](const std::string& line)
    {
        f1->Write(line.data());
    };
    const Writer write_input2 = [&](const std::string& line)
    {
        f2->Write(line.data());
    };
    const Writer write_input_both = [&](const std::string& line)
    {
        write_input1(line);
        write_input2(line);
    };

    ifstream output;
    output.open(file_path);
    Writer writer = write_input_both;
    while(output.good())
    {
        std::string line;
        std::getline(output, line);
        if(line.find("<<<<<<<") == 0)
        {
            writer = write_input1;
            continue;
        }
        else if(line.find("=======") == 0)
        {
            writer = write_input2;
            continue;
        }
        else if(line.find(">>>>>>>") == 0)
        {
            writer = write_input_both;
            continue;
        }
        writer(line);
    }

    output.close();

    // FIXME unicode
    f1->Close();
    f2->Close();
    return ResolveFileConflict.callback(f1->GetPath(), f2->GetPath(), file_path.string());
}

void GitRepo::rebase(const std::string& upstream, const std::string& dst, ResolveFileConflictCallback& ResolveFileConflict)
{
    if(repository == nullptr) {
        throw std::runtime_error("repository must be init first");
    }
    git_rebase* rebase = nullptr;
    git_rebase_options options = make_git_rebase_options();


    const auto resolve_git_conflict =
            [&]()
            {
                for(auto conflict : get_conflicted_objects()) {
                    filesystem::path pconflict;
                    pconflict = repo_path;
                    pconflict /= conflict;
                    if(handle_conflict(pconflict, ResolveFileConflict) == false) {
                        git_rebase_abort(rebase);
                        return false;
                    }
                    add_file(conflict);
                    git_oid oid;
                    memset(&oid, 0, sizeof oid);
                    git_rebase_commit(&oid, rebase, nullptr, make_signature().get(), nullptr, nullptr);
                }
                return true;
            };

    const auto handle_rebase_next_result =
            [&](int result, const git_rebase_operation* operation) {
                switch(result)
                {
                case GIT_ITEROVER:
                    return false;

                case GIT_OK:
                    switch(operation->type)
                    {
                    default:
                        return true;
                    case GIT_REBASE_OPERATION_PICK:
                        git_oid oid;
                        memset(&oid, 0, sizeof oid);
                        git_rebase_commit(&oid, rebase, nullptr, make_signature().get(), nullptr, nullptr);
                        return true;
                    }

                case GIT_ECONFLICT:
                    return true;

                default:
                    // FIXME cerr << "unhandle git_rebase_next result: " << result << endl;
                    check_git_error(git_rebase_abort(rebase));
                    check_git_error(result);
                    return false;
                }
            };


    if(git_rebase_open(&rebase, repository, &options) < 0)
    {

        git_annotated_commit* branch;
        git_reference *branch_ref = nullptr;
        check_git_error(git_reference_dwim(&branch_ref, repository, dst.c_str()));//, GIT_BRANCH_ALL));
        check_git_error(git_annotated_commit_from_ref(&branch, repository, branch_ref));
        git_reference_free(branch_ref);

        git_annotated_commit* upstream_;
        git_reference *upstream_ref = nullptr;

        check_git_error(git_reference_dwim(&upstream_ref, repository, upstream.c_str()));//, GIT_BRANCH_ALL));
        check_git_error(git_annotated_commit_from_ref(&upstream_, repository, upstream_ref));
        git_reference_free(upstream_ref);

        check_git_error(git_rebase_init(&rebase, repository, branch, upstream_, nullptr, &options));

        git_annotated_commit_free(branch);
        git_annotated_commit_free(upstream_);
    }

    git_rebase_operation* operation = nullptr;
    while (true) {
        int result = git_rebase_next(&operation, rebase);


        if(resolve_git_conflict() == false) {
            break;
        }

        if (handle_rebase_next_result(result, operation) == false){
            break;
        }

    }


    check_git_error(git_rebase_finish(rebase, make_signature().get()));

    git_rebase_free(rebase);
}
std::set<std::string> tags_to_set(const git_strarray* tags) {
    std::set<std::string> result_tags;
    for(size_t i = 0; i < tags->count; i++) {
        result_tags.insert(tags->strings[i]);
    }
    return result_tags;
}

std::set<std::string> GitRepo::get_tags() {
    git_strarray tags;
    memset(&tags, 0, sizeof tags);
    check_git_error(git_tag_list(&tags, repository));
    auto result = tags_to_set(&tags);
    git_strarray_free(&tags);
    return result;
}


std::set<std::string> GitRepo::get_tags(const std::string& pattern) {
    git_strarray tags;
    memset(&tags, 0, sizeof tags);
    check_git_error(git_tag_list_match(&tags, pattern.empty() ? "*": pattern.c_str(), repository));
    auto result = tags_to_set(&tags);
    git_strarray_free(&tags);
    return result;
}


void GitRepo::remove_tag(const std::string& tag_name) {
    if(tag_name.empty()) {
        throw std::runtime_error("tag name required");
    }
    check_git_error(git_tag_delete(repository, tag_name.c_str()));
}


void GitRepo::create_tag(const std::string& target, const std::string& tag_name, const std::string& message) {
//  git_repository *repo = state->repo;
//  tag_options *opts = state->opts;

    auto tagger = make_signature();
    git_oid oid;
    if(tag_name.empty()) {
        throw std::runtime_error("tag_name required");
    }

    string target_name = "HEAD";
    if(!target.empty()) {
        target_name = target;
    }


    auto target_ = MakeAutoFree<git_object>(
                [&](git_object** target_){
                    return git_revparse_single(target_, repository, target_name.c_str());
                },
                git_object_free
            );

    check_git_error(git_tag_create(&oid, repository, tag_name.c_str(),
            target_.get(), tagger.get(), message.c_str(), 1));
}
