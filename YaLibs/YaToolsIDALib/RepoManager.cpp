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
#include "../YaGitLib/ResolveFileConflictCallback.hpp"
#include "Logger.h"
#include "Yatools.h"
#include "Merger.hpp"
#include "IModelAccept.hpp" 

#include <libxml/xmlreader.h>
#include <memory>
#include <sstream>
#include <ctime>
#include <regex>

#ifdef _MSC_VER
#   include <filesystem>
#else
#   include <experimental/filesystem>
#endif

namespace fs = std::experimental::filesystem;

#ifdef __EA64__
#define EA_PREFIX   "ll"
#define EA_SIZE     "16"
#else
#define EA_PREFIX   ""
#define EA_SIZE     "8"
#endif
#define EA_FMT      "%0" EA_SIZE EA_PREFIX "X"

#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("repo_manager", (FMT "\n"), ## __VA_ARGS__)

#define YACO_IDA_MSG_PREFIX "[YaCo] "

#define IDA_LOG_INFO(FMT, ...) do{ \
    LOG(INFO, FMT, ## __VA_ARGS__); \
    msg((YACO_IDA_MSG_PREFIX FMT "\n"), ## __VA_ARGS__); \
} while(0)

#define IDA_LOG_WARNING(FMT, ...) do{ \
    LOG(WARNING, FMT, ## __VA_ARGS__); \
    msg((YACO_IDA_MSG_PREFIX "WARNING: " FMT "\n"), ## __VA_ARGS__); \
} while(0)

#define IDA_LOG_ERROR(FMT, ...) do{ \
    LOG(ERROR, FMT, ## __VA_ARGS__); \
    msg((YACO_IDA_MSG_PREFIX "ERROR: " FMT "\n"), ## __VA_ARGS__); \
} while(0)

#define IDA_LOG_GUI_WARNING(FMT, ...) do{ \
    IDA_LOG_WARNING(FMT, ## __VA_ARGS__); \
    warning(FMT, ## __VA_ARGS__); \
} while(0)

#define IDA_LOG_GUI_ERROR(FMT, ...) do{ \
    IDA_LOG_ERROR(FMT, ## __VA_ARGS__); \
    error(FMT, ## __VA_ARGS__); \
} while(0)

namespace
{
    static constexpr size_t TRUNCATE_COMMIT_MSG_LENGTH             = 4000;
    static constexpr int    GIT_PUSH_RETRIES                       = 3;
    static constexpr int    CONFLICT_RESOLVER_EDIT_MAX_FILE_LENGTH = 65536;
}

static bool remove_substring(std::string& str, const std::string& substr)
{
    if (substr.empty())
        return false;

    const size_t pos = str.rfind(substr);
    if (pos != std::string::npos)
    {
        str.erase(pos, substr.size());
        return true;
    }

    return false;
}

static bool is_valid_xml_file(const std::string& filename)
{
    std::shared_ptr<xmlTextReader> reader(xmlReaderForFile(filename.c_str(), NULL, 0), &xmlFreeTextReader);
    int ret = 1;
    while (ret == 1)
        ret = xmlTextReaderRead(reader.get());
    return ret != -1;
}

static void add_filename_suffix(std::string& file_path, const std::string& suffix)
{
    std::string file_extension{ fs::path{ file_path }.extension().string() };
    remove_substring(file_path, file_extension);
    file_path += suffix;
    file_path += file_extension;
}

static bool remove_filename_suffix(std::string& file_path, const std::string& suffix)
{
    // only remove the suffix from the filename even if it appear in the extention
    std::string file_extension{ fs::path{ file_path }.extension().string() };
    remove_substring(file_path, file_extension);
    const bool removed = remove_substring(file_path, suffix);
    file_path += file_extension;
    return removed;
}

namespace
{
    struct IDAPromptMergeConflict : public PromptMergeConflict
    {
        std::string merge_attributes_callback(const char* message_info, const char* input_attribute1, const char* input_attribute2) override;
    };
}

std::string IDAPromptMergeConflict::merge_attributes_callback(const char* message_info, const char* input_attribute1, const char* input_attribute2)
{
    qstring buffer;
    if(!ask_text(
        &buffer,
        0,
        input_attribute1,
        "%s\nValue from local : %s\nValue from remote : %s\n",
        message_info,
        input_attribute1,
        input_attribute2
    ))
        return std::string{ input_attribute1 };
    return std::string{ buffer.c_str() };
}

namespace
{
    struct IDAInteractiveFileConflictResolver : public ResolveFileConflictCallback
    {
        bool callback(const std::string& input_file1, const std::string& input_file2, const std::string& output_file_result) override;
    };
}

bool IDAInteractiveFileConflictResolver::callback(const std::string& input_file1, const std::string& input_file2, const std::string& output_file_result)
{
    if (!std::regex_match(output_file_result, std::regex{ ".*\\.xml$" }))
        return true;

    IDAPromptMergeConflict merger_conflict;
    Merger merger{ &merger_conflict, ObjectVersionMergeStrategy_e::OBJECT_VERSION_MERGE_PROMPT };
    if (merger.smartMerge(input_file1.c_str(), input_file2.c_str(), output_file_result.c_str()) != MergeStatus_e::OBJECT_MERGE_STATUS_NOT_UPDATED)
    {
        if (!is_valid_xml_file(output_file_result))
        {
            IDA_LOG_GUI_ERROR("Merger generated invalid xml file");
            return false;
        }
        return true;
    }

    warning("Auto merge failed, please edit manually %s then continue", output_file_result.c_str());
    if (!is_valid_xml_file(output_file_result))
    {
        IDA_LOG_GUI_ERROR("%s is an invalid xml file", output_file_result.c_str());
        return false;
    }
    return true;
}

namespace
{
    struct RepoManager
        : public IRepoManager
    {
        explicit RepoManager(bool ida_is_interactive);

        // IRepoManager
        void add_auto_comment(ea_t ea, const std::string& text) override;
        void check_valid_cache_startup() override;
        std::vector<std::string> update_cache() override;
        bool repo_commit(std::string commit_msg = "") override;
        void toggle_repo_auto_sync() override;
        void sync_and_push_original_idb() override;
        void discard_and_pull_idb() override;

        void ask_to_checkout_modified_files();
        void ensure_git_globals();
        bool repo_exists();
        void repo_init();
        void repo_open(const std::string& path);
        std::string get_commit(const std::string& ref);
        void fetch(const std::string& origin);
        bool rebase(const std::string& origin, const std::string& branch);
        void push_origin_master();
        bool repo_auto_sync_enabled();
        void ask_for_remote();

        bool ida_is_interactive_;
        GitRepo repo_;
        std::vector<std::tuple<std::string, std::string>> auto_comments_;
        bool repo_auto_sync_;
    };
}

RepoManager::RepoManager(bool ida_is_interactive): 
    ida_is_interactive_{ ida_is_interactive },
    repo_{ "." },
    repo_auto_sync_{ true }
{
    if (!repo_exists())
    {
        IDA_LOG_INFO("No repo found ! Creating repo");
        repo_init();
    }
    else
    {
        repo_open(".");
    }
    IDA_LOG_INFO("Repo opened");
}

void RepoManager::add_auto_comment(ea_t ea, const std::string & text)
{
    std::string prefix;
    if (get_struc(ea))
    {
        if (get_struc_idx(ea) == BADADDR)
        {
            prefix += "stackframe '";
            qstring func_name;
            get_func_name(&func_name, get_func_by_frame(ea));
            prefix += func_name.c_str();
            prefix += "'";
        }
        else
        {
            prefix += "structure '";
            prefix += get_struc_name(ea).c_str();
            prefix += "'";
        }
    }
    else if (get_enum_idx(ea) != BADADDR)
    {
        prefix += "enum '";
        prefix += get_enum_name(ea).c_str();
        prefix += "'";
    }
    else
    {
        prefix += ea_to_hex(ea);
        func_t* func = get_func(ea);
        if (func)
        {
            qstring func_name;
            get_func_name(&func_name, ea);
            if (!func_name.empty())
            {
                prefix += ',';
                prefix += func_name.c_str();

                if (ea != func->start_ea)
                {
                    qstring ea_name;
                    if (get_ea_name(&ea_name, ea, GN_LOCAL) && !ea_name.empty())
                    {
                        prefix += ':';
                        prefix += ea_name.c_str();
                    }
                    else
                    {
                        prefix += '+';
                        prefix += ea_to_hex(ea - func->start_ea);
                    }
                }
            }
        }
    }
    auto_comments_.emplace_back(std::move(prefix), text);
}

void RepoManager::check_valid_cache_startup()
{
    IDA_LOG_INFO("Cache validity check started");

    std::map<std::string, std::string> remotes;
    try
    {
        remotes = repo_.get_remotes();
    }
    catch (std::runtime_error error)
    {
        IDA_LOG_WARNING("Couldn't get repo remotes, error: %s", error.what());
    }

    if (remotes.find("origin") == remotes.end())
    {
        IDA_LOG_WARNING("origin not defined: ignoring origin and master sync check!");
    }
    else
    {
        if (repo_.get_commit("origin/master") != repo_.get_commit("master"))
        {
            IDA_LOG_WARNING("Master and origin/master doesn't point to the same commit, please update your master.");
        }
    }

    std::error_code ec;
    fs::create_directory("cache", ec);

    fs::path current_idb_path{ get_current_idb_path() };
    std::string idb_extension{ current_idb_path.extension().string() };
    std::string idb_prefix{ get_current_idb_path() };
    remove_substring(idb_prefix, idb_extension);

    if (!std::regex_match(idb_prefix, std::regex{ ".*_local$" }))
    {
        IDA_LOG_INFO("Current IDB does not have _local suffix");
        std::string local_idb_path{ idb_prefix + "_local" + idb_extension };
        bool local_idb_exist = fs::exists(local_idb_path, ec);
        if (!local_idb_exist)
        {
            IDA_LOG_INFO("Local IDB does not exist, it will be created");
            fs::copy_file(current_idb_path, local_idb_path, ec);
            if (ec)
                IDA_LOG_WARNING("Couldn't create local idb file, error: %s", ec.message().c_str());
        }

        if (ida_is_interactive_)
        {
            IDA_LOG_INFO("IDA need to restart with local IDB.");
            std::string msg{ "To use YaCo you must name your IDB with _local suffix. YaCo will create one for you.\nRestart IDA and open " };
            msg += fs::path{ local_idb_path }.filename().generic_string();
            msg += '.';
            set_database_flag(DBFL_KILL);
            warning(msg.c_str());
            qexit(0);
        }
    }

    IDA_LOG_INFO("Cache validity check ended");
}

std::vector<std::string> RepoManager::update_cache()
{
    std::map<std::string, std::string> remotes;
    try
    {
        remotes = repo_.get_remotes();
    }
    catch (std::runtime_error error)
    {
        IDA_LOG_ERROR("Couldn't get repo remotes, error: %s", error.what());
    }

    std::vector<std::string> modified_files;
    if (remotes.find("origin") == remotes.end())
        return modified_files; // No remote

    // check if files has been modified in background
    ask_to_checkout_modified_files();

    if (!repo_auto_sync_)
    {
        IDA_LOG_INFO("Repo auto sync disabled, ignoring cache update");
        return modified_files;
    }

    IDA_LOG_INFO("Cache update started");
    // get master commit
    std::string master_commit{ get_commit("master") };
    if (master_commit.empty())
    {
        IDA_LOG_INFO("Cache update failed");
        return modified_files;
    }
    LOG(DEBUG, "Current master commit: %s", master_commit.c_str());

    // fetch remote
    fetch("origin");
    LOG(DEBUG, "Fetched origin/master commit: %s", get_commit("origin/master").c_str());

    // rebase in master
    IDA_LOG_INFO("Rebasing from origin/master");
    if (!rebase("origin/master", "master"))
    {
        IDA_LOG_INFO("Cache update failed");
        // disable auto sync (when closing database)
        warning("You have errors during rebase. You have to resolve it manually.\nSee git_rebase.log for details.\nThen run save on IDA to complete rebase and update master");
        return modified_files;
    }

    // get modified files from origin
    std::set<std::string> new_objects{ repo_.get_new_objects(master_commit) };
    std::set<std::string> modified_objects{ repo_.get_modified_objects(master_commit) };
    std::set<std::string> deleted_objects{ repo_.get_deleted_objects(master_commit) };

    for (const std::string& f : new_objects)
    {
        IDA_LOG_INFO("added    %s", f.c_str());
        modified_files.push_back(f);
    }
    for (const std::string& f : modified_objects)
    {
        IDA_LOG_INFO("modified %s", f.c_str());
        modified_files.push_back(f);
    }
    for (const std::string& f : deleted_objects)
        IDA_LOG_INFO("deleted  %s", f.c_str());
    IDA_LOG_INFO("Rebased from origin/master");

    // push to origin
    bool push_success = false;
    int nb_try = 0;
    do
    {
        try
        {
            repo_.push("master", "master");
            LOG(DEBUG, "Push to master: success");
            push_success = true;
        }
        catch (std::runtime_error error)
        {
            LOG(DEBUG, "Push to master: fail, error: %s", error.what());
            ++nb_try;
            if (nb_try < GIT_PUSH_RETRIES)
                continue;

            IDA_LOG_WARNING("Errors occured during push to origin, they need to be resolved manually.");
            repo_auto_sync_ = false;
            IDA_LOG_INFO("Auto rebase/push disabled");
            warning("You have errors during push to origin. You have to resolve it manually.");
            return modified_files;
        }
    }
    while (!push_success);
    IDA_LOG_INFO("Pushed to origin/master");

    IDA_LOG_INFO("Cache update success");
    return modified_files;
}

bool RepoManager::repo_commit(std::string commit_msg)
{
    IDA_LOG_INFO("Committing changes");

    std::set<std::string> untracked_files{ repo_.get_untracked_objects_in_path("cache/") };
    std::set<std::string> modified_files{ repo_.get_modified_objects_in_path("cache/") };
    std::set<std::string> deleted_files{ repo_.get_deleted_objects_in_path("cache/") };

    if (untracked_files.empty() && modified_files.empty() && deleted_files.empty())
    {
        IDA_LOG_INFO("No changes to commit");
        return true;
    }

    for (const std::string& f : untracked_files)
    {
        repo_.add_file(f);
        IDA_LOG_INFO("added    %s", f.c_str());
    }
    for (const std::string& f : modified_files)
    {
        repo_.add_file(f);
        IDA_LOG_INFO("modified %s", f.c_str());
    }
    for (const std::string& f : deleted_files)
    {
        repo_.remove_file(f);
        IDA_LOG_INFO("deleted  %s", f.c_str());
    }

    size_t max_prefix_len = 0;
    size_t max_txt_len = 0;
    for (const std::tuple<std::string, std::string>& comment : auto_comments_)
    {
        max_prefix_len = std::max(std::get<0>(comment).size(), max_prefix_len);
        max_txt_len = std::max(std::get<1>(comment).size(), max_txt_len);
    }

    std::sort(auto_comments_.begin(), auto_comments_.end(),
        [](const std::tuple<std::string, std::string>& a, const std::tuple<std::string, std::string>& b)
    {
        int cmp = std::get<0>(a).compare(std::get<0>(b));
        if (cmp == 0)
        {
            cmp = std::get<1>(a).compare(std::get<1>(b));
        }
        return cmp < 0;
    });

    size_t max_total_len = max_prefix_len + max_txt_len + 4; // for '[', ']', ' ', '\0'
    std::unique_ptr<char[]> buffer = std::make_unique<char[]>(max_total_len);
    if (commit_msg.empty())
    {
        bool need_trucate = false;
        for (const std::tuple<std::string, std::string>& comment : auto_comments_)
        {
            snprintf(buffer.get(), max_total_len, "[%-*s] %s", static_cast<int>(max_prefix_len), std::get<0>(comment).c_str(), std::get<1>(comment).c_str());
            commit_msg += buffer.get();
            commit_msg += '\n';
            need_trucate = commit_msg.size() > TRUNCATE_COMMIT_MSG_LENGTH;
            if (need_trucate)
                break;
        }
        if (need_trucate)
        {
            commit_msg.erase(TRUNCATE_COMMIT_MSG_LENGTH);
            commit_msg += "\n...truncated";
        }
    }

    if (commit_msg.empty())
        return false;

    try
    {
        repo_.commit(commit_msg);
    }
    catch (std::runtime_error _error)
    {
        IDA_LOG_GUI_ERROR("An error occured during commit, error: %s", _error.what());
        return false;
    }
    auto_comments_.clear();

    IDA_LOG_INFO("Changes commited");
    return true;
}

void RepoManager::toggle_repo_auto_sync()
{
    repo_auto_sync_ = !repo_auto_sync_;
    if (repo_auto_sync_)
        IDA_LOG_INFO("Auto rebase/push enabled");
    else
        IDA_LOG_INFO("Auto rebase/push disabled");
}

void RepoManager::sync_and_push_original_idb()
{
    // sync original idb to current idb
    backup_original_idb();
    copy_current_idb_to_original_file();

    // remove xml cache files
    for (const fs::directory_entry& file_path : fs::recursive_directory_iterator("cache"))
    {
        std::error_code ec;
        bool is_regular_file = fs::is_regular_file(file_path.path(), ec);
        if (!is_regular_file)
            continue;

        // git remove xml
        try
        {
            repo_.remove_file(file_path.path().generic_string());
        }
        catch (std::runtime_error error)
        {
            IDA_LOG_WARNING("Couldn't remove %s from git, error: %s", file_path.path().generic_string().c_str(), error.what());
        }

        // filesystem remove xml
        fs::remove(file_path.path(), ec);
        if (ec)
            IDA_LOG_WARNING("Couldn't remove %s from filesystem, error: %s", file_path.path().generic_string().c_str(), ec.message().c_str());
    }

    // git add original idb file
    try
    {
        repo_.add_file(get_original_idb_name());
    }
    catch (std::runtime_error error)
    {
        IDA_LOG_WARNING("Couldn't add original idb file to git, error: %s", error.what());
    }

    // git commit and push
    try
    {
        repo_.commit("YaCo force push");
    }
    catch (std::runtime_error error)
    {
        IDA_LOG_WARNING("Couldn't commit, error: %s", error.what());
    }
    push_origin_master();
}

void RepoManager::discard_and_pull_idb()
{
    backup_current_idb();
    backup_original_idb();

    // delete all modified objects
    repo_.checkout_head();

    // get synced original idb
    fetch("origin");
    rebase("origin/master", "master");

    // sync current idb to original idb
    copy_original_idb_to_current_file();
}

void RepoManager::ask_to_checkout_modified_files()
{
    std::string modified_objects;
    bool idb_modified = false;

    std::string original_idb_name = get_original_idb_name();
    for (std::string modified_object : repo_.get_modified_objects())
    {
        if (modified_object == original_idb_name)
        {
            backup_original_idb();
            idb_modified = true;
            continue;
        }
        modified_objects += modified_object;
        modified_objects += '\n';
    }


    if (modified_objects.empty())
    {
        if (idb_modified)
            repo_.checkout_head(); // checkout silently
        return;
    }

    // modified_objects is now the message
    modified_objects += "\nhas been modified, this is not normal, do you want to checkout these files ? (Rebasing will be disabled if you answer no)";
    if (ask_yn(true, modified_objects.c_str()) != ASKBTN_NO)
    {
        repo_.checkout_head();
        return;
    }

    repo_auto_sync_ = false;
}

void RepoManager::ensure_git_globals()
{
    std::string user_name{ repo_.config_get_string("user.name") };
    if (user_name.empty())
    {
        qstring tmp;
        do
            tmp = "username";
        while (!ask_str(&tmp, 0, "Entrer git user.name") || tmp.empty());

        user_name = tmp.c_str();
        try
        {
            repo_.config_set_string("user.name", user_name);
        }
        catch (const std::runtime_error& error)
        {
            IDA_LOG_GUI_WARNING("Couldn't set git user name, error: %s", error.what());
        }
    }

    std::string user_email{ repo_.config_get_string("user.email") };
    if (user_email.empty())
    {
        qstring tmp;
        do
            tmp = "username@localdomain";
        while (!ask_str(&tmp, 0, "Entrer git user.email") || tmp.empty());

        user_email = tmp.c_str();
        try
        {
            repo_.config_set_string("user.email", user_email);
        }
        catch (const std::runtime_error& error)
        {
            IDA_LOG_GUI_WARNING("Couldn't set git user email, error: %s", error.what());
        }
    }
}

bool RepoManager::repo_exists()
{
    std::error_code ec;
    return fs::is_directory(".git", ec) && !ec;
}

void RepoManager::repo_init()
{
    try
    {
        repo_ = GitRepo{ "." };
        repo_.init();
        ensure_git_globals();

        //add current IDB to repo
        repo_.add_file(get_current_idb_name());

        //create an initial commit with IDB
        repo_.commit("Initial commit");
    }
    catch (std::runtime_error _error)
    {
        IDA_LOG_GUI_ERROR("An error occured during repo init, error: %s", _error.what());
        return;
    }

    if (ida_is_interactive_)
        ask_for_remote();

    push_origin_master();
}

void RepoManager::repo_open(const std::string& path)
{
    repo_ = GitRepo(path);
    try
    {
        repo_.init();
    }
    catch (std::runtime_error error)
    {
        IDA_LOG_WARNING("Couldn't init repository, error: %s", error.what());
    }
    ensure_git_globals();
}

std::string RepoManager::get_commit(const std::string& ref)
{
    std::string commit;
    try
    {
        commit = repo_.get_commit(ref);
    }
    catch (std::runtime_error error)
    {
        IDA_LOG_WARNING("Couldn't get commit from master, error: %s", error.what());
    }
    return commit;
}

void RepoManager::fetch(const std::string& origin)
{
    try
    {
        repo_.fetch(origin);
    }
    catch (std::runtime_error error)
    {
        IDA_LOG_WARNING("Couldn't fetch remote, error: %s", error.what());
    }
}

bool RepoManager::rebase(const std::string& upstream, const std::string& destination)
{
    IDAInteractiveFileConflictResolver resolver;
    try
    {
        repo_.rebase(upstream, destination, resolver);
    }
    catch (std::runtime_error error)
    {
        IDA_LOG_WARNING("Couldn't rebase %s from %s, error: %s", destination.c_str(), upstream.c_str(), error.what());
        return false;
    }
    return true;
}

void RepoManager::push_origin_master()
{
    const std::map<std::string, std::string> remotes{ repo_.get_remotes() };
    if (remotes.find(std::string("origin")) != remotes.end())
    {
        try
        {
            repo_.push("master", "master");
        }
        catch (std::runtime_error error)
        {
            IDA_LOG_WARNING("Couldn't push to remote origin, error: %s", error.what());
        }
    }
}

bool RepoManager::repo_auto_sync_enabled()
{
    return repo_auto_sync_;
}

void RepoManager::ask_for_remote()
{
    qstring tmp{ "ssh://gitolite@repo/" };
    if (!ask_str(&tmp, 0, "Specify a remote origin :"))
        return;

    std::string url{ tmp.c_str() };
    try
    {
        repo_.create_remote("origin", url);
    }
    catch (const std::runtime_error& _error)
    {
        IDA_LOG_GUI_ERROR("An error occured during remote creation, error: %s", _error.what());
        return;
    }

    if (std::regex_match(url, std::regex("^ssh://.*"))) // add http/https to regex ? ("^((ssh)|(https?))://.*")
        return;

    fs::path path{ url };
    if (fs::exists(path))
        return;

    if (ask_yn(true, "The target directory doesn't exist, do you want to create it ?") != ASKBTN_YES)
        return;

    if (!fs::create_directories(path))
    {
        IDA_LOG_GUI_WARNING("Directory %s creation failed.", url.c_str());
        return;
    }
    
    GitRepo tmp_repo{ url };
    try
    {
        tmp_repo.init_bare();
    }
    catch (std::runtime_error error)
    {
        IDA_LOG_GUI_WARNING("Couldn't init remote repo, error: %s", error.what());
    }
}

std::shared_ptr<IRepoManager> MakeRepoManager(bool ida_is_interactive)
{
    return std::make_shared<RepoManager>(ida_is_interactive);
}

std::string ea_to_hex(ea_t ea)
{
    char buffer[19]; // size for 0x%016X + \0
    std::snprintf(buffer, COUNT_OF(buffer), "0x" EA_FMT, ea);
    return std::string{ buffer };
}

std::string get_current_idb_path()
{
    return fs::path{ get_path(PATH_TYPE_IDB) }.generic_string();
}

std::string get_original_idb_path()
{
    std::string original_idb_path{ get_current_idb_path() };
    remove_filename_suffix(original_idb_path, "_local");
    return original_idb_path;
}

std::string get_current_idb_name()
{
    return fs::path{ get_current_idb_path() }.filename().string();
}

std::string get_original_idb_name()
{
    std::string original_idb_name{ get_current_idb_name() };
    remove_filename_suffix(original_idb_name, "_local");
    return original_idb_name;
}

bool backup_file(const std::string& file_path)
{
    std::time_t now{ std::time(nullptr) };
    std::string date{ std::ctime(&now) };
    date = date.substr(0, date.size() - 1); //remove final \n from ctime
    std::replace(date.begin(), date.end(), ' ', '_');
    std::replace(date.begin(), date.end(), ':', '_');
    std::string suffix{ "_bkp_" + date };
    std::string backup_file_path{ file_path };
    add_filename_suffix(backup_file_path, suffix);

    std::error_code ec;
    fs::copy_file(file_path, backup_file_path, ec);
    if (ec)
    {
        IDA_LOG_WARNING("Couldn't create backup for %s, error: %s", file_path.c_str(), ec.message().c_str());
        return false;
    }

    IDA_LOG_INFO("Created backup %s", backup_file_path.c_str());
    return true;
}

bool backup_current_idb()
{
    IDA_LOG_INFO("Backup of current IDB");
    return backup_file(get_current_idb_path());
}

bool backup_original_idb()
{
    IDA_LOG_INFO("Backup of original IDB");
    return backup_file(get_original_idb_path());
}

void remove_ida_temporary_files(const std::string& idb_path)
{
    std::string idb_no_ext{ idb_path };
    remove_substring(idb_no_ext, fs::path{ idb_path }.extension().string());

    std::error_code ec;
    const char* extensions_to_delete[] = { ".id0", ".id1", ".id2", ".nam", ".til" };
    for (const char* ext : extensions_to_delete)
        fs::remove(fs::path{ idb_no_ext + ext }, ec);
}

bool copy_original_idb_to_current_file()
{
    std::string current_idb_path{ get_current_idb_path() };
    std::string original_idb_path{ get_original_idb_path() };
    std::error_code ec;
    fs::copy_file(original_idb_path, current_idb_path, fs::copy_options::overwrite_existing, ec);
    if (ec)
    {
        LOG(WARNING, "Couldn't copy original idb to current idb, error: %s", ec.message().c_str());
        return false;
    }
    remove_ida_temporary_files(current_idb_path);
    IDA_LOG_INFO("Copied original IDB to current IDB");
    return true;
}

bool copy_current_idb_to_original_file()
{
    std::string current_idb_path{ get_current_idb_path() };
    std::string original_idb_path{ get_original_idb_path() };
    std::error_code ec;
    fs::copy_file(current_idb_path, original_idb_path, fs::copy_options::overwrite_existing, ec);
    if (ec)
    {
        LOG(WARNING, "Couldn't copy current idb to original idb, error: %s", ec.message().c_str());
        return false;
    }
    remove_ida_temporary_files(current_idb_path);
    IDA_LOG_INFO("Copied current IDB to original IDB");
    return true;
}


// temporary helper until hooks are moved to native
void yaco_update_helper(const std::shared_ptr<IRepoManager>& repo_manager, ModelAndVisitor& memory_exporter)
{
    std::vector<std::string> modified_files = repo_manager->update_cache();
    MakeXmlFilesDatabaseModel(modified_files)->accept(*(memory_exporter.visitor.get()));
}
