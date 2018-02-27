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

#include "Ida.h"
#include "Repository.hpp"

#include "IModelAccept.hpp"
#include "Logger.h"
#include "Merger.hpp"
#include "ResolveFileConflictCallback.hpp"
#include "YaGitLib.hpp"
#include "Yatools.h"
#include "Utils.hpp"

#define MODULE_NAME "repo"
#include "IdaUtils.hpp"

#include <ctime>
#include <libxml/xmlreader.h>
#include <memory>
#include <regex>
#include <sstream>

#ifdef _MSC_VER
#   include <filesystem>
#else
#   include <experimental/filesystem>
#endif

namespace fs = std::experimental::filesystem;

namespace
{
    const size_t TRUNCATE_COMMIT_MSG_LENGTH = 4000;
    const int    GIT_PUSH_RETRIES = 3;


    bool is_git_working_dir(const std::string& path)
    {
        std::error_code ec;
        return fs::is_directory(path + "/.git", ec) && !ec;
    }

    bool is_valid_xml_file(const std::string& filename)
    {
        std::shared_ptr<xmlTextReader> reader(xmlReaderForFile(filename.c_str(), NULL, 0), &xmlFreeTextReader);
        int ret = 1;
        while (ret == 1)
            ret = xmlTextReaderRead(reader.get());
        return ret != -1;
    }

    void add_filename_suffix(std::string& file_path, const std::string& suffix)
    {
        const std::string file_extension = fs::path(file_path).extension().string();
        remove_substring(file_path, file_extension);
        file_path += suffix;
        file_path += file_extension;
    }

    bool remove_filename_suffix(std::string& file_path, const std::string& suffix)
    {
        // only remove the suffix from the filename even if it appear in the extention
        const std::string file_extension = fs::path(file_path).extension().string();
        remove_substring(file_path, file_extension);
        const bool removed = remove_substring(file_path, suffix);
        file_path += file_extension;
        return removed;
    }

    std::string get_current_idb_path()
    {
        return fs::path(get_path(PATH_TYPE_IDB)).generic_string();
    }

    std::string get_original_idb_path()
    {
        std::string original_idb_path = get_current_idb_path();
        remove_filename_suffix(original_idb_path, "_local");
        return original_idb_path;
    }

    std::string get_current_idb_name()
    {
        return fs::path(get_current_idb_path()).filename().string();
    }

    std::string get_original_idb_name()
    {
        std::string original_idb_name = get_current_idb_name();
        remove_filename_suffix(original_idb_name, "_local");
        return original_idb_name;
    }

    bool backup_file(const std::string& file_path)
    {
        const std::time_t now = std::time(nullptr);
        std::string date = std::ctime(&now);
        date = date.substr(0, date.size() - 1); //remove final \n from ctime
        std::replace(date.begin(), date.end(), ' ', '_');
        std::replace(date.begin(), date.end(), ':', '_');
        const std::string suffix = "_bkp_" + date;
        std::string backup_file_path = file_path;
        add_filename_suffix(backup_file_path, suffix);

        std::error_code ec;
        fs::copy_file(file_path, backup_file_path, ec);
        if (ec)
        {
            IDA_LOG_WARNING("Failed to create backup for %s, error: %s", file_path.c_str(), ec.message().c_str());
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
        std::string idb_no_ext = idb_path;
        remove_substring(idb_no_ext, fs::path(idb_path).extension().string());

        std::error_code ec;
        const char extensions_to_delete[][6] = { ".id0", ".id1", ".id2", ".nam", ".til" };
        for (const char* ext : extensions_to_delete)
            fs::remove(fs::path(idb_no_ext + ext), ec);
    }

    bool copy_original_idb_to_current_file()
    {
        const std::string current_idb_path = get_current_idb_path();
        const std::string original_idb_path = get_original_idb_path();
        std::error_code ec;
        fs::copy_file(original_idb_path, current_idb_path, fs::copy_options::overwrite_existing, ec);
        if (ec)
        {
            IDA_LOG_GUI_WARNING("Failed to copy original idb to current idb, error: %s", ec.message().c_str());
            return false;
        }

        remove_ida_temporary_files(current_idb_path);
        IDA_LOG_INFO("Copied original IDB to current IDB");
        return true;
    }

    bool copy_current_idb_to_original_file()
    {
        const std::string current_idb_path = get_current_idb_path();
        const std::string original_idb_path = get_original_idb_path();
        std::error_code ec;
        fs::copy_file(current_idb_path, original_idb_path, fs::copy_options::overwrite_existing, ec);
        if (ec)
        {
            IDA_LOG_GUI_WARNING("Failed to copy current idb to original idb, error: %s", ec.message().c_str());
            return false;
        }

        remove_ida_temporary_files(current_idb_path);
        IDA_LOG_INFO("Copied current IDB to original IDB");
        return true;
    }
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
    if (!ask_text(
        &buffer,
        0,
        input_attribute1,
        "%s\nValue from local : %s\nValue from remote : %s\n",
        message_info,
        input_attribute1,
        input_attribute2
    ))
        return std::string(input_attribute1);
    return std::string(buffer.c_str());
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
    if (!std::regex_match(output_file_result, std::regex(".*\\.xml$")))
        return true;

    IDAPromptMergeConflict merger_conflict;
    Merger merger(&merger_conflict, ObjectVersionMergeStrategy_e::OBJECT_VERSION_MERGE_PROMPT);
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
    struct Repository
        : public IRepository
    {
        Repository(const std::string& path);

        // IRepository
        void add_comment(const std::string& msg) override;
        void check_valid_cache_startup() override; // can stop IDA
        std::string update_cache() override;
        bool commit_cache() override;
        void toggle_repo_auto_sync() override;
        void sync_and_push_original_idb() override;
        void discard_and_pull_idb() override;
        void diff_index(const std::string& from, const on_blob_fn& on_blob) const override;

        // Retrieve informations with IDA GUI
        void ask_to_checkout_modified_files();
        void ask_for_remote();
        bool ask_and_set_git_config_entry(const std::string& config_string, const std::string& default_value);
        bool ensure_git_globals();

        // GitRepo wrappers
        bool init();
        bool fetch(const std::string& remote);
        bool rebase(const std::string& origin, const std::string& branch);
        bool add_file_to_index(const std::string& path);
        bool remove_file_for_index(const std::string& path); // the file may exist, it is removed for the index but unchanged on the disk
        bool commit(const std::string& message);
        bool push(const std::string& src_branch, const std::string& dst_branch);
        bool remote_exist(const std::string& remote);
        std::string get_commit(const std::string& ref);

        GitRepo repo_;
        std::vector<std::string> comments_;
        bool repo_auto_sync_;
    };
}

Repository::Repository(const std::string& path)
    : repo_(path)
    , repo_auto_sync_(true)
{
    const bool repo_already_exists = is_git_working_dir(path);

    init();
    if (!ensure_git_globals())
        IDA_LOG_ERROR("Unable to ensure git globals");

    if (repo_already_exists)
    {
        LOG(DEBUG, "Repo opened");
        return;
    }
    IDA_LOG_INFO("Repo created");

    // add current IDB to repo, and create an initial commit
    if (add_file_to_index(get_current_idb_name()) && commit("Initial commit"))
        IDA_LOG_INFO("IDB Committed");
    else
        IDA_LOG_ERROR("Unable to commit IDB");

    ask_for_remote();

    if (!push("master", "master"))
        IDA_LOG_ERROR("Unable to push");
}

void Repository::add_comment(const std::string& msg)
{
    comments_.emplace_back(msg);
}

void Repository::check_valid_cache_startup()
{
    LOG(DEBUG, "Validating cache...");

    if (!remote_exist("origin"))
    {
        IDA_LOG_INFO("origin remote not defined: ignoring origin and master sync check");
    }
    else
    {
        const std::string master_commit = get_commit("master");
        const std::string origin_master_commit = get_commit("origin/master");
        if (master_commit.empty() || origin_master_commit.empty() || master_commit != origin_master_commit)
            IDA_LOG_WARNING("Master and origin/master does not point to same commit, please update your master");
    }

    std::error_code ec;
    fs::create_directory("cache", ec);
    if (ec)
        IDA_LOG_WARNING("Cache directory creation failed, error: %s", ec.message().c_str());

    const fs::path current_idb_path = get_current_idb_path();
    const std::string idb_extension = current_idb_path.extension().string();
    std::string idb_prefix = get_current_idb_path();
    remove_substring(idb_prefix, idb_extension);

    if (std::regex_match(idb_prefix, std::regex(".*_local$")))
    {
        LOG(DEBUG, "Cache validated");
        return;
    }

    IDA_LOG_INFO("Current IDB filename is missing _local suffix");
    const std::string local_idb_path = idb_prefix + "_local" + idb_extension;
    bool local_idb_exist = fs::exists(local_idb_path, ec);
    if (!local_idb_exist)
    {
        IDA_LOG_INFO("Creating required local idb");
        fs::copy_file(current_idb_path, local_idb_path, ec);
        if (ec)
        {
            IDA_LOG_ERROR("Unable to create local idb file, error: %s", ec.message().c_str());
            return;
        }
    }

    IDA_LOG_INFO("IDA need to restart with local IDB");
    std::string msg = "To use YaCo you must name your IDB with _local suffix. YaCo will create one for you.\nRestart IDA and open ";
    msg += fs::path(local_idb_path).filename().generic_string();
    msg += '.';
    set_database_flag(DBFL_KILL);
    warning("%s", msg.c_str());
    qexit(0);
}

std::string Repository::update_cache()
{
    std::string commit;
    if (!remote_exist("origin"))
        return commit;

    // check if files has been modified in background
    ask_to_checkout_modified_files();

    if (!repo_auto_sync_)
    {
        IDA_LOG_INFO("Repo auto sync disabled, ignoring cache update");
        return commit;
    }

    LOG(DEBUG, "Updating cache...");
    // get master commit
    commit = get_commit("master");
    if (commit.empty())
    {
        IDA_LOG_INFO("Unable to update cache");
        return commit;
    }
    LOG(DEBUG, "Current master: %s", commit.c_str());

    // fetch remote
    fetch("origin");
    LOG(DEBUG, "Fetched origin/master: %s", get_commit("origin/master").c_str());

    // rebase in master
    LOG(DEBUG, "Rebasing master on origin/master...");
    if (!rebase("origin/master", "master"))
    {
        IDA_LOG_INFO("Unable to update cache");
        // disable auto sync (when closing database)
        warning("You have errors during rebase. You have to resolve it manually.\nSee git_rebase.log for details.\nThen run save on IDA to complete rebase and update master");
        return commit;
    }

    LOG(DEBUG, "Master rebased");

    // push to origin
    for (int nb_try = 0; nb_try < GIT_PUSH_RETRIES; ++nb_try)
    {
        LOG(DEBUG, "Pushing master to origin...");
        if (!push("master", "master"))
            continue;

        LOG(DEBUG, "Master pushed to origin");
        LOG(DEBUG, "Cache updated");
        return commit;
    }

    IDA_LOG_WARNING("Errors occured during push to origin, they need to be resolved manually.");
    repo_auto_sync_ = false;
    IDA_LOG_INFO("Auto rebase/push disabled");

    warning("You have errors during push to origin. You have to resolve it manually.");
    return commit;
}

bool Repository::commit_cache()
{
    LOG(DEBUG, "Committing changes...");

    const std::set<std::string> untracked_files = repo_.get_untracked_objects_in_path("cache/");
    const std::set<std::string> modified_files = repo_.get_modified_objects_in_path("cache/");
    const std::set<std::string> deleted_files = repo_.get_deleted_objects_in_path("cache/");

    if (untracked_files.empty() && modified_files.empty() && deleted_files.empty())
    {
        LOG(DEBUG, "No changes to commit");
        return true;
    }

    for(const auto& f : untracked_files)
        if(!add_file_to_index(f))
            IDA_LOG_ERROR("unable to add %s to index", f.c_str());
    for(const auto& f : modified_files)
        if(!add_file_to_index(f))
            IDA_LOG_ERROR("unable to add %s to index", f.c_str());
    for(const auto& f : deleted_files)
        if(!remove_file_for_index(f))
            IDA_LOG_ERROR("unable to remove %s for index", f.c_str());
    IDA_LOG_INFO("commit: %zd added %zd updated %zd deleted", untracked_files.size(), modified_files.size(), deleted_files.size());

    // sort & dedup
    std::sort(comments_.begin(), comments_.end());
    comments_.erase(std::unique(comments_.begin(), comments_.end()), comments_.end());

    std::string commit_msg;
    for(const auto& it : comments_)
    {
        commit_msg.append(it);
        commit_msg.append("\n");
    }
    comments_.clear();

    if(commit_msg.size() > TRUNCATE_COMMIT_MSG_LENGTH)
    {
        commit_msg.erase(TRUNCATE_COMMIT_MSG_LENGTH);
        commit_msg += "\n...truncated";
    }
    if(commit_msg.empty())
        commit_msg = "unknown changes";

    if (!commit(commit_msg))
    {
        IDA_LOG_ERROR("Unable to commit");
        return false;
    }

    LOG(DEBUG, "Changes committed");
    return true;
}

void Repository::toggle_repo_auto_sync()
{
    repo_auto_sync_ = !repo_auto_sync_;
    if (repo_auto_sync_)
        IDA_LOG_INFO("Auto rebase/push enabled");
    else
        IDA_LOG_INFO("Auto rebase/push disabled");
}

void Repository::sync_and_push_original_idb()
{
    backup_original_idb();

    // sync original idb to current idb
    if (!copy_current_idb_to_original_file())
    {
        IDA_LOG_ERROR("Unable to sync original idb to current idb");
        return;
    }

    // remove xml cache files
    for (const fs::directory_entry& file_path : fs::recursive_directory_iterator("cache"))
    {
        std::error_code ec;
        const bool is_regular_file = fs::is_regular_file(file_path.path(), ec);
        if (!is_regular_file)
            continue;

        // git remove xml
        if (!remove_file_for_index(file_path.path().generic_string()))
        {
            IDA_LOG_ERROR("Unable to remove %s for index", file_path.path().generic_string().c_str());
            return;
        }

        // filesystem remove xml
        fs::remove(file_path.path(), ec);
        if (ec)
            IDA_LOG_ERROR("Unable to remove %s from filesystem, error: %s", file_path.path().generic_string().c_str(), ec.message().c_str());
    }

    // git add original idb file
    if (!add_file_to_index(get_original_idb_name()))
    {
        IDA_LOG_ERROR("Unable to add original idb file to index");
        return;
    }

    // git commit
    if (!commit("YaCo force push"))
    {
        IDA_LOG_ERROR("Unable to commit");
        return;
    }

    if (!remote_exist("origin"))
        return;

    // git push
    if (!push("master", "master"))
        IDA_LOG_ERROR("Unable to push");
}

void Repository::discard_and_pull_idb()
{
    backup_current_idb();
    backup_original_idb();

    // delete all modified objects
    repo_.checkout_head();

    // get synced original idb
    if (!fetch("origin"))
    {
        IDA_LOG_ERROR("Unable to fetch origin");
        return;
    }
    if (!rebase("origin/master", "master"))
    {
        IDA_LOG_ERROR("Unable to rebase master from origin/master");
        return;
    }

    // sync current idb to original idb
    if (!copy_original_idb_to_current_file())
        IDA_LOG_ERROR("Unable to sync current idb to original idb");
}

void Repository::ask_to_checkout_modified_files()
{
    std::string modified_objects;
    bool idb_modified = false;

    const std::string original_idb_name = get_original_idb_name();
    for (const std::string& modified_object : repo_.get_modified_objects())
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
    if (ask_yn(true, "%s", modified_objects.c_str()) != ASKBTN_NO)
    {
        repo_.checkout_head();
        return;
    }

    repo_auto_sync_ = false;
}

void Repository::ask_for_remote()
{
    qstring tmp = "ssh://username@repository_path/";
    if (!ask_str(&tmp, 0, "Specify a remote origin :"))
        return;

    const std::string url = tmp.c_str();
    try
    {
        repo_.create_remote("origin", url);
    }
    catch (const std::runtime_error& err)
    {
        IDA_LOG_GUI_ERROR("An error occured during remote creation, error: %s", err.what());
        return;
    }

    // FIXME add http/https to regex ? ("^((ssh)|(https?))://.*")
    if (std::regex_match(url, std::regex("^ssh://.*")))
        return;

    const fs::path path = url;
    if (fs::exists(path))
        return;

    if (ask_yn(true, "The target directory doesn't exist, do you want to create it ?") != ASKBTN_YES)
        return;

    if (!fs::create_directories(path))
    {
        IDA_LOG_GUI_WARNING("Directory %s creation failed.", url.c_str());
        return;
    }

    GitRepo tmp_repo(url);
    try
    {
        tmp_repo.init_bare();
    }
    catch (const std::runtime_error& _error)
    {
        IDA_LOG_GUI_ERROR("Unable to init remote repo, error: %s", _error.what());
    }
}

bool Repository::ask_and_set_git_config_entry(const std::string& config_entry, const std::string& default_value)
{
    std::string current_value;
    try
    {
        current_value = repo_.config_get_string(config_entry);
    }
    catch (const std::runtime_error& error)
    {
        IDA_LOG_WARNING("Failed get git %s, error: %s", config_entry.c_str(), error.what());
        return false;
    }

    if (!current_value.empty())
        return true;

    qstring value;
    do
        value = default_value.c_str();
    while (!ask_str(&value, 0, "Enter git %s", config_entry.c_str()) || value.empty());

    try
    {
        repo_.config_set_string(config_entry, value.c_str());
    }
    catch (const std::runtime_error& error)
    {
        IDA_LOG_WARNING("Failed to set git %s, error: %s", config_entry.c_str(), error.what());
        return false;
    }
    return true;
}

bool Repository::ensure_git_globals()
{
    if (!ask_and_set_git_config_entry("user.name", "username"))
    {
        IDA_LOG_GUI_WARNING("Problem during git user.name configuration");
        return false;
    }

    if (!ask_and_set_git_config_entry("user.email", "username@localdomain"))
    {
        IDA_LOG_GUI_WARNING("Problem during git user.email configuration");
        return false;
    }

    return true;
}

bool Repository::init()
{
    try
    {
        repo_.init();
    }
    catch (const std::runtime_error& error)
    {
        IDA_LOG_WARNING("Failed to init repository, error: %s", error.what());
        return false;
    }
    return true;
}

bool Repository::fetch(const std::string& remote)
{
    try
    {
        repo_.fetch(remote);
    }
    catch (const std::runtime_error& error)
    {
        IDA_LOG_WARNING("Failed to fetch %s, error: %s", remote.c_str(), error.what());
        return false;
    }
    return true;
}

bool Repository::rebase(const std::string& upstream, const std::string& destination)
{
    try
    {
        IDAInteractiveFileConflictResolver resolver;
        repo_.rebase(upstream, destination, resolver);
        return true;
    }
    catch (const std::runtime_error& error)
    {
        IDA_LOG_WARNING("Failed to rebase %s from %s, error: %s", destination.c_str(), upstream.c_str(), error.what());
        return false;
    }
}

bool Repository::add_file_to_index(const std::string& path)
{
    try
    {
        repo_.add_file(path);
    }
    catch (const std::runtime_error& error)
    {
        IDA_LOG_WARNING("Failed to add %s to index, error: %s", path.c_str(), error.what());
        return false;
    }
    return true;
}

bool Repository::remove_file_for_index(const std::string& path)
{
    try
    {
        repo_.remove_file(path);
    }
    catch (const std::runtime_error& error)
    {
        IDA_LOG_WARNING("Failed to remove %s for index, error: %s", path.c_str(), error.what());
        return false;
    }
    return true;
}

bool Repository::commit(const std::string& message)
{
    try
    {
        repo_.commit(message);
    }
    catch (const std::runtime_error& error)
    {
        IDA_LOG_WARNING("Failed to commit, error: %s", error.what());
        return false;
    }
    return true;
}

bool Repository::push(const std::string& src_branch, const std::string& dst_branch)
{
    if (!remote_exist("origin"))
        return true;

    try
    {
        repo_.push(src_branch, dst_branch);
    }
    catch (const std::runtime_error& error)
    {
        IDA_LOG_WARNING("Failed to push to remote, error: %s", error.what());
        return false;
    }
    return true;
}

bool Repository::remote_exist(const std::string& remote)
{
    std::map<std::string, std::string> remotes;
    try
    {
        remotes = repo_.get_remotes();
    }
    catch (const std::runtime_error& error)
    {
        IDA_LOG_WARNING("Failed to get repo remotes, error: %s", error.what());
        return false;
    }
    return remotes.find(remote) != remotes.end();
}

std::string Repository::get_commit(const std::string& ref)
{
    std::string commit;
    try
    {
        commit = repo_.get_commit(ref);
    }
    catch (const std::runtime_error& error)
    {
        IDA_LOG_WARNING("Failed to get commit from master, error: %s", error.what());
    }
    return commit;
}

void Repository::diff_index(const std::string& from, const on_blob_fn& on_blob) const
{
    return repo_.diff_index(from, on_blob);
}

std::shared_ptr<IRepository> MakeRepository(const std::string& path)
{
    return std::make_shared<Repository>(path);
}
