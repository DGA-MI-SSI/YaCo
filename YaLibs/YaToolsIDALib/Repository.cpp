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

#define USE_STANDARD_FILE_FUNCTIONS
#include "Ida.h"
#include "Repository.hpp"

#include "Merger.hpp"
#include "Git.hpp"
#include "Yatools.hpp"
#include "Utils.hpp"
#include "Helpers.h"
#include "git_version.h"
#include "YaHelpers.hpp"

#include <libxml/xmlreader.h>
#include <regex>
#include <fstream>

#ifdef _MSC_VER
#   include <filesystem>
#else
#   include <experimental/filesystem>
#endif

#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("repo", (FMT), ## __VA_ARGS__)

namespace fs = std::experimental::filesystem;

namespace
{
    const size_t        TRUNCATE_COMMIT_MSG_LENGTH = 1000;
    const std::string   default_remote_name = "origin";


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
            LOG(WARNING, "Failed to create backup for %s, error: %s\n", file_path.c_str(), ec.message().c_str());
            return false;
        }

        LOG(INFO, "Created backup %s\n", backup_file_path.c_str());
        return true;
    }

    bool backup_current_idb()
    {
        LOG(INFO, "Backup of current IDB\n");
        return backup_file(get_current_idb_path());
    }

    bool backup_original_idb()
    {
        LOG(INFO, "Backup of original IDB\n");
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
            LOG(WARNING, "Failed to copy original idb to current idb, error: %s\n", ec.message().c_str());
            return false;
        }

        remove_ida_temporary_files(current_idb_path);
        LOG(INFO, "Copied original IDB to current IDB\n");
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
            LOG(WARNING, "Failed to copy current idb to original idb, error: %s\n", ec.message().c_str());
            return false;
        }

        remove_ida_temporary_files(current_idb_path);
        LOG(INFO, "Copied current IDB to original IDB\n");
        return true;
    }
}

namespace
{
    std::string merge_attributes_callback(const std::string& message, const std::string& local, const std::string& remote)
    {
        if(ya::is_testing_mode())
            return remote;

        qstring buffer;
        const auto defval = merge_strings(make_string_ref(local), "local", make_string_ref(remote), "remote");
        const auto ok = ask_text(&buffer, 0, defval.data(), "%s\n", message.data());
        if(!ok)
            return local;

        return buffer.c_str();
    }

    const auto r_xml_end = std::regex{".*\\.xml$"};

    bool IDAInteractiveFileConflictResolver(const std::string& local, const std::string& remote, const std::string& filename)
    {
        if(fs::path(filename) == "yaco.version")
        {
            std::fstream(filename, std::fstream::out) << ver::latest(local, remote);
            return true;
        }

        if(!std::regex_match(filename, r_xml_end))
            return true;

        Merger merger(ObjectVersionMergeStrategy_e::OBJECT_VERSION_MERGE_PROMPT, &merge_attributes_callback);
        const auto err = merger.merge_files(local, remote, filename);
        if (err == MergeStatus_e::OBJECT_MERGE_STATUS_NOT_UPDATED)
            warning("Auto merge failed, please edit manually %s then continue\n", filename.data());

        if (!is_valid_xml_file(filename))
        {
            LOG(ERROR, "Merger generated invalid xml file\n");
            return false;
        }

        return true;
    }

    struct Repository
        : public IRepository
    {
        Repository(const std::string& path);

        // IRepository
        std::string get_cache() override;
        void        add_comment(const std::string& msg) override;
        bool        check_valid_cache_startup() override; // can stop IDA
        std::string update_cache(IPatcher& patcher, const on_fixup_fn& on_fixup) override;
        bool        commit_cache() override;
        void        toggle_repo_auto_sync() override;
        void        sync_and_push_original_idb() override;
        void        discard_and_pull_idb() override;
        void        diff_index(const std::string& from, const on_blob_fn& on_blob) const override;
        bool        idb_is_tracked();
        void        push() override;
        void        touch() override;

        // Retrieve informations with IDA GUI
        void ask_to_checkout_modified_files();
        void ask_for_remote();
        bool ask_and_set_git_config_entry(const std::string& config_string, const std::string& default_value);
        bool ensure_git_globals();
        bool ask_for_idb_tracking();

        // wrappers
        bool has_remote(const std::string& remote);

        std::shared_ptr<IGit>   git_;
        std::set<std::string>   comments_;
        bool                    repo_auto_sync_;
        bool                    include_idb_;
        bool                    is_tracked_;
    };

    fs::path get_version_path()
    {
        return fs::path(get_current_idb_path()).replace_filename("yaco.version");
    }

    bool overwrite_version(IGit& git, const fs::path& path)
    {
        std::fstream(path, std::fstream::out) << GIT_VERSION() << std::endl;
        auto ok = git.add_file(path.filename().generic_string());
        if(!ok)
        {
            LOG(ERROR, "Unable to update %s", path.filename().generic_string().data());
            return false;
        }

        ok = git.commit("version: yaco " GIT_VERSION() "\n");
        if(!ok)
        {
            LOG(ERROR, "Unable to commit %s", path.filename().generic_string().data());
            return false;
        }

        return true;
    }

    bool check_git_version(IGit& git)
    {
        const auto path = get_version_path();
        std::string version;

        // read version from file
        std::fstream(path, std::fstream::in) >> version;
        const auto check = ver::check(version, GIT_VERSION());
        switch(check)
        {
            case ver::OK:
                return true;

            default:
            case ver::OLDER:
            case ver::INVALID:
                return overwrite_version(git, path);

            case ver::NEWER:
                return ask_yn(true,
                              "Git server version: %s\n"
                              "Your local version: %s\n"
                              "Your version is outdated, do you want to continue?",
                              version.data(), GIT_VERSION()) == ASKBTN_YES;

            case ver::INCOMPATIBLE:
                warning("Git server version: %s\n"
                        "Your local version: %s\n"
                        "Git server version is outdated & incompatible\n"
                        "Please reset your repository with your version first,\n"
                        "and update other users to this version\n",
                        version.data(), GIT_VERSION());
                return false;
        }
    }
}

Repository::Repository(const std::string& path)
    : repo_auto_sync_(true)
    , include_idb_(false)
    , is_tracked_(is_git_directory(path))
{
    git_ = MakeGitAsync(path);
    if(!git_)
        return;

    if (!ensure_git_globals())
        LOG(ERROR, "Unable to ensure git globals\n");

    if (is_tracked_)
    {
        const auto ok = check_git_version(*git_);
        if(!ok)
        {
            git_.reset();
            LOG(ERROR, "Repo ignored\n");
            return;
        }

        include_idb_ = git_->is_tracked(get_original_idb_name());
        LOG(INFO, "%s %s\n", include_idb_ ? "tracking" : "ignoring", get_original_idb_name().data());
        LOG(DEBUG, "Repo opened\n");
        return;
    }

    include_idb_ = ask_for_idb_tracking();
    LOG(INFO, "%s %s\n", include_idb_ ? "tracking" : "ignoring", get_original_idb_name().data());
    LOG(INFO, "Repo created\n");

    // add .gitignore to repo
    const auto gitignore = fs::path(get_current_idb_path()).replace_filename(".gitignore");
    {
        std::fstream f(gitignore, std::fstream::out);
        if (!include_idb_)
            f << get_current_idb_name();
        f << std::endl;
    }
    if (!git_->add_file(gitignore.filename().generic_string()))
        LOG(ERROR, "Unable to add .gitignore\n");

    // add version tag
    const auto version = get_version_path();
    std::fstream(version, std::fstream::out) << GIT_VERSION() << std::endl;
    if(!git_->add_file(version.filename().generic_string()))
        LOG(ERROR, "Unable to add yaco.version");

    // add current IDB to repo if tracking is enabled
    if (include_idb_)
        if (!git_->add_file(get_current_idb_name()))
            LOG(ERROR, "Unable to add IDB\n");

    if (!git_->commit("Initial commit\n"))
        LOG(ERROR, "Unable to commit IDB\n");

    ask_for_remote();
    push();
}

void Repository::add_comment(const std::string& msg)
{
    comments_.insert(msg);
}

bool Repository::check_valid_cache_startup()
{
    LOG(DEBUG, "Validating cache...\n");
    if(!git_)
        return false;

    if (has_remote(default_remote_name))
    {
        const std::string master_commit = git_->get_commit("master");
        const std::string origin_master_commit = git_->get_commit(default_remote_name + "/master");
        if (master_commit.empty() || origin_master_commit.empty() || master_commit != origin_master_commit)
            LOG(WARNING, "Master and %s/master does not point to same commit, please update your master\n", default_remote_name.data());
    }

    std::error_code ec;
    fs::create_directory(get_cache(), ec);
    if (ec)
        LOG(WARNING, "Cache directory creation failed, error: %s\n", ec.message().c_str());

    const fs::path current_idb_path = get_current_idb_path();
    const std::string idb_extension = current_idb_path.extension().string();
    std::string idb_prefix = get_current_idb_path();
    remove_substring(idb_prefix, idb_extension);

    if (std::regex_match(idb_prefix, std::regex(".*_local$")))
    {
        LOG(DEBUG, "Cache validated\n");
        return true;
    }

    LOG(INFO, "Current IDB filename is missing _local suffix\n");
    const std::string local_idb_path = idb_prefix + "_local" + idb_extension;
    bool local_idb_exist = fs::exists(local_idb_path, ec);
    if (!local_idb_exist)
    {
        if(!is_tracked_)
        {
            // local idb is not tracked yet
            LOG(INFO, "wait for auto-analysis\n");
            auto_wait();
            LOG(INFO, "save current database\n");
            save_database(current_idb_path.generic_string().data(), 0, nullptr, nullptr);
        }
        LOG(INFO, "Creating required local idb\n");
        fs::copy_file(current_idb_path, local_idb_path, ec);
        if (ec)
        {
            LOG(ERROR, "Unable to create local idb file, error: %s\n", ec.message().c_str());
            return false;
        }
    }

    LOG(INFO, "IDA need to restart with local IDB\n");
    std::string msg = "To use YaCo you must name your IDB with _local suffix. YaCo will create one for you.\nRestart IDA and open ";
    msg += fs::path(local_idb_path).filename().generic_string();
    msg += '.';
    set_database_flag(DBFL_KILL);
    warning("%s", msg.c_str());
    return false;
}

std::string Repository::update_cache(IPatcher& patcher, const on_fixup_fn& on_fixup)
{
    std::string commit;
    if (!has_remote(default_remote_name))
        return commit;

    // check if files has been modified in background
    ask_to_checkout_modified_files();

    if (!repo_auto_sync_)
    {
        LOG(INFO, "Repo auto sync disabled, ignoring cache update\n");
        return commit;
    }

    LOG(DEBUG, "Updating cache...\n");
    // get master commit
    commit = git_->get_commit("master");
    if (commit.empty())
    {
        LOG(INFO, "Unable to update cache\n");
        return commit;
    }
    LOG(DEBUG, "Current master: %s\n", commit.c_str());

    // fetch remote
    git_->fetch(default_remote_name);
    LOG(DEBUG, "Fetched %s/master: %s\n", default_remote_name.data(), git_->get_commit(default_remote_name + "/master").data());

    // rebase in master
    LOG(DEBUG, "Rebasing master on %s/master...\n", default_remote_name.data());
    if (!git_->rebase(default_remote_name + "/master", "master", patcher, on_fixup, &IDAInteractiveFileConflictResolver))
    {
        LOG(INFO, "Unable to update cache\n");
        // disable auto sync (when closing database)
        warning("You have errors during rebase. You have to resolve it manually.\n");
        return commit;
    }
    LOG(DEBUG, "Master rebased\n");

    const auto now = git_->get_commit("master");
    return commit != now ? commit : std::string();
}

bool Repository::commit_cache()
{
    LOG(DEBUG, "Committing changes...\n");

    std::set<std::string> untracked, modified, deleted;
    git_->status(get_cache() + "/", [&](const char* name, const IGit::Status& status)
    {
        if(status.untracked)
            untracked.insert(name);
        if(status.modified)
            modified.insert(name);
        if(status.deleted)
            deleted.insert(name);
    });
    if(untracked.empty() && modified.empty() && deleted.empty())
    {
        LOG(DEBUG, "No changes to commit\n");
        return true;
    }

    for(const auto name : untracked)
        if(!git_->add_file(name))
            LOG(ERROR, "unable to add %s to index\n", name.data());
    for(const auto name : modified)
        if(!git_->add_file(name))
            LOG(ERROR, "unable to add %s to index\n", name.data());
    for(const auto name : deleted)
        if(!git_->remove_file(name))
            LOG(ERROR, "unable to remove %s from index\n", name.data());
    LOG(INFO, "commit: %zd added %zd updated %zd deleted\n", untracked.size(), modified.size(), deleted.size());

    // add single line prefix because libgit2 like to use commit messages
    // in filenames during rebases & commit messages can be too long
    auto commit_msg = "cache: "
                    + std::to_string(untracked.size()) + " added "
                    + std::to_string(modified.size())  + " updated "
                    + std::to_string(deleted.size())   + " deleted\n\n";
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
    if (!git_->commit(commit_msg))
    {
        LOG(ERROR, "Unable to commit\n");
        return false;
    }

    LOG(DEBUG, "Changes committed\n");
    return true;
}

void Repository::toggle_repo_auto_sync()
{
    repo_auto_sync_ = !repo_auto_sync_;
    if (repo_auto_sync_)
        LOG(INFO, "Auto rebase/push enabled\n");
    else
        LOG(INFO, "Auto rebase/push disabled\n");
}

void Repository::sync_and_push_original_idb()
{
    backup_original_idb();

    // sync original idb to current idb
    if (!copy_current_idb_to_original_file())
    {
        LOG(ERROR, "Unable to sync original idb to current idb\n");
        return;
    }

    // remove xml cache files
    for (const auto& file_path : fs::recursive_directory_iterator(get_cache()))
    {
        std::error_code ec;
        const bool is_regular_file = fs::is_regular_file(file_path.path(), ec);
        if (!is_regular_file)
            continue;

        // git remove xml
        if (!git_->remove_file(file_path.path().generic_string()))
        {
            LOG(ERROR, "Unable to remove %s for index\n", file_path.path().generic_string().c_str());
            return;
        }

        // filesystem remove xml
        fs::remove(file_path.path(), ec);
        if (ec)
            LOG(ERROR, "Unable to remove %s from filesystem, error: %s\n", file_path.path().generic_string().c_str(), ec.message().c_str());
    }

    // git add original idb file
    if (include_idb_ && !git_->add_file(get_original_idb_name()))
    {
        LOG(ERROR, "Unable to add original idb file to index\n");
        return;
    }

    // git commit
    if (!git_->commit("YaCo force push"))
    {
        LOG(ERROR, "Unable to commit\n");
        return;
    }

    push();
}

void Repository::discard_and_pull_idb()
{
    backup_current_idb();
    backup_original_idb();

    // delete all modified objects
    git_->checkout_head();

    // get synced original idb
    if (!git_->fetch(default_remote_name))
    {
        LOG(ERROR, "Unable to fetch %s\n", default_remote_name.data());
        return;
    }

    EmptyPatcher patcher;
    const auto ok = git_->rebase(default_remote_name + "/master", "master", patcher, {}, &IDAInteractiveFileConflictResolver);
    if(!ok)
    {
        LOG(ERROR, "Unable to rebase master from %s/master\n", default_remote_name.data());
        return;
    }

    // sync current idb to original idb
    if (!copy_original_idb_to_current_file())
        LOG(ERROR, "Unable to sync current idb to original idb\n");
}

void Repository::ask_to_checkout_modified_files()
{
    std::string modified;
    bool idb_modified = false;

    const std::string original_idb_name = get_original_idb_name();
    git_->status("", [&](const char* path, const IGit::Status& status)
    {
        if(!status.modified)
            return;

        if(original_idb_name == path)
        {
            backup_original_idb();
            idb_modified = true;
            return;
        }

        modified += path;
        modified += "\n";
    });

    if (modified.empty())
    {
        if (idb_modified)
            git_->checkout_head(); // checkout silently
        return;
    }

    // modified_objects is now the message
    modified += "\nhas been modified, this is not normal, do you want to checkout these files ? (Rebasing will be disabled if you answer no)";
    if (ask_yn(true, "%s", modified.c_str()) != ASKBTN_NO)
    {
        git_->checkout_head();
        return;
    }

    repo_auto_sync_ = false;
}

bool Repository::ask_for_idb_tracking()
{
    return ask_yn(true, "Should the IDB be tracked?") == ASKBTN_YES;
}

void Repository::ask_for_remote()
{
    qstring tmp = "ssh://username@repository_path/";
    if (!ask_str(&tmp, 0, "Specify remote:"))
        return;

    const std::string url = tmp.c_str();
    const auto ok = git_->add_remote(default_remote_name, url);
    if(!ok)
        return;

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
        LOG(WARNING, "Directory %s creation failed\n", url.c_str());
        return;
    }

    const auto git = MakeGitBare(url);
    if(!git)
    {
        LOG(ERROR, "Unable to init remote repo\n");
    }
}

bool Repository::ask_and_set_git_config_entry(const std::string& config_entry, const std::string& default_value)
{
    const auto current_value = git_->config_get_string(config_entry);
    if(!current_value.empty())
        return true;

    qstring value;
    do
    {
        value = default_value.c_str();
    }
    while (!ask_str(&value, 0, "Enter git %s", config_entry.c_str()) || value.empty());

    return git_->config_set_string(config_entry, value.c_str());
}

bool Repository::ensure_git_globals()
{
    if (!ask_and_set_git_config_entry("user.name", "username"))
    {
        LOG(WARNING, "Problem during git user.name configuration\n");
        return false;
    }

    if (!ask_and_set_git_config_entry("user.email", "username@localdomain"))
    {
        LOG(WARNING, "Problem during git user.email configuration\n");
        return false;
    }

    return true;
}

bool Repository::has_remote(const std::string& remote)
{
    bool found = false;
    const auto ok = git_->remotes([&](const char* src, const char* /*dst*/)
    {
        found |= remote == src;
    });
    return ok && found;
}

void Repository::diff_index(const std::string& from, const on_blob_fn& on_blob) const
{
    git_->diff_index(from, on_blob);
}

bool Repository::idb_is_tracked()
{
    return include_idb_;
}

std::string Repository::get_cache()
{
    return "cache";
}

void Repository::push()
{
    if(!has_remote(default_remote_name))
        return;

    git_->push("master", default_remote_name, "master");
}

void Repository::touch()
{
    git_->flush();
}

std::shared_ptr<IRepository> MakeRepository(const std::string& path)
{
    return std::make_shared<Repository>(path);
}
