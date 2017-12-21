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
#include "YaCo.hpp"

#include "YaToolsHashProvider.hpp"
#include "Repository.hpp"
#include "Hooks.hpp"
#include "IDANativeExporter.hpp"
#include "XML/XMLDatabaseModel.hpp"
#include "FlatBufferExporter.hpp"
#include "IDANativeModel.hpp"
#include "Utils.hpp"
#include "Yatools_swig.h"

#include "git_version.h"

#define MODULE_NAME "yaco"
#include "IDAUtils.hpp"

#include <chrono>

#ifdef _MSC_VER
#   include <filesystem>
#else
#   include <experimental/filesystem>
#endif

namespace fs = std::experimental::filesystem;

namespace
{
    fs::path get_current_idb_path()
    {
        return fs::path(get_path(PATH_TYPE_IDB));
    }

    void remove_file_extention(fs::path& file_path)
    {
        std::string filename = file_path.filename().string();
        const std::string extension = file_path.extension().string();
        remove_substring(filename, extension);
        file_path.replace_filename(filename);
    }

    struct YaCo;

    template<typename T>
    struct ahandler_t : public action_handler_t
    {
        ahandler_t(YaCo* yaco_, T func_)
            : yaco(yaco_)
            , func(func_)
        {
        }

        int idaapi activate(action_activation_ctx_t *ctx)
        {
            UNUSED(ctx);
            func(yaco);
            return 1; // not 0: graphical refresh
        }

        action_state_t idaapi update(action_update_ctx_t *ctx)
        {
            UNUSED(ctx);
            return action_state_t::AST_ENABLE_FOR_IDB;
        }

        YaCo* yaco;
        T func;
    };

    template<typename T>
    std::shared_ptr<action_handler_t> to_handler(YaCo* yaco, T func)
    {
        return std::make_shared<ahandler_t<T>>(yaco, func);
    }

    struct YaCo
        : public IYaCo
    {
        YaCo(IDAIsInteractive ida_is_interactive);

        // IYaCo
        void start() override;
        void save_and_update() override;
        void export_single_cache() override;
        void stop() override;

        // internal
        void initial_load();
        void toggle_auto_rebase_push();
        void create_reset();
        void retrieve_reset();

        // Variables
        std::shared_ptr<IHashProvider>   hash_provider_;
        std::shared_ptr<IRepository>     repository_;
        std::shared_ptr<IHooks>          hooks_;

        const std::shared_ptr<action_handler_t> toggle_auto_rebase_push_handler;
        const std::shared_ptr<action_handler_t> create_reset_handler;
        const std::shared_ptr<action_handler_t> retrieve_reset_handler;
        const std::shared_ptr<action_handler_t> export_single_cache_handler;

        const action_desc_t action_descs_[4];
    };

    #define YACO_EXT_FUNC(name) void CONCAT(ext_, name)(YaCo* yaco) { yaco->name(); }
    YACO_EXT_FUNC(toggle_auto_rebase_push);
    YACO_EXT_FUNC(create_reset);
    YACO_EXT_FUNC(retrieve_reset);
    YACO_EXT_FUNC(export_single_cache);
}

#define YACO_ACTION_DESC(name, label, handler) ACTION_DESC_LITERAL_OWNER(name, label, handler, nullptr, nullptr, nullptr, -1)
YaCo::YaCo(IDAIsInteractive ida_is_interactive)
    : hash_provider_(MakeHashProvider())
    , repository_(MakeRepository(".", ida_is_interactive))
    , hooks_(MakeHooks(*this, hash_provider_, repository_))
    , toggle_auto_rebase_push_handler(to_handler(this, &ext_toggle_auto_rebase_push))
    , create_reset_handler           (to_handler(this, &ext_create_reset))
    , retrieve_reset_handler         (to_handler(this, &ext_retrieve_reset))
    , export_single_cache_handler    (to_handler(this, &ext_export_single_cache))
    , action_descs_{
        YACO_ACTION_DESC("yaco_toggle_rebase_push",   "YaCo - Toggle YaCo auto rebase/push",   toggle_auto_rebase_push_handler.get()),
        YACO_ACTION_DESC("yaco_create_reset",         "YaCo - Resync idb & force push",        create_reset_handler.get()),
        YACO_ACTION_DESC("yaco_retrieve_reset",       "YaCo - Discard idb & force pull",       retrieve_reset_handler.get()),
        YACO_ACTION_DESC("yaco_export_single_file",   "YaCo - Export database",                export_single_cache_handler.get()),
    }
{
}

void YaCo::start()
{
    fs::path idb_path = get_current_idb_path();
    remove_file_extention(idb_path);
    StartYatools(idb_path.generic_string().c_str());

    IDA_LOG_INFO("YaCo %s", GitVersion);

    repository_->check_valid_cache_startup();

    // hooks not hooked yet
    initial_load();
    auto_wait();

    hooks_->hook();

    setflag(inf.s_genflags, INFFL_AUTO, false);

    for (const action_desc_t &action_desc : action_descs_)
    {
        register_action(action_desc);
        attach_action_to_menu("Edit/Yatools/", action_desc.name, SETMENU_APP);
    }
}

void YaCo::save_and_update()
{
    hooks_->save_and_update();
}

void YaCo::export_single_cache()
{
    IDA_LOG_INFO("Exporting database using one core");

    std::error_code ec;
    fs::create_directory("database", ec); //no error if directory already exist
    if (ec)
    {
        IDA_LOG_ERROR("Unable to create database directory");
        return;
    }

    std::shared_ptr<IFlatExporter> exporter = MakeFlatBufferExporter();
    MakeModel(hash_provider_.get())->accept(*exporter);
    ExportedBuffer buffer = exporter->GetBuffer();

    FILE* database = fopen("database/database.yadb", "wb");
    fwrite(buffer.value, 1, buffer.size, database);
    fclose(database);

    IDA_LOG_INFO("Export complete");
}

void YaCo::stop()
{
    hooks_->unhook();
    StopYatools();

    for (const action_desc_t &action_desc : action_descs_)
    {
        detach_action_from_menu("Edit/Yatools/", action_desc.name);
        unregister_action(action_desc.name);
    }
}

void YaCo::initial_load()
{
    const auto time_start = std::chrono::system_clock::now();
    IDA_LOG_INFO("Initial load started");

    export_to_ida(MakeXmlAllDatabaseModel("cache/").get(), hash_provider_.get());

    const auto time_end = std::chrono::system_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(time_end - time_start);
    IDA_LOG_INFO("Cache loaded in %d seconds", static_cast<int>(elapsed.count()));
}

void YaCo::toggle_auto_rebase_push()
{
    repository_->toggle_repo_auto_sync();
}

void YaCo::create_reset()
{
    const int answer = ask_buttons(
        "Yes", "No", "", ASKBTN_NO,
        "TITLE YaCo Force Push\n"
        "ICON QUESTION\n"
        "AUTOHIDE SESSION\n"
        "HIDECANCEL\n"
        "You are going to force push your IDB. Other YaCo users will need to stop working & force pull.\n"
        "Do you really want to force push?"
    );
    if (answer != ASKBTN_YES)
        return;

    hooks_->unhook();
    repository_->sync_and_push_original_idb();

    warning("Force push complete, you can restart IDA and other YaCo users can \"Force pull\"");
    qexit(0);
}

void YaCo::retrieve_reset()
{
    const int answer = ask_yn(
        ASKBTN_NO,
        "All your local changes will be lost!\n"
        "Do you really want to proceed ?"
    );
    if (answer != ASKBTN_YES)
        return;

    hooks_->unhook();
    repository_->discard_and_pull_idb();

    set_database_flag(DBFL_KILL);
    warning("Force pull complete, you can restart IDA");
    qexit(0);
}


std::shared_ptr<IYaCo> MakeYaCo(IDAIsInteractive ida_is_interactive)
{
    return std::make_shared<YaCo>(ida_is_interactive);
}
