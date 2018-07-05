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

#include "Repository.hpp"
#include "Hooks.hpp"
#include "IdaVisitor.hpp"
#include "Events.hpp"
#include "XmlAccept.hpp"
#include "Helpers.h"
#include "FlatBufferVisitor.hpp"
#include "IdaModel.hpp"
#include "Utils.hpp"
#include "MemoryModel.hpp"
#include "IModelSink.hpp"
#include "Yatools.hpp"

#include "git_version.h"

#include <chrono>

#ifdef _MSC_VER
#   include <filesystem>
#else
#   include <experimental/filesystem>
#endif

namespace fs = std::experimental::filesystem;

#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("yaco", (FMT), ## __VA_ARGS__)

namespace
{
    fs::path get_current_idb_path()
    {
        return fs::path(get_path(PATH_TYPE_IDB));
    }

    void remove_file_extension(fs::path& file_path)
    {
        std::string filename = file_path.filename().string();
        const std::string extension = file_path.extension().string();
        remove_substring(filename, extension);
        file_path.replace_filename(filename);
    }

    template<typename T>
    struct ahandler_t : public action_handler_t
    {
        ahandler_t(T func)
            : func_(func)
        {
        }

        int idaapi activate(action_activation_ctx_t *ctx) override
        {
            UNUSED(ctx);
            func_();
            return 1; // not 0: graphical refresh
        }

        action_state_t idaapi update(action_update_ctx_t *ctx) override
        {
            UNUSED(ctx);
            return action_state_t::AST_ENABLE_FOR_IDB;
        }

        const T func_;
    };

    template<typename T>
    action_handler_t* new_handler(const T& func)
    {
        return new ahandler_t<T>(func);
    }

    struct YaCo
        : public IYaCo
    {
         YaCo();
        ~YaCo();

        // IYaCo methods
        void sync_and_push_idb(IdaMode mode) override;
        void discard_and_pull_idb(IdaMode mode) override;

        // internal
        void export_database();
        void initial_load();
        void toggle_auto_rebase_push();

        // Variables
        std::shared_ptr<IRepository> repo_;
        std::shared_ptr<IEvents>     events_;
        std::shared_ptr<IHooks>      hooks_;

        std::vector<action_desc_t>   action_descs_;
    };
}


YaCo::YaCo()
    : repo_(MakeRepository("."))
    , events_(MakeEvents(*repo_))
    , hooks_(MakeHooks(*events_))
{
    LOG(INFO, "YaCo version %s\n", GitVersion);

    repo_->check_valid_cache_startup();

    // hooks not hooked yet
    initial_load();
    auto_wait();

    #define YACO_ACTION_DESC(name, label, handler) ACTION_DESC_LITERAL_OWNER(name, label, handler, nullptr, nullptr, nullptr, -1)
    action_descs_.push_back(YACO_ACTION_DESC("yaco_toggle_rebase_push",     "YaCo - Toggle YaCo auto rebase/push",   new_handler([&]{ toggle_auto_rebase_push(); })));
    if(repo_->idb_is_tracked())
    {
        action_descs_.push_back(YACO_ACTION_DESC("yaco_sync_and_push_idb", "YaCo - Resync idb & force push", new_handler([&] { sync_and_push_idb(IDA_INTERACTIVE); })));
        action_descs_.push_back(YACO_ACTION_DESC("yaco_discard_and_pull_idb", "YaCo - Discard idb & force pull", new_handler([&] { discard_and_pull_idb(IDA_INTERACTIVE); })));
    }
    action_descs_.push_back(YACO_ACTION_DESC("yaco_export_database",        "YaCo - Export database",                new_handler([&]{ export_database(); })));
    #undef YACO_ACTION_DESC

    for (const action_desc_t &action_desc : action_descs_)
    {
        register_action(action_desc);
        attach_action_to_menu("Edit/Yatools/", action_desc.name, SETMENU_APP);
    }

    hooks_->hook();
}

void YaCo::export_database()
{
    LOG(INFO, "Exporting database\n");

    std::error_code ec;
    fs::create_directory("database", ec); //no error if directory already exist
    if (ec)
    {
        LOG(ERROR, "Export failed, unable to create database directory\n");
        return;
    }

    const auto exporter = MakeFlatBufferVisitor();
    AcceptIdaModel(*exporter);
    ExportedBuffer buffer = exporter->GetBuffer();

    FILE* database = fopen("database/database.yadb", "wb");
    if (database == nullptr)
    {
        LOG(INFO, "Export failed, %s\n", strerror(errno));
        return;
    }

    const auto count = fwrite(buffer.value, buffer.size, 1, database);
    fclose(database);
    if(count != 1)
    {
        LOG(INFO, "Export failed\n");
        return;
    }

    LOG(INFO, "Export complete\n");
}

YaCo::~YaCo()
{
    for(const action_desc_t &action_desc : action_descs_)
    {
        detach_action_from_menu("Edit/Yatools/", action_desc.name);
        unregister_action(action_desc.name); // delete the handler
    }
    hooks_.reset();
    events_.reset();
    repo_.reset();
    LOG(INFO, "exit\n");
}

void YaCo::initial_load()
{
    const auto time_start = std::chrono::system_clock::now();
    LOG(DEBUG, "Loading...\n");

    const auto mem = MakeMemoryModel();
    AcceptXmlCache(*mem, "cache");
    MakeIdaSink()->update(*mem);

    const auto time_end = std::chrono::system_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(time_end - time_start).count();
    if(elapsed)
        LOG(INFO, "cache: imported in %d seconds\n", static_cast<int>(elapsed));
}

void YaCo::toggle_auto_rebase_push()
{
    repo_->toggle_repo_auto_sync();
}

void YaCo::sync_and_push_idb(IdaMode mode)
{
    const int answer = ask_buttons(
        "Yes", "No", "", mode == IDA_INTERACTIVE ? ASKBTN_NO : ASKBTN_YES,
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
    repo_->sync_and_push_original_idb();

    warning("Force push complete, you can restart IDA and other YaCo users can \"Force pull\"");
    qexit(0);
}

void YaCo::discard_and_pull_idb(IdaMode mode)
{
    const int answer = ask_yn(
        mode == IDA_INTERACTIVE ? ASKBTN_NO : ASKBTN_YES,
        "All your local changes will be lost!\n"
        "Do you really want to proceed ?"
    );
    if (answer != ASKBTN_YES)
        return;

    hooks_->unhook();
    repo_->discard_and_pull_idb();

    set_database_flag(DBFL_KILL);
    warning("Force pull complete, you can restart IDA");
    qexit(0);
}

std::shared_ptr<IYaCo> MakeYaCo()
{
    auto idb_path = get_current_idb_path();
    remove_file_extension(idb_path);
    auto& logger = *globals::Get().logger;
    globals::InitIdbLogger(logger, idb_path.generic_string().data());
    logger.Delegate([](size_t prefix, const char* message)
    {
        msg("%s", &message[prefix + 1]);
    });
    return std::make_shared<YaCo>();
}
