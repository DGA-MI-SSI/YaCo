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
#include "XmlModel.hpp"
#include "FlatBufferVisitor.hpp"
#include "IdaModel.hpp"
#include "Utils.hpp"
#include "Yatools_swig.h"

#include "git_version.h"

#define MODULE_NAME "yaco"
#include "IdaUtils.hpp"

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

        // IYaCo
        void export_database() override;
        void disable() override;

        // internal
        void initial_load();
        void toggle_auto_rebase_push();
        void sync_and_push_idb();
        void discard_and_pull_idb();

        // Variables
        std::shared_ptr<IRepository> repository_;
        std::shared_ptr<IHooks>      hooks_;

        std::vector<action_desc_t>   action_descs_;
    };

    #define YACO_EXT_FUNC(name) void CONCAT(ext_, name)(YaCo* yaco) { yaco->name(); }
    YACO_EXT_FUNC(toggle_auto_rebase_push);
    YACO_EXT_FUNC(sync_and_push_idb);
    YACO_EXT_FUNC(discard_and_pull_idb);
    YACO_EXT_FUNC(export_database);
}

#define YACO_ACTION_DESC(name, label, handler) ACTION_DESC_LITERAL_OWNER(name, label, handler, nullptr, nullptr, nullptr, -1)

YaCo::YaCo()
    : repository_(MakeRepository("."))
    , hooks_(MakeHooks(*this, *repository_))
{
    IDA_LOG_INFO("YaCo %s", GitVersion);

    repository_->check_valid_cache_startup();

    // hooks not hooked yet
    initial_load();
    auto_wait();
    setflag(inf.s_genflags, INFFL_AUTO, false);

    action_descs_.push_back(YACO_ACTION_DESC("yaco_toggle_rebase_push",     "YaCo - Toggle YaCo auto rebase/push",   new_handler([&]{ ext_toggle_auto_rebase_push(this); })));
    action_descs_.push_back(YACO_ACTION_DESC("yaco_sync_and_push_idb",      "YaCo - Resync idb & force push",        new_handler([&]{ ext_sync_and_push_idb(this); })));
    action_descs_.push_back(YACO_ACTION_DESC("yaco_discard_and_pull_idb",   "YaCo - Discard idb & force pull",       new_handler([&]{ ext_discard_and_pull_idb(this); })));
    action_descs_.push_back(YACO_ACTION_DESC("yaco_export_database",        "YaCo - Export database",                new_handler([&]{ ext_export_database(this); })));

    for (const action_desc_t &action_desc : action_descs_)
    {
        register_action(action_desc);
        attach_action_to_menu("Edit/Yatools/", action_desc.name, SETMENU_APP);
    }

    hooks_->hook();
}

void YaCo::export_database()
{
    IDA_LOG_INFO("Exporting database using one core");

    std::error_code ec;
    fs::create_directory("database", ec); //no error if directory already exist
    if (ec)
    {
        IDA_LOG_ERROR("Export failed, unable to create database directory");
        return;
    }

    const auto exporter = MakeFlatBufferVisitor();
    MakeIdaModel()->accept(*exporter);
    ExportedBuffer buffer = exporter->GetBuffer();

    FILE* database = fopen("database/database.yadb", "wb");
    if (database == nullptr)
    {
        IDA_LOG_INFO("Export failed, %s", strerror(errno));
        return;
    }

    if (fwrite(buffer.value, 1, buffer.size, database) != buffer.size)
    {
        IDA_LOG_INFO("Export failed");
        return;
    }

    fclose(database);

    IDA_LOG_INFO("Export complete");
}

YaCo::~YaCo()
{
    for(const action_desc_t &action_desc : action_descs_)
    {
        detach_action_from_menu("Edit/Yatools/", action_desc.name);
        unregister_action(action_desc.name); // delete the handler
    }
    hooks_.reset();
    repository_.reset();
    StopYatools();
}

void YaCo::disable()
{
    hooks_->unhook();
}

void YaCo::initial_load()
{
    const auto time_start = std::chrono::system_clock::now();
    IDA_LOG_INFO("Loading...");

    import_to_ida(*MakeXmlAllModel("."));

    const auto time_end = std::chrono::system_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(time_end - time_start);
    IDA_LOG_INFO("Cache loaded in %d seconds", static_cast<int>(elapsed.count()));
}

void YaCo::toggle_auto_rebase_push()
{
    repository_->toggle_repo_auto_sync();
}

void YaCo::sync_and_push_idb()
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

void YaCo::discard_and_pull_idb()
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

std::shared_ptr<IYaCo> MakeYaCo()
{
    auto idb_path = get_current_idb_path();
    remove_file_extention(idb_path);
    StartYatools(idb_path.generic_string().data());
    return std::make_shared<YaCo>();
}
