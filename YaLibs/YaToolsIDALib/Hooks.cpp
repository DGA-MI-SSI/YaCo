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
#include "Hooks.hpp"

#include "Repository.hpp"
#include "YaToolsHashProvider.hpp"
#include "IModel.hpp"
#include "Model.hpp"
#include "IDANativeModel.hpp"
#include "IDANativeExporter.hpp"
#include "XML/XMLExporter.hpp"
#include "XML/XMLDatabaseModel.hpp"
#include "Logger.h"
#include "Yatools.h"
#include "Utils.hpp"
#include "../Helpers.h"

#define MODULE_NAME "hooks"
#include "IDAUtils.hpp"

#include <cstdarg>
#include <memory>
#include <tuple>
#include <chrono>

#ifdef _MSC_VER
#   include <filesystem>
#else
#   include <experimental/filesystem>
#endif

namespace fs = std::experimental::filesystem;

// Log macro used for events logging
#define LOG_EVENT(format, ...) IDA_LOG_INFO("Event: " format, ##__VA_ARGS__)

namespace
{
    // Enable / disable events logging
    constexpr bool LOG_EVENTS = false;

    const char BOOL_STR[2][6] = { "false", "true" };
    const char REPEATABLE_STR[2][12] = { "", "repeatable " };

    std::string get_cache_folder_path()
    {
        std::string cache_folder_path = get_path(PATH_TYPE_IDB);
        remove_substring(cache_folder_path, fs::path(cache_folder_path).filename().string());
        cache_folder_path += "cache";
        return cache_folder_path;
    }

    struct Hooks
        : public IHooks
    {

        Hooks(const std::shared_ptr<IHashProvider>& hash_provider, const std::shared_ptr<IRepository>& repo_manager);

        // IHooks
        void rename(ea_t ea, const std::string& new_name, const std::string& type, const std::string& old_name) override;
        void change_comment(ea_t ea) override;
        void undefine(ea_t ea) override;
        void delete_function(ea_t ea) override;
        void make_code(ea_t ea) override;
        void make_data(ea_t ea) override;
        void add_function(ea_t ea) override;
        void update_function(ea_t ea) override;
        void update_structure(ea_t struct_id) override;
        void update_structure_member(tid_t struct_id, tid_t member_id, ea_t member_offset) override;
        void delete_structure_member(tid_t struct_id, tid_t member_id, ea_t offset) override;
        void update_enum(enum_t enum_id) override;
        void change_operand_type(ea_t ea) override;
        void add_segment(ea_t start_ea, ea_t end_ea) override;
        void change_type_information(ea_t ea) override;

        void hook() override;
        void unhook() override;

        void save() override;
        void save_and_update() override;

        void flush() override;

        // Internal
        void add_address_to_process(ea_t ea, const std::string& message);
        void add_strucmember_to_process(ea_t struct_id, tid_t member_id, ea_t member_offset, const std::string& message);

        void save_structures(std::shared_ptr<IModelIncremental>& ida_model, IModelVisitor* memory_exporter);
        void save_enums(std::shared_ptr<IModelIncremental>& ida_model, IModelVisitor* memory_exporter);

        // Events management
        void closebase_event(va_list args);
        void savebase_event(va_list args);
        void upgraded_event(va_list args);
        void auto_empty_event(va_list args);
        void auto_empty_finally_event(va_list args);
        void determined_main_event(va_list args);
        void local_types_changed_event(va_list args);
        void extlang_changed_event(va_list args);
        void idasgn_loaded_event(va_list args);
        void kernel_config_loaded_event(va_list args);
        void loader_finished_event(va_list args);
        void flow_chart_created_event(va_list args);
        void compiler_changed_event(va_list args);
        void changing_ti_event(va_list args);
        void ti_changed_event(va_list args);
        void changing_op_ti_event(va_list args);
        void op_ti_changed_event(va_list args);
        void changing_op_type_event(va_list args);
        void op_type_changed_event(va_list args);
        void enum_created_event(va_list args);
        void deleting_enum_event(va_list args);
        void enum_deleted_event(va_list args);
        void renaming_enum_event(va_list args);
        void enum_renamed_event(va_list args);
        void changing_enum_bf_event(va_list args);
        void enum_bf_changed_event(va_list args);
        void changing_enum_cmt_event(va_list args);
        void enum_cmt_changed_event(va_list args);
        void enum_member_created_event(va_list args);
        void deleting_enum_member_event(va_list args);

        // Variables
        std::shared_ptr<IHashProvider> hash_provider_;
        std::shared_ptr<IRepository> repo_manager_;

        std::set<ea_t> addresses_to_process_;
        std::set<tid_t> structures_to_process_;
        std::map<tid_t, std::tuple<tid_t, ea_t>> structmember_to_process_; // map<struct_id, tuple<member_id, offset>>
        std::set<enum_t> enums_to_process_;
        std::map<ea_t, tid_t> enummember_to_process_;
        std::set<ea_t> comments_to_process_;
        std::set<std::tuple<ea_t, ea_t>> segments_to_process_; // set<tuple<seg_ea_start, seg_ea_end>>
    };
}

namespace
{
    ssize_t idp_event_handler(void* user_data, int notification_code, va_list va)
    {
        Hooks* hooks = static_cast<Hooks*>(user_data);
        UNUSED(hooks);
        UNUSED(notification_code);
        UNUSED(va);
        return 0;
    }

    ssize_t idb_event_handler(void* user_data, int notification_code, va_list args)
    {
        using envent_code = idb_event::event_code_t;
        Hooks* hooks = static_cast<Hooks*>(user_data);
        envent_code ecode = static_cast<idb_event::event_code_t>(notification_code);
        switch (ecode)
        {
            case envent_code::closebase:               hooks->closebase_event(args); break;
            case envent_code::savebase:                hooks->savebase_event(args); break;
            case envent_code::upgraded:                hooks->upgraded_event(args); break;
            case envent_code::auto_empty:              hooks->auto_empty_event(args); break;
            case envent_code::auto_empty_finally:      hooks->auto_empty_finally_event(args); break;
            case envent_code::determined_main:         hooks->determined_main_event(args); break;
            case envent_code::local_types_changed:     hooks->local_types_changed_event(args); break;
            case envent_code::extlang_changed:         hooks->extlang_changed_event(args); break;
            case envent_code::idasgn_loaded:           hooks->idasgn_loaded_event(args); break;
            case envent_code::kernel_config_loaded:    hooks->kernel_config_loaded_event(args); break;
            case envent_code::loader_finished:         hooks->loader_finished_event(args); break;
            case envent_code::flow_chart_created:      hooks->flow_chart_created_event(args); break;
            case envent_code::compiler_changed:        hooks->compiler_changed_event(args); break;
            case envent_code::changing_ti:             hooks->changing_ti_event(args); break;
            case envent_code::ti_changed:              hooks->ti_changed_event(args); break;
            case envent_code::changing_op_ti:          hooks->changing_op_ti_event(args); break;
            case envent_code::op_ti_changed:           hooks->op_ti_changed_event(args); break;
            case envent_code::changing_op_type:        hooks->changing_op_type_event(args); break;
            case envent_code::op_type_changed:         hooks->op_type_changed_event(args); break;
            case envent_code::enum_created:            hooks->enum_created_event(args); break;
            case envent_code::deleting_enum:           hooks->deleting_enum_event(args); break;
            case envent_code::enum_deleted:            hooks->enum_deleted_event(args); break;
            case envent_code::renaming_enum:           hooks->renaming_enum_event(args); break;
            case envent_code::enum_renamed:            hooks->enum_renamed_event(args); break;
            case envent_code::changing_enum_bf:        hooks->changing_enum_bf_event(args); break;
            case envent_code::enum_bf_changed:         hooks->enum_bf_changed_event(args); break;
            case envent_code::changing_enum_cmt:       hooks->changing_enum_cmt_event(args); break;
            case envent_code::enum_cmt_changed:        hooks->enum_cmt_changed_event(args); break;
            case envent_code::enum_member_created:     hooks->enum_member_created_event(args); break;
            case envent_code::deleting_enum_member:    hooks->deleting_enum_member_event(args); break;
            case envent_code::enum_member_deleted:     LOG_EVENT("enum_member_deleted"); break;
            case envent_code::struc_created:           LOG_EVENT("struc_created"); break;
            case envent_code::deleting_struc:          LOG_EVENT("deleting_struc"); break;
            case envent_code::struc_deleted:           LOG_EVENT("struc_deleted"); break;
            case envent_code::changing_struc_align:    LOG_EVENT("changing_struc_align"); break;
            case envent_code::struc_align_changed:     LOG_EVENT("struc_align_changed"); break;
            case envent_code::renaming_struc:          LOG_EVENT("renaming_struc"); break;
            case envent_code::struc_renamed:           LOG_EVENT("struc_renamed"); break;
            case envent_code::expanding_struc:         LOG_EVENT("expanding_struc"); break;
            case envent_code::struc_expanded:          LOG_EVENT("struc_expanded"); break;
            case envent_code::struc_member_created:    LOG_EVENT("struc_member_created"); break;
            case envent_code::deleting_struc_member:   LOG_EVENT("deleting_struc_member"); break;
            case envent_code::struc_member_deleted:    LOG_EVENT("struc_member_deleted"); break;
            case envent_code::renaming_struc_member:   LOG_EVENT("renaming_struc_member"); break;
            case envent_code::struc_member_renamed:    LOG_EVENT("struc_member_renamed"); break;
            case envent_code::changing_struc_member:   LOG_EVENT("changing_struc_member"); break;
            case envent_code::struc_member_changed:    LOG_EVENT("struc_member_changed"); break;
            case envent_code::changing_struc_cmt:      LOG_EVENT("changing_struc_cmt"); break;
            case envent_code::struc_cmt_changed:       LOG_EVENT("struc_cmt_changed"); break;
            case envent_code::segm_added:              LOG_EVENT("segm_added"); break;
            case envent_code::deleting_segm:           LOG_EVENT("deleting_segm"); break;
            case envent_code::segm_deleted:            LOG_EVENT("segm_deleted"); break;
            case envent_code::changing_segm_start:     LOG_EVENT("changing_segm_start"); break;
            case envent_code::segm_start_changed:      LOG_EVENT("segm_start_changed"); break;
            case envent_code::changing_segm_end:       LOG_EVENT("changing_segm_end"); break;
            case envent_code::segm_end_changed:        LOG_EVENT("segm_end_changed"); break;
            case envent_code::changing_segm_name:      LOG_EVENT("changing_segm_name"); break;
            case envent_code::segm_name_changed:       LOG_EVENT("segm_name_changed"); break;
            case envent_code::changing_segm_class:     LOG_EVENT("changing_segm_class"); break;
            case envent_code::segm_class_changed:      LOG_EVENT("segm_class_changed"); break;
            case envent_code::segm_attrs_updated:      LOG_EVENT("segm_attrs_updated"); break;
            case envent_code::segm_moved:              LOG_EVENT("segm_moved"); break;
            case envent_code::allsegs_moved:           LOG_EVENT("allsegs_moved"); break;
            case envent_code::func_added:              LOG_EVENT("func_added"); break;
            case envent_code::func_updated:            LOG_EVENT("func_updated"); break;
            case envent_code::set_func_start:          LOG_EVENT("set_func_start"); break;
            case envent_code::set_func_end:            LOG_EVENT("set_func_end"); break;
            case envent_code::deleting_func:           LOG_EVENT("deleting_func"); break;
            case envent_code::frame_deleted:           LOG_EVENT("frame_deleted"); break;
            case envent_code::thunk_func_created:      LOG_EVENT("thunk_func_created"); break;
            case envent_code::func_tail_appended:      LOG_EVENT("func_tail_appended"); break;
            case envent_code::deleting_func_tail:      LOG_EVENT("deleting_func_tail"); break;
            case envent_code::func_tail_deleted:       LOG_EVENT("func_tail_deleted"); break;
            case envent_code::tail_owner_changed:      LOG_EVENT("tail_owner_changed"); break;
            case envent_code::func_noret_changed:      LOG_EVENT("func_noret_changed"); break;
            case envent_code::stkpnts_changed:         LOG_EVENT("stkpnts_changed"); break;
            case envent_code::updating_tryblks:        LOG_EVENT("updating_tryblks"); break;
            case envent_code::tryblks_updated:         LOG_EVENT("tryblks_updated"); break;
            case envent_code::deleting_tryblks:        LOG_EVENT("deleting_tryblks"); break;
            case envent_code::sgr_changed:             LOG_EVENT("sgr_changed"); break;
            case envent_code::make_code:               LOG_EVENT("make_code"); break;
            case envent_code::make_data:               LOG_EVENT("make_data"); break;
            case envent_code::destroyed_items:         LOG_EVENT("destroyed_items"); break;
            case envent_code::renamed:                 LOG_EVENT("renamed"); break;
            case envent_code::byte_patched:            LOG_EVENT("byte_patched"); break;
            case envent_code::changing_cmt:            LOG_EVENT("changing_cmt"); break;
            case envent_code::cmt_changed:             LOG_EVENT("cmt_changed"); break;
            case envent_code::changing_range_cmt:      LOG_EVENT("changing_range_cmt"); break;
            case envent_code::range_cmt_changed:       LOG_EVENT("range_cmt_changed"); break;
            case envent_code::extra_cmt_changed:       LOG_EVENT("extra_cmt_changed"); break;
        }
        return 0;
    }
}

Hooks::Hooks(const std::shared_ptr<IHashProvider>& hash_provider, const std::shared_ptr<IRepository>& repo_manager)
    : hash_provider_{ hash_provider }
    , repo_manager_{ repo_manager }
{

}

void Hooks::rename(ea_t ea, const std::string& new_name, const std::string& type, const std::string& old_name)
{
    std::string message{ type };
    if (!type.empty())
        message += ' ';
    message += "renamed ";
    if (!old_name.empty())
    {
        message += "from ";
        message += old_name;
    }
    message += "to ";
    message += new_name;
    add_address_to_process(ea, message);
}

void Hooks::change_comment(ea_t ea)
{
    comments_to_process_.insert(ea);
}

void Hooks::undefine(ea_t ea)
{
    add_address_to_process(ea, "Undefne");
}

void Hooks::delete_function(ea_t ea)
{
    add_address_to_process(ea, "Delete function");
}

void Hooks::make_code(ea_t ea)
{
    add_address_to_process(ea, "Create code");
}

void Hooks::make_data(ea_t ea)
{
    add_address_to_process(ea, "Create data");
}

void Hooks::add_function(ea_t ea)
{
    // Comments from Python:
    // invalid all addresses in this function(they depend(relatively) on this function now, no on code)
    // Warning : deletion of objects not implemented
    // TODO : implement deletion of objects inside newly created function range
    // TODO : use function chunks to iterate over function code
    add_address_to_process(ea, "Create function");
}

void Hooks::update_function(ea_t ea)
{
    add_address_to_process(ea, "Create function");
}

void Hooks::update_structure(ea_t struct_id)
{
    structures_to_process_.insert(struct_id);
    repo_manager_->add_auto_comment(struct_id, "Updated");
}

void Hooks::update_structure_member(tid_t struct_id, tid_t member_id, ea_t member_offset)
{
    std::string message{ "Member updated at offset " };
    message += ea_to_hex(member_offset);
    message += " : ";
    qstring member_id_fullname;
    get_member_fullname(&member_id_fullname, member_id);
    message += member_id_fullname.c_str();
    add_strucmember_to_process(struct_id, member_id, member_offset, message);
}

void Hooks::delete_structure_member(tid_t struct_id, tid_t member_id, ea_t offset)
{
    add_strucmember_to_process(struct_id, member_id, offset, "Member deleted");
}

void Hooks::update_enum(enum_t enum_id)
{
    enums_to_process_.insert(enum_id);
    repo_manager_->add_auto_comment(enum_id, "Updated");
}

void Hooks::change_operand_type(ea_t ea)
{
    if (get_func(ea) || is_code(get_flags(ea)))
    {
        addresses_to_process_.insert(ea);
        repo_manager_->add_auto_comment(ea, "Operand type change");
        return;
    }

    if (is_member_id(ea))
        return; // this is a member id: hook already present (update_structure_member)

    IDA_LOG_WARNING("Operand type changed at %s, code out of a function: not implemented", ea_to_hex(ea).c_str());
}

void Hooks::add_segment(ea_t start_ea, ea_t end_ea)
{
    segments_to_process_.insert(std::make_tuple(start_ea, end_ea));
}

void Hooks::change_type_information(ea_t ea)
{
    add_address_to_process(ea, "Type information changed");
}

void Hooks::hook()
{
    hook_to_notification_point(HT_IDP, &idp_event_handler, this);
    hook_to_notification_point(HT_IDB, &idb_event_handler, this);
}

void Hooks::unhook()
{
    unhook_from_notification_point(HT_IDP, &idp_event_handler, this);
    unhook_from_notification_point(HT_IDB, &idb_event_handler, this);
}

void Hooks::save()
{
    const auto time_start = std::chrono::system_clock::now();

    std::shared_ptr<IModelIncremental> ida_model = MakeModelIncremental(hash_provider_.get());
    ModelAndVisitor db = MakeModel();

    db.visitor->visit_start();

    // add comments to adresses to process
    for (ea_t ea : comments_to_process_)
        add_address_to_process(ea, "Changed comment");

    // process structures
    save_structures(ida_model, db.visitor.get());

    // process enums
    save_enums(ida_model, db.visitor.get());

    // process addresses
    for (ea_t ea : addresses_to_process_)
        ida_model->accept_ea(*db.visitor, ea);

    // process segments
    for (const std::tuple<ea_t, ea_t>& segment_ea : segments_to_process_)
        ida_model->accept_segment(*db.visitor, std::get<0>(segment_ea));

    db.visitor->visit_end();

    db.model->accept(*MakeXmlExporter(get_cache_folder_path()));

    const auto time_end = std::chrono::system_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(time_end - time_start);
    IDA_LOG_INFO("Saved in %d seconds", static_cast<int>(elapsed.count()));
}

void Hooks::save_and_update()
{
    // save and commit changes
    save();
    if (!repo_manager_->commit_cache())
    {
        IDA_LOG_WARNING("An error occurred during YaCo commit");
        warning("An error occured during YaCo commit: please relaunch IDA");
    }
    flush();

    unhook();

    // update cache and export modifications to IDA
    std::vector<std::string> modified_files = repo_manager_->update_cache();
    ModelAndVisitor memory_exporter = MakeModel();
    MakeXmlFilesDatabaseModel(modified_files)->accept(*(memory_exporter.visitor));
    export_to_ida(memory_exporter.model.get(), hash_provider_.get());

    // Let IDA apply modifications
    setflag(inf.s_genflags, INFFL_AUTO, true);
    auto_wait();
    setflag(inf.s_genflags, INFFL_AUTO, false);
    refresh_idaview_anyway();

    hook();
}

void Hooks::flush()
{
    addresses_to_process_.clear();
    structures_to_process_.clear();
    structmember_to_process_.clear();
    enums_to_process_.clear();
    enummember_to_process_.clear();
    comments_to_process_.clear();
    segments_to_process_.clear();
}

void Hooks::add_address_to_process(ea_t ea, const std::string& message)
{
    addresses_to_process_.insert(ea);
    repo_manager_->add_auto_comment(ea, message);
}

void Hooks::add_strucmember_to_process(ea_t struct_id, tid_t member_id, ea_t member_offset, const std::string& message)
{
    structmember_to_process_[struct_id] = std::make_tuple(member_id, member_offset);
    repo_manager_->add_auto_comment(struct_id, message);
}

void Hooks::save_structures(std::shared_ptr<IModelIncremental>& ida_model, IModelVisitor* memory_exporter)
{
    // structures: export modified ones, delete deleted ones
    for (tid_t struct_id : structures_to_process_)
    {
        uval_t struct_idx = get_struc_idx(struct_id);
        if (struct_idx != BADADDR)
        {
            // structure or stackframe modified
            ida_model->accept_struct(*memory_exporter, BADADDR, struct_id);
            continue;
        }

        // structure or stackframe deleted
        // need to export the parent (function)
        ea_t func_ea = get_func_by_frame(struct_id);
        if (func_ea != BADADDR)
        {
            // if stackframe
            ida_model->accept_struct(*memory_exporter, func_ea, struct_id);
            ida_model->accept_ea(*memory_exporter, func_ea);
            continue;
        }
        // if structure
        ida_model->delete_struct(*memory_exporter, struct_id);
    }

    // structures members : update modified ones, remove deleted ones
    for (const std::pair<const tid_t, std::tuple<tid_t, ea_t>>& struct_info : structmember_to_process_)
    {
        tid_t struct_id = struct_info.first;
        ea_t member_offset = std::get<1>(struct_info.second);

        struc_t* ida_struct = get_struc(struct_id);
        uval_t struct_idx = get_struc_idx(struct_id);

        ea_t stackframe_func_addr = BADADDR;

        if (!ida_struct || struct_idx == BADADDR)
        {
            // structure or stackframe deleted
            ea_t func_ea = get_func_by_frame(struct_id);
            if (func_ea == BADADDR)
            {
                // if structure
                ida_model->delete_struct_member(*memory_exporter, BADADDR, struct_id, member_offset);
                continue;
            }
            // if stackframe
            stackframe_func_addr = func_ea;
            ida_model->accept_function(*memory_exporter, stackframe_func_addr);
        }

        // structure or stackframe modified
        member_t* ida_member = get_member(ida_struct, member_offset);
        if (!ida_member || ida_member->id == BADADDR)
        {
            // if member deleted
            ida_model->delete_struct_member(*memory_exporter, stackframe_func_addr, struct_id, member_offset);
            continue;
        }

        if (member_offset > 0)
        {
            member_t* ida_prev_member = get_member(ida_struct, member_offset - 1);
            if (ida_prev_member && ida_prev_member->id == ida_member->id)
            {
                // if member deleted and replaced by member starting above it
                ida_model->delete_struct_member(*memory_exporter, stackframe_func_addr, struct_id, member_offset);
                continue;
            }
        }

        // if member updated
        ida_model->accept_struct_member(*memory_exporter, stackframe_func_addr, ida_member->id);
    }
}

void Hooks::save_enums(std::shared_ptr<IModelIncremental>& ida_model, IModelVisitor* memory_exporter)
{
    // enums: export modified ones, delete deleted ones
    for (enum_t enum_id : enums_to_process_)
    {
        uval_t enum_idx = get_enum_idx(enum_id);
        if (enum_idx == BADADDR)
        {
            // enum deleted
            ida_model->delete_enum(*memory_exporter, enum_id);
            continue;
        }

        // enum modified
        ida_model->accept_enum(*memory_exporter, enum_id);
    }

    // not implemented in Python, TODO after porting to C++ events
    // enums members : update modified ones, remove deleted ones
    /*
    iterate over members :
        -if the parent enum has been deleted, delete the member
        -otherwise, detect if the member has been updated or removed
            -updated : accept enum_member
            -removed : accept enum_member_deleted
    */
}

void Hooks::closebase_event(va_list args)
{
    UNUSED(args);

    if (LOG_EVENTS)
        LOG_EVENT("The database will be closed now");
}

void Hooks::savebase_event(va_list args)
{
    UNUSED(args);

    msg("\n");
    if (LOG_EVENTS)
        LOG_EVENT("The database is being saved");

    save_and_update();
}

void Hooks::upgraded_event(va_list args)
{
    int from = va_arg(args, int);

    if (LOG_EVENTS)
        LOG_EVENT("The database has been upgraded (old IDB version: %d)", from);
}

void Hooks::auto_empty_event(va_list args)
{
    UNUSED(args);

    if (LOG_EVENTS)
        LOG_EVENT("All analysis queues are empty");
}

void Hooks::auto_empty_finally_event(va_list args)
{
    UNUSED(args);

    if (LOG_EVENTS)
        LOG_EVENT("All analysis queues are empty definitively");
}

void Hooks::determined_main_event(va_list args)
{
    ea_t main = va_arg(args, ea_t);

    if (LOG_EVENTS)
        LOG_EVENT("The main() function has been determined (address of the main() function: " EA_FMT ")", main);
}

void Hooks::local_types_changed_event(va_list args)
{
    UNUSED(args);

    if (LOG_EVENTS)
        LOG_EVENT("Local types have been changed");
}

void Hooks::extlang_changed_event(va_list args)
{
    int kind = va_arg(args, int); //0: extlang installed, 1: extlang removed, 2: default extlang changed
    extlang_t* el = va_arg(args, extlang_t*);
    int idx = va_arg(args, int);

    UNUSED(idx);
    if (LOG_EVENTS)
    {
        switch (kind)
        {
        case 1:
            LOG_EVENT("Extlang %s installed", el->name);
            break;
        case 2:
            LOG_EVENT("Extlang %s removed", el->name);
            break;
        case 3:
            LOG_EVENT("Default extlang changed: %s", el->name);
            break;
        default:
            LOG_EVENT("The list of extlangs or the default extlang was changed");
            break;
        }
    }
}

void Hooks::idasgn_loaded_event(va_list args)
{
    const char* short_sig_name = va_arg(args, const char*);

    if (LOG_EVENTS)
    {
        // FLIRT = Fast Library Identificationand Regognition Technology
        // normal processing = not for recognition of startup sequences
        LOG_EVENT("FLIRT signature %s has been loaded for normal processing", short_sig_name);
    }
}

void Hooks::kernel_config_loaded_event(va_list args)
{
    UNUSED(args);

    if (LOG_EVENTS)
        LOG_EVENT("Kernel configuration loaded (ida.cfg parsed)");
}

void Hooks::loader_finished_event(va_list args)
{
    linput_t* li = va_arg(args, linput_t*);
    uint16 neflags = static_cast<uint16>(va_arg(args, int)); // NEF_.+ defines from loader.hpp
    const char* filetypename = va_arg(args, const char*);

    UNUSED(li);
    UNUSED(neflags);
    if (LOG_EVENTS)
        LOG_EVENT("External file loader for %s files finished its work", filetypename);
}

void Hooks::flow_chart_created_event(va_list args)
{
    qflow_chart_t* fc = va_arg(args, qflow_chart_t*);

    if (LOG_EVENTS)
    {
        qstring buffer;
        get_func_name(&buffer, fc->pfn->start_ea);
        LOG_EVENT("Gui has retrieved a function flow chart (from " EA_FMT " to " EA_FMT ", name: %s, function: %s)", fc->bounds.start_ea, fc->bounds.end_ea, fc->title.c_str(), buffer.c_str());
    }
}

void Hooks::compiler_changed_event(va_list args)
{
    UNUSED(args);

    if (LOG_EVENTS)
        LOG_EVENT("The kernel has changed the compiler information");
}

void Hooks::changing_ti_event(va_list args)
{
    ea_t ea = va_arg(args, ea_t);
    type_t* new_type = va_arg(args, type_t*);
    p_list* new_fnames = va_arg(args, p_list*);

    UNUSED(new_type);
    UNUSED(new_fnames);
    if (LOG_EVENTS)
        LOG_EVENT("An item typestring (c/c++ prototype) is to be changed (ea: " EA_FMT ")", ea);
}

void Hooks::ti_changed_event(va_list args)
{
    ea_t ea = va_arg(args, ea_t);
    type_t* type = va_arg(args, type_t*);
    p_list* fnames = va_arg(args, p_list*);

    change_type_information(ea);

    UNUSED(type);
    UNUSED(fnames);
    if (LOG_EVENTS)
        LOG_EVENT("An item typestring (c/c++ prototype) has been changed (ea: " EA_FMT ")", ea);
}

void Hooks::changing_op_ti_event(va_list args)
{
    ea_t ea = va_arg(args, ea_t);
    int n = va_arg(args, int);
    type_t* new_type = va_arg(args, type_t*);
    p_list* new_fnames = va_arg(args, p_list*);

    UNUSED(n);
    UNUSED(new_type);
    UNUSED(new_fnames);
    if (LOG_EVENTS)
        LOG_EVENT("An operand typestring (c/c++ prototype) is to be changed (ea: " EA_FMT ")", ea);
}

void Hooks::op_ti_changed_event(va_list args)
{
    ea_t ea = va_arg(args, ea_t);
    int n = va_arg(args, int);
    type_t* new_type = va_arg(args, type_t*);
    p_list* new_fnames = va_arg(args, p_list*);

    change_type_information(ea);

    UNUSED(n);
    UNUSED(new_type);
    UNUSED(new_fnames);
    if (LOG_EVENTS)
        LOG_EVENT("An operand typestring (c/c++ prototype) has been changed (ea: " EA_FMT ")", ea);
}

void Hooks::changing_op_type_event(va_list args)
{
    ea_t ea = va_arg(args, ea_t);
    int n = va_arg(args, int);
    const opinfo_t* opinfo = va_arg(args, const opinfo_t*);

    UNUSED(n);
    UNUSED(opinfo);
    if (LOG_EVENTS)
        LOG_EVENT("An operand type (offset, hex, etc...) is to be changed (ea: " EA_FMT ")", ea);
}

void Hooks::op_type_changed_event(va_list args)
{
    ea_t ea = va_arg(args, ea_t);
    int n = va_arg(args, int);

    UNUSED(n);
    if (LOG_EVENTS)
        LOG_EVENT("An operand type (offset, hex, etc...) has been set or deleted (ea: " EA_FMT ")", ea);
}

void Hooks::enum_created_event(va_list args)
{
    enum_t id = va_arg(args, enum_t);

    if (LOG_EVENTS)
    {
        qstring buffer;
        get_enum_name(&buffer, id);
        LOG_EVENT("Enum type %s has been created", buffer.c_str());
    }
}

void Hooks::deleting_enum_event(va_list args)
{
    enum_t id = va_arg(args, enum_t);

    if (LOG_EVENTS)
    {
        qstring buffer;
        get_enum_name(&buffer, id);
        LOG_EVENT("Enum type %s is to be deleted", buffer.c_str());
    }
}

void Hooks::enum_deleted_event(va_list args)
{
    enum_t id = va_arg(args, enum_t);

    UNUSED(id);
    if (LOG_EVENTS)
        LOG_EVENT("An enum type has been deleted");
}

void Hooks::renaming_enum_event(va_list args)
{
    tid_t id = va_arg(args, tid_t);
    bool is_enum = static_cast<bool>(va_arg(args, int));
    const char* newname = va_arg(args, const char*);

    if (LOG_EVENTS)
    {
        qstring enum_name;
        if (is_enum)
        {
            get_enum_name(&enum_name, id);
            LOG_EVENT("Enum %s is to be renamed to %s", enum_name.c_str(), newname);
        }
        else
        {
            qstring enum_member_name;
            get_enum_member_name(&enum_member_name, id);
            get_enum_name(&enum_name, get_enum_member_enum(id));
            LOG_EVENT("A member of enum %s is to be renamed from %s to %s", enum_name.c_str(), enum_member_name.c_str(), newname);
        }
    }
}

void Hooks::enum_renamed_event(va_list args)
{
    tid_t id = va_arg(args, tid_t);

    if (LOG_EVENTS)
    {
        qstring enum_name;
        if (get_enum_member_enum(id) == BADADDR)
        {
            get_enum_name(&enum_name, id);
            LOG_EVENT("An enum has been renamed %s", enum_name.c_str());
        }
        else
        {
            qstring enum_member_name;
            get_enum_member_name(&enum_member_name, id);
            get_enum_name(&enum_name, get_enum_member_enum(id));
            LOG_EVENT("A member of enum %s has been renamed %s", enum_name.c_str(), enum_member_name.c_str());
        }
    }
}

void Hooks::changing_enum_bf_event(va_list args)
{
    enum_t id = va_arg(args, enum_t);
    bool new_bf = static_cast<bool>(va_arg(args, int));

    if (LOG_EVENTS)
    {
        qstring enum_name;
        get_enum_name(&enum_name, id);
        LOG_EVENT("Enum %s 'bitfield' attribute is to be changed to %s", enum_name.c_str(), BOOL_STR[new_bf]);
    }
}

void Hooks::enum_bf_changed_event(va_list args)
{
    enum_t id = va_arg(args, enum_t);

    if (LOG_EVENTS)
    {
        qstring enum_name;
        get_enum_name(&enum_name, id);
        LOG_EVENT("Enum %s 'bitfield' attribute has been changed", enum_name.c_str());
    }
}

void Hooks::changing_enum_cmt_event(va_list args)
{
    enum_t id = va_arg(args, enum_t);
    bool repeatable = static_cast<bool>(va_arg(args, int));
    const char* newcmt = va_arg(args, const char*);

    if (LOG_EVENTS)
    {
        qstring enum_name;
        qstring cmt;
        if (get_enum_member_enum(id) == BADADDR)
        {
            get_enum_name(&enum_name, id);
            get_enum_cmt(&cmt, id, repeatable);
            LOG_EVENT("Enum %s %scomment is to be changed from \"%s\" to \"%s\"", enum_name.c_str(), REPEATABLE_STR[repeatable], cmt.c_str(), newcmt);
        }
        else
        {
            qstring enum_member_name;
            get_enum_member_name(&enum_member_name, id);
            get_enum_name(&enum_name, get_enum_member_enum(id));
            get_enum_member_cmt(&cmt, id, repeatable);
            LOG_EVENT("Enum %s member %s %scomment is to be changed from \"%s\" to \"%s\"", enum_name.c_str(), enum_member_name.c_str(), REPEATABLE_STR[repeatable], cmt.c_str(), newcmt);
        }
    }
}

void Hooks::enum_cmt_changed_event(va_list args)
{
    enum_t id = va_arg(args, enum_t);
    bool repeatable = static_cast<bool>(va_arg(args, int));

    if (LOG_EVENTS)
    {
        qstring enum_name;
        qstring cmt;
        if (get_enum_member_enum(id) == BADADDR)
        {
            get_enum_name(&enum_name, id);
            get_enum_cmt(&cmt, id, repeatable);
            LOG_EVENT("Enum %s %scomment has been changed to \"%s\"", enum_name.c_str(), REPEATABLE_STR[repeatable], cmt.c_str());
        }
        else
        {
            qstring enum_member_name;
            get_enum_member_name(&enum_member_name, id);
            get_enum_name(&enum_name, get_enum_member_enum(id));
            get_enum_member_cmt(&cmt, id, repeatable);
            LOG_EVENT("Enum %s member %s %scomment has been changed to \"%s\"", enum_name.c_str(), enum_member_name.c_str(), REPEATABLE_STR[repeatable], cmt.c_str());
        }
    }
}

void Hooks::enum_member_created_event(va_list args)
{
    enum_t id = va_arg(args, enum_t);
    const_t cid = va_arg(args, const_t);

    if (LOG_EVENTS)
    {
        qstring enum_name;
        get_enum_name(&enum_name, id);
        qstring enum_member_name;
        get_enum_member_name(&enum_member_name, cid);
        LOG_EVENT("Enum %s member %s has been created", enum_name.c_str(), enum_member_name.c_str());
    }
}

void Hooks::deleting_enum_member_event(va_list args)
{
    enum_t id = va_arg(args, enum_t);
    const_t cid = va_arg(args, const_t);

    if (LOG_EVENTS)
    {
        qstring enum_name;
        get_enum_name(&enum_name, id);
        qstring enum_member_name;
        get_enum_member_name(&enum_member_name, cid);
        LOG_EVENT("Enum %s member %s is to be deleted", enum_name.c_str(), enum_member_name.c_str());
    }
}


std::shared_ptr<IHooks> MakeHooks(const std::shared_ptr<IHashProvider>& hash_provider, const std::shared_ptr<IRepository>& repo_manager)
{
    return std::make_shared<Hooks>(hash_provider, repo_manager);
}
