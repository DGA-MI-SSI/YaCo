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
#include "Pool.hpp"
#include "../Helpers.h"

#define MODULE_NAME "hooks"
#include "IDAUtils.hpp"

#include <cstdarg>
#include <chrono>
#include <math.h>

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

    const char* range_kind_to_str(range_kind_t kind)
    {
        switch (kind)
        {
        case RANGE_KIND_UNKNOWN:
            return "Unknow";
        case RANGE_KIND_FUNC:
            return "Function";
        case RANGE_KIND_SEGMENT:
            return "Segment";
        case RANGE_KIND_HIDDEN_RANGE:
            return "Hidden";
        }
        return "";
    }

    std::string get_cache_folder_path()
    {
        std::string cache_folder_path = get_path(PATH_TYPE_IDB);
        remove_substring(cache_folder_path, fs::path(cache_folder_path).filename().string());
        cache_folder_path += "cache";
        return cache_folder_path;
    }

    using Eas = std::set<ea_t>;
    using Structs = std::set<tid_t>;
    using StructMembers = std::map<tid_t, ea_t>;
    using Enums = std::set<enum_t>;
    using EnumMembers = std::map<ea_t, tid_t>;
    using Comments = std::set<ea_t>;
    using Segments = std::set<ea_t>;

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
        void delete_structure_member(tid_t struct_id, ea_t offset) override;
        void update_enum(enum_t enum_id) override;
        void change_operand_type(ea_t ea) override;
        void update_segment(ea_t start_ea) override;
        void change_type_information(ea_t ea) override;

        void hook() override;
        void unhook() override;

        void save() override;
        void save_and_update() override;

        void flush() override;

        // Internal
        void add_address_to_process(ea_t ea, const std::string& message);
        void add_strucmember_to_process(ea_t struct_id, ea_t member_offset, const std::string& message);

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
        void enum_member_deleted_event(va_list args);
        void struc_created_event(va_list args);
        void deleting_struc_event(va_list args);
        void struc_deleted_event(va_list args);
        void changing_struc_align_event(va_list args);
        void struc_align_changed_event(va_list args);
        void renaming_struc_event(va_list args);
        void struc_renamed_event(va_list args);
        void expanding_struc_event(va_list args);
        void struc_expanded_event(va_list args);
        void struc_member_created_event(va_list args);
        void deleting_struc_member_event(va_list args);
        void struc_member_deleted_event(va_list args);
        void renaming_struc_member_event(va_list args);
        void struc_member_renamed_event(va_list args);
        void changing_struc_member_event(va_list args);
        void struc_member_changed_event(va_list args);
        void changing_struc_cmt_event(va_list args);
        void struc_cmt_changed_event(va_list args);
        void segm_added_event(va_list args);
        void deleting_segm_event(va_list args);
        void segm_deleted_event(va_list args);
        void changing_segm_start_event(va_list args);
        void segm_start_changed_event(va_list args);
        void changing_segm_end_event(va_list args);
        void segm_end_changed_event(va_list args);
        void changing_segm_name_event(va_list args);
        void segm_name_changed_event(va_list args);
        void changing_segm_class_event(va_list args);
        void segm_class_changed_event(va_list args);
        void segm_attrs_updated_event(va_list args);
        void segm_moved_event(va_list args);
        void allsegs_moved_event(va_list args);
        void func_added_event(va_list args);
        void func_updated_event(va_list args);
        void set_func_start_event(va_list args);
        void set_func_end_event(va_list args);
        void deleting_func_event(va_list args);
        void frame_deleted_event(va_list args);
        void thunk_func_created_event(va_list args);
        void func_tail_appended_event(va_list args);
        void deleting_func_tail_event(va_list args);
        void func_tail_deleted_event(va_list args);
        void tail_owner_changed_event(va_list args);
        void func_noret_changed_event(va_list args);
        void stkpnts_changed_event(va_list args);
        void updating_tryblks_event(va_list args);
        void tryblks_updated_event(va_list args);
        void deleting_tryblks_event(va_list args);
        void sgr_changed_event(va_list args);
        void make_code_event(va_list args);
        void make_data_event(va_list args);
        void destroyed_items_event(va_list args);
        void renamed_event(va_list args);
        void byte_patched_event(va_list args);
        void changing_cmt_event(va_list args);
        void cmt_changed_event(va_list args);
        void changing_range_cmt_event(va_list args);
        void range_cmt_changed_event(va_list args);
        void extra_cmt_changed_event(va_list args);

        // Variables
        std::shared_ptr<IHashProvider> hash_provider_;
        std::shared_ptr<IRepository> repo_manager_;
        Pool<qstring> qpool_;

        Eas             addresses_to_process_;
        Structs         structures_to_process_;
        StructMembers   structmember_to_process_;
        Enums           enums_to_process_;
        EnumMembers     enummember_to_process_;
        Comments        comments_to_process_;
        Segments        segments_to_process_;
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
            case envent_code::enum_member_deleted:     hooks->enum_member_deleted_event(args); break;
            case envent_code::struc_created:           hooks->struc_created_event(args); break;
            case envent_code::deleting_struc:          hooks->deleting_struc_event(args); break;
            case envent_code::struc_deleted:           hooks->struc_deleted_event(args); break;
            case envent_code::changing_struc_align:    hooks->changing_struc_align_event(args); break;
            case envent_code::struc_align_changed:     hooks->struc_align_changed_event(args); break;
            case envent_code::renaming_struc:          hooks->renaming_struc_event(args); break;
            case envent_code::struc_renamed:           hooks->struc_renamed_event(args); break;
            case envent_code::expanding_struc:         hooks->expanding_struc_event(args); break;
            case envent_code::struc_expanded:          hooks->struc_expanded_event(args); break;
            case envent_code::struc_member_created:    hooks->struc_member_created_event(args); break;
            case envent_code::deleting_struc_member:   hooks->deleting_struc_member_event(args); break;
            case envent_code::struc_member_deleted:    hooks->struc_member_deleted_event(args); break;
            case envent_code::renaming_struc_member:   hooks->renaming_struc_member_event(args); break;
            case envent_code::struc_member_renamed:    hooks->struc_member_renamed_event(args); break;
            case envent_code::changing_struc_member:   hooks->changing_struc_member_event(args); break;
            case envent_code::struc_member_changed:    hooks->struc_member_changed_event(args); break;
            case envent_code::changing_struc_cmt:      hooks->changing_struc_cmt_event(args); break;
            case envent_code::struc_cmt_changed:       hooks->struc_cmt_changed_event(args); break;
            case envent_code::segm_added:              hooks->segm_added_event(args); break;
            case envent_code::deleting_segm:           hooks->deleting_segm_event(args); break;
            case envent_code::segm_deleted:            hooks->segm_deleted_event(args); break;
            case envent_code::changing_segm_start:     hooks->changing_segm_start_event(args); break;
            case envent_code::segm_start_changed:      hooks->segm_start_changed_event(args); break;
            case envent_code::changing_segm_end:       hooks->changing_segm_end_event(args); break;
            case envent_code::segm_end_changed:        hooks->segm_end_changed_event(args); break;
            case envent_code::changing_segm_name:      hooks->changing_segm_name_event(args); break;
            case envent_code::segm_name_changed:       hooks->segm_name_changed_event(args); break;
            case envent_code::changing_segm_class:     hooks->changing_segm_class_event(args); break;
            case envent_code::segm_class_changed:      hooks->segm_class_changed_event(args); break;
            case envent_code::segm_attrs_updated:      hooks->segm_attrs_updated_event(args); break;
            case envent_code::segm_moved:              hooks->segm_moved_event(args); break;
            case envent_code::allsegs_moved:           hooks->allsegs_moved_event(args); break;
            case envent_code::func_added:              hooks->func_added_event(args); break;
            case envent_code::func_updated:            hooks->func_updated_event(args); break;
            case envent_code::set_func_start:          hooks->set_func_start_event(args); break;
            case envent_code::set_func_end:            hooks->set_func_end_event(args); break;
            case envent_code::deleting_func:           hooks->deleting_func_event(args); break;
            case envent_code::frame_deleted:           hooks->frame_deleted_event(args); break;
            case envent_code::thunk_func_created:      hooks->thunk_func_created_event(args); break;
            case envent_code::func_tail_appended:      hooks->func_tail_appended_event(args); break;
            case envent_code::deleting_func_tail:      hooks->deleting_func_tail_event(args); break;
            case envent_code::func_tail_deleted:       hooks->func_tail_deleted_event(args); break;
            case envent_code::tail_owner_changed:      hooks->tail_owner_changed_event(args); break;
            case envent_code::func_noret_changed:      hooks->func_noret_changed_event(args); break;
            case envent_code::stkpnts_changed:         hooks->stkpnts_changed_event(args); break;
            case envent_code::updating_tryblks:        hooks->updating_tryblks_event(args); break;
            case envent_code::tryblks_updated:         hooks->tryblks_updated_event(args); break;
            case envent_code::deleting_tryblks:        hooks->deleting_tryblks_event(args); break;
            case envent_code::sgr_changed:             hooks->sgr_changed_event(args); break;
            case envent_code::make_code:               hooks->make_code_event(args); break;
            case envent_code::make_data:               hooks->make_data_event(args); break;
            case envent_code::destroyed_items:         hooks->destroyed_items_event(args); break;
            case envent_code::renamed:                 hooks->renamed_event(args); break;
            case envent_code::byte_patched:            hooks->byte_patched_event(args); break;
            case envent_code::changing_cmt:            hooks->changing_cmt_event(args); break;
            case envent_code::cmt_changed:             hooks->cmt_changed_event(args); break;
            case envent_code::changing_range_cmt:      hooks->changing_range_cmt_event(args); break;
            case envent_code::range_cmt_changed:       hooks->range_cmt_changed_event(args); break;
            case envent_code::extra_cmt_changed:       hooks->extra_cmt_changed_event(args); break;
        }
        return 0;
    }
}

Hooks::Hooks(const std::shared_ptr<IHashProvider>& hash_provider, const std::shared_ptr<IRepository>& repo_manager)
    : hash_provider_{ hash_provider }
    , repo_manager_{ repo_manager }
    , qpool_(3)
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
    const auto member_id_fullname = qpool_.acquire();
    get_member_fullname(&*member_id_fullname, member_id);
    message += member_id_fullname->c_str();
    add_strucmember_to_process(struct_id, member_offset, message);
}

void Hooks::delete_structure_member(tid_t struct_id, ea_t offset)
{
    add_strucmember_to_process(struct_id, offset, "Member deleted");
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

void Hooks::update_segment(ea_t start_ea)
{
    segments_to_process_.insert(start_ea);
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
    for (const ea_t ea : comments_to_process_)
        add_address_to_process(ea, "Changed comment");

    // process structures
    save_structures(ida_model, db.visitor.get());

    // process enums
    save_enums(ida_model, db.visitor.get());

    // process addresses
    for (const ea_t ea : addresses_to_process_)
        ida_model->accept_ea(*db.visitor, ea);

    // process segments
    for (const ea_t segment_ea : segments_to_process_)
        ida_model->accept_segment(*db.visitor, segment_ea);

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

void Hooks::add_strucmember_to_process(ea_t struct_id, ea_t member_offset, const std::string& message)
{
    structmember_to_process_[struct_id] = member_offset;
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
    for (const std::pair<const tid_t, ea_t>& struct_info : structmember_to_process_)
    {
        tid_t struct_id = struct_info.first;
        ea_t member_offset = struct_info.second;

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
        const auto func_name = qpool_.acquire();
        get_func_name(&*func_name, fc->pfn->start_ea);
        LOG_EVENT("Gui has retrieved a function flow chart (from " EA_FMT " to " EA_FMT ", name: %s, function: %s)", fc->bounds.start_ea, fc->bounds.end_ea, fc->title.c_str(), func_name->c_str());
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

    change_operand_type(ea);

    UNUSED(n);
    if (LOG_EVENTS)
        LOG_EVENT("An operand type (offset, hex, etc...) has been set or deleted (ea: " EA_FMT ")", ea);
}

void Hooks::enum_created_event(va_list args)
{
    enum_t id = va_arg(args, enum_t);

    update_enum(id);

    if (LOG_EVENTS)
    {
        const auto enum_name = qpool_.acquire();
        get_enum_name(&*enum_name, id);
        LOG_EVENT("Enum type %s has been created", enum_name->c_str());
    }
}

void Hooks::deleting_enum_event(va_list args)
{
    enum_t id = va_arg(args, enum_t);

    if (LOG_EVENTS)
    {
        const auto enum_name = qpool_.acquire();
        get_enum_name(&*enum_name, id);
        LOG_EVENT("Enum type %s is to be deleted", enum_name->c_str());
    }
}

void Hooks::enum_deleted_event(va_list args)
{
    enum_t id = va_arg(args, enum_t);

    update_enum(id);

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
        const auto enum_name = qpool_.acquire();
        if (is_enum)
        {
            get_enum_name(&*enum_name, id);
            LOG_EVENT("Enum type %s is to be renamed to %s", enum_name->c_str(), newname);
        }
        else
        {
            const auto enum_member_name = qpool_.acquire();
            get_enum_member_name(&*enum_member_name, id);
            get_enum_name(&*enum_name, get_enum_member_enum(id));
            LOG_EVENT("A member of enum type %s is to be renamed from %s to %s", enum_name->c_str(), enum_member_name->c_str(), newname);
        }
    }
}

void Hooks::enum_renamed_event(va_list args)
{
    tid_t id = va_arg(args, tid_t);

    update_enum(id);

    if (LOG_EVENTS)
    {
        const auto enum_name = qpool_.acquire();
        if (get_enum_member_enum(id) == BADADDR)
        {
            get_enum_name(&*enum_name, id);
            LOG_EVENT("An enum type has been renamed %s", enum_name->c_str());
        }
        else
        {
            const auto enum_member_name = qpool_.acquire();
            get_enum_member_name(&*enum_member_name, id);
            get_enum_name(&*enum_name, get_enum_member_enum(id));
            LOG_EVENT("A member of enum type %s has been renamed %s", enum_name->c_str(), enum_member_name->c_str());
        }
    }
}

void Hooks::changing_enum_bf_event(va_list args)
{
    enum_t id = va_arg(args, enum_t);
    bool new_bf = static_cast<bool>(va_arg(args, int));

    if (LOG_EVENTS)
    {
        const auto enum_name = qpool_.acquire();
        get_enum_name(&*enum_name, id);
        LOG_EVENT("Enum type %s 'bitfield' attribute is to be changed to %s", enum_name->c_str(), BOOL_STR[new_bf]);
    }
}

void Hooks::enum_bf_changed_event(va_list args)
{
    enum_t id = va_arg(args, enum_t);

    update_enum(id);

    if (LOG_EVENTS)
    {
        const auto enum_name = qpool_.acquire();
        get_enum_name(&*enum_name, id);
        LOG_EVENT("Enum type %s 'bitfield' attribute has been changed", enum_name->c_str());
    }
}

void Hooks::changing_enum_cmt_event(va_list args)
{
    enum_t id = va_arg(args, enum_t);
    bool repeatable = static_cast<bool>(va_arg(args, int));
    const char* newcmt = va_arg(args, const char*);

    if (LOG_EVENTS)
    {
        const auto enum_name = qpool_.acquire();
        const auto cmt = qpool_.acquire();
        if (get_enum_member_enum(id) == BADADDR)
        {
            get_enum_name(&*enum_name, id);
            get_enum_cmt(&*cmt, id, repeatable);
            LOG_EVENT("Enum type %s %scomment is to be changed from \"%s\" to \"%s\"", enum_name->c_str(), REPEATABLE_STR[repeatable], cmt->c_str(), newcmt);
        }
        else
        {
            const auto enum_member_name = qpool_.acquire();
            get_enum_member_name(&*enum_member_name, id);
            get_enum_name(&*enum_name, get_enum_member_enum(id));
            get_enum_member_cmt(&*cmt, id, repeatable);
            LOG_EVENT("Enum type %s member %s %scomment is to be changed from \"%s\" to \"%s\"", enum_name->c_str(), enum_member_name->c_str(), REPEATABLE_STR[repeatable], cmt->c_str(), newcmt);
        }
    }
}

void Hooks::enum_cmt_changed_event(va_list args)
{
    enum_t id = va_arg(args, enum_t);
    bool repeatable = static_cast<bool>(va_arg(args, int));

    enum_t enum_id = get_enum_member_enum(id);
    if (enum_id == BADADDR)
        enum_id = id;

    update_enum(enum_id);

    if (LOG_EVENTS)
    {
        const auto enum_name = qpool_.acquire();
        const auto cmt = qpool_.acquire();
        if (enum_id == id)
        {
            get_enum_name(&*enum_name, id);
            get_enum_cmt(&*cmt, id, repeatable);
            LOG_EVENT("Enum type %s %scomment has been changed to \"%s\"", enum_name->c_str(), REPEATABLE_STR[repeatable], cmt->c_str());
        }
        else
        {
            const auto enum_member_name = qpool_.acquire();
            get_enum_member_name(&*enum_member_name, id);
            get_enum_name(&*enum_name, get_enum_member_enum(id));
            get_enum_member_cmt(&*cmt, id, repeatable);
            LOG_EVENT("Enum type %s member %s %scomment has been changed to \"%s\"", enum_name->c_str(), enum_member_name->c_str(), REPEATABLE_STR[repeatable], cmt->c_str());
        }
    }
}

void Hooks::enum_member_created_event(va_list args)
{
    enum_t id = va_arg(args, enum_t);
    const_t cid = va_arg(args, const_t);

    update_enum(id);

    if (LOG_EVENTS)
    {
        const auto enum_name = qpool_.acquire();
        get_enum_name(&*enum_name, id);
        const auto enum_member_name = qpool_.acquire();
        get_enum_member_name(&*enum_member_name, cid);
        LOG_EVENT("Enum type %s member %s has been created", enum_name->c_str(), enum_member_name->c_str());
    }
}

void Hooks::deleting_enum_member_event(va_list args)
{
    enum_t id = va_arg(args, enum_t);
    const_t cid = va_arg(args, const_t);

    if (LOG_EVENTS)
    {
        const auto enum_name = qpool_.acquire();
        get_enum_name(&*enum_name, id);
        const auto enum_member_name = qpool_.acquire();
        get_enum_member_name(&*enum_member_name, cid);
        LOG_EVENT("Enum type %s member %s is to be deleted", enum_name->c_str(), enum_member_name->c_str());
    }
}

void Hooks::enum_member_deleted_event(va_list args)
{
    enum_t id = va_arg(args, enum_t);
    const_t cid = va_arg(args, const_t);

    update_enum(id);

    UNUSED(cid);
    if (LOG_EVENTS)
    {
        const auto enum_name = qpool_.acquire();
        get_enum_name(&*enum_name, id);
        LOG_EVENT("A member of enum type %s has been deleted", enum_name->c_str());
    }
}

void Hooks::struc_created_event(va_list args)
{
    tid_t struc_id = va_arg(args, tid_t);

    update_structure(struc_id);

    if (LOG_EVENTS)
    {
        ea_t func_ea = get_func_by_frame(struc_id);
        if (func_ea != BADADDR)
        {
            const auto func_name = qpool_.acquire();
            get_func_name(&*func_name, func_ea);
            LOG_EVENT("Stackframe of function %s has been created", func_name->c_str());
        }
        else
        {
            const auto struc_name = qpool_.acquire();
            get_struc_name(&*struc_name, struc_id);
            LOG_EVENT("Structure type %s has been created", struc_name->c_str());
        }
    }
}

void Hooks::deleting_struc_event(va_list args)
{
    struc_t* sptr = va_arg(args, struc_t*);

    if (LOG_EVENTS)
    {
        ea_t func_ea = get_func_by_frame(sptr->id);
        if (func_ea != BADADDR)
        {
            const auto func_name = qpool_.acquire();
            get_func_name(&*func_name, func_ea);
            LOG_EVENT("Stackframe of function %s is to be deleted", func_name->c_str());
        }
        else
        {
            const auto struc_name = qpool_.acquire();
            get_struc_name(&*struc_name, sptr->id);
            LOG_EVENT("Structure type %s is to be deleted", struc_name->c_str());
        }
    }
}

void Hooks::struc_deleted_event(va_list args)
{
    tid_t struc_id = va_arg(args, tid_t);

    update_structure(struc_id);

    UNUSED(struc_id);
    if (LOG_EVENTS)
        LOG_EVENT("A structure type or stackframe has been deleted");
}

void Hooks::changing_struc_align_event(va_list args)
{
    struc_t* sptr = va_arg(args, struc_t*);

    if (LOG_EVENTS)
    {
        const auto struc_name = qpool_.acquire();
        get_struc_name(&*struc_name, sptr->id);
        LOG_EVENT("Structure type %s alignment is being changed from 0x%X", struc_name->c_str(), static_cast<int>(std::pow(2, sptr->get_alignment())));
    }
}

void Hooks::struc_align_changed_event(va_list args)
{
    struc_t* sptr = va_arg(args, struc_t*);

    if (LOG_EVENTS)
    {
        const auto struc_name = qpool_.acquire();
        get_struc_name(&*struc_name, sptr->id);
        LOG_EVENT("Structure type %s alignment has been changed to 0x%X", struc_name->c_str(), static_cast<int>(std::pow(2, sptr->get_alignment())));
    }
}

void Hooks::renaming_struc_event(va_list args)
{
    tid_t struc_id = va_arg(args, tid_t);
    const char* oldname = va_arg(args, const char*);
    const char* newname = va_arg(args, const char*);

    UNUSED(struc_id);
    if (LOG_EVENTS)
        LOG_EVENT("Structure type %s is to be renamed to %s", oldname, newname);
}

void Hooks::struc_renamed_event(va_list args)
{
    struc_t* sptr = va_arg(args, struc_t*);

    update_structure(sptr->id);

    if (LOG_EVENTS)
    {
        const auto struc_name = qpool_.acquire();
        get_struc_name(&*struc_name, sptr->id);
        LOG_EVENT("A structure type has been renamed %s", struc_name->c_str());
    }
}

void Hooks::expanding_struc_event(va_list args)
{
    struc_t* sptr = va_arg(args, struc_t*);
    ea_t offset = va_arg(args, ea_t);
    adiff_t delta = va_arg(args, adiff_t);

    if (LOG_EVENTS)
    {
        ea_t func_ea = get_func_by_frame(sptr->id);
        if (func_ea != BADADDR)
        {
            const auto func_name = qpool_.acquire();
            get_func_name(&*func_name, func_ea);
            if (delta > 0)
                LOG_EVENT("Stackframe of function %s is to be expanded of 0x%" EA_PREFIX "X bytes at offset 0x%" EA_PREFIX "X", func_name->c_str(), delta, offset);
            else
                LOG_EVENT("Stackframe of function %s is to be shrunk of 0x%" EA_PREFIX "X bytes at offset 0x%" EA_PREFIX "X", func_name->c_str(), ~delta + 1, offset);
        }
        else
        {
            const auto struc_name = qpool_.acquire();
            get_struc_name(&*struc_name, sptr->id);
            if (delta > 0)
                LOG_EVENT("Structure type %s is to be expanded of 0x%" EA_PREFIX "X bytes at offset 0x%" EA_PREFIX "X", struc_name->c_str(), delta, offset);
            else
                LOG_EVENT("Structure type %s is to be shrunk of 0x%" EA_PREFIX "X bytes at offset 0x%" EA_PREFIX "X", struc_name->c_str(), ~delta + 1, offset);
        }
    }
}

void Hooks::struc_expanded_event(va_list args)
{
    struc_t* sptr = va_arg(args, struc_t*);

    if (LOG_EVENTS)
    {
        ea_t func_ea = get_func_by_frame(sptr->id);
        if (func_ea != BADADDR)
        {
            const auto func_name = qpool_.acquire();
            get_func_name(&*func_name, func_ea);
            LOG_EVENT("Stackframe of function %s has been expanded/shrank", func_name->c_str());
        }
        else
        {
            const auto struc_name = qpool_.acquire();
            get_struc_name(&*struc_name, sptr->id);
            LOG_EVENT("Structure type %s has been expanded/shrank", struc_name->c_str());
        }
    }
}

void Hooks::struc_member_created_event(va_list args)
{
    struc_t* sptr = va_arg(args, struc_t*);
    member_t* mptr = va_arg(args, member_t*);

    update_structure(sptr->id);

    if (LOG_EVENTS)
    {
        const auto member_name = qpool_.acquire();
        get_member_name(&*member_name, mptr->id);
        ea_t func_ea = get_func_by_frame(sptr->id);
        if (func_ea != BADADDR)
        {
            const auto func_name = qpool_.acquire();
            get_func_name(&*func_name, func_ea);
            LOG_EVENT("Stackframe of function %s member %s has been created", func_name->c_str(), member_name->c_str());
        }
        else
        {
            const auto struc_name = qpool_.acquire();
            get_struc_name(&*struc_name, sptr->id);
            LOG_EVENT("Structure type %s member %s has been created", struc_name->c_str(), member_name->c_str());
        }
    }
}

void Hooks::deleting_struc_member_event(va_list args)
{
    struc_t* sptr = va_arg(args, struc_t*);
    member_t* mptr = va_arg(args, member_t*);

    if (LOG_EVENTS)
    {
        const auto member_name = qpool_.acquire();
        get_member_name(&*member_name, mptr->id);
        ea_t func_ea = get_func_by_frame(sptr->id);
        if (func_ea != BADADDR)
        {
            const auto func_name = qpool_.acquire();
            get_func_name(&*func_name, func_ea);
            LOG_EVENT("Stackframe of function %s member %s is to be deleted", func_name->c_str(), member_name->c_str());
        }
        else
        {
            const auto struc_name = qpool_.acquire();
            get_struc_name(&*struc_name, sptr->id);
            LOG_EVENT("Structure type %s member %s is to be deleted", struc_name->c_str(), member_name->c_str());
        }
    }
}

void Hooks::struc_member_deleted_event(va_list args)
{
    struc_t* sptr = va_arg(args, struc_t*);
    tid_t member_id = va_arg(args, tid_t);
    ea_t offset = va_arg(args, ea_t);

    delete_structure_member(sptr->id, offset);

    UNUSED(member_id);
    if (LOG_EVENTS)
    {
        ea_t func_ea = get_func_by_frame(sptr->id);
        if (func_ea != BADADDR)
        {
            const auto func_name = qpool_.acquire();
            get_func_name(&*func_name, func_ea);
            LOG_EVENT("Stackframe of function %s member at offset 0x%" EA_PREFIX "X has been deleted", func_name->c_str(), offset);
        }
        else
        {
            const auto struc_name = qpool_.acquire();
            get_struc_name(&*struc_name, sptr->id);
            LOG_EVENT("Structure type %s member at offset 0x%" EA_PREFIX "X has been deleted", struc_name->c_str(), offset);
        }
    }
}

void Hooks::renaming_struc_member_event(va_list args)
{
    struc_t* sptr = va_arg(args, struc_t*);
    member_t* mptr = va_arg(args, member_t*);
    const char* newname = va_arg(args, const char*);

    if (LOG_EVENTS)
    {
        const auto member_name = qpool_.acquire();
        get_member_name(&*member_name, mptr->id);
        ea_t func_ea = get_func_by_frame(sptr->id);
        if (func_ea != BADADDR)
        {
            const auto func_name = qpool_.acquire();
            get_func_name(&*func_name, func_ea);
            LOG_EVENT("A member of stackframe of function %s is to be renamed from %s to %s", func_name->c_str(), member_name->c_str(), newname);
        }
        else
        {
            const auto struc_name = qpool_.acquire();
            get_struc_name(&*struc_name, sptr->id);
            LOG_EVENT("A member of structure type %s is to be renamed from %s to %s", struc_name->c_str(), member_name->c_str(), newname);
        }
    }
}

void Hooks::struc_member_renamed_event(va_list args)
{
    struc_t* sptr = va_arg(args, struc_t*);
    member_t* mptr = va_arg(args, member_t*);

    update_structure_member(sptr->id, mptr->id, mptr->eoff);

    if (LOG_EVENTS)
    {
        const auto member_name = qpool_.acquire();
        get_member_name(&*member_name, mptr->id);
        ea_t func_ea = get_func_by_frame(sptr->id);
        if (func_ea != BADADDR)
        {
            const auto func_name = qpool_.acquire();
            get_func_name(&*func_name, func_ea);
            LOG_EVENT("A member of stackframe of function %s has been renamed to %s", func_name->c_str(), member_name->c_str());
        }
        else
        {
            const auto struc_name = qpool_.acquire();
            get_struc_name(&*struc_name, sptr->id);
            LOG_EVENT("A member of structure type %s has been renamed to %s", struc_name->c_str(), member_name->c_str());
        }
    }
}

void Hooks::changing_struc_member_event(va_list args)
{
    struc_t* sptr = va_arg(args, struc_t*);
    member_t* mptr = va_arg(args, member_t*);
    flags_t flag = va_arg(args, flags_t);
    const opinfo_t* ti = va_arg(args, const opinfo_t*);
    asize_t nbytes = va_arg(args, asize_t);

    UNUSED(flag);
    UNUSED(ti);
    UNUSED(nbytes);
    if (LOG_EVENTS)
    {
        const auto member_name = qpool_.acquire();
        get_member_name(&*member_name, mptr->id);
        ea_t func_ea = get_func_by_frame(sptr->id);
        if (func_ea != BADADDR)
        {
            const auto func_name = qpool_.acquire();
            get_func_name(&*func_name, func_ea);
            LOG_EVENT("Stackframe of function %s member %s is to be changed", func_name->c_str(), member_name->c_str());
        }
        else
        {
            const auto struc_name = qpool_.acquire();
            get_struc_name(&*struc_name, sptr->id);
            LOG_EVENT("Structure type %s member %s is to be changed", struc_name->c_str(), member_name->c_str());
        }
    }
}

void Hooks::struc_member_changed_event(va_list args)
{
    struc_t* sptr = va_arg(args, struc_t*);
    member_t* mptr = va_arg(args, member_t*);

    update_structure(sptr->id);
    update_structure_member(sptr->id, mptr->id, mptr->eoff);

    if (LOG_EVENTS)
    {
        const auto member_name = qpool_.acquire();
        get_member_name(&*member_name, mptr->id);
        ea_t func_ea = get_func_by_frame(sptr->id);
        if (func_ea != BADADDR)
        {
            const auto func_name = qpool_.acquire();
            get_func_name(&*func_name, func_ea);
            LOG_EVENT("Stackframe of function %s member %s has been changed", func_name->c_str(), member_name->c_str());
        }
        else
        {
            const auto struc_name = qpool_.acquire();
            get_struc_name(&*struc_name, sptr->id);
            LOG_EVENT("Structure type %s member %s has been changed", struc_name->c_str(), member_name->c_str());
        }
    }
}

void Hooks::changing_struc_cmt_event(va_list args)
{
    tid_t struc_id = va_arg(args, tid_t);
    bool repeatable = static_cast<bool>(va_arg(args, int));
    const char* newcmt = va_arg(args, const char*);

    if (LOG_EVENTS)
    {
        const auto cmt = qpool_.acquire();
        if (get_struc(struc_id))
        {
            const auto struc_name = qpool_.acquire();
            get_struc_name(&*struc_name, struc_id);
            get_struc_cmt(&*cmt, struc_id, repeatable);
            LOG_EVENT("Structure type %s %scomment is to be changed from \"%s\" to \"%s\"", struc_name->c_str(), REPEATABLE_STR[repeatable], cmt->c_str(), newcmt);
        }
        else
        {
            get_member_cmt(&*cmt, struc_id, repeatable);
            const auto member_name = qpool_.acquire();
            get_member_name(&*member_name, struc_id);

            const auto member_fullname = qpool_.acquire();
            get_member_fullname(&*member_fullname, struc_id);
            struc_t* struc = get_member_struc(member_fullname->c_str());
            ea_t func_ea = get_func_by_frame(struc->id);
            if (func_ea != BADADDR)
            {
                const auto func_name = qpool_.acquire();
                get_func_name(&*func_name, func_ea);
                LOG_EVENT("Stackframe of function %s member %s %scomment is to be changed from \"%s\" to \"%s\"", func_name->c_str(), member_name->c_str(), REPEATABLE_STR[repeatable], cmt->c_str(), newcmt);
            }
            else
            {
                const auto struc_name = qpool_.acquire();
                get_struc_name(&*struc_name, struc->id);
                LOG_EVENT("Structure type %s member %s %scomment is to be changed from \"%s\" to \"%s\"", struc_name->c_str(), member_name->c_str(), REPEATABLE_STR[repeatable], cmt->c_str(), newcmt);
            }
        }
    }
}

void Hooks::struc_cmt_changed_event(va_list args)
{
    tid_t struc_id = va_arg(args, tid_t);
    bool repeatable = static_cast<bool>(va_arg(args, int));

    tid_t real_struc_id = struc_id;
    const bool is_member = !get_struc(struc_id);
    if (is_member)
    {
        const auto member_fullname = qpool_.acquire();
        get_member_fullname(&*member_fullname, struc_id);
        struc_t* struc = get_member_struc(member_fullname->c_str());
        if(struc)
            real_struc_id = struc->id;
    }
    update_structure(real_struc_id);

    if (LOG_EVENTS)
    {
        const auto cmt = qpool_.acquire();
        if (!is_member)
        {
            const auto struc_name = qpool_.acquire();
            get_struc_name(&*struc_name, struc_id);
            get_struc_cmt(&*cmt, struc_id, repeatable);
            LOG_EVENT("Structure type %s %scomment has been changed to \"%s\"", struc_name->c_str(), REPEATABLE_STR[repeatable], cmt->c_str());
        }
        else
        {
            get_member_cmt(&*cmt, struc_id, repeatable);
            const auto member_name = qpool_.acquire();
            get_member_name(&*member_name, struc_id);

            ea_t func_ea = get_func_by_frame(real_struc_id);
            if (func_ea != BADADDR)
            {
                const auto func_name = qpool_.acquire();
                get_func_name(&*func_name, func_ea);
                LOG_EVENT("Stackframe of function %s member %s %scomment has been changed to \"%s\"", func_name->c_str(), member_name->c_str(), REPEATABLE_STR[repeatable], cmt->c_str());
            }
            else
            {
                const auto struc_name = qpool_.acquire();
                get_struc_name(&*struc_name, real_struc_id);
                LOG_EVENT("Structure type %s member %s %scomment has been changed to \"%s\"", struc_name->c_str(), member_name->c_str(), REPEATABLE_STR[repeatable], cmt->c_str());
            }
        }
    }
}

void Hooks::segm_added_event(va_list args)
{
    segment_t* s = va_arg(args, segment_t*);

    update_segment(s->start_ea);

    if (LOG_EVENTS)
    {
        const auto segm_name = qpool_.acquire();
        get_segm_name(&*segm_name, s);
        LOG_EVENT("Segment %s has been created from " EA_FMT " to " EA_FMT, segm_name->c_str(), s->start_ea, s->end_ea);
    }
}

void Hooks::deleting_segm_event(va_list args)
{
    ea_t start_ea = va_arg(args, ea_t);

    if (LOG_EVENTS)
    {
        const segment_t* s = getseg(start_ea);
        const auto segm_name = qpool_.acquire();
        get_segm_name(&*segm_name, s);
        LOG_EVENT("Segment %s (from " EA_FMT " to " EA_FMT ") is to be deleted", segm_name->c_str(), s->start_ea, s->end_ea);
    }
}

void Hooks::segm_deleted_event(va_list args)
{
    ea_t start_ea = va_arg(args, ea_t);
    ea_t end_ea = va_arg(args, ea_t);

    update_segment(start_ea);

    if (LOG_EVENTS)
        LOG_EVENT("A segment (from " EA_FMT " to " EA_FMT ") has been deleted", start_ea, end_ea);
}

void Hooks::changing_segm_start_event(va_list args)
{
    segment_t* s = va_arg(args, segment_t*);
    ea_t new_start = va_arg(args, ea_t);
    int segmod_flags = va_arg(args, int);

    UNUSED(segmod_flags);
    if (LOG_EVENTS)
    {
        const auto segm_name = qpool_.acquire();
        get_segm_name(&*segm_name, s);
        LOG_EVENT("Segment %s start address is to be changed from " EA_FMT " to " EA_FMT, segm_name->c_str(), s->start_ea, new_start);
    }
}

void Hooks::segm_start_changed_event(va_list args)
{
    segment_t* s = va_arg(args, segment_t*);
    ea_t oldstart = va_arg(args, ea_t);

    update_segment(s->start_ea);

    if (LOG_EVENTS)
    {
        const auto segm_name = qpool_.acquire();
        get_segm_name(&*segm_name, s);
        LOG_EVENT("Segment %s start address has been changed from " EA_FMT " to " EA_FMT, segm_name->c_str(), oldstart, s->start_ea);
    }
}

void Hooks::changing_segm_end_event(va_list args)
{
    segment_t* s = va_arg(args, segment_t*);
    ea_t new_end = va_arg(args, ea_t);
    int segmod_flags = va_arg(args, int);

    UNUSED(segmod_flags);
    if (LOG_EVENTS)
    {
        const auto segm_name = qpool_.acquire();
        get_segm_name(&*segm_name, s);
        LOG_EVENT("Segment %s end address is to be changed from " EA_FMT " to " EA_FMT, segm_name->c_str(), s->end_ea, new_end);
    }
}

void Hooks::segm_end_changed_event(va_list args)
{
    segment_t* s = va_arg(args, segment_t*);
    ea_t oldend = va_arg(args, ea_t);

    update_segment(s->start_ea);

    if (LOG_EVENTS)
    {
        const auto segm_name = qpool_.acquire();
        get_segm_name(&*segm_name, s);
        LOG_EVENT("Segment %s end address has been changed from " EA_FMT " to " EA_FMT, segm_name->c_str(), oldend, s->end_ea);
    }
}

void Hooks::changing_segm_name_event(va_list args)
{
    segment_t* s = va_arg(args, segment_t*);
    const char* oldname = va_arg(args, const char*);

    UNUSED(s);
    if (LOG_EVENTS)
        LOG_EVENT("Segment %s is being renamed", oldname);
}

void Hooks::segm_name_changed_event(va_list args)
{
    segment_t* s = va_arg(args, segment_t*);
    const char* name = va_arg(args, const char*);

    update_segment(s->start_ea);

    UNUSED(s);
    if (LOG_EVENTS)
        LOG_EVENT("A segment has been renamed %s", name);
}

void Hooks::changing_segm_class_event(va_list args)
{
    segment_t* s = va_arg(args, segment_t*);

    if (LOG_EVENTS)
    {
        const auto segm_name = qpool_.acquire();
        get_segm_name(&*segm_name, s);
        const auto segm_class = qpool_.acquire();
        get_segm_class(&*segm_class, s);
        LOG_EVENT("Segment %s class is being changed from %s", segm_name->c_str(), segm_class->c_str());
    }
}

void Hooks::segm_class_changed_event(va_list args)
{
    segment_t* s = va_arg(args, segment_t*);
    const char* sclass = va_arg(args, const char*);

    update_segment(s->start_ea);

    if (LOG_EVENTS)
    {
        const auto segm_name = qpool_.acquire();
        get_segm_name(&*segm_name, s);
        LOG_EVENT("Segment %s class has been changed to %s", segm_name->c_str(), sclass);
    }
}

void Hooks::segm_attrs_updated_event(va_list args)
{
    // This event is generated for secondary segment attributes (examples: color, permissions, etc)
    segment_t* s = va_arg(args, segment_t*);

    update_segment(s->start_ea);

    if (LOG_EVENTS)
    {
        const auto segm_name = qpool_.acquire();
        get_segm_name(&*segm_name, s);
        LOG_EVENT("Segment %s attributes has been changed", segm_name->c_str());
    }
}

void Hooks::segm_moved_event(va_list args)
{
    ea_t from = va_arg(args, ea_t);
    ea_t to = va_arg(args, ea_t);
    asize_t size = va_arg(args, asize_t);
    bool changed_netmap = static_cast<bool>(va_arg(args, int));

    const segment_t* s = getseg(to);
    update_segment(s->start_ea);

    if (LOG_EVENTS)
    {
        const auto segm_name = qpool_.acquire();
        get_segm_name(&*segm_name, s);
        const char changed_netmap_txt[2][18] = { "", " (changed netmap)" };
        LOG_EVENT("Segment %s has been moved from " EA_FMT "-" EA_FMT " to " EA_FMT "-" EA_FMT "%s", segm_name->c_str(), from, from + size, to, to + size, changed_netmap_txt[changed_netmap]);
    }
}

void Hooks::allsegs_moved_event(va_list args)
{
    segm_move_infos_t* info = va_arg(args, segm_move_infos_t*);

    if (LOG_EVENTS)
        LOG_EVENT("Program rebasing is complete, %zd segments have been moved", info->size());
}

void Hooks::func_added_event(va_list args)
{
    func_t* pfn = va_arg(args, func_t*);

    add_function(pfn->start_ea);

    if (LOG_EVENTS)
    {
        const auto func_name = qpool_.acquire();
        get_func_name(&*func_name, pfn->start_ea);
        LOG_EVENT("Function %s has been created from " EA_FMT " to " EA_FMT, func_name->c_str(), pfn->start_ea, pfn->end_ea);
    }
}

void Hooks::func_updated_event(va_list args)
{
    func_t* pfn = va_arg(args, func_t*);

    update_function(pfn->start_ea);

    if (LOG_EVENTS)
    {
        const auto func_name = qpool_.acquire();
        get_func_name(&*func_name, pfn->start_ea);
        LOG_EVENT("Function %s has been updated", func_name->c_str());
    }
}

void Hooks::set_func_start_event(va_list args)
{
    func_t* pfn = va_arg(args, func_t*);
    ea_t new_start = va_arg(args, ea_t);

    update_function(pfn->start_ea);

    if (LOG_EVENTS)
    {
        const auto func_name = qpool_.acquire();
        get_func_name(&*func_name, pfn->start_ea);
        LOG_EVENT("Function %s chunk start address will be changed from " EA_FMT " to " EA_FMT, func_name->c_str(), pfn->start_ea, new_start);
    }
}

void Hooks::set_func_end_event(va_list args)
{
    func_t* pfn = va_arg(args, func_t*);
    ea_t new_end = va_arg(args, ea_t);

    update_function(pfn->start_ea);

    if (LOG_EVENTS)
    {
        const auto func_name = qpool_.acquire();
        get_func_name(&*func_name, pfn->start_ea);
        LOG_EVENT("Function %s chunk end address will be changed from " EA_FMT " to " EA_FMT, func_name->c_str(), pfn->end_ea, new_end);
    }
}

void Hooks::deleting_func_event(va_list args)
{
    func_t* pfn = va_arg(args, func_t*);

    delete_function(pfn->start_ea);

    if (LOG_EVENTS)
    {
        const auto func_name = qpool_.acquire();
        get_func_name(&*func_name, pfn->start_ea);
        LOG_EVENT("Function %s is about to be deleted (" EA_FMT " to " EA_FMT")", func_name->c_str(), pfn->start_ea, pfn->end_ea);
    }
}

void Hooks::frame_deleted_event(va_list args)
{
    func_t* pfn = va_arg(args, func_t*);

    UNUSED(pfn);
    if (LOG_EVENTS)
        LOG_EVENT("A function frame has been deleted");
}

void Hooks::thunk_func_created_event(va_list args)
{
    func_t* pfn = va_arg(args, func_t*);

    update_function(pfn->start_ea);

    if (LOG_EVENTS)
    {
        const auto func_name = qpool_.acquire();
        get_func_name(&*func_name, pfn->start_ea);
        LOG_EVENT("Function %s thunk bit has been set to %s", func_name->c_str(), BOOL_STR[!!(pfn->flags & FUNC_THUNK)]);
    }
}

void Hooks::func_tail_appended_event(va_list args)
{
    func_t* pfn = va_arg(args, func_t*);
    func_t* tail = va_arg(args, func_t*);

    update_function(pfn->start_ea);

    if (LOG_EVENTS)
    {
        const auto func_name = qpool_.acquire();
        get_func_name(&*func_name, pfn->start_ea);
        LOG_EVENT("Function %s tail chunk from " EA_FMT " to " EA_FMT " has been appended", func_name->c_str(), tail->start_ea, tail->end_ea);
    }
}

void Hooks::deleting_func_tail_event(va_list args)
{
    func_t* pfn = va_arg(args, func_t*);
    const range_t* tail = va_arg(args, const range_t*);

    if (LOG_EVENTS)
    {
        const auto func_name = qpool_.acquire();
        get_func_name(&*func_name, pfn->start_ea);
        LOG_EVENT("Function %s tail chunk from " EA_FMT " to " EA_FMT " is to be removed", func_name->c_str(), tail->start_ea, tail->end_ea);
    }
}

void Hooks::func_tail_deleted_event(va_list args)
{
    func_t* pfn = va_arg(args, func_t*);
    ea_t tail_ea = va_arg(args, ea_t);

    update_function(pfn->start_ea);

    if (LOG_EVENTS)
    {
        const auto func_name = qpool_.acquire();
        get_func_name(&*func_name, pfn->start_ea);
        LOG_EVENT("Function %s tail chunk at " EA_FMT " has been removed", func_name->c_str(), tail_ea);
    }
}

void Hooks::tail_owner_changed_event(va_list args)
{
    func_t* pfn = va_arg(args, func_t*);
    ea_t owner_func = va_arg(args, ea_t);
    ea_t old_owner = va_arg(args, ea_t);

    update_function(owner_func);
    update_function(old_owner);

    if (LOG_EVENTS)
    {
        const auto owner_func_name = qpool_.acquire();
        get_func_name(&*owner_func_name, owner_func);
        const auto old_owner_func_name = qpool_.acquire();
        get_func_name(&*old_owner_func_name, old_owner);
        LOG_EVENT("Tail chunk from " EA_FMT " to " EA_FMT " owner function changed from %s to %s", pfn->start_ea, pfn->end_ea, old_owner_func_name->c_str(), owner_func_name->c_str());
    }
}

void Hooks::func_noret_changed_event(va_list args)
{
    func_t* pfn = va_arg(args, func_t*);

    update_function(pfn->start_ea);

    if (LOG_EVENTS)
    {
        const auto func_name = qpool_.acquire();
        get_func_name(&*func_name, pfn->start_ea);
        LOG_EVENT("Function %s FUNC_NORET flag has been changed to %s", func_name->c_str(), BOOL_STR[!!(pfn->flags & FUNC_NORET)]);
    }
}

void Hooks::stkpnts_changed_event(va_list args)
{
    func_t* pfn = va_arg(args, func_t*);

    update_function(pfn->start_ea);

    if (LOG_EVENTS)
    {
        const auto func_name = qpool_.acquire();
        get_func_name(&*func_name, pfn->start_ea);
        LOG_EVENT("Function %s stack change points have been modified", func_name->c_str());
    }
}

void Hooks::updating_tryblks_event(va_list args)
{
    const tryblks_t* tbv = va_arg(args, const tryblks_t*);

    UNUSED(tbv);
    if (LOG_EVENTS)
        LOG_EVENT("About to update try block information");
}

void Hooks::tryblks_updated_event(va_list args)
{
    const tryblks_t* tbv = va_arg(args, const tryblks_t*);

    UNUSED(tbv);
    if (LOG_EVENTS)
        LOG_EVENT("Updated try block information");
}

void Hooks::deleting_tryblks_event(va_list args)
{
    const range_t* range = va_arg(args, const range_t*);

    if (LOG_EVENTS)
        LOG_EVENT("About to delete try block information in range " EA_FMT "-" EA_FMT, range->start_ea, range->end_ea);
}

void Hooks::sgr_changed_event(va_list args)
{
    ea_t start_ea = va_arg(args, ea_t);
    ea_t end_ea = va_arg(args, ea_t);
    int regnum = va_arg(args, int);
    sel_t value = va_arg(args, sel_t);
    sel_t old_value = va_arg(args, sel_t);
    uchar tag = static_cast<uchar>(va_arg(args, int));

    UNUSED(start_ea);
    UNUSED(end_ea);
    UNUSED(regnum);
    UNUSED(value);
    UNUSED(old_value);
    UNUSED(tag);
    if (LOG_EVENTS)
        LOG_EVENT("The kernel has changed a segment register value");
}

void Hooks::make_code_event(va_list args)
{
    const insn_t* insn = va_arg(args, const insn_t*);

    make_code(insn->ea);

    if (LOG_EVENTS)
        LOG_EVENT("An instruction is being created at " EA_FMT, insn->ea);
}

void Hooks::make_data_event(va_list args)
{
    ea_t ea = va_arg(args, ea_t);
    flags_t flags = va_arg(args, flags_t);
    tid_t tid = va_arg(args, tid_t);
    asize_t len = va_arg(args, asize_t);

    make_data(ea);

    UNUSED(flags);
    UNUSED(tid);
    UNUSED(len);
    if (LOG_EVENTS)
        LOG_EVENT("A data item is being created at " EA_FMT, ea);
}

void Hooks::destroyed_items_event(va_list args)
{
    ea_t ea1 = va_arg(args, ea_t);
    ea_t ea2 = va_arg(args, ea_t);
    bool will_disable_range = static_cast<bool>(va_arg(args, int));

    UNUSED(will_disable_range);
    if (LOG_EVENTS)
        LOG_EVENT("Instructions/data have been destroyed in " EA_FMT "-" EA_FMT, ea1, ea2);
}

void Hooks::renamed_event(va_list args)
{
    ea_t ea = va_arg(args, ea_t);
    const char* new_name = va_arg(args, const char*);
    bool local_name = static_cast<bool>(va_arg(args, int));

    rename(ea, new_name, "", "");

    UNUSED(local_name);
    if (LOG_EVENTS)
        LOG_EVENT("Byte at " EA_FMT " renamed to %s", ea, new_name);
}

void Hooks::byte_patched_event(va_list args)
{
    ea_t ea = va_arg(args, ea_t);
    uint32 old_value = va_arg(args, uint32);

    if (LOG_EVENTS)
        LOG_EVENT("Byte at " EA_FMT " has been changed from 0x%02X to 0x%02X", ea, old_value, get_byte(ea));
}

void Hooks::changing_cmt_event(va_list args)
{
    ea_t ea = va_arg(args, ea_t);
    bool repeatable_cmt = static_cast<bool>(va_arg(args, int));
    const char* newcmt = va_arg(args, const char*);

    if (LOG_EVENTS)
    {
        const auto cmt = qpool_.acquire();
        get_cmt(&*cmt, ea, repeatable_cmt);
        LOG_EVENT("Item at " EA_FMT " %scomment is to be changed from \"%s\" to \"%s\"", ea, REPEATABLE_STR[repeatable_cmt], cmt->c_str(), newcmt);
    }
}

void Hooks::cmt_changed_event(va_list args)
{
    ea_t ea = va_arg(args, ea_t);
    bool repeatable_cmt = static_cast<bool>(va_arg(args, int));

    change_comment(ea);

    if (LOG_EVENTS)
    {
        const auto cmt = qpool_.acquire();
        get_cmt(&*cmt, ea, repeatable_cmt);
        LOG_EVENT("Item at " EA_FMT " %scomment has been changed to \"%s\"", ea, REPEATABLE_STR[repeatable_cmt], cmt->c_str());
    }
}

void Hooks::changing_range_cmt_event(va_list args)
{
    range_kind_t kind = static_cast<range_kind_t>(va_arg(args, int));
    const range_t* a = va_arg(args, const range_t*);
    const char* cmt = va_arg(args, const char*);
    bool repeatable = static_cast<bool>(va_arg(args, int));

    if (LOG_EVENTS)
        LOG_EVENT("%s range from " EA_FMT " to " EA_FMT " %scomment is to be changed to \"%s\"", range_kind_to_str(kind), a->start_ea, a->end_ea, REPEATABLE_STR[repeatable], cmt);
}

void Hooks::range_cmt_changed_event(va_list args)
{
    range_kind_t kind = static_cast<range_kind_t>(va_arg(args, int));
    const range_t* a = va_arg(args, const range_t*);
    const char* cmt = va_arg(args, const char*);
    bool repeatable = static_cast<bool>(va_arg(args, int));

    change_comment(a->start_ea);

    if (LOG_EVENTS)
        LOG_EVENT("%s range from " EA_FMT " to " EA_FMT " %scomment has been changed to \"%s\"", range_kind_to_str(kind), a->start_ea, a->end_ea, REPEATABLE_STR[repeatable], cmt);
}

void Hooks::extra_cmt_changed_event(va_list args)
{
    ea_t ea = va_arg(args, ea_t);
    int line_idx = va_arg(args, int);
    const char* cmt = va_arg(args, const char*);

    change_comment(ea);

    UNUSED(line_idx);
    if (LOG_EVENTS)
        LOG_EVENT("Extra comment at " EA_FMT " has been changed to \"%s\"", ea, cmt);
}


std::shared_ptr<IHooks> MakeHooks(const std::shared_ptr<IHashProvider>& hash_provider, const std::shared_ptr<IRepository>& repo_manager)
{
    return std::make_shared<Hooks>(hash_provider, repo_manager);
}
