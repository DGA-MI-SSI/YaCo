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

#include "YaCo.hpp"
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

    qstring get_func_name(ea_t ea)
    {
        qstring name;
        get_func_name(&name, ea);
        return name;
    }

    qstring get_enum_member_name(ea_t ea)
    {
        qstring name;
        get_enum_member_name(&name, ea);
        return name;
    }

    qstring get_enum_cmt(enum_t id, bool repeatable)
    {
        qstring name;
        get_enum_cmt(&name, id, repeatable);
        return name;
    }

    qstring get_enum_member_cmt(enum_t id, bool repeatable)
    {
        qstring name;
        get_enum_member_cmt(&name, id, repeatable);
        return name;
    }

    qstring get_struc_cmt(tid_t id, bool repeatable)
    {
        qstring cmt;
        get_struc_cmt(&cmt, id, repeatable);
        return cmt;
    }

    qstring get_member_cmt(tid_t mid, bool repeatable)
    {
        qstring cmt;
        get_member_cmt(&cmt, mid, repeatable);
        return cmt;
    }

    qstring get_member_fullname(tid_t mid)
    {
        qstring name;
        get_member_fullname(&name, mid);
        return name;
    }

    qstring get_segm_name(const segment_t *s)
    {
        qstring name;
        get_segm_name(&name, s);
        return name;
    }

    qstring get_segm_class(const segment_t *s)
    {
        qstring name;
        get_segm_class(&name, s);
        return name;
    }

    qstring get_cmt(ea_t ea, bool repeatable)
    {
        qstring name;
        get_cmt(&name, ea, repeatable);
        return name;
    }

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

        Hooks(IYaCo& yaco, IHashProvider& hash_provider, IRepository& repo_manager);

        // IHooks
        void rename(ea_t ea, const std::string& new_name, const std::string& type, const std::string& old_name) override;
        void update_comment(ea_t ea) override;
        void undefine(ea_t ea) override;
        void delete_function(ea_t ea) override;
        void make_code(ea_t ea) override;
        void make_data(ea_t ea) override;
        void add_function(ea_t ea) override;
        void update_function(ea_t ea) override;
        void update_struct(ea_t struct_id) override;
        void update_struct_member(tid_t struct_id, tid_t member_id, ea_t offset) override;
        void delete_struct_member(tid_t struct_id, ea_t offset) override;
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
        void add_ea(ea_t ea, const std::string& message);
        void add_struct_member(ea_t struct_id, ea_t member_offset, const std::string& message);

        void save_structs(const std::shared_ptr<IModelIncremental>& ida_model, IModelVisitor* memory_exporter);
        void save_enums(const std::shared_ptr<IModelIncremental>& ida_model, IModelVisitor* memory_exporter);

        // Events management
        void closebase(va_list args);
        void savebase(va_list args);
        void upgraded(va_list args);
        void auto_empty(va_list args);
        void auto_empty_finally(va_list args);
        void determined_main(va_list args);
        void local_types_changed(va_list args);
        void extlang_changed(va_list args);
        void idasgn_loaded(va_list args);
        void kernel_config_loaded(va_list args);
        void loader_finished(va_list args);
        void flow_chart_created(va_list args);
        void compiler_changed(va_list args);
        void changing_ti(va_list args);
        void ti_changed(va_list args);
        void changing_op_ti(va_list args);
        void op_ti_changed(va_list args);
        void changing_op_type(va_list args);
        void op_type_changed(va_list args);
        void enum_created(va_list args);
        void deleting_enum(va_list args);
        void enum_deleted(va_list args);
        void renaming_enum(va_list args);
        void enum_renamed(va_list args);
        void changing_enum_bf(va_list args);
        void enum_bf_changed(va_list args);
        void changing_enum_cmt(va_list args);
        void enum_cmt_changed(va_list args);
        void enum_member_created(va_list args);
        void deleting_enum_member(va_list args);
        void enum_member_deleted(va_list args);
        void struc_created(va_list args);
        void deleting_struc(va_list args);
        void struc_deleted(va_list args);
        void changing_struc_align(va_list args);
        void struc_align_changed(va_list args);
        void renaming_struc(va_list args);
        void struc_renamed(va_list args);
        void expanding_struc(va_list args);
        void struc_expanded(va_list args);
        void struc_member_created(va_list args);
        void deleting_struc_member(va_list args);
        void struc_member_deleted(va_list args);
        void renaming_struc_member(va_list args);
        void struc_member_renamed(va_list args);
        void changing_struc_member(va_list args);
        void struc_member_changed(va_list args);
        void changing_struc_cmt(va_list args);
        void struc_cmt_changed(va_list args);
        void segm_added(va_list args);
        void deleting_segm(va_list args);
        void segm_deleted(va_list args);
        void changing_segm_start(va_list args);
        void segm_start_changed(va_list args);
        void changing_segm_end(va_list args);
        void segm_end_changed(va_list args);
        void changing_segm_name(va_list args);
        void segm_name_changed(va_list args);
        void changing_segm_class(va_list args);
        void segm_class_changed(va_list args);
        void segm_attrs_updated(va_list args);
        void segm_moved(va_list args);
        void allsegs_moved(va_list args);
        void func_added(va_list args);
        void func_updated(va_list args);
        void set_func_start(va_list args);
        void set_func_end(va_list args);
        void deleting_func(va_list args);
        void frame_deleted(va_list args);
        void thunk_func_created(va_list args);
        void func_tail_appended(va_list args);
        void deleting_func_tail(va_list args);
        void func_tail_deleted(va_list args);
        void tail_owner_changed(va_list args);
        void func_noret_changed(va_list args);
        void stkpnts_changed(va_list args);
        void updating_tryblks(va_list args);
        void tryblks_updated(va_list args);
        void deleting_tryblks(va_list args);
        void sgr_changed(va_list args);
        void make_code(va_list args);
        void make_data(va_list args);
        void destroyed_items(va_list args);
        void renamed(va_list args);
        void byte_patched(va_list args);
        void changing_cmt(va_list args);
        void cmt_changed(va_list args);
        void changing_range_cmt(va_list args);
        void range_cmt_changed(va_list args);
        void extra_cmt_changed(va_list args);

        // Variables
        IYaCo&           yaco_;
        IHashProvider&   hash_provider_;
        IRepository&     repo_manager_;
        Pool<qstring>    qpool_;

        Eas             eas_;
        Structs         structs_;
        StructMembers   struct_members_;
        Enums           enums_;
        EnumMembers     enum_members_;
        Comments        comments_;
        Segments        segments_;
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
            case envent_code::closebase:               hooks->closebase(args); break;
            case envent_code::savebase:                hooks->savebase(args); break;
            case envent_code::upgraded:                hooks->upgraded(args); break;
            case envent_code::auto_empty:              hooks->auto_empty(args); break;
            case envent_code::auto_empty_finally:      hooks->auto_empty_finally(args); break;
            case envent_code::determined_main:         hooks->determined_main(args); break;
            case envent_code::local_types_changed:     hooks->local_types_changed(args); break;
            case envent_code::extlang_changed:         hooks->extlang_changed(args); break;
            case envent_code::idasgn_loaded:           hooks->idasgn_loaded(args); break;
            case envent_code::kernel_config_loaded:    hooks->kernel_config_loaded(args); break;
            case envent_code::loader_finished:         hooks->loader_finished(args); break;
            case envent_code::flow_chart_created:      hooks->flow_chart_created(args); break;
            case envent_code::compiler_changed:        hooks->compiler_changed(args); break;
            case envent_code::changing_ti:             hooks->changing_ti(args); break;
            case envent_code::ti_changed:              hooks->ti_changed(args); break;
            case envent_code::changing_op_ti:          hooks->changing_op_ti(args); break;
            case envent_code::op_ti_changed:           hooks->op_ti_changed(args); break;
            case envent_code::changing_op_type:        hooks->changing_op_type(args); break;
            case envent_code::op_type_changed:         hooks->op_type_changed(args); break;
            case envent_code::enum_created:            hooks->enum_created(args); break;
            case envent_code::deleting_enum:           hooks->deleting_enum(args); break;
            case envent_code::enum_deleted:            hooks->enum_deleted(args); break;
            case envent_code::renaming_enum:           hooks->renaming_enum(args); break;
            case envent_code::enum_renamed:            hooks->enum_renamed(args); break;
            case envent_code::changing_enum_bf:        hooks->changing_enum_bf(args); break;
            case envent_code::enum_bf_changed:         hooks->enum_bf_changed(args); break;
            case envent_code::changing_enum_cmt:       hooks->changing_enum_cmt(args); break;
            case envent_code::enum_cmt_changed:        hooks->enum_cmt_changed(args); break;
            case envent_code::enum_member_created:     hooks->enum_member_created(args); break;
            case envent_code::deleting_enum_member:    hooks->deleting_enum_member(args); break;
            case envent_code::enum_member_deleted:     hooks->enum_member_deleted(args); break;
            case envent_code::struc_created:           hooks->struc_created(args); break;
            case envent_code::deleting_struc:          hooks->deleting_struc(args); break;
            case envent_code::struc_deleted:           hooks->struc_deleted(args); break;
            case envent_code::changing_struc_align:    hooks->changing_struc_align(args); break;
            case envent_code::struc_align_changed:     hooks->struc_align_changed(args); break;
            case envent_code::renaming_struc:          hooks->renaming_struc(args); break;
            case envent_code::struc_renamed:           hooks->struc_renamed(args); break;
            case envent_code::expanding_struc:         hooks->expanding_struc(args); break;
            case envent_code::struc_expanded:          hooks->struc_expanded(args); break;
            case envent_code::struc_member_created:    hooks->struc_member_created(args); break;
            case envent_code::deleting_struc_member:   hooks->deleting_struc_member(args); break;
            case envent_code::struc_member_deleted:    hooks->struc_member_deleted(args); break;
            case envent_code::renaming_struc_member:   hooks->renaming_struc_member(args); break;
            case envent_code::struc_member_renamed:    hooks->struc_member_renamed(args); break;
            case envent_code::changing_struc_member:   hooks->changing_struc_member(args); break;
            case envent_code::struc_member_changed:    hooks->struc_member_changed(args); break;
            case envent_code::changing_struc_cmt:      hooks->changing_struc_cmt(args); break;
            case envent_code::struc_cmt_changed:       hooks->struc_cmt_changed(args); break;
            case envent_code::segm_added:              hooks->segm_added(args); break;
            case envent_code::deleting_segm:           hooks->deleting_segm(args); break;
            case envent_code::segm_deleted:            hooks->segm_deleted(args); break;
            case envent_code::changing_segm_start:     hooks->changing_segm_start(args); break;
            case envent_code::segm_start_changed:      hooks->segm_start_changed(args); break;
            case envent_code::changing_segm_end:       hooks->changing_segm_end(args); break;
            case envent_code::segm_end_changed:        hooks->segm_end_changed(args); break;
            case envent_code::changing_segm_name:      hooks->changing_segm_name(args); break;
            case envent_code::segm_name_changed:       hooks->segm_name_changed(args); break;
            case envent_code::changing_segm_class:     hooks->changing_segm_class(args); break;
            case envent_code::segm_class_changed:      hooks->segm_class_changed(args); break;
            case envent_code::segm_attrs_updated:      hooks->segm_attrs_updated(args); break;
            case envent_code::segm_moved:              hooks->segm_moved(args); break;
            case envent_code::allsegs_moved:           hooks->allsegs_moved(args); break;
            case envent_code::func_added:              hooks->func_added(args); break;
            case envent_code::func_updated:            hooks->func_updated(args); break;
            case envent_code::set_func_start:          hooks->set_func_start(args); break;
            case envent_code::set_func_end:            hooks->set_func_end(args); break;
            case envent_code::deleting_func:           hooks->deleting_func(args); break;
            case envent_code::frame_deleted:           hooks->frame_deleted(args); break;
            case envent_code::thunk_func_created:      hooks->thunk_func_created(args); break;
            case envent_code::func_tail_appended:      hooks->func_tail_appended(args); break;
            case envent_code::deleting_func_tail:      hooks->deleting_func_tail(args); break;
            case envent_code::func_tail_deleted:       hooks->func_tail_deleted(args); break;
            case envent_code::tail_owner_changed:      hooks->tail_owner_changed(args); break;
            case envent_code::func_noret_changed:      hooks->func_noret_changed(args); break;
            case envent_code::stkpnts_changed:         hooks->stkpnts_changed(args); break;
            case envent_code::updating_tryblks:        hooks->updating_tryblks(args); break;
            case envent_code::tryblks_updated:         hooks->tryblks_updated(args); break;
            case envent_code::deleting_tryblks:        hooks->deleting_tryblks(args); break;
            case envent_code::sgr_changed:             hooks->sgr_changed(args); break;
            case envent_code::make_code:               hooks->make_code(args); break;
            case envent_code::make_data:               hooks->make_data(args); break;
            case envent_code::destroyed_items:         hooks->destroyed_items(args); break;
            case envent_code::renamed:                 hooks->renamed(args); break;
            case envent_code::byte_patched:            hooks->byte_patched(args); break;
            case envent_code::changing_cmt:            hooks->changing_cmt(args); break;
            case envent_code::cmt_changed:             hooks->cmt_changed(args); break;
            case envent_code::changing_range_cmt:      hooks->changing_range_cmt(args); break;
            case envent_code::range_cmt_changed:       hooks->range_cmt_changed(args); break;
            case envent_code::extra_cmt_changed:       hooks->extra_cmt_changed(args); break;
        }
        return 0;
    }

    void log_closebase()
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("The database will be closed now");
    }

    void log_savebase()
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("The database is being saved");
    }

    void log_upgraded(int from)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("The database has been upgraded (old IDB version: %d)", from);
    }

    void log_auto_empty()
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("All analysis queues are empty");
    }

    void log_auto_empty_finally()
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("All analysis queues are empty definitively");
    }

    void log_determined_main(ea_t main)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("The main() function has been determined (address of the main() function: " EA_FMT ")", main);
    }

    void log_local_types_changed()
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Local types have been changed");
    }

    void log_extlang_changed(int kind, const extlang_t* el, int idx)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(idx);
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

    void log_idasgn_loaded(const char* short_sig_name)
    {
        if (!LOG_EVENTS)
            return;

        // FLIRT = Fast Library Identificationand Regognition Technology
        // normal processing = not for recognition of startup sequences
        LOG_EVENT("FLIRT signature %s has been loaded for normal processing", short_sig_name);
    }

    void log_kernel_config_loaded()
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Kernel configuration loaded (ida.cfg parsed)");
    }

    void log_loader_finished(const linput_t* li, uint16 neflags, const char* filetypename)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(li);
        UNUSED(neflags);
        LOG_EVENT("External file loader for %s files finished its work", filetypename);
    }

    void log_flow_chart_created(const qflow_chart_t* fc)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Gui has retrieved a function flow chart (from " EA_FMT " to " EA_FMT ", name: %s, function: %s)", fc->bounds.start_ea, fc->bounds.end_ea, fc->title.c_str(), get_func_name(fc->pfn->start_ea).c_str());
    }

    void log_compiler_changed()
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("The kernel has changed the compiler information");
    }

    void log_changing_ti(ea_t ea, const type_t* new_type, const p_list* new_fnames)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(new_type);
        UNUSED(new_fnames);
        LOG_EVENT("An item typestring (c/c++ prototype) is to be changed (ea: " EA_FMT ")", ea);
    }

    void log_ti_changed(ea_t ea, const type_t* type, const p_list* fnames)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(type);
        UNUSED(fnames);
        LOG_EVENT("An item typestring (c/c++ prototype) has been changed (ea: " EA_FMT ")", ea);
    }

    void log_changing_op_ti(ea_t ea, int n, const type_t* new_type, const p_list* new_fnames)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(n);
        UNUSED(new_type);
        UNUSED(new_fnames);
        LOG_EVENT("An operand typestring (c/c++ prototype) is to be changed (ea: " EA_FMT ")", ea);
    }

    void log_op_ti_changed(ea_t ea, int n, const type_t* new_type, const p_list* new_fnames)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(n);
        UNUSED(new_type);
        UNUSED(new_fnames);
        LOG_EVENT("An operand typestring (c/c++ prototype) has been changed (ea: " EA_FMT ")", ea);
    }

    void log_changing_op_type(ea_t ea, int n, const opinfo_t* opinfo)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(n);
        UNUSED(opinfo);
        LOG_EVENT("An operand type at " EA_FMT " is to be changed", ea);
    }

    void log_op_type_changed(ea_t ea, int n)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(n);
        LOG_EVENT("An operand type at " EA_FMT " has been set or deleted", ea);
    }

    void log_enum_created(enum_t id)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Enum type %s has been created", get_enum_name(id).c_str());
    }

    void log_deleting_enum(enum_t id)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Enum type %s is to be deleted", get_enum_name(id).c_str());
    }

    void log_enum_deleted(enum_t id)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(id);
        LOG_EVENT("An enum type has been deleted");
    }

    void log_renaming_enum(tid_t id, bool is_enum, const char* newname)
    {
        if (!LOG_EVENTS)
            return;

        if (is_enum)
            LOG_EVENT("Enum type %s is to be renamed to %s", get_enum_name(id).c_str(), newname);
        else
            LOG_EVENT("A member of enum type %s is to be renamed from %s to %s", get_enum_member_name(id).c_str(), get_enum_name(get_enum_member_enum(id)).c_str(), newname);
    }

    void log_enum_renamed(tid_t id)
    {
        if (!LOG_EVENTS)
            return;

        if (get_enum_member_enum(id) == BADADDR)
            LOG_EVENT("An enum type has been renamed %s", get_enum_name(id).c_str());
        else
            LOG_EVENT("A member of enum type %s has been renamed %s", get_enum_name(get_enum_member_enum(id)).c_str(), get_enum_member_name(id).c_str());
    }

    void log_changing_enum_bf(enum_t id, bool new_bf)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Enum type %s 'bitfield' attribute is to be changed to %s", get_enum_name(id).c_str(), BOOL_STR[new_bf]);
    }

    void log_enum_bf_changed(enum_t id)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Enum type %s 'bitfield' attribute has been changed", get_enum_name(id).c_str());
    }

    void log_changing_enum_cmt(enum_t id, bool repeatable, const char* newcmt)
    {
        if (!LOG_EVENTS)
            return;

        if (get_enum_member_enum(id) == BADADDR)
            LOG_EVENT("Enum type %s %scomment is to be changed from \"%s\" to \"%s\"", get_enum_name(id).c_str(), REPEATABLE_STR[repeatable], get_enum_cmt(id, repeatable).c_str(), newcmt);
        else
            LOG_EVENT("Enum type %s member %s %scomment is to be changed from \"%s\" to \"%s\"", get_enum_name(get_enum_member_enum(id)).c_str(), get_enum_member_name(id).c_str(), REPEATABLE_STR[repeatable], get_enum_member_cmt(id, repeatable).c_str(), newcmt);
    }

    void log_enum_cmt_changed(enum_t id, bool repeatable)
    {
        if (!LOG_EVENTS)
            return;

        if (get_enum_member_enum(id) == BADADDR)
            LOG_EVENT("Enum type %s %scomment has been changed to \"%s\"", get_enum_name(id).c_str(), REPEATABLE_STR[repeatable], get_enum_cmt(id, repeatable).c_str());
        else
            LOG_EVENT("Enum type %s member %s %scomment has been changed to \"%s\"", get_enum_name(get_enum_member_enum(id)).c_str(), get_enum_member_name(id).c_str(), REPEATABLE_STR[repeatable], get_enum_member_cmt(id, repeatable).c_str());
    }

    void log_enum_member_created(enum_t id, const_t cid)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Enum type %s member %s has been created", get_enum_name(id).c_str(), get_enum_member_name(cid).c_str());
    }

    void log_deleting_enum_member(enum_t id, const_t cid)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Enum type %s member %s is to be deleted", get_enum_name(id).c_str(), get_enum_member_name(cid).c_str());
    }

    void log_enum_member_deleted(enum_t id, const_t cid)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(cid);
        LOG_EVENT("A member of enum type %s has been deleted", get_enum_name(id).c_str());
    }

    void log_struc_created(tid_t struc_id)
    {
        if (!LOG_EVENTS)
            return;

        ea_t func_ea = get_func_by_frame(struc_id);
        if (func_ea != BADADDR)
            LOG_EVENT("Stackframe of function %s has been created", get_func_name(func_ea).c_str());
        else
            LOG_EVENT("Structure type %s has been created", get_struc_name(struc_id).c_str());
    }

    void log_deleting_struc(const struc_t* sptr)
    {
        if (!LOG_EVENTS)
            return;

        ea_t func_ea = get_func_by_frame(sptr->id);
        if (func_ea != BADADDR)
            LOG_EVENT("Stackframe of function %s is to be deleted", get_func_name(func_ea).c_str());
        else
            LOG_EVENT("Structure type %s is to be deleted", get_struc_name(sptr->id).c_str());
    }

    void log_struc_deleted(tid_t struc_id)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(struc_id);
        LOG_EVENT("A structure type or stackframe has been deleted");
    }

    void log_changing_struc_align(const struc_t* sptr)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Structure type %s alignment is being changed from 0x%X", get_struc_name(sptr->id).c_str(), static_cast<int>(std::pow(2, sptr->get_alignment())));
    }

    void log_struc_align_changed(const struc_t* sptr)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Structure type %s alignment has been changed to 0x%X", get_struc_name(sptr->id).c_str(), static_cast<int>(std::pow(2, sptr->get_alignment())));
    }

    void log_renaming_struc(tid_t struc_id, const char* oldname, const char* newname)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(struc_id);
        LOG_EVENT("Structure type %s is to be renamed to %s", oldname, newname);
    }

    void log_struc_renamed(const struc_t* sptr)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("A structure type has been renamed %s", get_struc_name(sptr->id).c_str());
    }

    void log_expanding_struc(const struc_t* sptr, ea_t offset, adiff_t delta)
    {
        if (!LOG_EVENTS)
            return;

        ea_t func_ea = get_func_by_frame(sptr->id);
        if (func_ea != BADADDR)
        {
            if (delta > 0)
                LOG_EVENT("Stackframe of function %s is to be expanded of 0x%" EA_PREFIX "X bytes at offset 0x%" EA_PREFIX "X", get_func_name(func_ea).c_str(), delta, offset);
            else
                LOG_EVENT("Stackframe of function %s is to be shrunk of 0x%" EA_PREFIX "X bytes at offset 0x%" EA_PREFIX "X", get_func_name(func_ea).c_str(), ~delta + 1, offset);
        }
        else
        {
            if (delta > 0)
                LOG_EVENT("Structure type %s is to be expanded of 0x%" EA_PREFIX "X bytes at offset 0x%" EA_PREFIX "X", get_struc_name(sptr->id).c_str(), delta, offset);
            else
                LOG_EVENT("Structure type %s is to be shrunk of 0x%" EA_PREFIX "X bytes at offset 0x%" EA_PREFIX "X", get_struc_name(sptr->id).c_str(), ~delta + 1, offset);
        }
    }

    void log_struc_expanded(const struc_t* sptr)
    {
        if (!LOG_EVENTS)
            return;

        ea_t func_ea = get_func_by_frame(sptr->id);
        if (func_ea != BADADDR)
            LOG_EVENT("Stackframe of function %s has been expanded/shrank", get_func_name(func_ea).c_str());
        else
            LOG_EVENT("Structure type %s has been expanded/shrank", get_struc_name(sptr->id).c_str());
    }

    void log_struc_member_created(const struc_t* sptr, const member_t* mptr)
    {
        if (!LOG_EVENTS)
            return;

        ea_t func_ea = get_func_by_frame(sptr->id);
        if (func_ea != BADADDR)
            LOG_EVENT("Stackframe of function %s member %s has been created", get_func_name(func_ea).c_str(), get_member_name(mptr->id).c_str());
        else
            LOG_EVENT("Structure type %s member %s has been created", get_struc_name(sptr->id).c_str(), get_member_name(mptr->id).c_str());
    }

    void log_deleting_struc_member(const struc_t* sptr, const member_t* mptr)
    {
        if (!LOG_EVENTS)
            return;

        ea_t func_ea = get_func_by_frame(sptr->id);
        if (func_ea != BADADDR)
            LOG_EVENT("Stackframe of function %s member %s is to be deleted", get_func_name(func_ea).c_str(), get_member_name(mptr->id).c_str());
        else
            LOG_EVENT("Structure type %s member %s is to be deleted", get_struc_name(sptr->id).c_str(), get_member_name(mptr->id).c_str());
    }

    void log_struc_member_deleted(const struc_t* sptr, tid_t member_id, ea_t offset)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(member_id);
        ea_t func_ea = get_func_by_frame(sptr->id);
        if (func_ea != BADADDR)
            LOG_EVENT("Stackframe of function %s member at offset 0x%" EA_PREFIX "X has been deleted", get_func_name(func_ea).c_str(), offset);
        else
            LOG_EVENT("Structure type %s member at offset 0x%" EA_PREFIX "X has been deleted", get_struc_name(sptr->id).c_str(), offset);
    }

    void log_renaming_struc_member(const struc_t* sptr, const member_t* mptr, const char* newname)
    {
        if (!LOG_EVENTS)
            return;

        ea_t func_ea = get_func_by_frame(sptr->id);
        if (func_ea != BADADDR)
            LOG_EVENT("A member of stackframe of function %s is to be renamed from %s to %s", get_func_name(func_ea).c_str(), get_member_name(mptr->id).c_str(), newname);
        else
            LOG_EVENT("A member of structure type %s is to be renamed from %s to %s", get_struc_name(sptr->id).c_str(), get_member_name(mptr->id).c_str(), newname);
    }

    void log_struc_member_renamed(const struc_t* sptr, const member_t* mptr)
    {
        if (!LOG_EVENTS)
            return;

        ea_t func_ea = get_func_by_frame(sptr->id);
        if (func_ea != BADADDR)
            LOG_EVENT("A member of stackframe of function %s has been renamed to %s", get_func_name(func_ea).c_str(), get_member_name(mptr->id).c_str());
        else
            LOG_EVENT("A member of structure type %s has been renamed to %s", get_struc_name(sptr->id).c_str(), get_member_name(mptr->id).c_str());
    }

    void log_changing_struc_member(const struc_t* sptr, const member_t* mptr, flags_t flag, const opinfo_t* ti, asize_t nbytes)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(flag);
        UNUSED(ti);
        UNUSED(nbytes);
        ea_t func_ea = get_func_by_frame(sptr->id);
        if (func_ea != BADADDR)
            LOG_EVENT("Stackframe of function %s member %s is to be changed", get_func_name(func_ea).c_str(), get_member_name(mptr->id).c_str());
        else
            LOG_EVENT("Structure type %s member %s is to be changed", get_struc_name(sptr->id).c_str(), get_member_name(mptr->id).c_str());
    }

    void log_struc_member_changed(const struc_t* sptr, const member_t* mptr)
    {
        if (!LOG_EVENTS)
            return;

        ea_t func_ea = get_func_by_frame(sptr->id);
        if (func_ea != BADADDR)
            LOG_EVENT("Stackframe of function %s member %s has been changed", get_func_name(func_ea).c_str(), get_member_name(mptr->id).c_str());
        else
            LOG_EVENT("Structure type %s member %s has been changed", get_struc_name(sptr->id).c_str(), get_member_name(mptr->id).c_str());
    }

    void log_changing_struc_cmt(tid_t struc_id, bool repeatable, const char* newcmt)
    {
        if (!LOG_EVENTS)
            return;

        if (get_struc(struc_id))
        {
            LOG_EVENT("Structure type %s %scomment is to be changed from \"%s\" to \"%s\"", get_struc_name(struc_id).c_str(), REPEATABLE_STR[repeatable], get_struc_cmt(struc_id, repeatable).c_str(), newcmt);
        }
        else
        {
            struc_t* struc = get_member_struc(get_member_fullname(struc_id).c_str());
            ea_t func_ea = get_func_by_frame(struc->id);
            if (func_ea != BADADDR)
                LOG_EVENT("Stackframe of function %s member %s %scomment is to be changed from \"%s\" to \"%s\"", get_func_name(func_ea).c_str(), get_member_name(struc_id).c_str(), REPEATABLE_STR[repeatable], get_member_name(struc_id).c_str(), newcmt);
            else
                LOG_EVENT("Structure type %s member %s %scomment is to be changed from \"%s\" to \"%s\"", get_struc_name(struc->id).c_str(), get_member_name(struc_id).c_str(), REPEATABLE_STR[repeatable], get_member_name(struc_id).c_str(), newcmt);
        }
    }

    void log_struc_cmt_changed(tid_t struc_id, bool repeatable)
    {
        if (!LOG_EVENTS)
            return;

        if (get_struc(struc_id))
        {
            LOG_EVENT("Structure type %s %scomment has been changed to \"%s\"", get_struc_name(struc_id).c_str(), REPEATABLE_STR[repeatable], get_struc_cmt(struc_id, repeatable).c_str());
        }
        else
        {
            struc_t* struc = get_member_struc(get_member_fullname(struc_id).c_str());
            ea_t func_ea = get_func_by_frame(struc->id);
            if (func_ea != BADADDR)
                LOG_EVENT("Stackframe of function %s member %s %scomment has been changed to \"%s\"", get_func_name(func_ea).c_str(), get_member_name(struc_id).c_str(), REPEATABLE_STR[repeatable], get_member_name(struc_id).c_str());
            else
                LOG_EVENT("Structure type %s member %s %scomment has been changed to \"%s\"", get_struc_name(struc->id).c_str(), get_member_name(struc_id).c_str(), REPEATABLE_STR[repeatable], get_member_name(struc_id).c_str());
        }
    }

    void log_segm_added(const segment_t* s)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Segment %s has been created from " EA_FMT " to " EA_FMT, get_segm_name(s).c_str(), s->start_ea, s->end_ea);
    }

    void log_deleting_segm(ea_t start_ea)
    {
        if (!LOG_EVENTS)
            return;

        const segment_t* s = getseg(start_ea);
        LOG_EVENT("Segment %s (from " EA_FMT " to " EA_FMT ") is to be deleted", get_segm_name(s).c_str(), s->start_ea, s->end_ea);
    }

    void log_segm_deleted(ea_t start_ea, ea_t end_ea)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("A segment (from " EA_FMT " to " EA_FMT ") has been deleted", start_ea, end_ea);
    }

    void log_changing_segm_start(const segment_t* s, ea_t new_start, int segmod_flags)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(segmod_flags);
        LOG_EVENT("Segment %s start address is to be changed from " EA_FMT " to " EA_FMT, get_segm_name(s).c_str(), s->start_ea, new_start);
    }

    void log_segm_start_changed(const segment_t* s, ea_t oldstart)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Segment %s start address has been changed from " EA_FMT " to " EA_FMT, get_segm_name(s).c_str(), oldstart, s->start_ea);
    }

    void log_changing_segm_end(const segment_t* s, ea_t new_end, int segmod_flags)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(segmod_flags);
        LOG_EVENT("Segment %s end address is to be changed from " EA_FMT " to " EA_FMT, get_segm_name(s).c_str(), s->end_ea, new_end);
    }

    void log_segm_end_changed(const segment_t* s, ea_t oldend)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Segment %s end address has been changed from " EA_FMT " to " EA_FMT, get_segm_name(s).c_str(), oldend, s->end_ea);
    }

    void log_changing_segm_name(const segment_t* s, const char* oldname)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(s);
        LOG_EVENT("Segment %s is being renamed", oldname);
    }

    void log_segm_name_changed(const segment_t* s, const char* name)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(s);
        LOG_EVENT("A segment has been renamed %s", name);
    }

    void log_changing_segm_class(const segment_t* s)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Segment %s class is being changed from %s", get_segm_name(s).c_str(), get_segm_class(s).c_str());
    }

    void log_segm_class_changed(const segment_t* s, const char* sclass)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Segment %s class has been changed to %s", get_segm_name(s).c_str(), sclass);
    }

    void log_segm_attrs_updated(const segment_t* s)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Segment %s attributes has been changed", get_segm_name(s).c_str());
    }

    void log_segm_moved(ea_t from, ea_t to, asize_t size, bool changed_netmap)
    {
        if (!LOG_EVENTS)
            return;

        const segment_t* s = getseg(to);
        const char changed_netmap_txt[2][18] = { "", " (changed netmap)" };
        LOG_EVENT("Segment %s has been moved from " EA_FMT "-" EA_FMT " to " EA_FMT "-" EA_FMT "%s", get_segm_name(s).c_str(), from, from + size, to, to + size, changed_netmap_txt[changed_netmap]);
    }

    void log_allsegs_moved(const segm_move_infos_t* info)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Program rebasing is complete, %zd segments have been moved", info->size());
    }

    void log_func_added(const func_t* pfn)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Function %s has been created from " EA_FMT " to " EA_FMT, get_func_name(pfn->start_ea).c_str(), pfn->start_ea, pfn->end_ea);
    }

    void log_func_updated(const func_t* pfn)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Function %s has been updated", get_func_name(pfn->start_ea).c_str());
    }

    void log_set_func_start(const func_t* pfn, ea_t new_start)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Function %s chunk start address will be changed from " EA_FMT " to " EA_FMT, get_func_name(pfn->start_ea).c_str(), pfn->start_ea, new_start);
    }

    void log_set_func_end(const func_t* pfn, ea_t new_end)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Function %s chunk end address will be changed from " EA_FMT " to " EA_FMT, get_func_name(pfn->start_ea).c_str(), pfn->end_ea, new_end);
    }

    void log_deleting_func(const func_t* pfn)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Function %s is about to be deleted (" EA_FMT " to " EA_FMT")", get_func_name(pfn->start_ea).c_str(), pfn->start_ea, pfn->end_ea);
    }

    void log_frame_deleted(const func_t* pfn)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(pfn);
        LOG_EVENT("A function frame has been deleted");
    }

    void log_thunk_func_created(const func_t* pfn)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Function %s thunk bit has been set to %s", get_func_name(pfn->start_ea).c_str(), BOOL_STR[!!(pfn->flags & FUNC_THUNK)]);
    }

    void log_func_tail_appended(const func_t* pfn, const func_t* tail)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Function %s tail chunk from " EA_FMT " to " EA_FMT " has been appended", get_func_name(pfn->start_ea).c_str(), tail->start_ea, tail->end_ea);
    }

    void log_deleting_func_tail(const func_t* pfn, const range_t* tail)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Function %s tail chunk from " EA_FMT " to " EA_FMT " is to be removed", get_func_name(pfn->start_ea).c_str(), tail->start_ea, tail->end_ea);
    }

    void log_func_tail_deleted(const func_t* pfn, ea_t tail_ea)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Function %s tail chunk at " EA_FMT " has been removed", get_func_name(pfn->start_ea).c_str(), tail_ea);
    }

    void log_tail_owner_changed(const func_t* pfn, ea_t owner_func, ea_t old_owner)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Tail chunk from " EA_FMT " to " EA_FMT " owner function changed from %s to %s", pfn->start_ea, pfn->end_ea, get_func_name(old_owner).c_str(), get_func_name(owner_func).c_str());
    }

    void log_func_noret_changed(const func_t* pfn)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Function %s FUNC_NORET flag has been changed to %s", get_func_name(pfn->start_ea).c_str(), BOOL_STR[!!(pfn->flags & FUNC_NORET)]);
    }

    void log_stkpnts_changed(const func_t* pfn)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Function %s stack change points have been modified", get_func_name(pfn->start_ea).c_str());
    }

    void log_updating_tryblks(const tryblks_t* tbv)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(tbv);
        LOG_EVENT("About to update try block information");
    }

    void log_tryblks_updated(const tryblks_t* tbv)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(tbv);
        LOG_EVENT("Updated try block information");
    }

    void log_deleting_tryblks(const range_t* range)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("About to delete try block information in range " EA_FMT "-" EA_FMT, range->start_ea, range->end_ea);
    }

    void log_sgr_changed(ea_t start_ea, ea_t end_ea, int regnum, sel_t value, sel_t old_value, uchar tag)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(start_ea);
        UNUSED(end_ea);
        UNUSED(regnum);
        UNUSED(value);
        UNUSED(old_value);
        UNUSED(tag);
        LOG_EVENT("The kernel has changed a segment register value");
    }

    void log_make_code(const insn_t* insn)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("An instruction is being created at " EA_FMT, insn->ea);
    }

    void log_make_data(ea_t ea, flags_t flags, tid_t tid, asize_t len)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(flags);
        UNUSED(tid);
        UNUSED(len);
        LOG_EVENT("A data item is being created at " EA_FMT, ea);
    }

    void log_destroyed_items(ea_t ea1, ea_t ea2, bool will_disable_range)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(will_disable_range);
        LOG_EVENT("Instructions/data have been destroyed in " EA_FMT "-" EA_FMT, ea1, ea2);
    }

    void log_renamed(ea_t ea, const char* new_name, bool local_name)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(local_name);
        LOG_EVENT("Byte at " EA_FMT " renamed to %s", ea, new_name);
    }

    void log_byte_patched(ea_t ea, uint32 old_value)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Byte at " EA_FMT " has been changed from 0x%02X to 0x%02X", ea, old_value, get_byte(ea));
    }

    void log_changing_cmt(ea_t ea, bool repeatable_cmt, const char* newcmt)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Item at " EA_FMT " %scomment is to be changed from \"%s\" to \"%s\"", ea, REPEATABLE_STR[repeatable_cmt], get_cmt(ea, repeatable_cmt).c_str(), newcmt);
    }

    void log_cmt_changed(ea_t ea, bool repeatable_cmt)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("Item at " EA_FMT " %scomment has been changed to \"%s\"", ea, REPEATABLE_STR[repeatable_cmt], get_cmt(ea, repeatable_cmt).c_str());
    }

    void log_changing_range_cmt(range_kind_t kind, const range_t* a, const char* cmt, bool repeatable)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("%s range from " EA_FMT " to " EA_FMT " %scomment is to be changed to \"%s\"", range_kind_to_str(kind), a->start_ea, a->end_ea, REPEATABLE_STR[repeatable], cmt);
    }

    void log_range_cmt_changed(range_kind_t kind, const range_t* a, const char* cmt, bool repeatable)
    {
        if (!LOG_EVENTS)
            return;

        LOG_EVENT("%s range from " EA_FMT " to " EA_FMT " %scomment has been changed to \"%s\"", range_kind_to_str(kind), a->start_ea, a->end_ea, REPEATABLE_STR[repeatable], cmt);
    }

    void log_extra_cmt_changed(ea_t ea, int line_idx, const char* cmt)
    {
        if (!LOG_EVENTS)
            return;

        UNUSED(line_idx);
        LOG_EVENT("Extra comment at " EA_FMT " has been changed to \"%s\"", ea, cmt);
    }
}

Hooks::Hooks(IYaCo& yaco, IHashProvider& hash_provider, IRepository& repo_manager)
    : yaco_(yaco)
    , hash_provider_(hash_provider)
    , repo_manager_ (repo_manager)
    , qpool_        (3)
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
    add_ea(ea, message);
}

void Hooks::update_comment(ea_t ea)
{
    comments_.insert(ea);
}

void Hooks::undefine(ea_t ea)
{
    add_ea(ea, "Undefine");
}

void Hooks::delete_function(ea_t ea)
{
    add_ea(ea, "Delete function");
}

void Hooks::make_code(ea_t ea)
{
    add_ea(ea, "Create code");
}

void Hooks::make_data(ea_t ea)
{
    add_ea(ea, "Create data");
}

void Hooks::add_function(ea_t ea)
{
    // Comments from Python:
    // invalid all addresses in this function(they depend(relatively) on this function now, no on code)
    // Warning : deletion of objects not implemented
    // TODO : implement deletion of objects inside newly created function range
    // TODO : use function chunks to iterate over function code
    add_ea(ea, "Create function");
}

void Hooks::update_function(ea_t ea)
{
    add_ea(ea, "Update function");
}

void Hooks::update_struct(ea_t struct_id)
{
    structs_.insert(struct_id);
    repo_manager_.add_auto_comment(struct_id, "Updated");
}

void Hooks::update_struct_member(tid_t struct_id, tid_t member_id, ea_t offset)
{
    const auto fullname = qpool_.acquire();
    get_member_fullname(&*fullname, member_id);
    const std::string message = "Member updated at offset " + ea_to_hex(offset) + " : " + fullname->c_str();
    add_struct_member(struct_id, offset, message);
}

void Hooks::delete_struct_member(tid_t struct_id, ea_t offset)
{
    add_struct_member(struct_id, offset, "Member deleted");
}

void Hooks::update_enum(enum_t enum_id)
{
    enums_.insert(enum_id);
    repo_manager_.add_auto_comment(enum_id, "Updated");
}

void Hooks::change_operand_type(ea_t ea)
{
    if (get_func(ea) || is_code(get_flags(ea)))
    {
        eas_.insert(ea);
        repo_manager_.add_auto_comment(ea, "Operand type change");
        return;
    }

    if (is_member_id(ea))
        return; // this is a member id: hook already present (update_struct_member)

    IDA_LOG_WARNING("Operand type changed at %s, code out of a function: not implemented", ea_to_hex(ea).c_str());
}

void Hooks::update_segment(ea_t start_ea)
{
    segments_.insert(start_ea);
}

void Hooks::change_type_information(ea_t ea)
{
    add_ea(ea, "Type information changed");
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

    // add comments to adresses to process
    for (const ea_t ea : comments_)
        add_ea(ea, "Changed comment");

    ModelAndVisitor db = MakeModel();
    db.visitor->visit_start();

    {
        const auto model = MakeModelIncremental(&hash_provider_);

        // process structures
        save_structs(model, db.visitor.get());

        // process enums
        save_enums(model, db.visitor.get());

        // process addresses
        for (const ea_t ea : eas_)
            model->accept_ea(*db.visitor, ea);

        // process segments
        for (const ea_t segment_ea : segments_)
            model->accept_segment(*db.visitor, segment_ea);

        db.visitor->visit_end();

        db.model->accept(*MakeXmlExporter(get_cache_folder_path()));
    }

    const auto time_end = std::chrono::system_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(time_end - time_start);
    IDA_LOG_INFO("Saved in %d seconds", static_cast<int>(elapsed.count()));
}

void Hooks::save_and_update()
{
    // save and commit changes
    save();
    if (!repo_manager_.commit_cache())
    {
        IDA_LOG_WARNING("An error occurred during YaCo commit");
        warning("An error occured during YaCo commit: please relaunch IDA");
    }
    flush();

    unhook();

    // update cache and export modifications to IDA
    {
        const std::vector<std::string> modified_files = repo_manager_.update_cache();
        const ModelAndVisitor memory_exporter = MakeModel();
        MakeXmlFilesDatabaseModel(modified_files)->accept(*(memory_exporter.visitor));
        export_to_ida(memory_exporter.model.get(), &hash_provider_);
    }

    // Let IDA apply modifications
    setflag(inf.s_genflags, INFFL_AUTO, true);
    auto_wait();
    setflag(inf.s_genflags, INFFL_AUTO, false);
    refresh_idaview_anyway();

    hook();
}

void Hooks::flush()
{
    eas_.clear();
    structs_.clear();
    struct_members_.clear();
    enums_.clear();
    enum_members_.clear();
    comments_.clear();
    segments_.clear();
}

void Hooks::add_ea(ea_t ea, const std::string& message)
{
    eas_.insert(ea);
    repo_manager_.add_auto_comment(ea, message);
}

void Hooks::add_struct_member(ea_t struct_id, ea_t member_offset, const std::string& message)
{
    struct_members_[struct_id] = member_offset;
    repo_manager_.add_auto_comment(struct_id, message);
}

void Hooks::save_structs(const std::shared_ptr<IModelIncremental>& ida_model, IModelVisitor* memory_exporter)
{
    // structures: export modified ones, delete deleted ones
    for (const tid_t struct_id : structs_)
    {
        const uval_t struct_idx = get_struc_idx(struct_id);
        if (struct_idx != BADADDR)
        {
            // structure or stackframe modified
            ida_model->accept_struct(*memory_exporter, BADADDR, struct_id);
            continue;
        }

        // structure or stackframe deleted
        // need to export the parent (function)
        const ea_t func_ea = get_func_by_frame(struct_id);
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
    for (const std::pair<const tid_t, ea_t>& struct_info : struct_members_)
    {
        const tid_t struct_id = struct_info.first;
        const ea_t member_offset = struct_info.second;

        const struc_t* ida_struct = get_struc(struct_id);
        const uval_t struct_idx = get_struc_idx(struct_id);

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
            continue;
        }

        // structure or stackframe modified
        const member_t* ida_member = get_member(ida_struct, member_offset);
        if (!ida_member || ida_member->id == BADADDR)
        {
            // if member deleted
            ida_model->delete_struct_member(*memory_exporter, stackframe_func_addr, struct_id, member_offset);
            continue;
        }

        if (member_offset > 0)
        {
            const member_t* ida_prev_member = get_member(ida_struct, member_offset - 1);
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

void Hooks::save_enums(const std::shared_ptr<IModelIncremental>& ida_model, IModelVisitor* memory_exporter)
{
    // enums: export modified ones, delete deleted ones
    for (const enum_t enum_id : enums_)
    {
        const uval_t enum_idx = get_enum_idx(enum_id);
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

void Hooks::closebase(va_list args)
{
    UNUSED(args);

    log_closebase();

    yaco_.stop();
}

void Hooks::savebase(va_list args)
{
    UNUSED(args);

    msg("\n");
    log_savebase();

    save_and_update();
}

void Hooks::upgraded(va_list args)
{
    const auto from = va_arg(args, int);

    log_upgraded(from);
}

void Hooks::auto_empty(va_list args)
{
    UNUSED(args);

    log_auto_empty();
}

void Hooks::auto_empty_finally(va_list args)
{
    UNUSED(args);

    log_auto_empty_finally();
}

void Hooks::determined_main(va_list args)
{
    const auto main = va_arg(args, ea_t);

    log_determined_main(main);
}

void Hooks::local_types_changed(va_list args)
{
    UNUSED(args);

    log_local_types_changed();
}

void Hooks::extlang_changed(va_list args)
{
    const auto kind = va_arg(args, int); //0: extlang installed, 1: extlang removed, 2: default extlang changed
    const auto el   = va_arg(args, extlang_t*);
    const auto idx  = va_arg(args, int);

    log_extlang_changed(kind, el, idx);
}

void Hooks::idasgn_loaded(va_list args)
{
    const auto short_sig_name = va_arg(args, const char*);

    log_idasgn_loaded(short_sig_name);
}

void Hooks::kernel_config_loaded(va_list args)
{
    UNUSED(args);

    log_kernel_config_loaded();
}

void Hooks::loader_finished(va_list args)
{
    const auto li           = va_arg(args, linput_t*);
    const auto neflags      = static_cast<uint16>(va_arg(args, int)); // NEF_.+ defines from loader.hpp
    const auto filetypename = va_arg(args, const char*);

    log_loader_finished(li, neflags, filetypename);
}

void Hooks::flow_chart_created(va_list args)
{
    qflow_chart_t* fc = va_arg(args, qflow_chart_t*);

    log_flow_chart_created(fc);
}

void Hooks::compiler_changed(va_list args)
{
    UNUSED(args);

    log_compiler_changed();
}

void Hooks::changing_ti(va_list args)
{
    const auto ea         = va_arg(args, ea_t);
    const auto new_type   = va_arg(args, type_t*);
    const auto new_fnames = va_arg(args, p_list*);

    log_changing_ti(ea, new_type, new_fnames);
}

void Hooks::ti_changed(va_list args)
{
    const auto ea     = va_arg(args, ea_t);
    const auto type   = va_arg(args, type_t*);
    const auto fnames = va_arg(args, p_list*);

    log_ti_changed(ea, type, fnames);

    change_type_information(ea);
}

void Hooks::changing_op_ti(va_list args)
{
    const auto ea         = va_arg(args, ea_t);
    const auto n          = va_arg(args, int);
    const auto new_type   = va_arg(args, type_t*);
    const auto new_fnames = va_arg(args, p_list*);

    log_changing_op_ti(ea, n, new_type, new_fnames);
}

void Hooks::op_ti_changed(va_list args)
{
    const auto ea         = va_arg(args, ea_t);
    const auto n          = va_arg(args, int);
    const auto new_type   = va_arg(args, type_t*);
    const auto new_fnames = va_arg(args, p_list*);

    log_op_ti_changed(ea, n, new_type, new_fnames);

    change_type_information(ea);
}

void Hooks::changing_op_type(va_list args)
{
    const auto ea     = va_arg(args, ea_t);
    const auto n      = va_arg(args, int);
    const auto opinfo = va_arg(args, const opinfo_t*);

    log_changing_op_type(ea, n, opinfo);
}

void Hooks::op_type_changed(va_list args)
{
    const auto ea = va_arg(args, ea_t);
    const auto n  = va_arg(args, int);

    log_op_type_changed(ea, n);

    change_operand_type(ea);
}

void Hooks::enum_created(va_list args)
{
    const auto id = va_arg(args, enum_t);

    log_enum_created(id);

    update_enum(id);
}

void Hooks::deleting_enum(va_list args)
{
    const auto id = va_arg(args, enum_t);

    log_deleting_enum(id);
}

void Hooks::enum_deleted(va_list args)
{
    const auto id = va_arg(args, enum_t);

    log_enum_deleted(id);

    update_enum(id);
}

void Hooks::renaming_enum(va_list args)
{
    const auto id      = va_arg(args, tid_t);
    const auto is_enum = static_cast<bool>(va_arg(args, int));
    const auto newname = va_arg(args, const char*);

    log_renaming_enum(id, is_enum, newname);
}

void Hooks::enum_renamed(va_list args)
{
    const auto id = va_arg(args, tid_t);

    log_enum_renamed(id);

    update_enum(id);
}

void Hooks::changing_enum_bf(va_list args)
{
    const auto id     = va_arg(args, enum_t);
    const auto new_bf = static_cast<bool>(va_arg(args, int));

    log_changing_enum_bf(id, new_bf);
}

void Hooks::enum_bf_changed(va_list args)
{
    const auto id = va_arg(args, enum_t);

    log_enum_bf_changed(id);

    update_enum(id);
}

void Hooks::changing_enum_cmt(va_list args)
{
    const auto id         = va_arg(args, enum_t);
    const auto repeatable = static_cast<bool>(va_arg(args, int));
    const auto newcmt     = va_arg(args, const char*);

    log_changing_enum_cmt(id, repeatable, newcmt);
}

void Hooks::enum_cmt_changed(va_list args)
{
    const auto id         = va_arg(args, enum_t);
    const auto repeatable = static_cast<bool>(va_arg(args, int));

    log_enum_cmt_changed(id, repeatable);

    enum_t enum_id = get_enum_member_enum(id);
    if (enum_id == BADADDR)
        enum_id = id;
    update_enum(enum_id);
}

void Hooks::enum_member_created(va_list args)
{
    const auto id  = va_arg(args, enum_t);
    const auto cid = va_arg(args, const_t);

    log_enum_member_created(id, cid);

    update_enum(id);
}

void Hooks::deleting_enum_member(va_list args)
{
    const auto id  = va_arg(args, enum_t);
    const auto cid = va_arg(args, const_t);

    log_deleting_enum_member(id, cid);
}

void Hooks::enum_member_deleted(va_list args)
{
    const auto id  = va_arg(args, enum_t);
    const auto cid = va_arg(args, const_t);

    log_enum_member_deleted(id, cid);

    update_enum(id);
}

void Hooks::struc_created(va_list args)
{
    const auto struc_id = va_arg(args, tid_t);

    log_struc_created(struc_id);

    update_struct(struc_id);
}

void Hooks::deleting_struc(va_list args)
{
    const auto sptr = va_arg(args, struc_t*);

    log_deleting_struc(sptr);
}

void Hooks::struc_deleted(va_list args)
{
    const auto struc_id = va_arg(args, tid_t);

    log_struc_deleted(struc_id);

    update_struct(struc_id);
}

void Hooks::changing_struc_align(va_list args)
{
    const auto sptr = va_arg(args, struc_t*);

    log_changing_struc_align(sptr);
}

void Hooks::struc_align_changed(va_list args)
{
    const auto sptr = va_arg(args, struc_t*);

    log_struc_align_changed(sptr);
}

void Hooks::renaming_struc(va_list args)
{
    const auto struc_id = va_arg(args, tid_t);
    const auto oldname  = va_arg(args, const char*);
    const auto newname  = va_arg(args, const char*);

    log_renaming_struc(struc_id, oldname, newname);
}

void Hooks::struc_renamed(va_list args)
{
    const auto sptr = va_arg(args, struc_t*);

    log_struc_renamed(sptr);

    update_struct(sptr->id);
}

void Hooks::expanding_struc(va_list args)
{
    const auto sptr   = va_arg(args, struc_t*);
    const auto offset = va_arg(args, ea_t);
    const auto delta  = va_arg(args, adiff_t);

    log_expanding_struc(sptr, offset, delta);
}

void Hooks::struc_expanded(va_list args)
{
    const auto sptr = va_arg(args, struc_t*);

    log_struc_expanded(sptr);
}

void Hooks::struc_member_created(va_list args)
{
    const auto sptr = va_arg(args, struc_t*);
    const auto mptr = va_arg(args, member_t*);

    log_struc_member_created(sptr, mptr);

    update_struct(sptr->id);
}

void Hooks::deleting_struc_member(va_list args)
{
    const auto sptr = va_arg(args, struc_t*);
    const auto mptr = va_arg(args, member_t*);

    log_deleting_struc_member(sptr, mptr);
}

void Hooks::struc_member_deleted(va_list args)
{
    const auto sptr      = va_arg(args, struc_t*);
    const auto member_id = va_arg(args, tid_t);
    const auto offset    = va_arg(args, ea_t);

    log_struc_member_deleted(sptr, member_id, offset);

    delete_struct_member(sptr->id, offset);
}

void Hooks::renaming_struc_member(va_list args)
{
    const auto sptr    = va_arg(args, struc_t*);
    const auto mptr    = va_arg(args, member_t*);
    const auto newname = va_arg(args, const char*);

    log_renaming_struc_member(sptr, mptr, newname);
}

void Hooks::struc_member_renamed(va_list args)
{
    const auto sptr = va_arg(args, struc_t*);
    const auto mptr = va_arg(args, member_t*);

    log_struc_member_renamed(sptr, mptr);

    update_struct_member(sptr->id, mptr->id, mptr->eoff);
}

void Hooks::changing_struc_member(va_list args)
{
    const auto sptr   = va_arg(args, struc_t*);
    const auto mptr   = va_arg(args, member_t*);
    const auto flag   = va_arg(args, flags_t);
    const auto ti     = va_arg(args, const opinfo_t*);
    const auto nbytes = va_arg(args, asize_t);

    log_changing_struc_member(sptr, mptr, flag, ti, nbytes);
}

void Hooks::struc_member_changed(va_list args)
{
    const auto sptr = va_arg(args, struc_t*);
    const auto mptr = va_arg(args, member_t*);

    log_struc_member_changed(sptr, mptr);

    update_struct(sptr->id);
    update_struct_member(sptr->id, mptr->id, mptr->eoff);
}

void Hooks::changing_struc_cmt(va_list args)
{
    const auto struc_id   = va_arg(args, tid_t);
    const auto repeatable = static_cast<bool>(va_arg(args, int));
    const auto newcmt     = va_arg(args, const char*);

    log_changing_struc_cmt(struc_id, repeatable, newcmt);
}

void Hooks::struc_cmt_changed(va_list args)
{
    const auto struc_id   = va_arg(args, tid_t);
    const auto repeatable = static_cast<bool>(va_arg(args, int));

    log_struc_cmt_changed(struc_id, repeatable);

    tid_t real_struc_id = struc_id;
    if (!get_struc(struc_id))
    {
        const auto member_fullname = qpool_.acquire();
        get_member_fullname(&*member_fullname, struc_id);
        struc_t* struc = get_member_struc(member_fullname->c_str());
        if(struc)
            real_struc_id = struc->id;
    }
    update_struct(real_struc_id);
}

void Hooks::segm_added(va_list args)
{
    const auto s = va_arg(args, segment_t*);

    log_segm_added(s);

    update_segment(s->start_ea);
}

void Hooks::deleting_segm(va_list args)
{
    const auto start_ea = va_arg(args, ea_t);

    log_deleting_segm(start_ea);
}

void Hooks::segm_deleted(va_list args)
{
    const auto start_ea = va_arg(args, ea_t);
    const auto end_ea   = va_arg(args, ea_t);

    log_segm_deleted(start_ea, end_ea);

    update_segment(start_ea);
}

void Hooks::changing_segm_start(va_list args)
{
    const auto s            = va_arg(args, segment_t*);
    const auto new_start    = va_arg(args, ea_t);
    const auto segmod_flags = va_arg(args, int);

    log_changing_segm_start(s, new_start, segmod_flags);
}

void Hooks::segm_start_changed(va_list args)
{
    const auto s        = va_arg(args, segment_t*);
    const auto oldstart = va_arg(args, ea_t);

    log_segm_start_changed(s, oldstart);

    update_segment(s->start_ea);
}

void Hooks::changing_segm_end(va_list args)
{
    const auto s            = va_arg(args, segment_t*);
    const auto new_end      = va_arg(args, ea_t);
    const auto segmod_flags = va_arg(args, int);

    log_changing_segm_end(s, new_end, segmod_flags);
}

void Hooks::segm_end_changed(va_list args)
{
    const auto s      = va_arg(args, segment_t*);
    const auto oldend = va_arg(args, ea_t);

    log_segm_end_changed(s, oldend);

    update_segment(s->start_ea);
}

void Hooks::changing_segm_name(va_list args)
{
    const auto s       = va_arg(args, segment_t*);
    const auto oldname = va_arg(args, const char*);

    log_changing_segm_name(s, oldname);
}

void Hooks::segm_name_changed(va_list args)
{
    const auto s    = va_arg(args, segment_t*);
    const auto name = va_arg(args, const char*);

    log_segm_name_changed(s, name);

    update_segment(s->start_ea);
}

void Hooks::changing_segm_class(va_list args)
{
    const auto s = va_arg(args, segment_t*);

    log_changing_segm_class(s);
}

void Hooks::segm_class_changed(va_list args)
{
    const auto s      = va_arg(args, segment_t*);
    const auto sclass = va_arg(args, const char*);

    log_segm_class_changed(s, sclass);

    update_segment(s->start_ea);
}

void Hooks::segm_attrs_updated(va_list args)
{
    // This event is generated for secondary segment attributes (examples: color, permissions, etc)
    const auto s = va_arg(args, segment_t*);

    log_segm_attrs_updated(s);

    update_segment(s->start_ea);
}

void Hooks::segm_moved(va_list args)
{
    const auto from           = va_arg(args, ea_t);
    const auto to             = va_arg(args, ea_t);
    const auto size           = va_arg(args, asize_t);
    const auto changed_netmap = static_cast<bool>(va_arg(args, int));

    log_segm_moved(from, to, size, changed_netmap);

    const segment_t* s = getseg(to);
    update_segment(s->start_ea);
}

void Hooks::allsegs_moved(va_list args)
{
    const auto info = va_arg(args, segm_move_infos_t*);

    log_allsegs_moved(info);
}

void Hooks::func_added(va_list args)
{
    const auto pfn = va_arg(args, func_t*);

    log_func_added(pfn);

    add_function(pfn->start_ea);
}

void Hooks::func_updated(va_list args)
{
    const auto pfn = va_arg(args, func_t*);

    log_func_updated(pfn);

    update_function(pfn->start_ea);
}

void Hooks::set_func_start(va_list args)
{
    const auto pfn       = va_arg(args, func_t*);
    const auto new_start = va_arg(args, ea_t);

    log_set_func_start(pfn, new_start);

    update_function(pfn->start_ea);
}

void Hooks::set_func_end(va_list args)
{
    const auto pfn     = va_arg(args, func_t*);
    const auto new_end = va_arg(args, ea_t);

    log_set_func_end(pfn, new_end);

    update_function(pfn->start_ea);
}

void Hooks::deleting_func(va_list args)
{
    const auto pfn = va_arg(args, func_t*);

    log_deleting_func(pfn);

    delete_function(pfn->start_ea);
}

void Hooks::frame_deleted(va_list args)
{
    const auto pfn = va_arg(args, func_t*);

    log_frame_deleted(pfn);
}

void Hooks::thunk_func_created(va_list args)
{
    const auto pfn = va_arg(args, func_t*);

    log_thunk_func_created(pfn);

    update_function(pfn->start_ea);
}

void Hooks::func_tail_appended(va_list args)
{
    const auto pfn  = va_arg(args, func_t*);
    const auto tail = va_arg(args, func_t*);

    log_func_tail_appended(pfn, tail);

    update_function(pfn->start_ea);
}

void Hooks::deleting_func_tail(va_list args)
{
    const auto pfn  = va_arg(args, func_t*);
    const auto tail = va_arg(args, const range_t*);

    log_deleting_func_tail(pfn, tail);
}

void Hooks::func_tail_deleted(va_list args)
{
    const auto pfn     = va_arg(args, func_t*);
    const auto tail_ea = va_arg(args, ea_t);

    log_func_tail_deleted(pfn, tail_ea);

    update_function(pfn->start_ea);
}

void Hooks::tail_owner_changed(va_list args)
{
    const auto pfn        = va_arg(args, func_t*);
    const auto owner_func = va_arg(args, ea_t);
    const auto old_owner  = va_arg(args, ea_t);

    log_tail_owner_changed(pfn, owner_func, old_owner);

    update_function(owner_func);
    update_function(old_owner);
}

void Hooks::func_noret_changed(va_list args)
{
    const auto pfn = va_arg(args, func_t*);

    log_func_noret_changed(pfn);

    update_function(pfn->start_ea);
}

void Hooks::stkpnts_changed(va_list args)
{
    const auto pfn = va_arg(args, func_t*);

    log_stkpnts_changed(pfn);

    update_function(pfn->start_ea);
}

void Hooks::updating_tryblks(va_list args)
{
    const auto tbv = va_arg(args, const tryblks_t*);

    log_updating_tryblks(tbv);
}

void Hooks::tryblks_updated(va_list args)
{
    const auto tbv = va_arg(args, const tryblks_t*);

    log_tryblks_updated(tbv);
}

void Hooks::deleting_tryblks(va_list args)
{
    const auto range = va_arg(args, const range_t*);

    log_deleting_tryblks(range);
}

void Hooks::sgr_changed(va_list args)
{
    const auto start_ea  = va_arg(args, ea_t);
    const auto end_ea    = va_arg(args, ea_t);
    const auto regnum    = va_arg(args, int);
    const auto value     = va_arg(args, sel_t);
    const auto old_value = va_arg(args, sel_t);
    const auto tag       = static_cast<uchar>(va_arg(args, int));

    log_sgr_changed(start_ea, end_ea, regnum, value, old_value, tag);
}

void Hooks::make_code(va_list args)
{
    const auto insn = va_arg(args, const insn_t*);

    log_make_code(insn);

    make_code(insn->ea);
}

void Hooks::make_data(va_list args)
{
    const auto ea    = va_arg(args, ea_t);
    const auto flags = va_arg(args, flags_t);
    const auto tid   = va_arg(args, tid_t);
    const auto len   = va_arg(args, asize_t);

    log_make_data(ea, flags, tid, len);

    make_data(ea);
}

void Hooks::destroyed_items(va_list args)
{
    const auto ea1                = va_arg(args, ea_t);
    const auto ea2                = va_arg(args, ea_t);
    const auto will_disable_range = static_cast<bool>(va_arg(args, int));

    log_destroyed_items(ea1, ea2, will_disable_range);
}

void Hooks::renamed(va_list args)
{
    const auto ea         = va_arg(args, ea_t);
    const auto new_name   = va_arg(args, const char*);
    const auto local_name = static_cast<bool>(va_arg(args, int));

    log_renamed(ea, new_name, local_name);

    rename(ea, new_name, "", "");
}

void Hooks::byte_patched(va_list args)
{
    const auto ea        = va_arg(args, ea_t);
    const auto old_value = va_arg(args, uint32);

    log_byte_patched(ea, old_value);
}

void Hooks::changing_cmt(va_list args)
{
    const auto ea             = va_arg(args, ea_t);
    const auto repeatable_cmt = static_cast<bool>(va_arg(args, int));
    const auto newcmt         = va_arg(args, const char*);

    log_changing_cmt(ea, repeatable_cmt, newcmt);
}

void Hooks::cmt_changed(va_list args)
{
    const auto ea             = va_arg(args, ea_t);
    const auto repeatable_cmt = static_cast<bool>(va_arg(args, int));

    log_cmt_changed(ea, repeatable_cmt);

    update_comment(ea);
}

void Hooks::changing_range_cmt(va_list args)
{
    const auto kind       = static_cast<range_kind_t>(va_arg(args, int));
    const auto a          = va_arg(args, const range_t*);
    const auto cmt        = va_arg(args, const char*);
    const auto repeatable = static_cast<bool>(va_arg(args, int));

    log_changing_range_cmt(kind, a, cmt, repeatable);
}

void Hooks::range_cmt_changed(va_list args)
{
    const auto kind       = static_cast<range_kind_t>(va_arg(args, int));
    const auto a          = va_arg(args, const range_t*);
    const auto cmt        = va_arg(args, const char*);
    const auto repeatable = static_cast<bool>(va_arg(args, int));

    log_range_cmt_changed(kind, a, cmt, repeatable);

    update_comment(a->start_ea);
}

void Hooks::extra_cmt_changed(va_list args)
{
    const auto ea       = va_arg(args, ea_t);
    const auto line_idx = va_arg(args, int);
    const auto cmt      = va_arg(args, const char*);

    log_extra_cmt_changed(ea, line_idx, cmt);

    update_comment(ea);
}


std::shared_ptr<IHooks> MakeHooks(IYaCo& yaco, const std::shared_ptr<IHashProvider>& hash_provider, const std::shared_ptr<IRepository>& repo_manager)
{
    return std::make_shared<Hooks>(yaco, *hash_provider, *repo_manager);
}
