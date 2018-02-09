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
#include "Hash.hpp"
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
#include "YaHelpers.hpp"
#include "../Helpers.h"
#include "BinHex.hpp"
#include "HObject.hpp"
#include "HVersion.hpp"
#include "DelegatingVisitor.hpp"

#define MODULE_NAME "hooks"
#include "IDAUtils.hpp"

#include <cstdarg>
#include <chrono>
#include <math.h>
#include <unordered_set>

#ifdef _MSC_VER
#   include <filesystem>
#else
#   include <experimental/filesystem>
#endif

namespace fs = std::experimental::filesystem;

// Log macro used for events logging
#define LOG_IDP_EVENT(format, ...) do{ if(LOG_IDP_EVENTS) IDA_LOG_INFO("idp: " format, ##__VA_ARGS__); }while(0)
#define LOG_DBG_EVENT(format, ...) do{ if(LOG_DBG_EVENTS) IDA_LOG_INFO("dbg: " format, ##__VA_ARGS__); }while(0)
#define LOG_IDB_EVENT(format, ...) do{ if(LOG_IDB_EVENTS) IDA_LOG_INFO("idb: " format, ##__VA_ARGS__); }while(0)

namespace
{
    // Enable / disable events logging
    const bool LOG_IDP_EVENTS = false;
    const bool LOG_DBG_EVENTS = false;
    const bool LOG_IDB_EVENTS = false;

    const char BOOL_STR[][6] = { "false", "true" };
    const char REPEATABLE_STR[][12] = { "", "repeatable " };

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

    const char* idp_event_to_txt(processor_t::event_t event)
    {
        switch (event)
        {
            case processor_t::event_t::ev_add_cref:                        return "ev_add_cref";
            case processor_t::event_t::ev_add_dref:                        return "ev_add_dref";
            case processor_t::event_t::ev_adjust_argloc:                   return "ev_adjust_argloc";
            case processor_t::event_t::ev_adjust_libfunc_ea:               return "ev_adjust_libfunc_ea";
            case processor_t::event_t::ev_adjust_refinfo:                  return "ev_adjust_refinfo";
            case processor_t::event_t::ev_ana_insn:                        return "ev_ana_insn";
            case processor_t::event_t::ev_arg_addrs_ready:                 return "ev_arg_addrs_ready";
            case processor_t::event_t::ev_assemble:                        return "ev_assemble";
            case processor_t::event_t::ev_auto_queue_empty:                return "ev_auto_queue_empty";
            case processor_t::event_t::ev_calc_arglocs:                    return "ev_calc_arglocs";
            case processor_t::event_t::ev_calc_cdecl_purged_bytes:         return "ev_calc_cdecl_purged_bytes";
            case processor_t::event_t::ev_calc_next_eas:                   return "ev_calc_next_eas";
            case processor_t::event_t::ev_calc_purged_bytes:               return "ev_calc_purged_bytes";
            case processor_t::event_t::ev_calc_retloc:                     return "ev_calc_retloc";
            case processor_t::event_t::ev_calc_step_over:                  return "ev_calc_step_over";
            case processor_t::event_t::ev_calc_switch_cases:               return "ev_calc_switch_cases";
            case processor_t::event_t::ev_calc_varglocs:                   return "ev_calc_varglocs";
            case processor_t::event_t::ev_can_have_type:                   return "ev_can_have_type";
            case processor_t::event_t::ev_clean_tbit:                      return "ev_clean_tbit";
            case processor_t::event_t::ev_cmp_operands:                    return "ev_cmp_operands";
            case processor_t::event_t::ev_coagulate:                       return "ev_coagulate";
            case processor_t::event_t::ev_coagulate_dref:                  return "ev_coagulate_dref";
            case processor_t::event_t::ev_create_flat_group:               return "ev_create_flat_group";
            case processor_t::event_t::ev_create_func_frame:               return "ev_create_func_frame";
            case processor_t::event_t::ev_create_switch_xrefs:             return "ev_create_switch_xrefs";
            case processor_t::event_t::ev_creating_segm:                   return "ev_creating_segm";
            case processor_t::event_t::ev_decorate_name:                   return "ev_decorate_name";
            case processor_t::event_t::ev_del_cref:                        return "ev_del_cref";
            case processor_t::event_t::ev_del_dref:                        return "ev_del_dref";
            case processor_t::event_t::ev_delay_slot_insn:                 return "ev_delay_slot_insn";
            case processor_t::event_t::ev_demangle_name:                   return "ev_demangle_name";
            case processor_t::event_t::ev_emu_insn:                        return "ev_emu_insn";
            case processor_t::event_t::ev_endbinary:                       return "ev_endbinary";
            case processor_t::event_t::ev_equal_reglocs:                   return "ev_equal_reglocs";
            case processor_t::event_t::ev_extract_address:                 return "ev_extract_address";
            case processor_t::event_t::ev_func_bounds:                     return "ev_func_bounds";
            case processor_t::event_t::ev_gen_asm_or_lst:                  return "ev_gen_asm_or_lst";
            case processor_t::event_t::ev_gen_map_file:                    return "ev_gen_map_file";
            case processor_t::event_t::ev_gen_regvar_def:                  return "ev_gen_regvar_def";
            case processor_t::event_t::ev_gen_src_file_lnnum:              return "ev_gen_src_file_lnnum";
            case processor_t::event_t::ev_gen_stkvar_def:                  return "ev_gen_stkvar_def";
            case processor_t::event_t::ev_get_abi_info:                    return "ev_get_abi_info";
            case processor_t::event_t::ev_get_autocmt:                     return "ev_get_autocmt";
            case processor_t::event_t::ev_get_bg_color:                    return "ev_get_bg_color";
            case processor_t::event_t::ev_get_cc_regs:                     return "ev_get_cc_regs";
            case processor_t::event_t::ev_get_dbr_opnum:                   return "ev_get_dbr_opnum";
            case processor_t::event_t::ev_get_default_enum_size:           return "ev_get_default_enum_size";
            case processor_t::event_t::ev_get_frame_retsize:               return "ev_get_frame_retsize";
            case processor_t::event_t::ev_get_idd_opinfo:                  return "ev_get_idd_opinfo";
            case processor_t::event_t::ev_get_macro_insn_head:             return "ev_get_macro_insn_head";
            case processor_t::event_t::ev_get_operand_string:              return "ev_get_operand_string";
            case processor_t::event_t::ev_get_reg_info:                    return "ev_get_reg_info";
            case processor_t::event_t::ev_get_reg_name:                    return "ev_get_reg_name";
            case processor_t::event_t::ev_get_simd_types:                  return "ev_get_simd_types";
            case processor_t::event_t::ev_get_stkarg_offset:               return "ev_get_stkarg_offset";
            case processor_t::event_t::ev_get_stkvar_scale_factor:         return "ev_get_stkvar_scale_factor";
            case processor_t::event_t::ev_getreg:                          return "ev_getreg";
            case processor_t::event_t::ev_init:                            return "ev_init";
            case processor_t::event_t::ev_insn_reads_tbit:                 return "ev_insn_reads_tbit";
            case processor_t::event_t::ev_is_align_insn:                   return "ev_is_align_insn";
            case processor_t::event_t::ev_is_alloca_probe:                 return "ev_is_alloca_probe";
            case processor_t::event_t::ev_is_basic_block_end:              return "ev_is_basic_block_end";
            case processor_t::event_t::ev_is_call_insn:                    return "ev_is_call_insn";
            case processor_t::event_t::ev_is_cond_insn:                    return "ev_is_cond_insn";
            case processor_t::event_t::ev_is_far_jump:                     return "ev_is_far_jump";
            case processor_t::event_t::ev_is_indirect_jump:                return "ev_is_indirect_jump";
            case processor_t::event_t::ev_is_insn_table_jump:              return "ev_is_insn_table_jump";
            case processor_t::event_t::ev_is_jump_func:                    return "ev_is_jump_func";
            case processor_t::event_t::ev_is_ret_insn:                     return "ev_is_ret_insn";
            case processor_t::event_t::ev_is_sane_insn:                    return "ev_is_sane_insn";
            case processor_t::event_t::ev_is_sp_based:                     return "ev_is_sp_based";
            case processor_t::event_t::ev_is_switch:                       return "ev_is_switch";
            case processor_t::event_t::ev_last_cb_before_debugger:         return "ev_last_cb_before_debugger";
            case processor_t::event_t::ev_last_cb_before_type_callbacks:   return "ev_last_cb_before_type_callbacks";
            case processor_t::event_t::ev_loader:                          return "ev_loader";
            case processor_t::event_t::ev_loader_elf_machine:              return "ev_loader_elf_machine";
            case processor_t::event_t::ev_lower_func_type:                 return "ev_lower_func_type";
            case processor_t::event_t::ev_max_ptr_size:                    return "ev_max_ptr_size";
            case processor_t::event_t::ev_may_be_func:                     return "ev_may_be_func";
            case processor_t::event_t::ev_may_show_sreg:                   return "ev_may_show_sreg";
            case processor_t::event_t::ev_moving_segm:                     return "ev_moving_segm";
            case processor_t::event_t::ev_newasm:                          return "ev_newasm";
            case processor_t::event_t::ev_newbinary:                       return "ev_newbinary";
            case processor_t::event_t::ev_newfile:                         return "ev_newfile";
            case processor_t::event_t::ev_newprc:                          return "ev_newprc";
            case processor_t::event_t::ev_next_exec_insn:                  return "ev_next_exec_insn";
            case processor_t::event_t::ev_oldfile:                         return "ev_oldfile";
            case processor_t::event_t::ev_out_assumes:                     return "ev_out_assumes";
            case processor_t::event_t::ev_out_data:                        return "ev_out_data";
            case processor_t::event_t::ev_out_footer:                      return "ev_out_footer";
            case processor_t::event_t::ev_out_header:                      return "ev_out_header";
            case processor_t::event_t::ev_out_insn:                        return "ev_out_insn";
            case processor_t::event_t::ev_out_label:                       return "ev_out_label";
            case processor_t::event_t::ev_out_mnem:                        return "ev_out_mnem";
            case processor_t::event_t::ev_out_operand:                     return "ev_out_operand";
            case processor_t::event_t::ev_out_segend:                      return "ev_out_segend";
            case processor_t::event_t::ev_out_segstart:                    return "ev_out_segstart";
            case processor_t::event_t::ev_out_special_item:                return "ev_out_special_item";
            case processor_t::event_t::ev_realcvt:                         return "ev_realcvt";
            case processor_t::event_t::ev_rename:                          return "ev_rename";
            case processor_t::event_t::ev_set_idp_options:                 return "ev_set_idp_options";
            case processor_t::event_t::ev_set_proc_options:                return "ev_set_proc_options";
            case processor_t::event_t::ev_setup_til:                       return "ev_setup_til";
            case processor_t::event_t::ev_shadow_args_size:                return "ev_shadow_args_size";
            case processor_t::event_t::ev_str2reg:                         return "ev_str2reg";
            case processor_t::event_t::ev_term:                            return "ev_term";
            case processor_t::event_t::ev_treat_hindering_item:            return "ev_treat_hindering_item";
            case processor_t::event_t::ev_undefine:                        return "ev_undefine";
            case processor_t::event_t::ev_use_arg_types:                   return "ev_use_arg_types";
            case processor_t::event_t::ev_use_regarg_type:                 return "ev_use_regarg_type";
            case processor_t::event_t::ev_use_stkarg_type:                 return "ev_use_stkarg_type";
            case processor_t::event_t::ev_validate_flirt_func:             return "ev_validate_flirt_func";
            case processor_t::event_t::ev_verify_noreturn:                 return "ev_verify_noreturn";
            case processor_t::event_t::ev_verify_sp:                       return "ev_verify_sp";
        }
        return "";
    }

    const char* dbg_event_to_txt(dbg_notification_t event)
    {
        switch (event)
        {
            case dbg_notification_t::dbg_bpt:               return "dbg_bpt";
            case dbg_notification_t::dbg_bpt_changed:       return "dbg_bpt_changed";
            case dbg_notification_t::dbg_exception:         return "dbg_exception";
            case dbg_notification_t::dbg_information:       return "dbg_information";
            case dbg_notification_t::dbg_last:              return "dbg_last";
            case dbg_notification_t::dbg_library_load:      return "dbg_library_load";
            case dbg_notification_t::dbg_library_unload:    return "dbg_library_unload";
            case dbg_notification_t::dbg_null:              return "dbg_null";
            case dbg_notification_t::dbg_process_attach:    return "dbg_process_attach";
            case dbg_notification_t::dbg_process_detach:    return "dbg_process_detach";
            case dbg_notification_t::dbg_process_exit:      return "dbg_process_exit";
            case dbg_notification_t::dbg_process_start:     return "dbg_process_start";
            case dbg_notification_t::dbg_request_error:     return "dbg_request_error";
            case dbg_notification_t::dbg_run_to:            return "dbg_run_to";
            case dbg_notification_t::dbg_step_into:         return "dbg_step_into";
            case dbg_notification_t::dbg_step_over:         return "dbg_step_over";
            case dbg_notification_t::dbg_step_until_ret:    return "dbg_step_until_ret";
            case dbg_notification_t::dbg_suspend_process:   return "dbg_suspend_process";
            case dbg_notification_t::dbg_thread_exit:       return "dbg_thread_exit";
            case dbg_notification_t::dbg_thread_start:      return "dbg_thread_start";
            case dbg_notification_t::dbg_trace:             return "dbg_trace";
        }
        return "";
    }

    const char* range_kind_to_str(range_kind_t kind)
    {
        switch (kind)
        {
            case RANGE_KIND_UNKNOWN:        return "unknown";
            case RANGE_KIND_FUNC:           return "function";
            case RANGE_KIND_SEGMENT:        return "segment";
            case RANGE_KIND_HIDDEN_RANGE:   return "hidden";
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

    struct Struc
    {
        tid_t id;
        ea_t  func_ea;
    };

    struct StrucMember
    {
        YaToolObjectId  parent_id;
        Struc           struc;
        ea_t            offset;
    };

    struct EnumMember
    {
        YaToolObjectId parent_id;
        enum_t         eid;
        const_t        mid;
    };

    using Eas           = std::set<ea_t>;
    using Structs       = std::map<YaToolObjectId, Struc>;
    using StructMembers = std::map<YaToolObjectId, StrucMember>;
    using Enums         = std::map<YaToolObjectId, enum_t>;
    using EnumMembers   = std::map<YaToolObjectId, EnumMember>;
    using Comments      = std::set<ea_t>;
    using Segments      = std::set<ea_t>;

    struct Hooks
        : public IHooks
    {

        Hooks(IYaCo& yaco, IRepository& repo);
        ~Hooks();

        // IHooks
        void hook() override;
        void unhook() override;

        // Internal
        void rename(ea_t ea, const std::string& new_name, const std::string& type, const std::string& old_name);
        void update_comment(ea_t ea);
        void delete_function(ea_t ea);
        void make_code(ea_t ea);
        void make_data(ea_t ea);
        void add_function(ea_t ea);
        void update_function(ea_t ea);
        void update_struct(ea_t struct_id);
        void update_struct_member(tid_t struct_id, tid_t member_id, ea_t offset);
        void delete_struct_member(tid_t struct_id, ea_t offset);
        void update_enum(enum_t enum_id);
        void change_operand_type(ea_t ea);
        void update_segment(ea_t start_ea);
        void change_type_information(ea_t ea);

        void add_ea(ea_t ea, const std::string& message);
        void add_struct_member(ea_t struct_id, ea_t member_offset, const std::string& message);

        void save_structs(IModelIncremental& model, IModelVisitor& visitor);
        void save_enums(IModelIncremental& model, IModelVisitor& visitor);
        void save();
        void save_and_update();

        void flush();

        // Events management
        void allsegs_moved(va_list args);
        void auto_empty(va_list args);
        void auto_empty_finally(va_list args);
        void byte_patched(va_list args);
        void changing_cmt(va_list args);
        void changing_enum_bf(va_list args);
        void changing_enum_cmt(va_list args);
        void changing_op_ti(va_list args);
        void changing_op_type(va_list args);
        void changing_range_cmt(va_list args);
        void changing_segm_class(va_list args);
        void changing_segm_end(va_list args);
        void changing_segm_name(va_list args);
        void changing_segm_start(va_list args);
        void changing_struc_align(va_list args);
        void changing_struc_cmt(va_list args);
        void changing_struc_member(va_list args);
        void changing_ti(va_list args);
        void cmt_changed(va_list args);
        void compiler_changed(va_list args);
        void deleting_enum(va_list args);
        void deleting_enum_member(va_list args);
        void deleting_func(va_list args);
        void deleting_func_tail(va_list args);
        void deleting_segm(va_list args);
        void deleting_struc(va_list args);
        void deleting_struc_member(va_list args);
        void deleting_tryblks(va_list args);
        void destroyed_items(va_list args);
        void determined_main(va_list args);
        void enum_bf_changed(va_list args);
        void enum_cmt_changed(va_list args);
        void enum_created(va_list args);
        void enum_deleted(va_list args);
        void enum_member_created(va_list args);
        void enum_member_deleted(va_list args);
        void enum_renamed(va_list args);
        void expanding_struc(va_list args);
        void extlang_changed(va_list args);
        void extra_cmt_changed(va_list args);
        void flow_chart_created(va_list args);
        void frame_deleted(va_list args);
        void func_added(va_list args);
        void func_noret_changed(va_list args);
        void func_tail_appended(va_list args);
        void func_tail_deleted(va_list args);
        void func_updated(va_list args);
        void idasgn_loaded(va_list args);
        void kernel_config_loaded(va_list args);
        void loader_finished(va_list args);
        void local_types_changed(va_list args);
        void make_code(va_list args);
        void make_data(va_list args);
        void op_ti_changed(va_list args);
        void op_type_changed(va_list args);
        void range_cmt_changed(va_list args);
        void renamed(va_list args);
        void renaming_enum(va_list args);
        void renaming_struc(va_list args);
        void renaming_struc_member(va_list args);
        void savebase(va_list args);
        void segm_added(va_list args);
        void segm_attrs_updated(va_list args);
        void segm_class_changed(va_list args);
        void segm_deleted(va_list args);
        void segm_end_changed(va_list args);
        void segm_moved(va_list args);
        void segm_name_changed(va_list args);
        void segm_start_changed(va_list args);
        void set_func_end(va_list args);
        void set_func_start(va_list args);
        void sgr_changed(va_list args);
        void stkpnts_changed(va_list args);
        void struc_align_changed(va_list args);
        void struc_cmt_changed(va_list args);
        void struc_created(va_list args);
        void struc_deleted(va_list args);
        void struc_expanded(va_list args);
        void struc_member_changed(va_list args);
        void struc_member_created(va_list args);
        void struc_member_deleted(va_list args);
        void struc_member_renamed(va_list args);
        void struc_renamed(va_list args);
        void tail_owner_changed(va_list args);
        void thunk_func_created(va_list args);
        void ti_changed(va_list args);
        void tryblks_updated(va_list args);
        void updating_tryblks(va_list args);
        void upgraded(va_list args);
        void closebase(va_list args);

        // Variables
        IYaCo&           yaco_;
        IRepository&     repo_;
        Pool<qstring>    qpool_;

        Eas             eas_;
        Structs         strucs_;
        StructMembers   struc_members_;
        Enums           enums_;
        EnumMembers     enum_members_;
        Comments        comments_;
        Segments        segments_;

        bool            enabled_;
    };
}

namespace
{
    ssize_t idp_event_handler(void* user_data, int notification_code, va_list va)
    {
        UNUSED(va);

        Hooks* hooks = static_cast<Hooks*>(user_data);
        if(!hooks->enabled_)
            return 0;

        const processor_t::event_t event = static_cast<processor_t::event_t>(notification_code);
        LOG_IDP_EVENT("%s", idp_event_to_txt(event));
        return 0;
    }

    ssize_t dbg_event_handler(void* user_data, int notification_code, va_list va)
    {
        UNUSED(va);

        Hooks* hooks = static_cast<Hooks*>(user_data);
        if(!hooks->enabled_)
            return 0;

        dbg_notification_t event = static_cast<dbg_notification_t>(notification_code);
        LOG_DBG_EVENT("%s", dbg_event_to_txt(event));
        return 0;
    }

    ssize_t idb_event_handler(void* user_data, int notification_code, va_list args)
    {
        Hooks* hooks = static_cast<Hooks*>(user_data);
        if(!hooks->enabled_)
            return 0;

        idb_event::event_code_t event = static_cast<idb_event::event_code_t>(notification_code);
        switch (event)
        {
            case idb_event::event_code_t::allsegs_moved:           hooks->allsegs_moved(args); break;
            case idb_event::event_code_t::auto_empty:              hooks->auto_empty(args); break;
            case idb_event::event_code_t::auto_empty_finally:      hooks->auto_empty_finally(args); break;
            case idb_event::event_code_t::byte_patched:            hooks->byte_patched(args); break;
            case idb_event::event_code_t::changing_cmt:            hooks->changing_cmt(args); break;
            case idb_event::event_code_t::changing_enum_bf:        hooks->changing_enum_bf(args); break;
            case idb_event::event_code_t::changing_enum_cmt:       hooks->changing_enum_cmt(args); break;
            case idb_event::event_code_t::changing_op_ti:          hooks->changing_op_ti(args); break;
            case idb_event::event_code_t::changing_op_type:        hooks->changing_op_type(args); break;
            case idb_event::event_code_t::changing_range_cmt:      hooks->changing_range_cmt(args); break;
            case idb_event::event_code_t::changing_segm_class:     hooks->changing_segm_class(args); break;
            case idb_event::event_code_t::changing_segm_end:       hooks->changing_segm_end(args); break;
            case idb_event::event_code_t::changing_segm_name:      hooks->changing_segm_name(args); break;
            case idb_event::event_code_t::changing_segm_start:     hooks->changing_segm_start(args); break;
            case idb_event::event_code_t::changing_struc_align:    hooks->changing_struc_align(args); break;
            case idb_event::event_code_t::changing_struc_cmt:      hooks->changing_struc_cmt(args); break;
            case idb_event::event_code_t::changing_struc_member:   hooks->changing_struc_member(args); break;
            case idb_event::event_code_t::changing_ti:             hooks->changing_ti(args); break;
            case idb_event::event_code_t::closebase:               hooks->closebase(args); break;
            case idb_event::event_code_t::cmt_changed:             hooks->cmt_changed(args); break;
            case idb_event::event_code_t::compiler_changed:        hooks->compiler_changed(args); break;
            case idb_event::event_code_t::deleting_enum:           hooks->deleting_enum(args); break;
            case idb_event::event_code_t::deleting_enum_member:    hooks->deleting_enum_member(args); break;
            case idb_event::event_code_t::deleting_func:           hooks->deleting_func(args); break;
            case idb_event::event_code_t::deleting_func_tail:      hooks->deleting_func_tail(args); break;
            case idb_event::event_code_t::deleting_segm:           hooks->deleting_segm(args); break;
            case idb_event::event_code_t::deleting_struc:          hooks->deleting_struc(args); break;
            case idb_event::event_code_t::deleting_struc_member:   hooks->deleting_struc_member(args); break;
            case idb_event::event_code_t::deleting_tryblks:        hooks->deleting_tryblks(args); break;
            case idb_event::event_code_t::destroyed_items:         hooks->destroyed_items(args); break;
            case idb_event::event_code_t::determined_main:         hooks->determined_main(args); break;
            case idb_event::event_code_t::enum_bf_changed:         hooks->enum_bf_changed(args); break;
            case idb_event::event_code_t::enum_cmt_changed:        hooks->enum_cmt_changed(args); break;
            case idb_event::event_code_t::enum_created:            hooks->enum_created(args); break;
            case idb_event::event_code_t::enum_deleted:            hooks->enum_deleted(args); break;
            case idb_event::event_code_t::enum_member_created:     hooks->enum_member_created(args); break;
            case idb_event::event_code_t::enum_member_deleted:     hooks->enum_member_deleted(args); break;
            case idb_event::event_code_t::enum_renamed:            hooks->enum_renamed(args); break;
            case idb_event::event_code_t::expanding_struc:         hooks->expanding_struc(args); break;
            case idb_event::event_code_t::extlang_changed:         hooks->extlang_changed(args); break;
            case idb_event::event_code_t::extra_cmt_changed:       hooks->extra_cmt_changed(args); break;
            case idb_event::event_code_t::flow_chart_created:      hooks->flow_chart_created(args); break;
            case idb_event::event_code_t::frame_deleted:           hooks->frame_deleted(args); break;
            case idb_event::event_code_t::func_added:              hooks->func_added(args); break;
            case idb_event::event_code_t::func_noret_changed:      hooks->func_noret_changed(args); break;
            case idb_event::event_code_t::func_tail_appended:      hooks->func_tail_appended(args); break;
            case idb_event::event_code_t::func_tail_deleted:       hooks->func_tail_deleted(args); break;
            case idb_event::event_code_t::func_updated:            hooks->func_updated(args); break;
            case idb_event::event_code_t::idasgn_loaded:           hooks->idasgn_loaded(args); break;
            case idb_event::event_code_t::kernel_config_loaded:    hooks->kernel_config_loaded(args); break;
            case idb_event::event_code_t::loader_finished:         hooks->loader_finished(args); break;
            case idb_event::event_code_t::local_types_changed:     hooks->local_types_changed(args); break;
            case idb_event::event_code_t::make_code:               hooks->make_code(args); break;
            case idb_event::event_code_t::make_data:               hooks->make_data(args); break;
            case idb_event::event_code_t::op_ti_changed:           hooks->op_ti_changed(args); break;
            case idb_event::event_code_t::op_type_changed:         hooks->op_type_changed(args); break;
            case idb_event::event_code_t::range_cmt_changed:       hooks->range_cmt_changed(args); break;
            case idb_event::event_code_t::renamed:                 hooks->renamed(args); break;
            case idb_event::event_code_t::renaming_enum:           hooks->renaming_enum(args); break;
            case idb_event::event_code_t::renaming_struc:          hooks->renaming_struc(args); break;
            case idb_event::event_code_t::renaming_struc_member:   hooks->renaming_struc_member(args); break;
            case idb_event::event_code_t::savebase:                hooks->savebase(args); break;
            case idb_event::event_code_t::segm_added:              hooks->segm_added(args); break;
            case idb_event::event_code_t::segm_attrs_updated:      hooks->segm_attrs_updated(args); break;
            case idb_event::event_code_t::segm_class_changed:      hooks->segm_class_changed(args); break;
            case idb_event::event_code_t::segm_deleted:            hooks->segm_deleted(args); break;
            case idb_event::event_code_t::segm_end_changed:        hooks->segm_end_changed(args); break;
            case idb_event::event_code_t::segm_moved:              hooks->segm_moved(args); break;
            case idb_event::event_code_t::segm_name_changed:       hooks->segm_name_changed(args); break;
            case idb_event::event_code_t::segm_start_changed:      hooks->segm_start_changed(args); break;
            case idb_event::event_code_t::set_func_end:            hooks->set_func_end(args); break;
            case idb_event::event_code_t::set_func_start:          hooks->set_func_start(args); break;
            case idb_event::event_code_t::sgr_changed:             hooks->sgr_changed(args); break;
            case idb_event::event_code_t::stkpnts_changed:         hooks->stkpnts_changed(args); break;
            case idb_event::event_code_t::struc_align_changed:     hooks->struc_align_changed(args); break;
            case idb_event::event_code_t::struc_cmt_changed:       hooks->struc_cmt_changed(args); break;
            case idb_event::event_code_t::struc_created:           hooks->struc_created(args); break;
            case idb_event::event_code_t::struc_deleted:           hooks->struc_deleted(args); break;
            case idb_event::event_code_t::struc_expanded:          hooks->struc_expanded(args); break;
            case idb_event::event_code_t::struc_member_changed:    hooks->struc_member_changed(args); break;
            case idb_event::event_code_t::struc_member_created:    hooks->struc_member_created(args); break;
            case idb_event::event_code_t::struc_member_deleted:    hooks->struc_member_deleted(args); break;
            case idb_event::event_code_t::struc_member_renamed:    hooks->struc_member_renamed(args); break;
            case idb_event::event_code_t::struc_renamed:           hooks->struc_renamed(args); break;
            case idb_event::event_code_t::tail_owner_changed:      hooks->tail_owner_changed(args); break;
            case idb_event::event_code_t::thunk_func_created:      hooks->thunk_func_created(args); break;
            case idb_event::event_code_t::ti_changed:              hooks->ti_changed(args); break;
            case idb_event::event_code_t::tryblks_updated:         hooks->tryblks_updated(args); break;
            case idb_event::event_code_t::updating_tryblks:        hooks->updating_tryblks(args); break;
            case idb_event::event_code_t::upgraded:                hooks->upgraded(args); break;
        }
        return 0;
    }
}

Hooks::Hooks(IYaCo& yaco, IRepository& repo)
    : yaco_(yaco)
    , repo_(repo)
    , qpool_(3)
    , enabled_(false)
{
    hook_to_notification_point(HT_IDP, &idp_event_handler, this);
    hook_to_notification_point(HT_DBG, &dbg_event_handler, this);
    hook_to_notification_point(HT_IDB, &idb_event_handler, this);
}

Hooks::~Hooks()
{
    unhook_from_notification_point(HT_IDP, &idp_event_handler, this);
    unhook_from_notification_point(HT_DBG, &dbg_event_handler, this);
    unhook_from_notification_point(HT_IDB, &idb_event_handler, this);
}

void Hooks::hook()
{
    enabled_ = true;
}

void Hooks::unhook()
{
    enabled_ = false;
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

void Hooks::update_struct(ea_t struc_id)
{
    const auto name = qpool_.acquire();
    ya::wrap(&get_struc_name, *name, struc_id);
    const auto id = hash::hash_struc(ya::to_string_ref(*name));
    strucs_.emplace(id, Struc{struc_id, get_func_by_frame(struc_id)});
    repo_.add_auto_comment(struc_id, "Updated");
}

void Hooks::update_struct_member(tid_t struct_id, tid_t member_id, ea_t offset)
{
    const auto fullname = qpool_.acquire();
    ya::wrap(&::get_member_fullname, *fullname, member_id);
    const std::string message = "Member updated at offset " + ea_to_hex(offset) + " : " + fullname->c_str();
    add_struct_member(struct_id, offset, message);
}

void Hooks::delete_struct_member(tid_t struct_id, ea_t offset)
{
    add_struct_member(struct_id, offset, "Member deleted");
}

namespace
{
    void update_enum_member(Hooks& hooks, YaToolObjectId enum_id, enum_t eid, const_t cid)
    {
        const auto qbuf = hooks.qpool_.acquire();
        ya::wrap(&::get_enum_member_name, *qbuf, cid);
        const auto id = hash::hash_enum_member(enum_id, ya::to_string_ref(*qbuf));
        hooks.enum_members_.emplace(id, EnumMember{enum_id, eid, cid});
    }
}

void Hooks::update_enum(enum_t enum_id)
{
    // check first whether enum_id is actually a member id
    const auto parent_id = get_enum_member_enum(enum_id);
    if(parent_id != BADADDR)
        enum_id = parent_id;

    const auto name = qpool_.acquire();
    ya::wrap(&::get_enum_name, *name, enum_id);
    const auto id = hash::hash_enum(ya::to_string_ref(*name));
    enums_.emplace(id, enum_id);
    ya::walk_enum_members(enum_id, [&](const_t cid, uval_t /*value*/, uchar /*serial*/, bmask_t /*bmask*/)
    {
        ::update_enum_member(*this, id, enum_id, cid);
    });
    repo_.add_auto_comment(enum_id, "Updated");
}

void Hooks::change_operand_type(ea_t ea)
{
    if (get_func(ea) || is_code(get_flags(ea)))
    {
        eas_.insert(ea);
        repo_.add_auto_comment(ea, "Operand type change");
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

void Hooks::add_ea(ea_t ea, const std::string& message)
{
    eas_.insert(ea);
    repo_.add_auto_comment(ea, message);
}

void Hooks::add_struct_member(ea_t struc_id, ea_t offset, const std::string& message)
{
    const auto func_ea = get_func_by_frame(struc_id);
    const auto name = qpool_.acquire();
    ya::wrap(&::get_struc_name, *name, struc_id);
    const auto parent_id = func_ea != BADADDR ?
        hash::hash_stack(func_ea) :
        hash::hash_struc(ya::to_string_ref(*name));
    const auto id = hash::hash_member(parent_id, offset);
    struc_members_.emplace(id, StrucMember{parent_id, {struc_id, func_ea}, offset});
    repo_.add_auto_comment(struc_id, message);
}

namespace
{
    bool try_accept_struc(YaToolObjectId id, const Struc& struc, qstring& qbuf)
    {
        if(struc.func_ea != BADADDR)
            return get_func_by_frame(struc.id) == struc.func_ea;

        // on struc renames, as struc_id is still valid, we need to validate its id again
        ya::wrap(&get_struc_name, qbuf, struc.id);
        const auto got_id = hash::hash_struc(ya::to_string_ref(qbuf));
        const auto idx = get_struc_idx(struc.id);
        return id == got_id && idx != BADADDR;
    }
}

void Hooks::save_structs(IModelIncremental& model, IModelVisitor& visitor)
{
    const auto qbuf = qpool_.acquire();
    for(const auto p : strucs_)
    {
        // if frame, we need to update parent function
        if(p.second.func_ea != BADADDR)
            model.accept_function(visitor, p.second.func_ea);
        if(try_accept_struc(p.first, p.second, *qbuf))
            model.accept_struct(visitor, p.second.func_ea, p.second.id);
        else if(p.second.func_ea == BADADDR)
            model.delete_struc(visitor, p.first);
        else
            model.delete_stack(visitor, p.first);
    }

    for(const auto p : struc_members_)
    {
        const auto is_valid_parent = try_accept_struc(p.second.parent_id, p.second.struc, *qbuf);
        const auto struc = p.second.struc.func_ea != BADADDR ?
            get_frame(p.second.struc.func_ea) :
            get_struc(p.second.struc.id);
        const auto member = get_member(struc, p.second.offset);
        const auto id = hash::hash_member(p.second.parent_id, member ? member->soff : -1);
        const auto is_valid_member = p.first == id;
        if(is_valid_parent && is_valid_member)
            model.accept_struct(visitor, p.second.struc.func_ea, p.second.struc.id);
        else if(p.second.struc.func_ea == BADADDR)
            model.delete_struc_member(visitor, p.first);
        else
            model.delete_stack_member(visitor, p.first);
    }
}

void Hooks::save_enums(IModelIncremental& model, IModelVisitor& visitor)
{
    const auto qbuf = qpool_.acquire();
    for(const auto p : enums_)
    {
        // on renames, as enum_id is still valid, we need to validate its id again
        ya::wrap(&get_enum_name, *qbuf, p.second);
        const auto id = hash::hash_enum(ya::to_string_ref(*qbuf));
        const auto idx = get_enum_idx(p.second);
        if(idx == BADADDR || id != p.first)
            model.delete_enum(visitor, p.first);
        else
            model.accept_enum(visitor, p.second);
    }
    for(const auto p : enum_members_)
    {
        // on renames, we need to check both ids
        ya::wrap(&get_enum_name, *qbuf, p.second.eid);
        const auto parent_id = hash::hash_enum(ya::to_string_ref(*qbuf));
        ya::wrap(&::get_enum_member_name, *qbuf, p.second.mid);
        const auto id = hash::hash_enum_member(parent_id, ya::to_string_ref(*qbuf));
        const auto parent = get_enum_member_enum(p.second.mid);
        if(parent == BADADDR || id != p.first || parent_id != p.second.parent_id)
            model.delete_enum_member(visitor, p.first);
        else
            model.accept_enum(visitor, p.second.eid);
    }
}

void Hooks::save()
{
    IDA_LOG_INFO("Saving cache...");
    const auto time_start = std::chrono::system_clock::now();

    // add comments to adresses to process
    for (const ea_t ea : comments_)
        add_ea(ea, "Changed comment");

    ModelAndVisitor db = MakeModel();
    db.visitor->visit_start();
    {
        const auto model = MakeModelIncremental();
        save_structs(*model, *db.visitor);
        save_enums(*model, *db.visitor);
        for (const ea_t ea : eas_)
            model->accept_ea(*db.visitor, ea);
        for (const ea_t segment_ea : segments_)
            model->accept_segment(*db.visitor, segment_ea);
    }
    db.visitor->visit_end();
    db.model->accept(*MakeXmlExporter(get_cache_folder_path()));

    const auto time_end = std::chrono::system_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(time_end - time_start);
    IDA_LOG_INFO("Cache saved in %d seconds", static_cast<int>(elapsed.count()));
}

namespace
{
    struct DepCtx
    {
        DepCtx(const IModel& model)
            : model(model)
            , cache_prefix(fs::path(get_cache_folder_path()).filename())
            , xml_suffix(".xml")
        {
        }

        const IModel&                       model;
        const fs::path                      cache_prefix;
        const std::string                   xml_suffix;
        std::vector<std::string>            files;
        std::unordered_set<YaToolObjectId>  seen;
    };

    // will add id to file list if not already seen
    bool try_add_id(DepCtx& ctx, YaToolObjectType_e type, YaToolObjectId id)
    {
        // remember which ids have been seen already
        const auto inserted = ctx.seen.emplace(id).second;
        if(!inserted)
            return false;

        char hexname[17];
        to_hex<NullTerminate>(hexname, id);
        ctx.files.push_back((ctx.cache_prefix / get_object_type_string(type) / (hexname + ctx.xml_suffix)).generic_string());
        return true;
    }

    enum DepsMode
    {
        SKIP_DEPENDENCIES,
        USE_DEPENDENCIES,
    };

    bool must_add_dependencies(const HVersion& hver)
    {
        const auto type = hver.type();
        // as we always recreate stacks & strucs, we always need every members
        return type == OBJECT_TYPE_STACKFRAME
            || type == OBJECT_TYPE_STRUCT
            || type == OBJECT_TYPE_ENUM;
    }

    void add_id_and_dependencies(DepCtx& ctx, YaToolObjectId id, DepsMode mode)
    {
        const auto hobj = ctx.model.get_object(id);
        if(!hobj.is_valid())
            return;

        // add this id to file list
        const auto ok = try_add_id(ctx, hobj.type(), id);
        if(!ok)
            return;

        hobj.walk_versions([&](const HVersion& hver)
        {
            // add parent id & its dependencies
            add_id_and_dependencies(ctx, hver.parent_id(), SKIP_DEPENDENCIES);
            if(mode != USE_DEPENDENCIES && !must_add_dependencies(hver))
                return WALK_CONTINUE;
            hver.walk_xrefs([&](offset_t, operand_t, auto xref_id, auto)
            {
                // add xref id & its dependencies
                add_id_and_dependencies(ctx, xref_id, SKIP_DEPENDENCIES);
                return WALK_CONTINUE;
            });
            return WALK_CONTINUE;
        });
    }

    void SkipDelete(IModelVisitor* ptr)
    {
        UNUSED(ptr);
    }

    struct SkipVisitStartEndVisitor : public DelegatingVisitor
    {
        SkipVisitStartEndVisitor(IModelVisitor& next_visitor)
        {
            add_delegate(std::shared_ptr<IModelVisitor>(&next_visitor, &SkipDelete));
        }
        void visit_start() override {}
        void visit_end()   override {}
    };

    void load_xml_files_to(IModelVisitor& visitor, const State& state)
    {
        visitor.visit_start();

        SkipVisitStartEndVisitor v(visitor);
        for(const auto& it : state.deleted)
        {
            auto path = fs::path(it);
            path.replace_extension("");
            const auto idstr = path.filename().generic_string();
            const auto id = YaToolObjectId_From_String(idstr.data(), idstr.size());
            path.remove_filename();
            const auto typestr = path.filename();
            const auto type = get_object_type(typestr.generic_string().data());
            v.visit_start_deleted_object(type);
            v.visit_id(id);
            v.visit_end_deleted_object();
        }

        // state.updated contain only git modified files
        // i.e: if you apply a stack member on a basic block
        //      and the stack member is already in xml
        //      modified only contains one file, the basic block with one xref added
        // so we need to add all dependencies from this object
        // we do it by loading the full xml model
        // and add all parents recursively from all modified objects
        const auto files = [&]
        {
            // load all xml files into a new model which we will query
            const auto full = MakeModel();
            MakeXmlAllDatabaseModel(".")->accept(*full.visitor);

            // load all modified objects
            const auto diff = MakeModel();
            MakeXmlFilesDatabaseModel(state.updated)->accept(*diff.visitor);

            DepCtx deps(*full.model);
            diff.model->walk_objects([&](auto id, const HObject& /*hobj*/)
            {
                // add this id & its dependencies
                add_id_and_dependencies(deps, id, USE_DEPENDENCIES);
                return WALK_CONTINUE;
            });
            return deps.files;
        }();
        MakeXmlFilesDatabaseModel(files)->accept(v);
        visitor.visit_end();
    }
}

void Hooks::save_and_update()
{
    // save and commit changes
    save();
    if (!repo_.commit_cache())
    {
        IDA_LOG_WARNING("An error occurred during YaCo commit");
        warning("An error occured during YaCo commit: please relaunch IDA");
    }
    flush();

    unhook();

    // update cache and export modifications to IDA
    {
        auto state = repo_.update_cache();
        const auto cache = fs::path(get_cache_folder_path()).filename();
        state.updated.erase(std::remove_if(state.updated.begin(), state.updated.end(), [&](const auto& item)
        {
            const auto p = fs::path(item);
            const auto it = p.begin();
            return it == p.end() || *it != cache;
        }), state.updated.end());
        const ModelAndVisitor db = MakeModel();
        load_xml_files_to(*db.visitor, state);
        import_to_ida(*db.model);
    }

    // Let IDA apply modifications
    IDA_LOG_INFO("Running IDA auto-analysis...");
    const auto time_start = std::chrono::system_clock::now();
    const auto prev = inf.is_auto_enabled();
    inf.set_auto_enabled(true);
    auto_wait();
    inf.set_auto_enabled(prev);
    refresh_idaview_anyway();
    const auto time_end = std::chrono::system_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(time_end - time_start);
    IDA_LOG_INFO("Auto-analysis done in %d seconds", static_cast<int>(elapsed.count()));

    hook();
}

void Hooks::flush()
{
    eas_.clear();
    strucs_.clear();
    struc_members_.clear();
    enums_.clear();
    enum_members_.clear();
    comments_.clear();
    segments_.clear();
}

static void log_closebase()
{
    LOG_IDB_EVENT("The database will be closed now");
}

void Hooks::closebase(va_list args)
{
    UNUSED(args);

    log_closebase();

    yaco_.stop();
}

static void log_savebase()
{
    LOG_IDB_EVENT("The database is being saved");
}

void Hooks::savebase(va_list args)
{
    UNUSED(args);

    msg("\n");
    log_savebase();

    save_and_update();
}

static void log_upgraded(int from)
{
    LOG_IDB_EVENT("The database has been upgraded (old IDB version: %d)", from);
}

void Hooks::upgraded(va_list args)
{
    const auto from = va_arg(args, int);

    log_upgraded(from);
}

static void log_auto_empty()
{
    LOG_IDB_EVENT("All analysis queues are empty");
}

void Hooks::auto_empty(va_list args)
{
    UNUSED(args);

    log_auto_empty();
}

static void log_auto_empty_finally()
{
    LOG_IDB_EVENT("All analysis queues are empty definitively");
}

void Hooks::auto_empty_finally(va_list args)
{
    UNUSED(args);

    log_auto_empty_finally();
}

static void log_determined_main(ea_t main)
{
    LOG_IDB_EVENT("The main() function has been determined (address of the main() function: " EA_FMT ")", main);
}

void Hooks::determined_main(va_list args)
{
    const auto main = va_arg(args, ea_t);

    log_determined_main(main);
}

static void log_local_types_changed()
{
    LOG_IDB_EVENT("Local types have been changed");
}

void Hooks::local_types_changed(va_list args)
{
    UNUSED(args);

    log_local_types_changed();
}

static void log_extlang_changed(int kind, const extlang_t* el, int idx)
{
    if (!LOG_IDB_EVENTS)
        return;

    UNUSED(idx);
    switch (kind)
    {
    case 1:
        LOG_IDB_EVENT("Extlang %s installed", el->name);
        break;
    case 2:
        LOG_IDB_EVENT("Extlang %s removed", el->name);
        break;
    case 3:
        LOG_IDB_EVENT("Default extlang changed: %s", el->name);
        break;
    default:
        LOG_IDB_EVENT("The list of extlangs or the default extlang was changed");
        break;
    }
}

void Hooks::extlang_changed(va_list args)
{
    const auto kind = va_arg(args, int); //0: extlang installed, 1: extlang removed, 2: default extlang changed
    const auto el   = va_arg(args, extlang_t*);
    const auto idx  = va_arg(args, int);

    log_extlang_changed(kind, el, idx);
}

static void log_idasgn_loaded(const char* short_sig_name)
{
    // FLIRT = Fast Library Identificationand Recognition Technology
    // normal processing = not for recognition of startup sequences
    LOG_IDB_EVENT("FLIRT signature %s has been loaded for normal processing", short_sig_name);
}

void Hooks::idasgn_loaded(va_list args)
{
    const auto short_sig_name = va_arg(args, const char*);

    log_idasgn_loaded(short_sig_name);
}

static void log_kernel_config_loaded()
{
    LOG_IDB_EVENT("Kernel configuration loaded (ida.cfg parsed)");
}

void Hooks::kernel_config_loaded(va_list args)
{
    UNUSED(args);

    log_kernel_config_loaded();
}

static void log_loader_finished(const linput_t* li, uint16 neflags, const char* filetypename)
{
    UNUSED(li);
    UNUSED(neflags);
    LOG_IDB_EVENT("External file loader for %s files finished its work", filetypename);
}

void Hooks::loader_finished(va_list args)
{
    const auto li           = va_arg(args, linput_t*);
    const auto neflags      = static_cast<uint16>(va_arg(args, int)); // NEF_.+ defines from loader.hpp
    const auto filetypename = va_arg(args, const char*);

    log_loader_finished(li, neflags, filetypename);
}

static void log_flow_chart_created(const qflow_chart_t* fc)
{
    LOG_IDB_EVENT("Gui has retrieved a function flow chart (from " EA_FMT " to " EA_FMT ", name: %s, function: %s)", fc->bounds.start_ea, fc->bounds.end_ea, fc->title.c_str(), get_func_name(fc->pfn->start_ea).c_str());
}

void Hooks::flow_chart_created(va_list args)
{
    qflow_chart_t* fc = va_arg(args, qflow_chart_t*);

    log_flow_chart_created(fc);
}

static void log_compiler_changed()
{
    LOG_IDB_EVENT("The kernel has changed the compiler information");
}

void Hooks::compiler_changed(va_list args)
{
    UNUSED(args);

    log_compiler_changed();
}

static void log_changing_ti(ea_t ea, const type_t* new_type, const p_list* new_fnames)
{
    UNUSED(new_type);
    UNUSED(new_fnames);
    LOG_IDB_EVENT("An item typestring (c/c++ prototype) is to be changed (ea: " EA_FMT ")", ea);
}

void Hooks::changing_ti(va_list args)
{
    const auto ea         = va_arg(args, ea_t);
    const auto new_type   = va_arg(args, type_t*);
    const auto new_fnames = va_arg(args, p_list*);

    log_changing_ti(ea, new_type, new_fnames);
}

static void log_ti_changed(ea_t ea, const type_t* type, const p_list* fnames)
{
    UNUSED(type);
    UNUSED(fnames);
    LOG_IDB_EVENT("An item typestring (c/c++ prototype) has been changed (ea: " EA_FMT ")", ea);
}

void Hooks::ti_changed(va_list args)
{
    const auto ea     = va_arg(args, ea_t);
    const auto type   = va_arg(args, type_t*);
    const auto fnames = va_arg(args, p_list*);

    log_ti_changed(ea, type, fnames);

    change_type_information(ea);
}

static void log_changing_op_ti(ea_t ea, int n, const type_t* new_type, const p_list* new_fnames)
{
    UNUSED(n);
    UNUSED(new_type);
    UNUSED(new_fnames);
    LOG_IDB_EVENT("An operand typestring (c/c++ prototype) is to be changed (ea: " EA_FMT ")", ea);
}

void Hooks::changing_op_ti(va_list args)
{
    const auto ea         = va_arg(args, ea_t);
    const auto n          = va_arg(args, int);
    const auto new_type   = va_arg(args, type_t*);
    const auto new_fnames = va_arg(args, p_list*);

    log_changing_op_ti(ea, n, new_type, new_fnames);
}

static void log_op_ti_changed(ea_t ea, int n, const type_t* new_type, const p_list* new_fnames)
{
    UNUSED(n);
    UNUSED(new_type);
    UNUSED(new_fnames);
    LOG_IDB_EVENT("An operand typestring (c/c++ prototype) has been changed (ea: " EA_FMT ")", ea);
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

static void log_changing_op_type(ea_t ea, int n, const opinfo_t* opinfo)
{
    UNUSED(n);
    UNUSED(opinfo);
    LOG_IDB_EVENT("An operand type at " EA_FMT " is to be changed", ea);
}

void Hooks::changing_op_type(va_list args)
{
    const auto ea     = va_arg(args, ea_t);
    const auto n      = va_arg(args, int);
    const auto opinfo = va_arg(args, const opinfo_t*);

    log_changing_op_type(ea, n, opinfo);
}

static void log_op_type_changed(ea_t ea, int n)
{
    UNUSED(n);
    LOG_IDB_EVENT("An operand type at " EA_FMT " has been set or deleted", ea);
}

void Hooks::op_type_changed(va_list args)
{
    const auto ea = va_arg(args, ea_t);
    const auto n  = va_arg(args, int);

    log_op_type_changed(ea, n);

    change_operand_type(ea);
}

static void log_enum_created(enum_t id)
{
    LOG_IDB_EVENT("Enum type %s has been created", get_enum_name(id).c_str());
}

void Hooks::enum_created(va_list args)
{
    const auto id = va_arg(args, enum_t);

    log_enum_created(id);

    update_enum(id);
}

static void log_deleting_enum(enum_t id)
{
    LOG_IDB_EVENT("Enum type %s is to be deleted", get_enum_name(id).c_str());
}

void Hooks::deleting_enum(va_list args)
{
    const auto id = va_arg(args, enum_t);

    log_deleting_enum(id);
    update_enum(id);
}

static void log_enum_deleted(enum_t id)
{
    UNUSED(id);
    LOG_IDB_EVENT("An enum type has been deleted");
}

void Hooks::enum_deleted(va_list args)
{
    const auto id = va_arg(args, enum_t);

    log_enum_deleted(id);
}

static void log_renaming_enum(tid_t id, bool is_enum, const char* newname)
{
    if (!LOG_IDB_EVENTS)
        return;

    if (is_enum)
        LOG_IDB_EVENT("Enum type %s is to be renamed to %s", get_enum_name(id).c_str(), newname);
    else
        LOG_IDB_EVENT("A member of enum type %s is to be renamed from %s to %s", get_enum_member_name(id).c_str(), get_enum_name(get_enum_member_enum(id)).c_str(), newname);
}

void Hooks::renaming_enum(va_list args)
{
    const auto id      = va_arg(args, tid_t);
    const auto is_enum = static_cast<bool>(va_arg(args, int));
    const auto newname = va_arg(args, const char*);

    log_renaming_enum(id, is_enum, newname);
    update_enum(id);
}

static void log_enum_renamed(tid_t id)
{
    if (!LOG_IDB_EVENTS)
        return;

    if (get_enum_member_enum(id) == BADADDR)
        LOG_IDB_EVENT("An enum type has been renamed %s", get_enum_name(id).c_str());
    else
        LOG_IDB_EVENT("A member of enum type %s has been renamed %s", get_enum_name(get_enum_member_enum(id)).c_str(), get_enum_member_name(id).c_str());
}

void Hooks::enum_renamed(va_list args)
{
    const auto id = va_arg(args, tid_t);

    log_enum_renamed(id);

    update_enum(id);
}

static void log_changing_enum_bf(enum_t id, bool new_bf)
{
    LOG_IDB_EVENT("Enum type %s 'bitfield' attribute is to be changed to %s", get_enum_name(id).c_str(), BOOL_STR[new_bf]);
}

void Hooks::changing_enum_bf(va_list args)
{
    const auto id     = va_arg(args, enum_t);
    const auto new_bf = static_cast<bool>(va_arg(args, int));

    log_changing_enum_bf(id, new_bf);
}

static void log_enum_bf_changed(enum_t id)
{
    LOG_IDB_EVENT("Enum type %s 'bitfield' attribute has been changed", get_enum_name(id).c_str());
}

void Hooks::enum_bf_changed(va_list args)
{
    const auto id = va_arg(args, enum_t);

    log_enum_bf_changed(id);

    update_enum(id);
}

static void log_changing_enum_cmt(enum_t id, bool repeatable, const char* newcmt)
{
    if (!LOG_IDB_EVENTS)
        return;

    if (get_enum_member_enum(id) == BADADDR)
        LOG_IDB_EVENT("Enum type %s %scomment is to be changed from \"%s\" to \"%s\"", get_enum_name(id).c_str(), REPEATABLE_STR[repeatable], get_enum_cmt(id, repeatable).c_str(), newcmt);
    else
        LOG_IDB_EVENT("Enum type %s member %s %scomment is to be changed from \"%s\" to \"%s\"", get_enum_name(get_enum_member_enum(id)).c_str(), get_enum_member_name(id).c_str(), REPEATABLE_STR[repeatable], get_enum_member_cmt(id, repeatable).c_str(), newcmt);
}

void Hooks::changing_enum_cmt(va_list args)
{
    const auto id         = va_arg(args, enum_t);
    const auto repeatable = static_cast<bool>(va_arg(args, int));
    const auto newcmt     = va_arg(args, const char*);

    log_changing_enum_cmt(id, repeatable, newcmt);
}

static void log_enum_cmt_changed(enum_t id, bool repeatable)
{
    if (!LOG_IDB_EVENTS)
        return;

    if (get_enum_member_enum(id) == BADADDR)
        LOG_IDB_EVENT("Enum type %s %scomment has been changed to \"%s\"", get_enum_name(id).c_str(), REPEATABLE_STR[repeatable], get_enum_cmt(id, repeatable).c_str());
    else
        LOG_IDB_EVENT("Enum type %s member %s %scomment has been changed to \"%s\"", get_enum_name(get_enum_member_enum(id)).c_str(), get_enum_member_name(id).c_str(), REPEATABLE_STR[repeatable], get_enum_member_cmt(id, repeatable).c_str());
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

static void log_enum_member_created(enum_t id, const_t cid)
{
    LOG_IDB_EVENT("Enum type %s member %s has been created", get_enum_name(id).c_str(), get_enum_member_name(cid).c_str());
}

void Hooks::enum_member_created(va_list args)
{
    const auto eid = va_arg(args, enum_t);
    const auto cid = va_arg(args, const_t);

    log_enum_member_created(eid, cid);
    update_enum(eid);
}

static void log_deleting_enum_member(enum_t id, const_t cid)
{
    LOG_IDB_EVENT("Enum type %s member %s is to be deleted", get_enum_name(id).c_str(), get_enum_member_name(cid).c_str());
}

void Hooks::deleting_enum_member(va_list args)
{
    const auto eid = va_arg(args, enum_t);
    const auto cid = va_arg(args, const_t);

    log_deleting_enum_member(eid, cid);
    update_enum(eid);
}

static void log_enum_member_deleted(enum_t id, const_t cid)
{
    UNUSED(cid);
    LOG_IDB_EVENT("A member of enum type %s has been deleted", get_enum_name(id).c_str());
}

void Hooks::enum_member_deleted(va_list args)
{
    const auto eid = va_arg(args, enum_t);
    const auto cid = va_arg(args, const_t);

    log_enum_member_deleted(eid, cid);
    update_enum(eid);
}

static void log_struc_created(tid_t struc_id)
{
    if (!LOG_IDB_EVENTS)
        return;

    ea_t func_ea = get_func_by_frame(struc_id);
    if (func_ea != BADADDR)
        LOG_IDB_EVENT("Stackframe of function %s has been created", get_func_name(func_ea).c_str());
    else
        LOG_IDB_EVENT("Structure type %s has been created", get_struc_name(struc_id).c_str());
}

void Hooks::struc_created(va_list args)
{
    const auto struc_id = va_arg(args, tid_t);

    log_struc_created(struc_id);
    update_struct(struc_id);
}

static void log_deleting_struc(const struc_t* sptr)
{
    if (!LOG_IDB_EVENTS)
        return;

    ea_t func_ea = get_func_by_frame(sptr->id);
    if (func_ea != BADADDR)
        LOG_IDB_EVENT("Stackframe of function %s is to be deleted", get_func_name(func_ea).c_str());
    else
        LOG_IDB_EVENT("Structure type %s is to be deleted", get_struc_name(sptr->id).c_str());
}

void Hooks::deleting_struc(va_list args)
{
    const auto sptr = va_arg(args, struc_t*);

    log_deleting_struc(sptr);
    update_struct(sptr->id);
}

static void log_struc_deleted(tid_t struc_id)
{
    UNUSED(struc_id);
    LOG_IDB_EVENT("A structure type or stackframe has been deleted");
}

void Hooks::struc_deleted(va_list args)
{
    const auto struc_id = va_arg(args, tid_t);

    log_struc_deleted(struc_id);
    update_struct(struc_id);
}

static void log_changing_struc_align(const struc_t* sptr)
{
    LOG_IDB_EVENT("Structure type %s alignment is being changed from 0x%X", get_struc_name(sptr->id).c_str(), static_cast<int>(std::pow(2, sptr->get_alignment())));
}

void Hooks::changing_struc_align(va_list args)
{
    const auto sptr = va_arg(args, struc_t*);

    log_changing_struc_align(sptr);
}

static void log_struc_align_changed(const struc_t* sptr)
{
    LOG_IDB_EVENT("Structure type %s alignment has been changed to 0x%X", get_struc_name(sptr->id).c_str(), static_cast<int>(std::pow(2, sptr->get_alignment())));
}

void Hooks::struc_align_changed(va_list args)
{
    const auto sptr = va_arg(args, struc_t*);

    log_struc_align_changed(sptr);
}

static void log_renaming_struc(tid_t struc_id, const char* oldname, const char* newname)
{
    UNUSED(struc_id);
    LOG_IDB_EVENT("Structure type %s is to be renamed to %s", oldname, newname);
}

void Hooks::renaming_struc(va_list args)
{
    const auto struc_id = va_arg(args, tid_t);
    const auto oldname  = va_arg(args, const char*);
    const auto newname  = va_arg(args, const char*);

    log_renaming_struc(struc_id, oldname, newname);

    update_struct(struc_id);
}

static void log_struc_renamed(const struc_t* sptr)
{
    LOG_IDB_EVENT("A structure type has been renamed %s", get_struc_name(sptr->id).c_str());
}

void Hooks::struc_renamed(va_list args)
{
    const auto sptr = va_arg(args, struc_t*);

    log_struc_renamed(sptr);
    update_struct(sptr->id);
}

static void log_expanding_struc(const struc_t* sptr, ea_t offset, adiff_t delta)
{
    if (!LOG_IDB_EVENTS)
        return;

    ea_t func_ea = get_func_by_frame(sptr->id);
    if (func_ea != BADADDR)
    {
        if (delta > 0)
            LOG_IDB_EVENT("Stackframe of function %s is to be expanded of 0x%" EA_PREFIX "X bytes at offset 0x%" EA_PREFIX "X", get_func_name(func_ea).c_str(), delta, offset);
        else
            LOG_IDB_EVENT("Stackframe of function %s is to be shrunk of 0x%" EA_PREFIX "X bytes at offset 0x%" EA_PREFIX "X", get_func_name(func_ea).c_str(), ~delta + 1, offset);
    }
    else
    {
        if (delta > 0)
            LOG_IDB_EVENT("Structure type %s is to be expanded of 0x%" EA_PREFIX "X bytes at offset 0x%" EA_PREFIX "X", get_struc_name(sptr->id).c_str(), delta, offset);
        else
            LOG_IDB_EVENT("Structure type %s is to be shrunk of 0x%" EA_PREFIX "X bytes at offset 0x%" EA_PREFIX "X", get_struc_name(sptr->id).c_str(), ~delta + 1, offset);
    }
}

void Hooks::expanding_struc(va_list args)
{
    const auto sptr   = va_arg(args, struc_t*);
    const auto offset = va_arg(args, ea_t);
    const auto delta  = va_arg(args, adiff_t);

    log_expanding_struc(sptr, offset, delta);
    update_struct(sptr->id);
}

static void log_struc_expanded(const struc_t* sptr)
{
    if (!LOG_IDB_EVENTS)
        return;

    ea_t func_ea = get_func_by_frame(sptr->id);
    if (func_ea != BADADDR)
        LOG_IDB_EVENT("Stackframe of function %s has been expanded/shrank", get_func_name(func_ea).c_str());
    else
        LOG_IDB_EVENT("Structure type %s has been expanded/shrank", get_struc_name(sptr->id).c_str());
}

void Hooks::struc_expanded(va_list args)
{
    const auto sptr = va_arg(args, struc_t*);

    log_struc_expanded(sptr);
    update_struct(sptr->id);
}

static void log_struc_member_created(const struc_t* sptr, const member_t* mptr)
{
    if (!LOG_IDB_EVENTS)
        return;

    ea_t func_ea = get_func_by_frame(sptr->id);
    if (func_ea != BADADDR)
        LOG_IDB_EVENT("Stackframe of function %s member %s has been created", get_func_name(func_ea).c_str(), get_member_name(mptr->id).c_str());
    else
        LOG_IDB_EVENT("Structure type %s member %s has been created", get_struc_name(sptr->id).c_str(), get_member_name(mptr->id).c_str());
}

void Hooks::struc_member_created(va_list args)
{
    const auto sptr = va_arg(args, struc_t*);
    const auto mptr = va_arg(args, member_t*);

    log_struc_member_created(sptr, mptr);
    update_struct(sptr->id);
    update_struct_member(sptr->id, mptr->id, mptr->soff);
}

static void log_deleting_struc_member(const struc_t* sptr, const member_t* mptr)
{
    if (!LOG_IDB_EVENTS)
        return;

    ea_t func_ea = get_func_by_frame(sptr->id);
    if (func_ea != BADADDR)
        LOG_IDB_EVENT("Stackframe of function %s member %s is to be deleted", get_func_name(func_ea).c_str(), get_member_name(mptr->id).c_str());
    else
        LOG_IDB_EVENT("Structure type %s member %s is to be deleted", get_struc_name(sptr->id).c_str(), get_member_name(mptr->id).c_str());
}

void Hooks::deleting_struc_member(va_list args)
{
    const auto sptr = va_arg(args, struc_t*);
    const auto mptr = va_arg(args, member_t*);

    log_deleting_struc_member(sptr, mptr);
    update_struct(sptr->id);
    update_struct_member(sptr->id, mptr->id, mptr->soff);
}

static void log_struc_member_deleted(const struc_t* sptr, tid_t member_id, ea_t offset)
{
    if (!LOG_IDB_EVENTS)
        return;

    UNUSED(member_id);
    ea_t func_ea = get_func_by_frame(sptr->id);
    if (func_ea != BADADDR)
        LOG_IDB_EVENT("Stackframe of function %s member at offset 0x%" EA_PREFIX "X has been deleted", get_func_name(func_ea).c_str(), offset);
    else
        LOG_IDB_EVENT("Structure type %s member at offset 0x%" EA_PREFIX "X has been deleted", get_struc_name(sptr->id).c_str(), offset);
}

void Hooks::struc_member_deleted(va_list args)
{
    const auto sptr      = va_arg(args, struc_t*);
    const auto member_id = va_arg(args, tid_t);
    const auto offset    = va_arg(args, ea_t);

    log_struc_member_deleted(sptr, member_id, offset);
    update_struct(sptr->id);
    delete_struct_member(sptr->id, offset);
}

static void log_renaming_struc_member(const struc_t* sptr, const member_t* mptr, const char* newname)
{
    if (!LOG_IDB_EVENTS)
        return;

    ea_t func_ea = get_func_by_frame(sptr->id);
    if (func_ea != BADADDR)
        LOG_IDB_EVENT("A member of stackframe of function %s is to be renamed from %s to %s", get_func_name(func_ea).c_str(), get_member_name(mptr->id).c_str(), newname);
    else
        LOG_IDB_EVENT("A member of structure type %s is to be renamed from %s to %s", get_struc_name(sptr->id).c_str(), get_member_name(mptr->id).c_str(), newname);
}

void Hooks::renaming_struc_member(va_list args)
{
    const auto sptr    = va_arg(args, struc_t*);
    const auto mptr    = va_arg(args, member_t*);
    const auto newname = va_arg(args, const char*);

    log_renaming_struc_member(sptr, mptr, newname);
    update_struct_member(sptr->id, mptr->id, mptr->soff);
}

static void log_struc_member_renamed(const struc_t* sptr, const member_t* mptr)
{
    if (!LOG_IDB_EVENTS)
        return;

    ea_t func_ea = get_func_by_frame(sptr->id);
    if (func_ea != BADADDR)
        LOG_IDB_EVENT("A member of stackframe of function %s has been renamed to %s", get_func_name(func_ea).c_str(), get_member_name(mptr->id).c_str());
    else
        LOG_IDB_EVENT("A member of structure type %s has been renamed to %s", get_struc_name(sptr->id).c_str(), get_member_name(mptr->id).c_str());
}

void Hooks::struc_member_renamed(va_list args)
{
    const auto sptr = va_arg(args, struc_t*);
    const auto mptr = va_arg(args, member_t*);

    log_struc_member_renamed(sptr, mptr);

    update_struct_member(sptr->id, mptr->id, mptr->soff);
}

static void log_changing_struc_member(const struc_t* sptr, const member_t* mptr, flags_t flag, const opinfo_t* ti, asize_t nbytes)
{
    if (!LOG_IDB_EVENTS)
        return;

    UNUSED(flag);
    UNUSED(ti);
    UNUSED(nbytes);
    ea_t func_ea = get_func_by_frame(sptr->id);
    if (func_ea != BADADDR)
        LOG_IDB_EVENT("Stackframe of function %s member %s is to be changed", get_func_name(func_ea).c_str(), get_member_name(mptr->id).c_str());
    else
        LOG_IDB_EVENT("Structure type %s member %s is to be changed", get_struc_name(sptr->id).c_str(), get_member_name(mptr->id).c_str());
}

void Hooks::changing_struc_member(va_list args)
{
    const auto sptr   = va_arg(args, struc_t*);
    const auto mptr   = va_arg(args, member_t*);
    const auto flag   = va_arg(args, flags_t);
    const auto ti     = va_arg(args, const opinfo_t*);
    const auto nbytes = va_arg(args, asize_t);

    log_changing_struc_member(sptr, mptr, flag, ti, nbytes);
    update_struct_member(sptr->id, mptr->id, mptr->soff);
}

static void log_struc_member_changed(const struc_t* sptr, const member_t* mptr)
{
    if (!LOG_IDB_EVENTS)
        return;

    ea_t func_ea = get_func_by_frame(sptr->id);
    if (func_ea != BADADDR)
        LOG_IDB_EVENT("Stackframe of function %s member %s has been changed", get_func_name(func_ea).c_str(), get_member_name(mptr->id).c_str());
    else
        LOG_IDB_EVENT("Structure type %s member %s has been changed", get_struc_name(sptr->id).c_str(), get_member_name(mptr->id).c_str());
}

void Hooks::struc_member_changed(va_list args)
{
    const auto sptr = va_arg(args, struc_t*);
    const auto mptr = va_arg(args, member_t*);

    log_struc_member_changed(sptr, mptr);

    update_struct(sptr->id);
    update_struct_member(sptr->id, mptr->id, mptr->soff);
}

static void log_changing_struc_cmt(tid_t struc_id, bool repeatable, const char* newcmt)
{
    if (!LOG_IDB_EVENTS)
        return;

    if (get_struc(struc_id))
    {
        LOG_IDB_EVENT("Structure type %s %scomment is to be changed from \"%s\" to \"%s\"", get_struc_name(struc_id).c_str(), REPEATABLE_STR[repeatable], get_struc_cmt(struc_id, repeatable).c_str(), newcmt);
    }
    else
    {
        struc_t* struc = get_member_struc(get_member_fullname(struc_id).c_str());
        ea_t func_ea = get_func_by_frame(struc->id);
        if (func_ea != BADADDR)
            LOG_IDB_EVENT("Stackframe of function %s member %s %scomment is to be changed from \"%s\" to \"%s\"", get_func_name(func_ea).c_str(), get_member_name(struc_id).c_str(), REPEATABLE_STR[repeatable], get_member_name(struc_id).c_str(), newcmt);
        else
            LOG_IDB_EVENT("Structure type %s member %s %scomment is to be changed from \"%s\" to \"%s\"", get_struc_name(struc->id).c_str(), get_member_name(struc_id).c_str(), REPEATABLE_STR[repeatable], get_member_name(struc_id).c_str(), newcmt);
    }
}

void Hooks::changing_struc_cmt(va_list args)
{
    const auto struc_id   = va_arg(args, tid_t);
    const auto repeatable = static_cast<bool>(va_arg(args, int));
    const auto newcmt     = va_arg(args, const char*);

    log_changing_struc_cmt(struc_id, repeatable, newcmt);
    update_struct(struc_id);
}

static void log_struc_cmt_changed(tid_t struc_id, bool repeatable)
{
    if (!LOG_IDB_EVENTS)
        return;

    if (get_struc(struc_id))
    {
        LOG_IDB_EVENT("Structure type %s %scomment has been changed to \"%s\"", get_struc_name(struc_id).c_str(), REPEATABLE_STR[repeatable], get_struc_cmt(struc_id, repeatable).c_str());
    }
    else
    {
        struc_t* struc = get_member_struc(get_member_fullname(struc_id).c_str());
        ea_t func_ea = get_func_by_frame(struc->id);
        if (func_ea != BADADDR)
            LOG_IDB_EVENT("Stackframe of function %s member %s %scomment has been changed to \"%s\"", get_func_name(func_ea).c_str(), get_member_name(struc_id).c_str(), REPEATABLE_STR[repeatable], get_member_name(struc_id).c_str());
        else
            LOG_IDB_EVENT("Structure type %s member %s %scomment has been changed to \"%s\"", get_struc_name(struc->id).c_str(), get_member_name(struc_id).c_str(), REPEATABLE_STR[repeatable], get_member_name(struc_id).c_str());
    }
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
        ya::wrap(&::get_member_fullname, *member_fullname, struc_id);
        struc_t* struc = get_member_struc(member_fullname->c_str());
        if(struc)
            real_struc_id = struc->id;
    }
    update_struct(real_struc_id);
}

static void log_segm_added(const segment_t* s)
{
    LOG_IDB_EVENT("Segment %s has been created from " EA_FMT " to " EA_FMT, get_segm_name(s).c_str(), s->start_ea, s->end_ea);
}

void Hooks::segm_added(va_list args)
{
    const auto s = va_arg(args, segment_t*);

    log_segm_added(s);

    update_segment(s->start_ea);
}

static void log_deleting_segm(ea_t start_ea)
{
    if (!LOG_IDB_EVENTS)
        return;

    const segment_t* s = getseg(start_ea);
    LOG_IDB_EVENT("Segment %s (from " EA_FMT " to " EA_FMT ") is to be deleted", get_segm_name(s).c_str(), s->start_ea, s->end_ea);
}

void Hooks::deleting_segm(va_list args)
{
    const auto start_ea = va_arg(args, ea_t);

    log_deleting_segm(start_ea);
}

static void log_segm_deleted(ea_t start_ea, ea_t end_ea)
{
    LOG_IDB_EVENT("A segment (from " EA_FMT " to " EA_FMT ") has been deleted", start_ea, end_ea);
}

void Hooks::segm_deleted(va_list args)
{
    const auto start_ea = va_arg(args, ea_t);
    const auto end_ea   = va_arg(args, ea_t);

    log_segm_deleted(start_ea, end_ea);

    update_segment(start_ea);
}

static void log_changing_segm_start(const segment_t* s, ea_t new_start, int segmod_flags)
{
    UNUSED(segmod_flags);
    LOG_IDB_EVENT("Segment %s start address is to be changed from " EA_FMT " to " EA_FMT, get_segm_name(s).c_str(), s->start_ea, new_start);
}

void Hooks::changing_segm_start(va_list args)
{
    const auto s            = va_arg(args, segment_t*);
    const auto new_start    = va_arg(args, ea_t);
    const auto segmod_flags = va_arg(args, int);

    log_changing_segm_start(s, new_start, segmod_flags);
}

static void log_segm_start_changed(const segment_t* s, ea_t oldstart)
{
    LOG_IDB_EVENT("Segment %s start address has been changed from " EA_FMT " to " EA_FMT, get_segm_name(s).c_str(), oldstart, s->start_ea);
}

void Hooks::segm_start_changed(va_list args)
{
    const auto s        = va_arg(args, segment_t*);
    const auto oldstart = va_arg(args, ea_t);

    log_segm_start_changed(s, oldstart);

    update_segment(s->start_ea);
}

static void log_changing_segm_end(const segment_t* s, ea_t new_end, int segmod_flags)
{
    UNUSED(segmod_flags);
    LOG_IDB_EVENT("Segment %s end address is to be changed from " EA_FMT " to " EA_FMT, get_segm_name(s).c_str(), s->end_ea, new_end);
}

void Hooks::changing_segm_end(va_list args)
{
    const auto s            = va_arg(args, segment_t*);
    const auto new_end      = va_arg(args, ea_t);
    const auto segmod_flags = va_arg(args, int);

    log_changing_segm_end(s, new_end, segmod_flags);
}

static void log_segm_end_changed(const segment_t* s, ea_t oldend)
{
    LOG_IDB_EVENT("Segment %s end address has been changed from " EA_FMT " to " EA_FMT, get_segm_name(s).c_str(), oldend, s->end_ea);
}

void Hooks::segm_end_changed(va_list args)
{
    const auto s      = va_arg(args, segment_t*);
    const auto oldend = va_arg(args, ea_t);

    log_segm_end_changed(s, oldend);

    update_segment(s->start_ea);
}

static void log_changing_segm_name(const segment_t* s, const char* oldname)
{
    UNUSED(s);
    LOG_IDB_EVENT("Segment %s is being renamed", oldname);
}

void Hooks::changing_segm_name(va_list args)
{
    const auto s       = va_arg(args, segment_t*);
    const auto oldname = va_arg(args, const char*);

    log_changing_segm_name(s, oldname);
}

static void log_segm_name_changed(const segment_t* s, const char* name)
{
    UNUSED(s);
    LOG_IDB_EVENT("A segment has been renamed %s", name);
}

void Hooks::segm_name_changed(va_list args)
{
    const auto s    = va_arg(args, segment_t*);
    const auto name = va_arg(args, const char*);

    log_segm_name_changed(s, name);

    update_segment(s->start_ea);
}

static void log_changing_segm_class(const segment_t* s)
{
    LOG_IDB_EVENT("Segment %s class is being changed from %s", get_segm_name(s).c_str(), get_segm_class(s).c_str());
}

void Hooks::changing_segm_class(va_list args)
{
    const auto s = va_arg(args, segment_t*);

    log_changing_segm_class(s);
}

static void log_segm_class_changed(const segment_t* s, const char* sclass)
{
    LOG_IDB_EVENT("Segment %s class has been changed to %s", get_segm_name(s).c_str(), sclass);
}

void Hooks::segm_class_changed(va_list args)
{
    const auto s      = va_arg(args, segment_t*);
    const auto sclass = va_arg(args, const char*);

    log_segm_class_changed(s, sclass);

    update_segment(s->start_ea);
}

static void log_segm_attrs_updated(const segment_t* s)
{
    LOG_IDB_EVENT("Segment %s attributes has been changed", get_segm_name(s).c_str());
}

void Hooks::segm_attrs_updated(va_list args)
{
    // This event is generated for secondary segment attributes (examples: color, permissions, etc)
    const auto s = va_arg(args, segment_t*);

    log_segm_attrs_updated(s);

    update_segment(s->start_ea);
}

static void log_segm_moved(ea_t from, ea_t to, asize_t size, bool changed_netmap)
{
    if (!LOG_IDB_EVENTS)
        return;

    const segment_t* s = getseg(to);
    const char changed_netmap_txt[2][18] = { "", " (changed netmap)" };
    LOG_IDB_EVENT("Segment %s has been moved from " EA_FMT "-" EA_FMT " to " EA_FMT "-" EA_FMT "%s", get_segm_name(s).c_str(), from, from + size, to, to + size, changed_netmap_txt[changed_netmap]);
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

static void log_allsegs_moved(const segm_move_infos_t* info)
{
    LOG_IDB_EVENT("Program rebasing is complete, %zd segments have been moved", info->size());
}

void Hooks::allsegs_moved(va_list args)
{
    const auto info = va_arg(args, segm_move_infos_t*);

    log_allsegs_moved(info);
}

static void log_func_added(const func_t* pfn)
{
    LOG_IDB_EVENT("Function %s has been created from " EA_FMT " to " EA_FMT, get_func_name(pfn->start_ea).c_str(), pfn->start_ea, pfn->end_ea);
}

void Hooks::func_added(va_list args)
{
    const auto pfn = va_arg(args, func_t*);

    log_func_added(pfn);

    add_function(pfn->start_ea);
}

static void log_func_updated(const func_t* pfn)
{
    LOG_IDB_EVENT("Function %s has been updated", get_func_name(pfn->start_ea).c_str());
}

void Hooks::func_updated(va_list args)
{
    const auto pfn = va_arg(args, func_t*);

    log_func_updated(pfn);

    update_function(pfn->start_ea);
}

static void log_set_func_start(const func_t* pfn, ea_t new_start)
{
    LOG_IDB_EVENT("Function %s chunk start address will be changed from " EA_FMT " to " EA_FMT, get_func_name(pfn->start_ea).c_str(), pfn->start_ea, new_start);
}

void Hooks::set_func_start(va_list args)
{
    const auto pfn       = va_arg(args, func_t*);
    const auto new_start = va_arg(args, ea_t);

    log_set_func_start(pfn, new_start);

    update_function(pfn->start_ea);
}

static void log_set_func_end(const func_t* pfn, ea_t new_end)
{
    LOG_IDB_EVENT("Function %s chunk end address will be changed from " EA_FMT " to " EA_FMT, get_func_name(pfn->start_ea).c_str(), pfn->end_ea, new_end);
}

void Hooks::set_func_end(va_list args)
{
    const auto pfn     = va_arg(args, func_t*);
    const auto new_end = va_arg(args, ea_t);

    log_set_func_end(pfn, new_end);

    update_function(pfn->start_ea);
}

static void log_deleting_func(const func_t* pfn)
{
    LOG_IDB_EVENT("Function %s is about to be deleted (" EA_FMT " to " EA_FMT")", get_func_name(pfn->start_ea).c_str(), pfn->start_ea, pfn->end_ea);
}

void Hooks::deleting_func(va_list args)
{
    const auto pfn = va_arg(args, func_t*);

    log_deleting_func(pfn);

    delete_function(pfn->start_ea);
}

static void log_frame_deleted(const func_t* pfn)
{
    UNUSED(pfn);
    LOG_IDB_EVENT("A function frame has been deleted");
}

void Hooks::frame_deleted(va_list args)
{
    const auto pfn = va_arg(args, func_t*);

    log_frame_deleted(pfn);
}

static void log_thunk_func_created(const func_t* pfn)
{
    LOG_IDB_EVENT("Function %s thunk bit has been set to %s", get_func_name(pfn->start_ea).c_str(), BOOL_STR[!!(pfn->flags & FUNC_THUNK)]);
}

void Hooks::thunk_func_created(va_list args)
{
    const auto pfn = va_arg(args, func_t*);

    log_thunk_func_created(pfn);

    update_function(pfn->start_ea);
}

static void log_func_tail_appended(const func_t* pfn, const func_t* tail)
{
    LOG_IDB_EVENT("Function %s tail chunk from " EA_FMT " to " EA_FMT " has been appended", get_func_name(pfn->start_ea).c_str(), tail->start_ea, tail->end_ea);
}

void Hooks::func_tail_appended(va_list args)
{
    const auto pfn  = va_arg(args, func_t*);
    const auto tail = va_arg(args, func_t*);

    log_func_tail_appended(pfn, tail);

    update_function(pfn->start_ea);
}

static void log_deleting_func_tail(const func_t* pfn, const range_t* tail)
{
    LOG_IDB_EVENT("Function %s tail chunk from " EA_FMT " to " EA_FMT " is to be removed", get_func_name(pfn->start_ea).c_str(), tail->start_ea, tail->end_ea);
}

void Hooks::deleting_func_tail(va_list args)
{
    const auto pfn  = va_arg(args, func_t*);
    const auto tail = va_arg(args, const range_t*);

    log_deleting_func_tail(pfn, tail);
}

static void log_func_tail_deleted(const func_t* pfn, ea_t tail_ea)
{
    LOG_IDB_EVENT("Function %s tail chunk at " EA_FMT " has been removed", get_func_name(pfn->start_ea).c_str(), tail_ea);
}

void Hooks::func_tail_deleted(va_list args)
{
    const auto pfn     = va_arg(args, func_t*);
    const auto tail_ea = va_arg(args, ea_t);

    log_func_tail_deleted(pfn, tail_ea);

    update_function(pfn->start_ea);
}

static void log_tail_owner_changed(const func_t* pfn, ea_t owner_func, ea_t old_owner)
{
    LOG_IDB_EVENT("Tail chunk from " EA_FMT " to " EA_FMT " owner function changed from %s to %s", pfn->start_ea, pfn->end_ea, get_func_name(old_owner).c_str(), get_func_name(owner_func).c_str());
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

static void log_func_noret_changed(const func_t* pfn)
{
    LOG_IDB_EVENT("Function %s FUNC_NORET flag has been changed to %s", get_func_name(pfn->start_ea).c_str(), BOOL_STR[!!(pfn->flags & FUNC_NORET)]);
}

void Hooks::func_noret_changed(va_list args)
{
    const auto pfn = va_arg(args, func_t*);

    log_func_noret_changed(pfn);

    update_function(pfn->start_ea);
}

static void log_stkpnts_changed(const func_t* pfn)
{
    LOG_IDB_EVENT("Function %s stack change points have been modified", get_func_name(pfn->start_ea).c_str());
}

void Hooks::stkpnts_changed(va_list args)
{
    const auto pfn = va_arg(args, func_t*);

    log_stkpnts_changed(pfn);

    update_function(pfn->start_ea);
}

static void log_updating_tryblks(const tryblks_t* tbv)
{
    UNUSED(tbv);
    LOG_IDB_EVENT("About to update try block information");
}

void Hooks::updating_tryblks(va_list args)
{
    const auto tbv = va_arg(args, const tryblks_t*);

    log_updating_tryblks(tbv);
}

static void log_tryblks_updated(const tryblks_t* tbv)
{
    UNUSED(tbv);
    LOG_IDB_EVENT("Updated try block information");
}

void Hooks::tryblks_updated(va_list args)
{
    const auto tbv = va_arg(args, const tryblks_t*);

    log_tryblks_updated(tbv);
}

static void log_deleting_tryblks(const range_t* range)
{
    LOG_IDB_EVENT("About to delete try block information in range " EA_FMT "-" EA_FMT, range->start_ea, range->end_ea);
}

void Hooks::deleting_tryblks(va_list args)
{
    const auto range = va_arg(args, const range_t*);

    log_deleting_tryblks(range);
}

static void log_sgr_changed(ea_t start_ea, ea_t end_ea, int regnum, sel_t value, sel_t old_value, uchar tag)
{
    UNUSED(start_ea);
    UNUSED(end_ea);
    UNUSED(regnum);
    UNUSED(value);
    UNUSED(old_value);
    UNUSED(tag);
    LOG_IDB_EVENT("The kernel has changed a segment register value");
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

static void log_make_code(const insn_t* insn)
{
    LOG_IDB_EVENT("An instruction is being created at " EA_FMT, insn->ea);
}

void Hooks::make_code(va_list args)
{
    const auto insn = va_arg(args, const insn_t*);

    log_make_code(insn);

    make_code(insn->ea);
}

static void log_make_data(ea_t ea, flags_t flags, tid_t tid, asize_t len)
{
    UNUSED(flags);
    UNUSED(tid);
    UNUSED(len);
    LOG_IDB_EVENT("A data item is being created at " EA_FMT, ea);
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

static void log_destroyed_items(ea_t ea1, ea_t ea2, bool will_disable_range)
{
    UNUSED(will_disable_range);
    LOG_IDB_EVENT("Instructions/data have been destroyed in " EA_FMT "-" EA_FMT, ea1, ea2);
}

void Hooks::destroyed_items(va_list args)
{
    const auto ea1                = va_arg(args, ea_t);
    const auto ea2                = va_arg(args, ea_t);
    const auto will_disable_range = static_cast<bool>(va_arg(args, int));

    log_destroyed_items(ea1, ea2, will_disable_range);
}

static void log_renamed(ea_t ea, const char* new_name, bool local_name)
{
    UNUSED(local_name);
    LOG_IDB_EVENT("Byte at " EA_FMT " renamed to %s", ea, new_name);
}

void Hooks::renamed(va_list args)
{
    const auto ea         = va_arg(args, ea_t);
    const auto new_name   = va_arg(args, const char*);
    const auto local_name = static_cast<bool>(va_arg(args, int));

    if(get_struc(ea))
        return;

    log_renamed(ea, new_name, local_name);
    rename(ea, new_name, "", "");
}

static void log_byte_patched(ea_t ea, uint32 old_value)
{
    LOG_IDB_EVENT("Byte at " EA_FMT " has been changed from 0x%02X to 0x%02X", ea, old_value, get_byte(ea));
}

void Hooks::byte_patched(va_list args)
{
    const auto ea        = va_arg(args, ea_t);
    const auto old_value = va_arg(args, uint32);

    log_byte_patched(ea, old_value);
}

static void log_changing_cmt(ea_t ea, bool repeatable_cmt, const char* newcmt)
{
    LOG_IDB_EVENT("Item at " EA_FMT " %scomment is to be changed from \"%s\" to \"%s\"", ea, REPEATABLE_STR[repeatable_cmt], get_cmt(ea, repeatable_cmt).c_str(), newcmt);
}

void Hooks::changing_cmt(va_list args)
{
    const auto ea             = va_arg(args, ea_t);
    const auto repeatable_cmt = static_cast<bool>(va_arg(args, int));
    const auto newcmt         = va_arg(args, const char*);

    log_changing_cmt(ea, repeatable_cmt, newcmt);
}

static void log_cmt_changed(ea_t ea, bool repeatable_cmt)
{
    LOG_IDB_EVENT("Item at " EA_FMT " %scomment has been changed to \"%s\"", ea, REPEATABLE_STR[repeatable_cmt], get_cmt(ea, repeatable_cmt).c_str());
}

void Hooks::cmt_changed(va_list args)
{
    const auto ea             = va_arg(args, ea_t);
    const auto repeatable_cmt = static_cast<bool>(va_arg(args, int));

    log_cmt_changed(ea, repeatable_cmt);

    update_comment(ea);
}

static void log_changing_range_cmt(range_kind_t kind, const range_t* a, const char* cmt, bool repeatable)
{
    LOG_IDB_EVENT("%s range from " EA_FMT " to " EA_FMT " %scomment is to be changed to \"%s\"", range_kind_to_str(kind), a->start_ea, a->end_ea, REPEATABLE_STR[repeatable], cmt);
}

void Hooks::changing_range_cmt(va_list args)
{
    const auto kind       = static_cast<range_kind_t>(va_arg(args, int));
    const auto a          = va_arg(args, const range_t*);
    const auto cmt        = va_arg(args, const char*);
    const auto repeatable = static_cast<bool>(va_arg(args, int));

    log_changing_range_cmt(kind, a, cmt, repeatable);
}

static void log_range_cmt_changed(range_kind_t kind, const range_t* a, const char* cmt, bool repeatable)
{
    LOG_IDB_EVENT("%s range from " EA_FMT " to " EA_FMT " %scomment has been changed to \"%s\"", range_kind_to_str(kind), a->start_ea, a->end_ea, REPEATABLE_STR[repeatable], cmt);
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

static void log_extra_cmt_changed(ea_t ea, int line_idx, const char* cmt)
{
    UNUSED(line_idx);
    LOG_IDB_EVENT("Extra comment at " EA_FMT " has been changed to \"%s\"", ea, cmt);
}

void Hooks::extra_cmt_changed(va_list args)
{
    const auto ea       = va_arg(args, ea_t);
    const auto line_idx = va_arg(args, int);
    const auto cmt      = va_arg(args, const char*);

    log_extra_cmt_changed(ea, line_idx, cmt);

    update_comment(ea);
}


std::shared_ptr<IHooks> MakeHooks(IYaCo& yaco, IRepository& repo)
{
    return std::make_shared<Hooks>(yaco, repo);
}
