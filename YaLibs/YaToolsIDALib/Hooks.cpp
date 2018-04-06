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

#include "Events.hpp"
#include "Helpers.h"
#include "Yatools.hpp"
#include "YaHelpers.hpp"

#include <math.h>

#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("hooks", (FMT), ## __VA_ARGS__)

// Log macro used for events logging
#define LOG_IDP_EVENT(format, ...) do { if(LOG_IDP_EVENTS) LOG(INFO, "idp: " format, ## __VA_ARGS__); } while(0)
#define LOG_DBG_EVENT(format, ...) do { if(LOG_DBG_EVENTS) LOG(INFO, "dbg: " format, ## __VA_ARGS__); } while(0)
#define LOG_IDB_EVENT(format, ...) do { if(LOG_IDB_EVENTS) LOG(INFO, "idb: " format, ## __VA_ARGS__); } while(0)

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
#if IDA_SDK_VERSION > 700
            case processor_t::event_t::ev_analyze_prolog:                  return "ev_analyze_prolog";
            case processor_t::event_t::ev_calc_spdelta:                    return "ev_calc_spdelta";
            case processor_t::event_t::ev_calcrel:                         return "ev_calcrel";
            case processor_t::event_t::ev_find_op_value:                   return "ev_find_op_value";
            case processor_t::event_t::ev_find_reg_value:                  return "ev_find_reg_value";
#endif
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

    struct Hooks
        : public IHooks
    {

         Hooks(IEvents& events);
        ~Hooks();

        // IHooks
        void hook() override;
        void unhook() override;

        void save_and_update();

        IEvents& events_;
        bool     enabled_;
    };
}

void Hooks::hook()
{
    enabled_ = true;
}

void Hooks::unhook()
{
    enabled_ = false;
}

void Hooks::save_and_update()
{
    events_.save();
    unhook();
    events_.update();
    hook();
}

namespace
{
    void closebase(Hooks& /*hooks*/, va_list args)
    {
        UNUSED(args);
        LOG_IDB_EVENT("The database will be closed now");
    }

    void savebase(Hooks& hooks, va_list args)
    {
        UNUSED(args);
        msg("\n");
        LOG_IDB_EVENT("The database is being saved");
        hooks.save_and_update();
    }

    void upgraded(Hooks& /*hooks*/, va_list args)
    {
        const auto from = va_arg(args, int);
        LOG_IDB_EVENT("The database has been upgraded (old IDB version: %d)", from);
    }

    void auto_empty(Hooks& /*hooks*/, va_list args)
    {
        UNUSED(args);
        LOG_IDB_EVENT("All analysis queues are empty");
    }

    void auto_empty_finally(Hooks& /*hooks*/, va_list args)
    {
        UNUSED(args);
        LOG_IDB_EVENT("All analysis queues are empty definitively");
    }

    void determined_main(Hooks& /*hooks*/, va_list args)
    {
        const auto main = va_arg(args, ea_t);
        LOG_IDB_EVENT("The main() function has been determined (address of the main() function: %" PRIxEA ")", main);
    }

    void local_types_changed(Hooks& /*hooks*/, va_list args)
    {
        UNUSED(args);
        LOG_IDB_EVENT("Local types have been changed");
    }

    void log_extlang_changed(int kind, const extlang_t* el, int idx)
    {
        if(!LOG_IDB_EVENTS)
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

    void extlang_changed(Hooks& /*hooks*/, va_list args)
    {
        const auto kind = va_arg(args, int); //0: extlang installed, 1: extlang removed, 2: default extlang changed
        const auto el   = va_arg(args, extlang_t*);
        const auto idx  = va_arg(args, int);
        log_extlang_changed(kind, el, idx);
    }

    void idasgn_loaded(Hooks& /*hooks*/, va_list args)
    {
        const auto short_sig_name = va_arg(args, const char*);
        // FLIRT = Fast Library Identification and Recognition Technology
        // normal processing = not for recognition of startup sequences
        LOG_IDB_EVENT("FLIRT signature %s has been loaded for normal processing", short_sig_name);
    }

    void kernel_config_loaded(Hooks& /*hooks*/, va_list args)
    {
        UNUSED(args);
        LOG_IDB_EVENT("Kernel configuration loaded (ida.cfg parsed)");
    }

    static void log_loader_finished(const linput_t* li, uint16 neflags, const char* filetypename)
    {
        UNUSED(li);
        UNUSED(neflags);
        LOG_IDB_EVENT("External file loader for %s files finished its work", filetypename);
    }

    void loader_finished(Hooks& /*hooks*/, va_list args)
    {
        const auto li           = va_arg(args, linput_t*);
        const auto neflags      = static_cast<uint16>(va_arg(args, int)); // NEF_.+ defines from loader.hpp
        const auto filetypename = va_arg(args, const char*);
        log_loader_finished(li, neflags, filetypename);
    }

    void flow_chart_created(Hooks& /*hooks*/, va_list args)
    {
        qflow_chart_t* fc = va_arg(args, qflow_chart_t*);
        LOG_IDB_EVENT("Gui has retrieved a function flow chart (from %" PRIxEA " to %" PRIxEA ", name: %s, function: %s)", fc->bounds.start_ea, fc->bounds.end_ea, fc->title.c_str(), get_func_name(fc->pfn->start_ea).c_str());
    }

    void compiler_changed(Hooks& /*hooks*/, va_list args)
    {
        UNUSED(args);
        LOG_IDB_EVENT("The kernel has changed the compiler information");
    }

    void changing_ti(Hooks& hooks, va_list args)
    {
        const auto ea = va_arg(args, ea_t);
        LOG_IDB_EVENT("An item typestring (c/c++ prototype) is to be changed (ea: %" PRIxEA ")", ea);
        hooks.events_.touch_ea(ea);
    }

    void ti_changed(Hooks& hooks, va_list args)
    {
        const auto ea = va_arg(args, ea_t);
        LOG_IDB_EVENT("An item typestring (c/c++ prototype) has been changed (ea: %" PRIxEA ")", ea);
        hooks.events_.touch_ea(ea);
    }

    void changing_op_ti(Hooks& hooks, va_list args)
    {
        const auto ea = va_arg(args, ea_t);
        LOG_IDB_EVENT("An operand typestring (c/c++ prototype) is to be changed (ea: %" PRIxEA ")", ea);
        hooks.events_.touch_ea(ea);
    }

    void op_ti_changed(Hooks& hooks, va_list args)
    {
        const auto ea = va_arg(args, ea_t);
        LOG_IDB_EVENT("An operand typestring (c/c++ prototype) has been changed (ea: %" PRIxEA ")", ea);
        hooks.events_.touch_ea(ea);
    }

    void changing_op_type(Hooks& hooks, va_list args)
    {
        const auto ea = va_arg(args, ea_t);
        LOG_IDB_EVENT("An operand type at %" PRIxEA " is to be changed", ea);
        hooks.events_.touch_ea(ea);
    }

    void op_type_changed(Hooks& hooks, va_list args)
    {
        const auto ea = va_arg(args, ea_t);
        LOG_IDB_EVENT("An operand type at %" PRIxEA " has been set or deleted", ea);
        hooks.events_.touch_ea(ea);
    }

    void enum_created(Hooks& hooks, va_list args)
    {
        const auto id = va_arg(args, enum_t);
        LOG_IDB_EVENT("Enum type %s has been created", get_enum_name(id).c_str());
        hooks.events_.touch_enum(id);
    }

    void deleting_enum(Hooks& hooks, va_list args)
    {
        const auto id = va_arg(args, enum_t);
        LOG_IDB_EVENT("Enum type %s is to be deleted", get_enum_name(id).c_str());
        hooks.events_.touch_enum(id);
    }

    void enum_deleted(Hooks& hooks, va_list args)
    {
        const auto id = va_arg(args, enum_t);
        LOG_IDB_EVENT("An enum type has been deleted");
        hooks.events_.touch_enum(id);
    }

    void log_renaming_enum(tid_t id, bool is_enum, const char* newname)
    {
        if(!LOG_IDB_EVENTS)
            return;
        if(is_enum)
            LOG_IDB_EVENT("Enum type %s is to be renamed to %s", get_enum_name(id).c_str(), newname);
        else
            LOG_IDB_EVENT("A member of enum type %s is to be renamed from %s to %s", get_enum_member_name(id).c_str(), get_enum_name(get_enum_member_enum(id)).c_str(), newname);
    }

    void renaming_enum(Hooks& hooks, va_list args)
    {
        const auto id      = va_arg(args, tid_t);
        const auto is_enum = static_cast<bool>(va_arg(args, int));
        const auto newname = va_arg(args, const char*);
        log_renaming_enum(id, is_enum, newname);
        hooks.events_.touch_enum(id);
    }

    static void log_enum_renamed(tid_t id)
    {
        if(!LOG_IDB_EVENTS)
            return;
        if(get_enum_member_enum(id) == BADADDR)
            LOG_IDB_EVENT("An enum type has been renamed %s", get_enum_name(id).c_str());
        else
            LOG_IDB_EVENT("A member of enum type %s has been renamed %s", get_enum_name(get_enum_member_enum(id)).c_str(), get_enum_member_name(id).c_str());
    }

    void enum_renamed(Hooks& hooks, va_list args)
    {
        const auto id = va_arg(args, tid_t);
        log_enum_renamed(id);
        hooks.events_.touch_enum(id);
    }

    void changing_enum_bf(Hooks& hooks, va_list args)
    {
        const auto id = va_arg(args, enum_t);
        const auto new_bf = static_cast<bool>(va_arg(args, int));
        LOG_IDB_EVENT("Enum type %s 'bitfield' attribute is to be changed to %s", get_enum_name(id).c_str(), BOOL_STR[new_bf]);
        hooks.events_.touch_enum(id);
    }

    void enum_bf_changed(Hooks& hooks, va_list args)
    {
        const auto id = va_arg(args, enum_t);
        LOG_IDB_EVENT("Enum type %s 'bitfield' attribute has been changed", get_enum_name(id).c_str());
        hooks.events_.touch_enum(id);
    }

    void log_changing_enum_cmt(enum_t id, bool repeatable, const char* newcmt)
    {
        if(!LOG_IDB_EVENTS)
            return;
        if(get_enum_member_enum(id) == BADADDR)
            LOG_IDB_EVENT("Enum type %s %scomment is to be changed from \"%s\" to \"%s\"", get_enum_name(id).c_str(), REPEATABLE_STR[repeatable], get_enum_cmt(id, repeatable).c_str(), newcmt);
        else
            LOG_IDB_EVENT("Enum type %s member %s %scomment is to be changed from \"%s\" to \"%s\"", get_enum_name(get_enum_member_enum(id)).c_str(), get_enum_member_name(id).c_str(), REPEATABLE_STR[repeatable], get_enum_member_cmt(id, repeatable).c_str(), newcmt);
    }

    void changing_enum_cmt(Hooks& hooks, va_list args)
    {
        const auto id         = va_arg(args, enum_t);
        const auto repeatable = static_cast<bool>(va_arg(args, int));
        const auto newcmt     = va_arg(args, const char*);
        log_changing_enum_cmt(id, repeatable, newcmt);
        hooks.events_.touch_enum(id);
    }

    void log_enum_cmt_changed(enum_t id, bool repeatable)
    {
        if(!LOG_IDB_EVENTS)
            return;
        if(get_enum_member_enum(id) == BADADDR)
            LOG_IDB_EVENT("Enum type %s %scomment has been changed to \"%s\"", get_enum_name(id).c_str(), REPEATABLE_STR[repeatable], get_enum_cmt(id, repeatable).c_str());
        else
            LOG_IDB_EVENT("Enum type %s member %s %scomment has been changed to \"%s\"", get_enum_name(get_enum_member_enum(id)).c_str(), get_enum_member_name(id).c_str(), REPEATABLE_STR[repeatable], get_enum_member_cmt(id, repeatable).c_str());
    }

    void enum_cmt_changed(Hooks& hooks, va_list args)
    {
        const auto id  = va_arg(args, enum_t);
        const auto repeatable = static_cast<bool>(va_arg(args, int));
        log_enum_cmt_changed(id, repeatable);
        hooks.events_.touch_enum(id);
    }

    void enum_member_created(Hooks& hooks, va_list args)
    {
        const auto eid = va_arg(args, enum_t);
        const auto cid = va_arg(args, const_t);
        LOG_IDB_EVENT("Enum type %s member %s has been created", get_enum_name(eid).c_str(), get_enum_member_name(cid).c_str());
        hooks.events_.touch_enum(eid);
    }

    void deleting_enum_member(Hooks& hooks, va_list args)
    {
        const auto eid = va_arg(args, enum_t);
        const auto cid = va_arg(args, const_t);
        LOG_IDB_EVENT("Enum type %s member %s is to be deleted", get_enum_name(eid).c_str(), get_enum_member_name(cid).c_str());
        hooks.events_.touch_enum(eid);
    }

    void enum_member_deleted(Hooks& hooks, va_list args)
    {
        const auto eid = va_arg(args, enum_t);
        const auto cid = va_arg(args, const_t);
        UNUSED(cid);
        LOG_IDB_EVENT("A member of enum type %s has been deleted", get_enum_name(eid).c_str());
        hooks.events_.touch_enum(eid);
    }

    void log_struc_created(tid_t struc_id)
    {
        if(!LOG_IDB_EVENTS)
            return;
        const auto func_ea = get_func_by_frame(struc_id);
        if(func_ea != BADADDR)
            LOG_IDB_EVENT("Stackframe of function %s has been created", get_func_name(func_ea).c_str());
        else
            LOG_IDB_EVENT("Structure type %s has been created", get_struc_name(struc_id).c_str());
    }

    void struc_created(Hooks& hooks, va_list args)
    {
        const auto struc_id = va_arg(args, tid_t);
        log_struc_created(struc_id);
        hooks.events_.touch_struc(struc_id);
    }

    void log_deleting_struc(const struc_t* sptr)
    {
        if(!LOG_IDB_EVENTS)
            return;
        const auto func_ea = get_func_by_frame(sptr->id);
        if(func_ea != BADADDR)
            LOG_IDB_EVENT("Stackframe of function %s is to be deleted", get_func_name(func_ea).c_str());
        else
            LOG_IDB_EVENT("Structure type %s is to be deleted", get_struc_name(sptr->id).c_str());
    }

    void deleting_struc(Hooks& hooks, va_list args)
    {
        const auto sptr = va_arg(args, struc_t*);
        log_deleting_struc(sptr);
        hooks.events_.touch_struc(sptr->id);
    }

    void struc_deleted(Hooks& hooks, va_list args)
    {
        const auto struc_id = va_arg(args, tid_t);
        UNUSED(struc_id);
        LOG_IDB_EVENT("A structure type or stackframe has been deleted");
        hooks.events_.touch_struc(struc_id);
    }

    void changing_struc_align(Hooks& hooks, va_list args)
    {
        const auto sptr = va_arg(args, struc_t*);
        LOG_IDB_EVENT("Structure type %s alignment is being changed from 0x%X", get_struc_name(sptr->id).c_str(), static_cast<int>(std::pow(2, sptr->get_alignment())));
        hooks.events_.touch_struc(sptr->id);
    }

    void struc_align_changed(Hooks& hooks, va_list args)
    {
        const auto sptr = va_arg(args, struc_t*);
        LOG_IDB_EVENT("Structure type %s alignment has been changed to 0x%X", get_struc_name(sptr->id).c_str(), static_cast<int>(std::pow(2, sptr->get_alignment())));
        hooks.events_.touch_struc(sptr->id);
    }

    void renaming_struc(Hooks& hooks, va_list args)
    {
        const auto struc_id = va_arg(args, tid_t);
        const auto oldname  = va_arg(args, const char*);
        const auto newname  = va_arg(args, const char*);
        LOG_IDB_EVENT("Structure type %s is to be renamed to %s", oldname, newname);
        hooks.events_.touch_struc(struc_id);
    }

    void struc_renamed(Hooks& hooks, va_list args)
    {
        const auto sptr = va_arg(args, struc_t*);
        LOG_IDB_EVENT("A structure type has been renamed %s", get_struc_name(sptr->id).c_str());
        hooks.events_.touch_struc(sptr->id);
    }

    void log_expanding_struc(const struc_t* sptr, ea_t offset, adiff_t delta)
    {
        if(!LOG_IDB_EVENTS)
            return;

        const auto func_ea = get_func_by_frame(sptr->id);
        if(func_ea != BADADDR)
        {
            if(delta > 0)
                LOG_IDB_EVENT("Stackframe of function %s is to be expanded of 0x%" PRIXEA " bytes at offset 0x%" PRIXEA, get_func_name(func_ea).c_str(), delta, offset);
            else
                LOG_IDB_EVENT("Stackframe of function %s is to be shrunk of 0x%" PRIXEA " bytes at offset 0x%" PRIXEA, get_func_name(func_ea).c_str(), ~delta + 1, offset);
        }
        else
        {
            if(delta > 0)
                LOG_IDB_EVENT("Structure type %s is to be expanded of 0x%" PRIXEA " bytes at offset 0x%" PRIXEA, get_struc_name(sptr->id).c_str(), delta, offset);
            else
                LOG_IDB_EVENT("Structure type %s is to be shrunk of 0x%" PRIXEA " bytes at offset 0x%" PRIXEA, get_struc_name(sptr->id).c_str(), ~delta + 1, offset);
        }
    }

    void expanding_struc(Hooks& hooks, va_list args)
    {
        const auto sptr   = va_arg(args, struc_t*);
        const auto offset = va_arg(args, ea_t);
        const auto delta  = va_arg(args, adiff_t);
        log_expanding_struc(sptr, offset, delta);
        hooks.events_.touch_struc(sptr->id);
    }

    void log_struc_expanded(const struc_t* sptr)
    {
        if(!LOG_IDB_EVENTS)
            return;

        const auto func_ea = get_func_by_frame(sptr->id);
        if(func_ea != BADADDR)
            LOG_IDB_EVENT("Stackframe of function %s has been expanded/shrank", get_func_name(func_ea).c_str());
        else
            LOG_IDB_EVENT("Structure type %s has been expanded/shrank", get_struc_name(sptr->id).c_str());
    }

    void struc_expanded(Hooks& hooks, va_list args)
    {
        const auto sptr = va_arg(args, struc_t*);
        log_struc_expanded(sptr);
        hooks.events_.touch_struc(sptr->id);
    }

    void log_struc_member_created(const struc_t* sptr, const member_t* mptr)
    {
        if(!LOG_IDB_EVENTS)
            return;

        const auto func_ea = get_func_by_frame(sptr->id);
        if(func_ea != BADADDR)
            LOG_IDB_EVENT("Stackframe of function %s member %s has been created", get_func_name(func_ea).c_str(), get_member_name(mptr->id).c_str());
        else
            LOG_IDB_EVENT("Structure type %s member %s has been created", get_struc_name(sptr->id).c_str(), get_member_name(mptr->id).c_str());
    }

    void struc_member_created(Hooks& hooks, va_list args)
    {
        const auto sptr = va_arg(args, struc_t*);
        const auto mptr = va_arg(args, member_t*);
        log_struc_member_created(sptr, mptr);
        hooks.events_.touch_struc(sptr->id);
    }

    void log_deleting_struc_member(const struc_t* sptr, const member_t* mptr)
    {
        if(!LOG_IDB_EVENTS)
            return;

        const auto func_ea = get_func_by_frame(sptr->id);
        if(func_ea != BADADDR)
            LOG_IDB_EVENT("Stackframe of function %s member %s is to be deleted", get_func_name(func_ea).c_str(), get_member_name(mptr->id).c_str());
        else
            LOG_IDB_EVENT("Structure type %s member %s is to be deleted", get_struc_name(sptr->id).c_str(), get_member_name(mptr->id).c_str());
    }

    void deleting_struc_member(Hooks& hooks, va_list args)
    {
        const auto sptr = va_arg(args, struc_t*);
        const auto mptr = va_arg(args, member_t*);
        log_deleting_struc_member(sptr, mptr);
        hooks.events_.touch_struc(sptr->id);
    }

    void log_struc_member_deleted(const struc_t* sptr, tid_t member_id, ea_t offset)
    {
        if(!LOG_IDB_EVENTS)
            return;

        UNUSED(member_id);
        const auto func_ea = get_func_by_frame(sptr->id);
        if(func_ea != BADADDR)
            LOG_IDB_EVENT("Stackframe of function %s member at offset 0x%" PRIXEA " has been deleted", get_func_name(func_ea).c_str(), offset);
        else
            LOG_IDB_EVENT("Structure type %s member at offset 0x%" PRIXEA " has been deleted", get_struc_name(sptr->id).c_str(), offset);
    }

    void struc_member_deleted(Hooks& hooks, va_list args)
    {
        const auto sptr      = va_arg(args, struc_t*);
        const auto member_id = va_arg(args, tid_t);
        const auto offset    = va_arg(args, ea_t);
        log_struc_member_deleted(sptr, member_id, offset);
        hooks.events_.touch_struc(sptr->id);
    }

    void log_renaming_struc_member(const struc_t* sptr, const member_t* mptr, const char* newname)
    {
        if(!LOG_IDB_EVENTS)
            return;

        const auto func_ea = get_func_by_frame(sptr->id);
        if(func_ea != BADADDR)
            LOG_IDB_EVENT("A member of stackframe of function %s is to be renamed from %s to %s", get_func_name(func_ea).c_str(), get_member_name(mptr->id).c_str(), newname);
        else
            LOG_IDB_EVENT("A member of structure type %s is to be renamed from %s to %s", get_struc_name(sptr->id).c_str(), get_member_name(mptr->id).c_str(), newname);
    }

    void renaming_struc_member(Hooks& hooks, va_list args)
    {
        const auto sptr    = va_arg(args, struc_t*);
        const auto mptr    = va_arg(args, member_t*);
        const auto newname = va_arg(args, const char*);
        log_renaming_struc_member(sptr, mptr, newname);
        hooks.events_.touch_struc(sptr->id);
    }

    void log_struc_member_renamed(const struc_t* sptr, const member_t* mptr)
    {
        if(!LOG_IDB_EVENTS)
            return;

        const auto func_ea = get_func_by_frame(sptr->id);
        if(func_ea != BADADDR)
            LOG_IDB_EVENT("A member of stackframe of function %s has been renamed to %s", get_func_name(func_ea).c_str(), get_member_name(mptr->id).c_str());
        else
            LOG_IDB_EVENT("A member of structure type %s has been renamed to %s", get_struc_name(sptr->id).c_str(), get_member_name(mptr->id).c_str());
    }

    void struc_member_renamed(Hooks& hooks, va_list args)
    {
        const auto sptr = va_arg(args, struc_t*);
        const auto mptr = va_arg(args, member_t*);
        log_struc_member_renamed(sptr, mptr);
        hooks.events_.touch_struc(sptr->id);
    }

    void log_changing_struc_member(const struc_t* sptr, const member_t* mptr, flags_t flag, const opinfo_t* ti, asize_t nbytes)
    {
        if(!LOG_IDB_EVENTS)
            return;

        UNUSED(flag);
        UNUSED(ti);
        UNUSED(nbytes);
    
        const auto  func_ea = get_func_by_frame(sptr->id);
        if(func_ea != BADADDR)
            LOG_IDB_EVENT("Stackframe of function %s member %s is to be changed", get_func_name(func_ea).c_str(), get_member_name(mptr->id).c_str());
        else
            LOG_IDB_EVENT("Structure type %s member %s is to be changed", get_struc_name(sptr->id).c_str(), get_member_name(mptr->id).c_str());
    }

    void changing_struc_member(Hooks& hooks, va_list args)
    {
        const auto sptr   = va_arg(args, struc_t*);
        const auto mptr   = va_arg(args, member_t*);
        const auto flag   = va_arg(args, flags_t);
        const auto ti     = va_arg(args, const opinfo_t*);
        const auto nbytes = va_arg(args, asize_t);
        log_changing_struc_member(sptr, mptr, flag, ti, nbytes);
        hooks.events_.touch_struc(sptr->id);
    }

    void log_struc_member_changed(const struc_t* sptr, const member_t* mptr)
    {
        if(!LOG_IDB_EVENTS)
            return;

        const auto func_ea = get_func_by_frame(sptr->id);
        if(func_ea != BADADDR)
            LOG_IDB_EVENT("Stackframe of function %s member %s has been changed", get_func_name(func_ea).c_str(), get_member_name(mptr->id).c_str());
        else
            LOG_IDB_EVENT("Structure type %s member %s has been changed", get_struc_name(sptr->id).c_str(), get_member_name(mptr->id).c_str());
    }

    void struc_member_changed(Hooks& hooks, va_list args)
    {
        const auto sptr = va_arg(args, struc_t*);
        const auto mptr = va_arg(args, member_t*);
        log_struc_member_changed(sptr, mptr);
        hooks.events_.touch_struc(sptr->id);
    }

    void log_changing_struc_cmt(tid_t struc_id, bool repeatable, const char* newcmt)
    {
        if(!LOG_IDB_EVENTS)
            return;

        if(get_struc(struc_id))
        {
            LOG_IDB_EVENT("Structure type %s %scomment is to be changed from \"%s\" to \"%s\"", get_struc_name(struc_id).c_str(), REPEATABLE_STR[repeatable], get_struc_cmt(struc_id, repeatable).c_str(), newcmt);
            return;
        }
     
        const auto struc = get_member_struc(get_member_fullname(struc_id).c_str());
        const auto func_ea = get_func_by_frame(struc->id);
        if(func_ea != BADADDR)
            LOG_IDB_EVENT("Stackframe of function %s member %s %scomment is to be changed from \"%s\" to \"%s\"", get_func_name(func_ea).c_str(), get_member_name(struc_id).c_str(), REPEATABLE_STR[repeatable], get_member_name(struc_id).c_str(), newcmt);
        else
            LOG_IDB_EVENT("Structure type %s member %s %scomment is to be changed from \"%s\" to \"%s\"", get_struc_name(struc->id).c_str(), get_member_name(struc_id).c_str(), REPEATABLE_STR[repeatable], get_member_name(struc_id).c_str(), newcmt);
    }

    void changing_struc_cmt(Hooks& hooks, va_list args)
    {
        const auto struc_id   = va_arg(args, tid_t);
        const auto repeatable = static_cast<bool>(va_arg(args, int));
        const auto newcmt     = va_arg(args, const char*);
        log_changing_struc_cmt(struc_id, repeatable, newcmt);
        hooks.events_.touch_struc(struc_id);
    }

    void log_struc_cmt_changed(tid_t struc_id, bool repeatable)
    {
        if(!LOG_IDB_EVENTS)
            return;

        if(get_struc(struc_id))
        {
            LOG_IDB_EVENT("Structure type %s %scomment has been changed to \"%s\"", get_struc_name(struc_id).c_str(), REPEATABLE_STR[repeatable], get_struc_cmt(struc_id, repeatable).c_str());
            return;
        }

        const auto struc = get_member_struc(get_member_fullname(struc_id).c_str());
        const auto func_ea = get_func_by_frame(struc->id);
        if(func_ea != BADADDR)
            LOG_IDB_EVENT("Stackframe of function %s member %s %scomment has been changed to \"%s\"", get_func_name(func_ea).c_str(), get_member_name(struc_id).c_str(), REPEATABLE_STR[repeatable], get_member_name(struc_id).c_str());
        else
            LOG_IDB_EVENT("Structure type %s member %s %scomment has been changed to \"%s\"", get_struc_name(struc->id).c_str(), get_member_name(struc_id).c_str(), REPEATABLE_STR[repeatable], get_member_name(struc_id).c_str());
    }

    void struc_cmt_changed(Hooks& hooks, va_list args)
    {
        const auto struc_id   = va_arg(args, tid_t);
        const auto repeatable = static_cast<bool>(va_arg(args, int));

        log_struc_cmt_changed(struc_id, repeatable);
        hooks.events_.touch_struc(struc_id);
    }

    void segm_added(Hooks& hooks, va_list args)
    {
        const auto s = va_arg(args, segment_t*);
        LOG_IDB_EVENT("Segment %s has been created from %" PRIxEA " to %" PRIxEA, get_segm_name(s).c_str(), s->start_ea, s->end_ea);
        hooks.events_.touch_ea(s->start_ea);
    }

    void log_deleting_segm(ea_t start_ea)
    {
        if(!LOG_IDB_EVENTS)
            return;
        const auto* s = getseg(start_ea);
        LOG_IDB_EVENT("Segment %s (from %" PRIxEA " to %" PRIxEA ") is to be deleted", get_segm_name(s).c_str(), s->start_ea, s->end_ea);
    }

    void deleting_segm(Hooks& hooks, va_list args)
    {
        const auto start_ea = va_arg(args, ea_t);
        log_deleting_segm(start_ea);
        hooks.events_.touch_ea(start_ea);
    }

    void segm_deleted(Hooks& hooks, va_list args)
    {
        const auto start_ea = va_arg(args, ea_t);
        const auto end_ea   = va_arg(args, ea_t);
        LOG_IDB_EVENT("A segment (from %" PRIxEA " to %" PRIxEA ") has been deleted", start_ea, end_ea);
        hooks.events_.touch_ea(start_ea);
    }

    void changing_segm_start(Hooks& /*hooks*/, va_list args)
    {
        const auto s            = va_arg(args, segment_t*);
        const auto new_start    = va_arg(args, ea_t);
        const auto segmod_flags = va_arg(args, int);
        UNUSED(segmod_flags);
        LOG_IDB_EVENT("Segment %s start address is to be changed from %" PRIxEA " to %" PRIxEA, get_segm_name(s).c_str(), s->start_ea, new_start);
    }

    void segm_start_changed(Hooks& hooks, va_list args)
    {
        const auto s        = va_arg(args, segment_t*);
        const auto oldstart = va_arg(args, ea_t);
        LOG_IDB_EVENT("Segment %s start address has been changed from %" PRIxEA " to %" PRIxEA, get_segm_name(s).c_str(), oldstart, s->start_ea);
        hooks.events_.touch_ea(s->start_ea);
    }

    void changing_segm_end(Hooks& hooks, va_list args)
    {
        const auto s            = va_arg(args, segment_t*);
        const auto new_end      = va_arg(args, ea_t);
        const auto segmod_flags = va_arg(args, int);
        UNUSED(segmod_flags);
        LOG_IDB_EVENT("Segment %s end address is to be changed from %" PRIxEA " to %" PRIxEA, get_segm_name(s).c_str(), s->end_ea, new_end);
        hooks.events_.touch_ea(s->start_ea);
    }

    void segm_end_changed(Hooks& hooks, va_list args)
    {
        const auto s      = va_arg(args, segment_t*);
        const auto oldend = va_arg(args, ea_t);
        LOG_IDB_EVENT("Segment %s end address has been changed from %" PRIxEA " to %" PRIxEA, get_segm_name(s).c_str(), oldend, s->end_ea);
        hooks.events_.touch_ea(s->start_ea);
    }

    void changing_segm_name(Hooks& hooks, va_list args)
    {
        const auto s       = va_arg(args, segment_t*);
        const auto oldname = va_arg(args, const char*);
        UNUSED(s);
        LOG_IDB_EVENT("Segment %s is being renamed", oldname);
        hooks.events_.touch_ea(s->start_ea);
    }

    void segm_name_changed(Hooks& hooks, va_list args)
    {
        const auto s    = va_arg(args, segment_t*);
        const auto name = va_arg(args, const char*);
        UNUSED(s);
        LOG_IDB_EVENT("A segment has been renamed %s", name);
        hooks.events_.touch_ea(s->start_ea);
    }

    void changing_segm_class(Hooks& hooks, va_list args)
    {
        const auto s = va_arg(args, segment_t*);
        LOG_IDB_EVENT("Segment %s class is being changed from %s", get_segm_name(s).c_str(), get_segm_class(s).c_str());
        hooks.events_.touch_ea(s->start_ea);
    }

    void segm_class_changed(Hooks& hooks, va_list args)
    {
        const auto s      = va_arg(args, segment_t*);
        const auto sclass = va_arg(args, const char*);
        LOG_IDB_EVENT("Segment %s class has been changed to %s", get_segm_name(s).c_str(), sclass);
        hooks.events_.touch_ea(s->start_ea);
    }

    void segm_attrs_updated(Hooks& hooks, va_list args)
    {
        // This event is generated for secondary segment attributes (examples: color, permissions, etc)
        const auto s = va_arg(args, segment_t*);
        LOG_IDB_EVENT("Segment %s attributes has been changed", get_segm_name(s).c_str());
        hooks.events_.touch_ea(s->start_ea);
    }

    void log_segm_moved(ea_t from, ea_t to, asize_t size, bool changed_netmap)
    {
        if(!LOG_IDB_EVENTS)
            return;

        const segment_t* s = getseg(to);
        const char changed_netmap_txt[][18] = { "", " (changed netmap)" };
        LOG_IDB_EVENT("Segment %s has been moved from %" PRIxEA "-%" PRIxEA " to %" PRIxEA "-%" PRIxEA "%s", get_segm_name(s).c_str(), from, from + size, to, to + size, changed_netmap_txt[changed_netmap]);
    }

    void segm_moved(Hooks& hooks, va_list args)
    {
        const auto from           = va_arg(args, ea_t);
        const auto to             = va_arg(args, ea_t);
        const auto size           = va_arg(args, asize_t);
        const auto changed_netmap = static_cast<bool>(va_arg(args, int));
        log_segm_moved(from, to, size, changed_netmap);
        const auto* s = getseg(to);
        hooks.events_.touch_ea(s->start_ea);
    }

    void allsegs_moved(Hooks& /*hooks*/, va_list args)
    {
        const auto info = va_arg(args, segm_move_infos_t*);
        LOG_IDB_EVENT("Program rebasing is complete, %zd segments have been moved", info->size());
    }

    void func_added(Hooks& hooks, va_list args)
    {
        const auto pfn = va_arg(args, func_t*);
        LOG_IDB_EVENT("Function %s has been created from %" PRIxEA " to %" PRIxEA, get_func_name(pfn->start_ea).c_str(), pfn->start_ea, pfn->end_ea);
        hooks.events_.touch_func(pfn->start_ea);
    }

    void func_updated(Hooks& hooks, va_list args)
    {
        const auto pfn = va_arg(args, func_t*);
        LOG_IDB_EVENT("Function %s has been updated", get_func_name(pfn->start_ea).c_str());
        hooks.events_.touch_func(pfn->start_ea);
    }

    void set_func_start(Hooks& hooks, va_list args)
    {
        const auto pfn       = va_arg(args, func_t*);
        const auto new_start = va_arg(args, ea_t);
        LOG_IDB_EVENT("Function %s chunk start address will be changed from %" PRIxEA " to %" PRIxEA, get_func_name(pfn->start_ea).c_str(), pfn->start_ea, new_start);
        hooks.events_.touch_func(pfn->start_ea);
    }

    void set_func_end(Hooks& hooks, va_list args)
    {
        const auto pfn     = va_arg(args, func_t*);
        const auto new_end = va_arg(args, ea_t);
        LOG_IDB_EVENT("Function %s chunk end address will be changed from %" PRIxEA " to %" PRIxEA, get_func_name(pfn->start_ea).c_str(), pfn->end_ea, new_end);
        hooks.events_.touch_func(pfn->start_ea);
    }

    void deleting_func(Hooks& hooks, va_list args)
    {
        const auto pfn = va_arg(args, func_t*);
        LOG_IDB_EVENT("Function %s is about to be deleted (%" PRIxEA " to %" PRIxEA")", get_func_name(pfn->start_ea).c_str(), pfn->start_ea, pfn->end_ea);
        hooks.events_.touch_func(pfn->start_ea);
    }

    void frame_deleted(Hooks& hooks, va_list args)
    {
        const auto pfn = va_arg(args, func_t*);
        LOG_IDB_EVENT("A function frame has been deleted");
        hooks.events_.touch_func(pfn->start_ea);
    }

    void thunk_func_created(Hooks& hooks, va_list args)
    {
        const auto pfn = va_arg(args, func_t*);
        LOG_IDB_EVENT("Function %s thunk bit has been set to %s", get_func_name(pfn->start_ea).c_str(), BOOL_STR[!!(pfn->flags & FUNC_THUNK)]);
        hooks.events_.touch_func(pfn->start_ea);
    }

    void func_tail_appended(Hooks& hooks, va_list args)
    {
        const auto pfn  = va_arg(args, func_t*);
        const auto tail = va_arg(args, func_t*);
        LOG_IDB_EVENT("Function %s tail chunk from %" PRIxEA " to %" PRIxEA " has been appended", get_func_name(pfn->start_ea).c_str(), tail->start_ea, tail->end_ea);
        hooks.events_.touch_func(pfn->start_ea);
    }

    void deleting_func_tail(Hooks& hooks, va_list args)
    {
        const auto pfn  = va_arg(args, func_t*);
        const auto tail = va_arg(args, const range_t*);
        LOG_IDB_EVENT("Function %s tail chunk from %" PRIxEA " to %" PRIxEA " is to be removed", get_func_name(pfn->start_ea).c_str(), tail->start_ea, tail->end_ea);
        hooks.events_.touch_func(pfn->start_ea);
    }

    void func_tail_deleted(Hooks& hooks, va_list args)
    {
        const auto pfn     = va_arg(args, func_t*);
        const auto tail_ea = va_arg(args, ea_t);
        LOG_IDB_EVENT("Function %s tail chunk at %" PRIxEA " has been removed", get_func_name(pfn->start_ea).c_str(), tail_ea);
        hooks.events_.touch_func(pfn->start_ea);
    }

    void tail_owner_changed(Hooks& hooks, va_list args)
    {
        const auto pfn        = va_arg(args, func_t*);
        const auto owner_func = va_arg(args, ea_t);
        const auto old_owner  = va_arg(args, ea_t);
        LOG_IDB_EVENT("Tail chunk from %" PRIxEA " to %" PRIxEA " owner function changed from %s to %s", pfn->start_ea, pfn->end_ea, get_func_name(old_owner).c_str(), get_func_name(owner_func).c_str());
        hooks.events_.touch_func(owner_func);
        hooks.events_.touch_func(old_owner);
    }

    void func_noret_changed(Hooks& hooks, va_list args)
    {
        const auto pfn = va_arg(args, func_t*);
        LOG_IDB_EVENT("Function %s FUNC_NORET flag has been changed to %s", get_func_name(pfn->start_ea).c_str(), BOOL_STR[!!(pfn->flags & FUNC_NORET)]);
        hooks.events_.touch_func(pfn->start_ea);
    }

    void stkpnts_changed(Hooks& hooks, va_list args)
    {
        const auto pfn = va_arg(args, func_t*);
        LOG_IDB_EVENT("Function %s stack change points have been modified", get_func_name(pfn->start_ea).c_str());
        hooks.events_.touch_func(pfn->start_ea);
    }

    void updating_tryblks(Hooks& /*hooks*/, va_list args)
    {
        const auto tbv = va_arg(args, const tryblks_t*);
        UNUSED(tbv);
        LOG_IDB_EVENT("About to update try block information");
    }

    void tryblks_updated(Hooks& /*hooks*/, va_list args)
    {
        const auto tbv = va_arg(args, const tryblks_t*);
        UNUSED(tbv);
        LOG_IDB_EVENT("Updated try block information");
    }

    void deleting_tryblks(Hooks& /*hooks*/, va_list args)
    {
        const auto range = va_arg(args, const range_t*);
        LOG_IDB_EVENT("About to delete try block information in range %" PRIxEA "-%" PRIxEA, range->start_ea, range->end_ea);
    }

    void log_sgr_changed(ea_t start_ea, ea_t end_ea, int regnum, sel_t value, sel_t old_value, uchar tag)
    {
        UNUSED(start_ea);
        UNUSED(end_ea);
        UNUSED(regnum);
        UNUSED(value);
        UNUSED(old_value);
        UNUSED(tag);
        LOG_IDB_EVENT("The kernel has changed a segment register value");
    }

    void sgr_changed(Hooks& /*hooks*/, va_list args)
    {
        const auto start_ea  = va_arg(args, ea_t);
        const auto end_ea    = va_arg(args, ea_t);
        const auto regnum    = va_arg(args, int);
        const auto value     = va_arg(args, sel_t);
        const auto old_value = va_arg(args, sel_t);
        const auto tag       = static_cast<uchar>(va_arg(args, int));
        log_sgr_changed(start_ea, end_ea, regnum, value, old_value, tag);
    }

    void make_code(Hooks& hooks, va_list args)
    {
        const auto insn = va_arg(args, const insn_t*);
        LOG_IDB_EVENT("An instruction is being created at %" PRIxEA, insn->ea);
        hooks.events_.touch_code(insn->ea);
    }

    void make_data(Hooks& hooks, va_list args)
    {
        const auto ea    = va_arg(args, ea_t);
        const auto flags = va_arg(args, flags_t);
        const auto tid   = va_arg(args, tid_t);
        const auto len   = va_arg(args, asize_t);
        UNUSED(flags);
        UNUSED(tid);
        UNUSED(len);
        LOG_IDB_EVENT("A data item is being created at %" PRIxEA, ea);
        hooks.events_.touch_data(ea);
    }

    void destroyed_items(Hooks& /*hooks*/, va_list args)
    {
        const auto ea1 = va_arg(args, ea_t);
        const auto ea2 = va_arg(args, ea_t);
        const auto will_disable_range = static_cast<bool>(va_arg(args, int));
        UNUSED(will_disable_range);
        LOG_IDB_EVENT("Instructions/data have been destroyed in %" PRIxEA "-%" PRIxEA, ea1, ea2);
    }

    void renamed(Hooks& hooks, va_list args)
    {
        const auto ea         = va_arg(args, ea_t);
        const auto new_name   = va_arg(args, const char*);
        const auto local_name = static_cast<bool>(va_arg(args, int));
        UNUSED(local_name);
        LOG_IDB_EVENT("Byte at %" PRIxEA " renamed to %s", ea, new_name);
        hooks.events_.touch_ea(ea);
    }

    void byte_patched(Hooks& hooks, va_list args)
    {
        const auto ea        = va_arg(args, ea_t);
        const auto old_value = va_arg(args, uint32);
        LOG_IDB_EVENT("Byte at %" PRIxEA " has been changed from 0x%02X to 0x%02X", ea, old_value, get_byte(ea));
        hooks.events_.touch_ea(ea);
    }

    void changing_cmt(Hooks& hooks, va_list args)
    {
        const auto ea             = va_arg(args, ea_t);
        const auto repeatable_cmt = static_cast<bool>(va_arg(args, int));
        const auto newcmt         = va_arg(args, const char*);
        LOG_IDB_EVENT("Item at %" PRIxEA " %scomment is to be changed from \"%s\" to \"%s\"", ea, REPEATABLE_STR[repeatable_cmt], get_cmt(ea, repeatable_cmt).c_str(), newcmt);
        hooks.events_.touch_ea(ea);
    }

    void cmt_changed(Hooks& hooks, va_list args)
    {
        const auto ea             = va_arg(args, ea_t);
        const auto repeatable_cmt = static_cast<bool>(va_arg(args, int));
        LOG_IDB_EVENT("Item at %" PRIxEA " %scomment has been changed to \"%s\"", ea, REPEATABLE_STR[repeatable_cmt], get_cmt(ea, repeatable_cmt).c_str());
        hooks.events_.touch_ea(ea);
    }

    void changing_range_cmt(Hooks& hooks, va_list args)
    {
        const auto kind       = static_cast<range_kind_t>(va_arg(args, int));
        const auto a          = va_arg(args, const range_t*);
        const auto cmt        = va_arg(args, const char*);
        const auto repeatable = static_cast<bool>(va_arg(args, int));
        LOG_IDB_EVENT("%s range from %" PRIxEA " to %" PRIxEA " %scomment is to be changed to \"%s\"", range_kind_to_str(kind), a->start_ea, a->end_ea, REPEATABLE_STR[repeatable], cmt);
        hooks.events_.touch_ea(a->start_ea);
    }

    void range_cmt_changed(Hooks& hooks, va_list args)
    {
        const auto kind       = static_cast<range_kind_t>(va_arg(args, int));
        const auto a          = va_arg(args, const range_t*);
        const auto cmt        = va_arg(args, const char*);
        const auto repeatable = static_cast<bool>(va_arg(args, int));
        LOG_IDB_EVENT("%s range from %" PRIxEA " to %" PRIxEA " %scomment has been changed to \"%s\"", range_kind_to_str(kind), a->start_ea, a->end_ea, REPEATABLE_STR[repeatable], cmt);
        hooks.events_.touch_ea(a->start_ea);
    }

    void extra_cmt_changed(Hooks& hooks, va_list args)
    {
        const auto ea       = va_arg(args, ea_t);
        const auto line_idx = va_arg(args, int);
        const auto cmt      = va_arg(args, const char*);
        UNUSED(line_idx);
        LOG_IDB_EVENT("Extra comment at %" PRIxEA " has been changed to \"%s\"", ea, cmt);
        hooks.events_.touch_ea(ea);
    }

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
            case idb_event::event_code_t::allsegs_moved:           allsegs_moved(*hooks, args); break;
            case idb_event::event_code_t::auto_empty:              auto_empty(*hooks, args); break;
            case idb_event::event_code_t::auto_empty_finally:      auto_empty_finally(*hooks, args); break;
            case idb_event::event_code_t::byte_patched:            byte_patched(*hooks, args); break;
            case idb_event::event_code_t::changing_cmt:            changing_cmt(*hooks, args); break;
            case idb_event::event_code_t::changing_enum_bf:        changing_enum_bf(*hooks, args); break;
            case idb_event::event_code_t::changing_enum_cmt:       changing_enum_cmt(*hooks, args); break;
            case idb_event::event_code_t::changing_op_ti:          changing_op_ti(*hooks, args); break;
            case idb_event::event_code_t::changing_op_type:        changing_op_type(*hooks, args); break;
            case idb_event::event_code_t::changing_range_cmt:      changing_range_cmt(*hooks, args); break;
            case idb_event::event_code_t::changing_segm_class:     changing_segm_class(*hooks, args); break;
            case idb_event::event_code_t::changing_segm_end:       changing_segm_end(*hooks, args); break;
            case idb_event::event_code_t::changing_segm_name:      changing_segm_name(*hooks, args); break;
            case idb_event::event_code_t::changing_segm_start:     changing_segm_start(*hooks, args); break;
            case idb_event::event_code_t::changing_struc_align:    changing_struc_align(*hooks, args); break;
            case idb_event::event_code_t::changing_struc_cmt:      changing_struc_cmt(*hooks, args); break;
            case idb_event::event_code_t::changing_struc_member:   changing_struc_member(*hooks, args); break;
            case idb_event::event_code_t::changing_ti:             changing_ti(*hooks, args); break;
            case idb_event::event_code_t::closebase:               closebase(*hooks, args); break;
            case idb_event::event_code_t::cmt_changed:             cmt_changed(*hooks, args); break;
            case idb_event::event_code_t::compiler_changed:        compiler_changed(*hooks, args); break;
            case idb_event::event_code_t::deleting_enum:           deleting_enum(*hooks, args); break;
            case idb_event::event_code_t::deleting_enum_member:    deleting_enum_member(*hooks, args); break;
            case idb_event::event_code_t::deleting_func:           deleting_func(*hooks, args); break;
            case idb_event::event_code_t::deleting_func_tail:      deleting_func_tail(*hooks, args); break;
            case idb_event::event_code_t::deleting_segm:           deleting_segm(*hooks, args); break;
            case idb_event::event_code_t::deleting_struc:          deleting_struc(*hooks, args); break;
            case idb_event::event_code_t::deleting_struc_member:   deleting_struc_member(*hooks, args); break;
            case idb_event::event_code_t::deleting_tryblks:        deleting_tryblks(*hooks, args); break;
            case idb_event::event_code_t::destroyed_items:         destroyed_items(*hooks, args); break;
            case idb_event::event_code_t::determined_main:         determined_main(*hooks, args); break;
            case idb_event::event_code_t::enum_bf_changed:         enum_bf_changed(*hooks, args); break;
            case idb_event::event_code_t::enum_cmt_changed:        enum_cmt_changed(*hooks, args); break;
            case idb_event::event_code_t::enum_created:            enum_created(*hooks, args); break;
            case idb_event::event_code_t::enum_deleted:            enum_deleted(*hooks, args); break;
            case idb_event::event_code_t::enum_member_created:     enum_member_created(*hooks, args); break;
            case idb_event::event_code_t::enum_member_deleted:     enum_member_deleted(*hooks, args); break;
            case idb_event::event_code_t::enum_renamed:            enum_renamed(*hooks, args); break;
            case idb_event::event_code_t::expanding_struc:         expanding_struc(*hooks, args); break;
            case idb_event::event_code_t::extlang_changed:         extlang_changed(*hooks, args); break;
            case idb_event::event_code_t::extra_cmt_changed:       extra_cmt_changed(*hooks, args); break;
            case idb_event::event_code_t::flow_chart_created:      flow_chart_created(*hooks, args); break;
            case idb_event::event_code_t::frame_deleted:           frame_deleted(*hooks, args); break;
            case idb_event::event_code_t::func_added:              func_added(*hooks, args); break;
            case idb_event::event_code_t::func_noret_changed:      func_noret_changed(*hooks, args); break;
            case idb_event::event_code_t::func_tail_appended:      func_tail_appended(*hooks, args); break;
            case idb_event::event_code_t::func_tail_deleted:       func_tail_deleted(*hooks, args); break;
            case idb_event::event_code_t::func_updated:            func_updated(*hooks, args); break;
            case idb_event::event_code_t::idasgn_loaded:           idasgn_loaded(*hooks, args); break;
            case idb_event::event_code_t::kernel_config_loaded:    kernel_config_loaded(*hooks, args); break;
            case idb_event::event_code_t::loader_finished:         loader_finished(*hooks, args); break;
            case idb_event::event_code_t::local_types_changed:     local_types_changed(*hooks, args); break;
            case idb_event::event_code_t::make_code:               make_code(*hooks, args); break;
            case idb_event::event_code_t::make_data:               make_data(*hooks, args); break;
            case idb_event::event_code_t::op_ti_changed:           op_ti_changed(*hooks, args); break;
            case idb_event::event_code_t::op_type_changed:         op_type_changed(*hooks, args); break;
            case idb_event::event_code_t::range_cmt_changed:       range_cmt_changed(*hooks, args); break;
            case idb_event::event_code_t::renamed:                 renamed(*hooks, args); break;
            case idb_event::event_code_t::renaming_enum:           renaming_enum(*hooks, args); break;
            case idb_event::event_code_t::renaming_struc:          renaming_struc(*hooks, args); break;
            case idb_event::event_code_t::renaming_struc_member:   renaming_struc_member(*hooks, args); break;
            case idb_event::event_code_t::savebase:                savebase(*hooks, args); break;
            case idb_event::event_code_t::segm_added:              segm_added(*hooks, args); break;
            case idb_event::event_code_t::segm_attrs_updated:      segm_attrs_updated(*hooks, args); break;
            case idb_event::event_code_t::segm_class_changed:      segm_class_changed(*hooks, args); break;
            case idb_event::event_code_t::segm_deleted:            segm_deleted(*hooks, args); break;
            case idb_event::event_code_t::segm_end_changed:        segm_end_changed(*hooks, args); break;
            case idb_event::event_code_t::segm_moved:              segm_moved(*hooks, args); break;
            case idb_event::event_code_t::segm_name_changed:       segm_name_changed(*hooks, args); break;
            case idb_event::event_code_t::segm_start_changed:      segm_start_changed(*hooks, args); break;
            case idb_event::event_code_t::set_func_end:            set_func_end(*hooks, args); break;
            case idb_event::event_code_t::set_func_start:          set_func_start(*hooks, args); break;
            case idb_event::event_code_t::sgr_changed:             sgr_changed(*hooks, args); break;
            case idb_event::event_code_t::stkpnts_changed:         stkpnts_changed(*hooks, args); break;
            case idb_event::event_code_t::struc_align_changed:     struc_align_changed(*hooks, args); break;
            case idb_event::event_code_t::struc_cmt_changed:       struc_cmt_changed(*hooks, args); break;
            case idb_event::event_code_t::struc_created:           struc_created(*hooks, args); break;
            case idb_event::event_code_t::struc_deleted:           struc_deleted(*hooks, args); break;
            case idb_event::event_code_t::struc_expanded:          struc_expanded(*hooks, args); break;
            case idb_event::event_code_t::struc_member_changed:    struc_member_changed(*hooks, args); break;
            case idb_event::event_code_t::struc_member_created:    struc_member_created(*hooks, args); break;
            case idb_event::event_code_t::struc_member_deleted:    struc_member_deleted(*hooks, args); break;
            case idb_event::event_code_t::struc_member_renamed:    struc_member_renamed(*hooks, args); break;
            case idb_event::event_code_t::struc_renamed:           struc_renamed(*hooks, args); break;
            case idb_event::event_code_t::tail_owner_changed:      tail_owner_changed(*hooks, args); break;
            case idb_event::event_code_t::thunk_func_created:      thunk_func_created(*hooks, args); break;
            case idb_event::event_code_t::ti_changed:              ti_changed(*hooks, args); break;
            case idb_event::event_code_t::tryblks_updated:         tryblks_updated(*hooks, args); break;
            case idb_event::event_code_t::updating_tryblks:        updating_tryblks(*hooks, args); break;
            case idb_event::event_code_t::upgraded:                upgraded(*hooks, args); break;
        }
        return 0;
    }
}

Hooks::Hooks(IEvents& events)
    : events_(events)
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

std::shared_ptr<IHooks> MakeHooks(IEvents& events)
{
    return std::make_shared<Hooks>(events);
}
