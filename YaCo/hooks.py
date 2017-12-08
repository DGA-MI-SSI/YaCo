#   Copyright (C) 2017 The YaCo Authors
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

import idc
import idaapi
import logging
import time
import traceback
import os
import YaCo

if idc.__EA64__:
    import YaToolsPy64 as ya
else:
    import YaToolsPy32 as ya

logger = logging.getLogger("YaCo")
# logger.setLevel(logging.DEBUG)

LOG_IDA_HOOKS_EVENTS = True
LOG_IDP_EVENTS = True
LOG_IDB_EVENTS = True
VALIDATE_EXPORTED_XML = False
VALIDATE_EXPORTED_XML_2 = False

hooks = None


class Hooks(object):
    def __init__(self, hash_provider, repo_manager):
        self.ida = ya.MakeHooks(hash_provider, repo_manager)
        self.idb = YaToolIDB_Hooks()
        self.idp = YaToolIDP_Hooks()
        self.current_rename_infos = {}
        global hooks
        hooks = self

    def hook(self):
        logger.debug("Hooks:hook")
        self.ida.hook() # native
        self.idb.hook()
        self.idp.hook()

    def unhook(self):
        logger.debug("Hooks:unhook")
        self.ida.unhook() # native
        self.idp.unhook()
        self.idb.unhook()



class YaToolIDP_Hooks(idaapi.IDP_Hooks):
    def debug_event(self, text):
        auto_display = idaapi.auto_display_t()
        logger.debug("event: auto=%d, AA_type=%d, AA_state=%d, text='%s'" %
                     (idaapi.autoIsOk(), auto_display.type, auto_display.state, text))

    def pre_hook(self):
        self.unhook()
        hooks.idb.unhook()

        idc.set_inf_attr(idc.INFFL_AUTO, True)
        idc.Wait()
        idaapi.request_refresh(idaapi.IWID_STRUCTS | idaapi.IWID_ENUMS | idaapi.IWID_XREFS)
        idc.set_inf_attr(idc.INFFL_AUTO, False)
        idaapi.request_refresh(idaapi.IWID_STRUCTS | idaapi.IWID_ENUMS | idaapi.IWID_XREFS)

        self.hook()
        hooks.idb.hook()

    def __init__(self):
        idaapi.IDP_Hooks.__init__(self)

    def ev_rename(self, ea, new_name):
        """
        This function only records information about the element *before* it is renamed
        """
        if idaapi.is_member_id(ea):
            name = idaapi.get_member_fullname(ea)
        elif idaapi.get_struc(ea) is not None:
            name = idaapi.get_struc_name(ea)
        elif idaapi.get_enum_idx(ea) != idc.BADADDR:
            name = idaapi.get_enum_name(ea)
        elif idaapi.get_enum_idx(idaapi.get_enum_member_enum(ea)) != idc.BADADDR:
            # this is an enum member id
            enum_id = idaapi.get_enum_member_enum(ea)
            name = idaapi.get_enum_name(enum_id) + "." + idaapi.get_enum_member_name(ea)
        else:
            name = idc.Name(ea)

        hooks.current_rename_infos[ea] = name

        return 0

    def ev_undefine(self, ea):
        self.pre_hook()
        if LOG_IDP_EVENTS:
            self.debug_event("Undefine at 0x%08x" % ea)
        self.unhook()
        hooks.idb.unhook()
        hooks.ida.undefine(ea)
        self.hook()
        hooks.idb.hook()
        return hooks.idp.ev_undefine(ea)


class YaToolIDB_Hooks(idaapi.IDB_Hooks):
    def __init__(self):
        idaapi.IDB_Hooks.__init__(self)
        # hooks.ida = model

    def pre_hook(self):
        hooks.idp.unhook()
        self.unhook()

        idc.set_inf_attr(idc.INFFL_AUTO, True)
        idc.Wait()
        idaapi.request_refresh(idaapi.IWID_STRUCTS | idaapi.IWID_ENUMS | idaapi.IWID_XREFS)
        idc.set_inf_attr(idc.INFFL_AUTO, False)

        idaapi.request_refresh(idaapi.IWID_STRUCTS | idaapi.IWID_ENUMS | idaapi.IWID_XREFS)

        hooks.idp.hook()
        self.hook()

    def closebase(self, *args):
        logger.debug("closebase")
        """
        closebase(self) -> int


        The database will be closed now
        """
        YaCo.close()
        return idaapi.IDB_Hooks.closebase(self, *args)

    def renamed(self, ea, new_name, local_name):
        if LOG_IDP_EVENTS:
            self.debug_event("Renamed at 0x%08x with' %s'" % (ea, new_name))
        if idaapi.is_member_id(ea):
            # this is a member id : hook already present (struc_member_renamed)
            pass
        elif idaapi.get_struc(ea) is not None:
            # this is a struc id : hook already present (struc_renamed)
            pass
        elif idaapi.get_enum_idx(ea) != idc.BADADDR:
            # this is an enum id : hook already present (enum_renamed) BUT NOT CALLED
            # (IDA BUG)
            hooks.idb.enum_renamed(ea)
        elif idaapi.get_enum_idx(idaapi.get_enum_member_enum(ea)) != idc.BADADDR:
            # this is an enum member id
            enum_id = idaapi.get_enum_member_enum(ea)
            hooks.idb.enum_member_renamed(enum_id, ea)
        else:
            self.pre_hook()

            # when we rename stackframe member, ea is member id
            # this case is supported by struc_member_renamed event
            try:
                old_name = hooks.current_rename_infos[ea]
                del hooks.current_rename_infos[ea]
            except KeyError:
                old_name = ""
            hooks.ida.rename(ea, new_name, "", old_name)

        return hooks.idp.ev_rename(ea, new_name)

    def make_code(self, insn):
        self.pre_hook()
        if LOG_IDP_EVENTS:
            self.debug_event("Make code at 0x%08x" % ea)
        hooks.ida.make_code(insn.ea)
        return idaapi.IDB_Hooks.make_code(self, ea, size)

    def make_data(self, ea, flags, tid, length):
        self.pre_hook()
        if LOG_IDP_EVENTS:
            self.debug_event("Make data at 0x%08x, length : 0x%08x" % (ea, length))
        hooks.ida.make_data(ea)
        return idaapi.IDB_Hooks.make_data(self, ea, flags, tid, length)

    def func_added(self, func):
        self.pre_hook()
        if LOG_IDP_EVENTS:
            self.debug_event("Add func")
        self.unhook()
        hooks.idb.unhook()
        hooks.ida.add_function(func.start_ea)
        self.hook()
        hooks.idb.hook()
        return idaapi.IDB_Hooks.func_added(self, func)

    def deleting_func(self, func):
        self.pre_hook()
        if LOG_IDP_EVENTS:
            self.debug_event("Del func : 0x%08x" % func.start_ea)
        self.unhook()
        hooks.idb.unhook()
        hooks.ida.delete_function(func.start_ea)
        self.hook()
        hooks.idb.hook()
        return idaapi.IDB_Hooks.deleting_func(self, func)

    def debug_event(self, text):
        auto_display = idaapi.auto_display_t()
        logger.debug("event: auto=%d, AA_type=%d, AA_state=%d, text='%s'" %
                     (idaapi.autoIsOk(), auto_display.type, auto_display.state, text))

    def cmt_changed(self, ea, repeatable):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("cmt_changed     (0x%.016X, %x)" % (ea, repeatable))

        hooks.ida.change_comment(ea)
        if (idc.LineA(ea, 0) is None) and (idc.LineB(ea, 0) is None):
            return idaapi.IDB_Hooks.cmt_changed(self, ea, repeatable)

        return 0

    def extra_cmt_changed(self, ea, line_idx, cmt):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("extra_cmt_changed     (0x%.016X)" % (ea))

        hooks.ida.change_comment(ea)

        return idaapi.IDB_Hooks.extra_cmt_changed(self, ea, line_idx, cmt)

    def range_cmt_changed(self, rangecb, range, cmt, repeatable):
        self.pre_hook()
        ea = range.start_ea

        if LOG_IDB_EVENTS:
            self.debug_event("range comment at 0x%08X" % ea)
        hooks.ida.change_comment(ea)
        return idaapi.IDB_Hooks.range_cmt_changed(self, rangecb, range, cmt, repeatable)

    def op_type_changed(self, address, operand):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("op_type_changed at 0x%08X" % address)
        hooks.ida.change_operand_type(address)
        return idaapi.IDB_Hooks.op_type_changed(self, address, operand)

    def enum_created(self, enum):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("enum_created : 0x%08X (%s)" % (enum, idc.GetEnumName(enum)))
        hooks.ida.update_enum(enum)
        return idaapi.IDB_Hooks.enum_created(self, enum)

    def enum_renamed(self, enum_id):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("enum_renamed : 0x%08X (name=%s)" % (enum_id, idc.GetEnumName(enum_id)))
        hooks.ida.update_enum(enum_id)
        return idaapi.IDB_Hooks.enum_renamed(self, enum_id)

    def enum_member_renamed(self, enum_id, member_id):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("enum_member_renamed : 0x%08X (name=%s)" % (enum_id, idc.GetEnumName(enum_id)))
        hooks.ida.update_enum(enum_id)
        return idaapi.IDB_Hooks.enum_renamed(self, enum_id)

    def enum_deleted(self, enum):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("enum_deleted")
        hooks.ida.update_enum(enum)
        return idaapi.IDB_Hooks.enum_deleted(self, enum)

    def enum_member_created(self, enum, mid):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("enum_member_created")
        hooks.ida.update_enum(enum)
        return idaapi.IDB_Hooks.enum_member_created(self, enum, mid)

    def enum_member_deleted(self, enum, const_id):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("enum_member_deleted")
        hooks.ida.update_enum(enum)
        logger.warning("enum_member_deleted not fully implemented yet")
        # TODO: finish enum_member_deleted implementation
        """
        when const hashs will be improved (see TODO+comment in YaToolHashProvider.get_enum_member_id)
        we should be able to now which enum member has been deleted, and
        thus delete its corresponding object
        """
        return idaapi.IDB_Hooks.enum_member_deleted(self, enum, const_id)

    def enum_cmt_changed(self, enum, *args):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("enum_cmt_changed")
        # enum can be an enum or an enum member
        enum_id = idc.GetConstEnum(enum)
        if enum_id != idc.BADADDR:
            enum = enum_id

        hooks.ida.update_enum(enum)
        return idaapi.IDB_Hooks.enum_cmt_changed(self, enum, *args)

    def enum_bf_changed(self, enum_id):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("enum_bf_changed : 0x%08X (%s)" % (enum_id, idc.GetEnumName(enum_id)))

        hooks.ida.update_enum(enum_id)

        return idaapi.IDB_Hooks.enum_bf_changed(self, enum_id)

    def struc_created(self, struc):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("struc_created : 0x%08X (%s)" % (struc, idc.GetStrucName(struc)))
        hooks.ida.update_structure(struc)
        return idaapi.IDB_Hooks.struc_created(self, struc)

    def struc_deleted(self, struc):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("struc_deleted")
        hooks.ida.update_structure(struc)
        return idaapi.IDB_Hooks.struc_deleted(self, struc)

    def struc_renamed(self, struc):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("struc_renamed : 0X%08x" % struc.id)
        hooks.ida.update_structure(struc.id)
        return idaapi.IDB_Hooks.struc_renamed(self, struc)

    def struc_cmt_changed(self, struc, *args):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("struc_cmt_changed for id 0x%08X (%s)" % (struc, idaapi.get_struc_name(struc)))
        sidx = idc.GetStrucIdx(struc)
        if sidx is None or sidx == idc.BADADDR or not sidx:
            # this is either a stackframe, or a member of a structure
            fullname = idaapi.get_struc_name(struc)
            if "." in fullname:
                # it is a member id, retreive the struc id
                st = idaapi.get_member_struc(fullname)
                struc = st.id
            else:
                # it is a stackframe id
                pass
        hooks.ida.update_structure(struc)
        return idaapi.IDB_Hooks.struc_cmt_changed(self, struc, *args)

    def struc_member_created(self, struc, member):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("struc_member_created")
        hooks.ida.update_structure(struc.id)
        return idaapi.IDB_Hooks.struc_member_created(self, struc, member)

    def struc_member_deleted(self, struc, member_id, offset):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("struc_member_deleted")
        hooks.ida.delete_structure_member(struc.id, member_id, offset)
        return idaapi.IDB_Hooks.struc_member_deleted(self, struc, member_id, offset)

    def struc_member_renamed(self, struc, member):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("struc_member_renamed")
        hooks.ida.update_structure_member(struc.id, member.id, member.soff)
        return idaapi.IDB_Hooks.struc_member_renamed(self, struc, member)

    def struc_member_changed(self, struc, member):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("struc_member_changed")
        # TODO: only call struc_updated if the member is the last one and its size changed
        hooks.ida.update_structure(struc.id)
        hooks.ida.update_structure_member(struc.id, member.id, member.soff)
        return idaapi.IDB_Hooks.struc_member_changed(self, struc, member)

    def func_noret_changed(self, *args):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("func_noret_changed")
        return idaapi.IDB_Hooks.func_noret_changed(self, *args)

    def segm_added(self, segment):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("segm_added")
        hooks.ida.add_segment(segment)
        return idaapi.IDB_Hooks.segm_added(self, segment)


    def func_updated(self, pfn):
        self.pre_hook()
        hooks.ida.update_function(pfn.start_ea)
        return idaapi.IDB_Hooks.func_updated(self, pfn)

# ======================================================================#
# Hooks
# ======================================================================#
class YaCoUI_Hooks(idaapi.UI_Hooks):
    def __init__(self, yaco):
        self.yaco = yaco
        idaapi.UI_Hooks.__init__(self)

    def hook(self, *args):
        logger.debug("YaCoUI_Hooks:hook")
        return idaapi.UI_Hooks.hook(self, *args)

    def unhook(self, *args):
        logger.debug("YaCoUI_Hooks:unhook")
        return idaapi.UI_Hooks.unhook(self, *args)

    def saving(self, *args):
        """
        saving(self)


        The kernel is saving the database.

        @return: Ignored
        """
        return idaapi.UI_Hooks.saving(self, *args)

    def saved(self, *args):
        """
        saved(self)


        The kernel has saved the database.

        @return: Ignored
        """
        return idaapi.UI_Hooks.saved(self, *args)

    def term(self, *args):
        """
        term(self)


        IDA is terminated and the database is already closed.
        The UI may close its windows in this callback.
        """
        try:
            self.yaco.ida_hooks.unhook()
            self.unhook()
        except Exception, e:
            ex = traceback.format_exc()
            logger.error("An error occurred while terminating")
            logger.error("%s", ex)
            raise e
        return idaapi.UI_Hooks.term(self, *args)

    def __del__(self):
        logger.warning("Destroying %r" % self)
