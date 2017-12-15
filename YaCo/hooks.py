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

    def debug_event(self, text):
        auto_display = idaapi.auto_display_t()
        logger.debug("event: auto=%d, AA_type=%d, AA_state=%d, text='%s'" %
                     (idaapi.autoIsOk(), auto_display.type, auto_display.state, text))

    def op_type_changed(self, address, operand):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("op_type_changed at 0x%08X" % address)
        hooks.ida.change_operand_type(address)
        return idaapi.IDB_Hooks.op_type_changed(self, address, operand)

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
