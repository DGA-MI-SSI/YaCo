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
        self.ida = YaToolIDAHooks(hash_provider, repo_manager)
        self.idb = YaToolIDB_Hooks()
        self.idp = YaToolIDP_Hooks()
        self.current_rename_infos = {}
        global hooks
        hooks = self

    def hook(self):
        logger.debug("Hooks:hook")
        self.idb.hook()
        self.idp.hook()

    def unhook(self):
        logger.debug("Hooks:unhook")
        self.idp.unhook()
        self.idb.unhook()


class YaToolIDAHooks(object):
    '''
    classdocs
    '''

    def __init__(self, hash_provider, repo_manager):
        '''
        Constructor
        '''
        self.native = ya.MakeHooks()

        self.hash_provider = hash_provider
        self.repo_manager = repo_manager

        self.new_marked_pos = set()
        # load marked pos
        for i in xrange(1, 1024):
            if idc.GetMarkedPos(i) == idc.BADADDR:
                break
            else:
                self.new_marked_pos.add(idc.GetMarkedPos(i))
        self.flush()

    # ==================================================================#
    # Hook forward
    # ==================================================================#
    # ==================== FUNCTIONS ===================================#
    def rename(self, ea, new_name, type=None, old_name=None):
        # TODO: Fix this when we received end function created event !
        # logger.debug("rename at 0x%.016X" % ea)
        self.addresses_to_process.add(ea)
        prefix = ""
        if type is not None:
            prefix = "%s " % type
        old_name_txt = ""
        if old_name is not None:
            old_name_txt = "from %s" % old_name
        self.repo_manager.add_auto_comment(ea, "%srenamed %s to %s" % (prefix, old_name_txt, new_name))

    def comment_changed(self, ea):
        # TODO: Fix this when we received end undefined event !
        # logger.debug("comment_changed(%.016X)" % ea)
        self.comments_to_process[ea] = "Add comment"

    def undefine(self, ea):
        # TODO: Fix this when we received end undefined event !
        self.addresses_to_process.add(ea)
        self.segment_address_to_process.add(ea)
        self.repo_manager.add_auto_comment(ea, "Undefine")

    def del_func(self, ea):
        self.addresses_to_process.add(ea)
        self.segment_address_to_process.add(ea)
        self.repo_manager.add_auto_comment(ea, "Delete function")

    def make_code(self, ea):
        # TODO: Fix this when we received end function created event !
        self.addresses_to_process.add(ea)
        self.segment_address_to_process.add(ea)
        self.repo_manager.add_auto_comment(ea, "Create code")

    def make_data(self, ea):
        # TODO: Fix this when we received end function created event !
        self.addresses_to_process.add(ea)
        self.segment_address_to_process.add(ea)
        self.repo_manager.add_auto_comment(ea, "Create data")

    def add_func(self, ea):
        # invalid all addresses in this function (they depend (relatively) on this function now, no on code)
        logger.warning("Warning : deletion of objects not implemented")
        # TODO : implement deletion of objects inside newly created function range
        # TODO : use function chunks to iterate over function code
        ea_index = int(ea)
        while ea_index < int(idc.FindFuncEnd(ea)):
            self.delete_object_version_for_ea(ea_index)
            ea_index += 1

        # self.update_object_version_from_idb(ea)
        self.addresses_to_process.add(ea)
        self.segment_address_to_process.add(ea)
        self.repo_manager.add_auto_comment(ea, "Create function")

    # =================== STRUCTURES ===================================#
    def struc_updated(self, struc):
        self.structures_to_process.add(struc)
        self.repo_manager.add_auto_comment(struc, "Updated")

    def struc_member_updated(self, struc_id, member_id, member_offset):
        try:
            struc_set = self.strucmember_to_process[struc_id]
        except KeyError:
            struc_set = set()
            self.strucmember_to_process[struc_id] = struc_set
        struc_set.add((member_id, member_offset))
        self.repo_manager.add_auto_comment(struc_id, "Member updated at offset 0x%X : %s" % (
            member_offset, idaapi.get_member_fullname(member_id)))

    def struc_member_deleted(self, struc_id, member_id, offset):
        self.struc_updated(struc_id)
        try:
            struc_set = self.strucmember_to_process[struc_id]
        except KeyError:
            struc_set = set()
            self.strucmember_to_process[struc_id] = struc_set
        struc_set.add((member_id, offset))
        # trigger struc file regeneration
        self.struc_updated(struc_id)
        self.repo_manager.add_auto_comment(struc_id, "Member deleted")

    def enum_updated(self, enum):
        if LOG_IDA_HOOKS_EVENTS:
            logger.debug("enum_updated : %s" % ya.ea_to_hex(enum))
        self.enums_to_process.add(enum)
        self.repo_manager.add_auto_comment(enum, "Updated")

    def op_type_changed(self, ea):
        # TODO: Fix this when we received end function created event !
        func = idaapi.get_func(ea)
        if func is not None:
            self.addresses_to_process.add(ea)
            self.repo_manager.add_auto_comment(ea, "Operand type change")
        elif idaapi.is_member_id(ea):
            # this is a member id : hook already present (struc_member_renamed)
            pass
        elif not idc.isCode(idc.GetFlags(ea)):
            self.addresses_to_process.add(ea)
            self.repo_manager.add_auto_comment(ea, "Operand type change")
        else:
            logger.warning("op_type_changed at 0x%08X : code but not in a function : not implemented")

    def segment_added(self, segment):
        self.updated_segments.add((segment.start_ea, segment.end_ea))

    def ti_changed(self, ea):
        if idaapi.is_member_id(ea):
            # ti_changed might be called for struc members??
            return
        self.addresses_to_process.add(ea)
        self.repo_manager.add_auto_comment(ea, "Type info changed")

    def func_updated(self, ea):
        self.addresses_to_process.add(ea)
        self.repo_manager.add_auto_comment(ea, "Function updated")

    def save_strucs(self, ida_model, memory_exporter):
        """
        Structures : export modified structures and delete those who have been deleted
        """
        for struc_id in self.structures_to_process:
            sidx = idc.GetStrucIdx(struc_id)
            if sidx is None or sidx == idc.BADADDR:
                # it is a deleted structure or a stackframe
                # in this last case we need to export the parent (function)
                eaFunc = idaapi.get_func_by_frame(struc_id)
                if eaFunc != idc.BADADDR:
                    # OK, it is a stackframe
                    ida_model.accept_struct(memory_exporter, eaFunc, struc_id)
                    ida_model.accept_ea(memory_exporter, eaFunc)
                else:
                    # it is a deleted structure
                    ida_model.delete_struct(memory_exporter, struc_id)
            else:

                ida_model.accept_struct(memory_exporter, idc.BADADDR, struc_id)

        logger.debug("Walking members")
        """
        Structure members : update modified ones, and remove deleted ones
        We iterate over members :
            -if the parent struc has been deleted, delete the member
            -otherwise, detect if the member has been updated or removed
                -updated : accept struc_member + accept_struct if not already exported!
                -removed : accept struc_member_deleted
        """
        for (struc_id, member_set) in self.strucmember_to_process.iteritems():
            ida_struc = idaapi.get_struc(struc_id)
            logger.debug("Walking struc 0x%08X" % struc_id)
            sidx = idc.GetStrucIdx(struc_id)
            is_stackframe = False
            struc_deleted = False
            if sidx is None or sidx == idc.BADADDR:
                f = idaapi.get_func_by_frame(struc_id)
                if f is not None and f != idc.BADADDR:
                    is_stackframe = True
                else:
                    struc_deleted = True

            stackframe_func_addr = idc.BADADDR
            if is_stackframe:
                eaFunc = idaapi.get_func_by_frame(struc_id)
                stackframe_func_addr = eaFunc
                ida_model.accept_function(memory_exporter, eaFunc)

            if struc_deleted:
                # The structure has been deleted : we need to delete the members
                # Note: at first sight, it is not a stackframe
                # TODO: handle function->stackframe deletion here
                for (member_id, offset) in member_set:
                    ida_model.delete_struct_member(memory_exporter, idc.BADADDR, struc_id, offset)
            else:
                # The structure or stackframe has been modified
                for (member_id, offset) in member_set:
                    ida_member = idaapi.get_member(ida_struc, offset)
                    if ida_member is None:
                        new_member_id = -1
                    else:
                        new_member_id = ida_member.id
                    if new_member_id == -1:
                        # the member has been deleted : delete it
                        ida_model.delete_struct_member(memory_exporter, stackframe_func_addr, struc_id, offset)
                    elif offset > 0 and idc.GetMemberId(struc_id, offset - 1) == new_member_id:
                        # the member was deleted, and replaced by a member starting above it
                        ida_model.delete_struct_member(memory_exporter, stackframe_func_addr, struc_id, offset)
                    else:
                        # the member has just been modified
                        ida_model.accept_struct_member(memory_exporter, stackframe_func_addr, ida_member.id)

    def save_enums(self, ida_model, memory_exporter):
        """
        export modified enums and delete those who have been deleted
        """
        for enum_id in self.enums_to_process:
            eidx = idc.GetEnumIdx(enum_id)
            if eidx is None or eidx == idc.BADADDR:
                # it is a deleted enum
                logger.debug("Accepting deleted enum: 0x%08X" % enum_id)
                ida_model.delete_enum(memory_exporter, enum_id)
            else:
                logger.debug("Accepting enum: 0x%08X" % enum_id)
                ida_model.accept_enum(memory_exporter, enum_id)

        """
        This is not fully implemented yet, as we have no way of detecting
        which enum members are deleted. Thus enummember_to_process remains empty

        Enum members : update modified ones, and remove deleted ones
        We iterate over members :
            -if the parent enum has been deleted, delete the member
            -otherwise, detect if the member has been updated or removed
                -updated : accept enum_member
                -removed : accept enum_member_deleted
        """

    def save(self):
        start_time = time.time()
        ida_model = ya.MakeModelIncremental(self.hash_provider)
        """
        TODO : improve cache re-generation
        pb : we should not regenerate the whole cache everytime
        pb : when we load strucmembers (from the cache) and they are
        later deleted, we get stalled XML files (they are not referenced
        in the parent struc/stackframe, which is good, but they still
        exist)


        *do not store objects here : store them in the memory exporter
        *make 3 pass :
            -delete deleted objects
            -create updated objects
            -create new objects

        """
        logger.debug("YaToolIDAHooks.save()")

        db = ya.MakeModel()
        memory_exporter = db.visitor
        if VALIDATE_EXPORTED_XML:
            memory_exporter = ya.MakeMultiplexerDebugger(db.visitor)
        memory_exporter.visit_start()
        """
        First, find modified informations : marked positions, comments, ...
        """
        # some marked comment may have been deleted
        self.new_marked_pos = set()
        for i in xrange(1, 1024):
            if idc.GetMarkedPos(i) == idc.BADADDR:
                break
            else:
                self.new_marked_pos.add(idc.GetMarkedPos(i))
        # get remove marked comments
        for removed_marked_pos in (self.marked_pos - self.new_marked_pos):
            self.addresses_to_process.add(removed_marked_pos)
            self.repo_manager.add_auto_comment(removed_marked_pos, "Removed marked comment")

        # process comments
        for (ea, value) in self.comments_to_process.iteritems():
            # do not save comments coming from function prototype
            # if not idaapi.is_tilcmt(ea):
            self.addresses_to_process.add(ea)
            self.repo_manager.add_auto_comment(ea, value)

        """
        Next, export strucs and enums
        This will also delete unneeded files
        """
        self.save_strucs(ida_model, memory_exporter)
        self.save_enums(ida_model, memory_exporter)

        """
        explore IDA yacoHooks for logged ea
        """
        for ea in self.addresses_to_process:
            ida_model.accept_ea(memory_exporter, ea)

        for seg_ea_start, seg_ea_end in self.updated_segments:
            ida_model.accept_segment(memory_exporter, seg_ea_start)

        memory_exporter.visit_end()
        """
        #before saving, we remove all cache (some files may have been deleted)
        order = ("struc", "strucmember", "enum", "enum_member", "segment", "function",
                "stackframe", "stackframe_member", "basic_block", "data", "code")
        for obj_type in order:
            current_dir = os.path.join(self.idb_directory, "cache", obj_type)
            if not os.path.isdir(current_dir):
                continue
            for f in os.listdir(current_dir):
                os.remove(os.path.join(current_dir, f))
        """
        logger.debug("Exporting from memory to XML")
        # now export to XML
        xml_exporter = ya.MakeXmlExporter(os.path.join(os.path.dirname(idc.GetIdbPath()), "cache"))
        if VALIDATE_EXPORTED_XML_2:
            db.model.accept(ya.MakePathDebuggerVisitor("SaveXMLValidator", ya.MakeExporterValidatorVisitor(), False))

        db.model.accept(xml_exporter)

        end_time = time.time()

        logger.debug("YaCo saved in %d seconds." % (end_time - start_time))

    def flush(self):
        self.addresses_to_process = set()
        self.segment_address_to_process = set()
        self.strucmember_to_process = {}
        self.structures_to_process = set()
        self.enums_to_process = set()
        self.enummember_to_process = {}
        self.comments_to_process = {}
        self.marked_pos = self.new_marked_pos
        self.updated_segments = set()


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

    def savebase(self, *args):
        logger.debug("savebase")
        YaCo.save()
        return idaapi.IDB_Hooks.savebase(self, *args)

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
                old_name = None
            hooks.ida.rename(ea, new_name, old_name=old_name)

        return hooks.idp.ev_rename(ea, new_name)

    def make_code(self, ea, size):
        self.pre_hook()
        if LOG_IDP_EVENTS:
            self.debug_event("Make code at 0x%08x" % ea)
        hooks.ida.make_code(ea)
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
        hooks.ida.add_func(func.start_ea)
        self.hook()
        hooks.idb.hook()
        return idaapi.IDB_Hooks.func_added(self, func)

    def deleting_func(self, func):
        self.pre_hook()
        if LOG_IDP_EVENTS:
            self.debug_event("Del func : 0x%08x" % func.start_ea)
        self.unhook()
        hooks.idb.unhook()
        hooks.ida.del_func(func.start_ea)
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

        hooks.ida.comment_changed(ea)
        if (idc.LineA(ea, 0) is None) and (idc.LineB(ea, 0) is None):
            return idaapi.IDB_Hooks.cmt_changed(self, ea, repeatable)

        return 0

    def extra_cmt_changed(self, ea, line_idx, cmt):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("extra_cmt_changed     (0x%.016X)" % (ea))

        hooks.ida.comment_changed(ea)

        return idaapi.IDB_Hooks.extra_cmt_changed(self, ea, line_idx, cmt)

    def range_cmt_changed(self, rangecb, range, cmt, repeatable):
        self.pre_hook()
        ea = range.start_ea

        if LOG_IDB_EVENTS:
            self.debug_event("range comment at 0x%08X" % ea)
        hooks.ida.comment_changed(ea)
        return idaapi.IDB_Hooks.range_cmt_changed(self, rangecb, range, cmt, repeatable)

    def ti_changed(self, ea, arg1, arg2):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("ti changed at 0x%08X" % ea)
        hooks.ida.ti_changed(ea)

        return idaapi.IDB_Hooks.ti_changed(self, ea, arg1, arg2)

    def op_ti_changed(self, arg0, arg1, arg2, arg3):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("op_ti_changed at 0x%08X" % arg0)
        return idaapi.IDB_Hooks.op_ti_changed(self, arg0, arg1, arg2, arg3)

    def op_type_changed(self, address, operand):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("op_type_changed at 0x%08X" % address)
        hooks.ida.op_type_changed(address)
        return idaapi.IDB_Hooks.op_type_changed(self, address, operand)

    def enum_created(self, enum):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("enum_created : 0x%08X (%s)" % (enum, idc.GetEnumName(enum)))
        hooks.ida.enum_updated(enum)
        return idaapi.IDB_Hooks.enum_created(self, enum)

    def enum_renamed(self, enum_id):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("enum_renamed : 0x%08X (name=%s)" % (enum_id, idc.GetEnumName(enum_id)))
        hooks.ida.enum_updated(enum_id)
        return idaapi.IDB_Hooks.enum_renamed(self, enum_id)

    def enum_member_renamed(self, enum_id, member_id):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("enum_member_renamed : 0x%08X (name=%s)" % (enum_id, idc.GetEnumName(enum_id)))
        hooks.ida.enum_updated(enum_id)
        return idaapi.IDB_Hooks.enum_renamed(self, enum_id)

    def enum_deleted(self, enum):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("enum_deleted")
        hooks.ida.enum_updated(enum)
        return idaapi.IDB_Hooks.enum_deleted(self, enum)

    def enum_member_created(self, enum, mid):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("enum_member_created")
        hooks.ida.enum_updated(enum)
        return idaapi.IDB_Hooks.enum_member_created(self, enum, mid)

    def enum_member_deleted(self, enum, const_id):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("enum_member_deleted")
        hooks.ida.enum_updated(enum)
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

        hooks.ida.enum_updated(enum)
        return idaapi.IDB_Hooks.enum_cmt_changed(self, enum, *args)

    def enum_bf_changed(self, enum_id):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("enum_bf_changed : 0x%08X (%s)" % (enum_id, idc.GetEnumName(enum_id)))

        hooks.ida.enum_updated(enum_id)

        return idaapi.IDB_Hooks.enum_bf_changed(self, enum_id)

    def struc_created(self, struc):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("struc_created : 0x%08X (%s)" % (struc, idc.GetStrucName(struc)))
        hooks.ida.struc_updated(struc)
        return idaapi.IDB_Hooks.struc_created(self, struc)

    def struc_deleted(self, struc):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("struc_deleted")
        hooks.ida.struc_updated(struc)
        return idaapi.IDB_Hooks.struc_deleted(self, struc)

    def struc_renamed(self, struc):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("struc_renamed : 0X%08x" % struc.id)
        hooks.ida.struc_updated(struc.id)
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
        hooks.ida.struc_updated(struc)
        return idaapi.IDB_Hooks.struc_cmt_changed(self, struc, *args)

    def struc_member_created(self, struc, member):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("struc_member_created")
        hooks.ida.struc_updated(struc.id)
        return idaapi.IDB_Hooks.struc_member_created(self, struc, member)

    def struc_member_deleted(self, struc, member_id, offset):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("struc_member_deleted")
        hooks.ida.struc_member_deleted(struc.id, member_id, offset)
        return idaapi.IDB_Hooks.struc_member_deleted(self, struc, member_id, offset)

    def struc_member_renamed(self, struc, member):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("struc_member_renamed")
        hooks.ida.struc_member_updated(struc.id, member.id, member.soff)
        return idaapi.IDB_Hooks.struc_member_renamed(self, struc, member)

    def struc_member_changed(self, struc, member):
        self.pre_hook()

        if LOG_IDB_EVENTS:
            self.debug_event("struc_member_changed")
        # TODO: only call struc_updated if the member is the last one and its size changed
        hooks.ida.struc_updated(struc.id)
        hooks.ida.struc_member_updated(struc.id, member.id, member.soff)
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
        hooks.ida.segment_added(segment)
        return idaapi.IDB_Hooks.segm_added(self, segment)


    def func_updated(self, pfn):
        self.pre_hook()
        hooks.ida.func_updated(pfn.start_ea)
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
