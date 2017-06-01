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

import glob
import os
import shutil
import sys
import time

sys.path.append(os.path.abspath("%s/../../bin/" % __file__))

import cProfile
import idc
import idaapi
import logging
import pstats
import traceback
import YaCoUtils

if idc.__EA64__:
    import YaToolsPy64 as ya
else:
    import YaToolsPy32 as ya

# from idaapi import ASKBTN_NO, ASKBTN_YES
from YaCoExporterMaster import master_handler
from ImportExport import YaToolIDATools
from ImportExport.YaToolIDAExporter import YaToolIDAExporter
from ImportExport.YaToolIDAHooks import Hooks, YaCoUI_Hooks
from ImportExport.YaTools import YaTools
from ImportExport.YaToolHashProvider import YaToolHashProvider
from ImportExport.YaToolIDAModel import YaToolIDAModel
from ImportExport.YaToolRepoManager import YaToolRepoManager
from ImportExport.YaToolIDATools import copy_idb_to_local_file, copy_idb_to_original_file
from ImportExport.YaToolIDATools import get_original_idb_name, get_local_idb_name

logging.basicConfig()
logger = None

YACO_VERSION = ya.GitVersion

PROFILE_YACO_LOADING = False
PROFILE_YACO_SAVING = False
CHECKOUT_IDB_ON_CLOSE = False
VALIDATE_EXPORTER_VISITOR = False


class YaCoHandler(idaapi.action_handler_t):
    def __init__(self, yaco, callback):
        self.callback = callback
        self.yaco = yaco

    def activate(self, ctx):
        self.callback(self.yaco)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_IDB


class YaCo:
    def initial_load(self):

        start_time = time.time()

        # load XML into memory
        logger.debug("Initial load")

        # export to IDB
        self.ida_exporter = YaToolIDAExporter(self.yatools, self.hash_provider)
        self.ida_export = ya.MakeDependencyResolverVisitor(self.ida_exporter,
                                                           VALIDATE_EXPORTER_VISITOR,
                                                           "LoadVisitor")
        ya.MakeXmlDatabaseModel("cache/").accept(self.ida_export.visitor)

        # TODO remove this call (it's done in the constructor)
        self.hash_provider.populate_struc_enum_ids()

        end_time = time.time()

        logger.debug("YaCo cache loaded in %d seconds.", (end_time - start_time))

    def update(self):
        YaToolIDATools.update_bookmarks()
        # pydevd.settrace()
        logger.debug("Yaco.update()")
        (modified_object_ids_str, deleted_object_ids_str, modified_files,
         _deleted_files) = self.repo_manager.update_cache()
        modified_object_ids = []
        deleted_object_ids = []
        for obj_id in modified_object_ids_str:
            modified_object_ids.append(ya.YaToolObjectId_From_String(obj_id))

        for obj_id in deleted_object_ids_str:
            deleted_object_ids.append(ya.YaToolObjectId_From_String(obj_id))

        logger.debug("delete objects")
        self.ida_export.deleter.delete_objects(deleted_object_ids)

        logger.debug("invalidate objects")
        self.ida_export.deleter.invalidate_objects(modified_object_ids, True)

        logger.debug("loading XML")
        logger.debug("modified files : %r", modified_files)
        from pprint import pprint
        pprint(modified_files)

        memory_exporter = ya.MakeStdModel()

        logger.debug("exporting XML to memory")
        ya.MakeXmlFilesDatabaseModel(modified_files).accept(memory_exporter.visitor)

        logger.debug("unhook")
        self.ida_hooks.unhook()

        logger.debug("export mem->ida")
        memory_exporter.model.accept(self.ida_export.visitor)

        idc.SetCharPrm(idc.INF_AUTO, True)
        idc.Wait()
        idc.SetCharPrm(idc.INF_AUTO, False)
        idc.Refresh()
        logger.debug("hook")
        self.ida_hooks.hook()

    def save_and_commit(self):
        try:
            idc.SaveBase("")
            self.commit_cache()
        except Exception, e:
            ex = traceback.format_exc()
            logger.error("An error occurred during YaCo commit")
            logger.error("%s", ex)

            traceback.print_exc()
            Warning("An error occured during YaCo commit : please relaunch IDA")

            raise e

    def commit_cache(self):
        if PROFILE_YACO_SAVING:
            pr = cProfile.Profile()
            pr.enable()
        self.ida_hooks.ida.save()
        if self.repo_manager.repo_commit():
            self.ida_hooks.ida.flush()
            logger.debug("YaCo commit saved.")
        try:
            self.update()
        except Exception, e:
            ex = traceback.format_exc()
            logger.error("An error occurred while updating")
            logger.error("%s", ex)
            raise e
        if PROFILE_YACO_SAVING:
            pr.disable()
            f = open("yaco-save.profile", 'w')
            ps = pstats.Stats(pr, stream=f).sort_stats('time')
            ps.print_stats()
            f.close()

    def toggle_auto_rebase_push(self, *args):
        if self.repo_manager.repo_auto_sync:
            self.repo_manager.repo_auto_sync = False
            idc.Message('Auto rebase/push disabled')
        else:
            self.repo_manager.repo_auto_sync = True
            idc.Message('Auto rebase/push enabled')

    def export_all_cache(self, num_cpu=None):
        logger.info("Exporting database using all cores")
        master_handler(self.yatools, self.hash_provider, db_dir="database", export_dir="export", num_cpu=num_cpu)
        idc.Message("Export complete.")

    def export_single_cache(self, *args):
        logger.info("Exporting database using one core")
        m = YaToolIDAModel(self.yatools, self.hash_provider)
        m.set_descending_mode(True)
        if not os.path.isdir("database"):
            os.mkdir("database")
        YaCoUtils.yadb_export(m, "database/database.yadb")
        idc.Message("Export complete.")

    def create_reset(self, *args):
        title = "YaCo Force Push"
        text = "You are going to force push your IDB. Other YaCo users will need to stop working & force pull.\n"
        "Do you really want to force push ?"
        val = idaapi.askbuttons_c(
            "Yes", "No", "", idaapi.ASKBTN_NO, "TITLE %s\nICON QUESTION\nAUTOHIDE SESSION\n"
            "HIDECANCEL\n%s" % (title, text))
        if val != idaapi.ASKBTN_YES:
            return

        # disable all yaco hooks
        self.YaCoUI.unhook()

        # create a backup of current idb
        copy_idb_to_local_file("_bkp_%s" % time.ctime().replace(" ", "_").replace(":", "_"))

        # restore original idb
        original_file = copy_idb_to_original_file()

        # get xml files
        xml_files = []
        for root, dirs, files in os.walk('cache/'):
            for file in files:
                xml_files.append("%s/%s" % (root, file))

        # add idb
        self.repo_manager.repo.add_file(original_file)

        # remove xml cache
        self.repo_manager.repo.remove_files(xml_files)
        for xml_file in xml_files:
            os.remove(xml_file)

        # create commit
        self.repo_manager.repo.commit("YaCo force push")

        # push commit
        self.repo_manager.push_origin_master()

        idc.Warning("Force push complete, you can restart IDA and other YaCo users can \"Force pull\"")

        idc.Exit(0)

    def retrieve_reset(self, *args):
        if not idaapi.askyn_c(False, "All your local changes will be lost !\nDo you really want to proceed ?"):
            return

        # disable all yaco hooks
        self.YaCoUI.unhook()

        # create a backup of current idb
        copy_idb_to_local_file("_bkp_%s" % time.ctime().replace(" ", "_").replace(":", "_"))

        # delete all modified objects
        self.repo_manager.repo.checkout_head()

        # get reset
        self.repo_manager.fetch_origin()
        self.repo_manager.rebase_from_origin()

        original_idb_name = get_original_idb_name(idc.GetIdbPath())

        # remove current idb
        os.remove(idc.GetIdbPath())

        # recreate local idb
        shutil.copy(original_idb_name, get_local_idb_name(original_idb_name))

        # local should not be overwritten, so we have to close IDA brutally !
        idaapi.cvar.database_flags |= idaapi.DBFL_KILL
        idc.Warning("Force pull complete, you can restart IDA")
        idc.Exit(0)

    # ======================================================================#
    # Main
    # ======================================================================#

    def __init__(self):

        if PROFILE_YACO_LOADING:
            self.pr = cProfile.Profile()
            self.pr.enable()

        """
        Create and initialize native subsystem
        """
        name, ext = os.path.splitext(idc.GetIdbPath())
        ya.StartYatools(name)

        logging.basicConfig()
        global logger
        logger = logging.getLogger("YaCo")

        logger.setLevel(LOGGING_LEVEL)
        logger.propagate = True
        for h in logger.handlers:
            h.setLevel(logging.WARN)

        handler = YaLogHandler()
        handler.setLevel(LOGGING_LEVEL)
        logger.addHandler(handler)

        # logger.setLevel(logging.DEBUG)

        def set_console_level_(level):
            for h in logger.handlers:
                if h not in [handler]:
                    h.setLevel(level)

        """
        Create and initialize Python subsystem
        """
        idaapi.msg("YaCo %s\n" % YACO_VERSION)

        self.yatools = YaTools()
        self.hash_provider = YaToolHashProvider()

        self.repo_manager = YaToolRepoManager(self.yatools, idc.GetIdbPath())
        self.repo_manager.check_valid_cache_startup()

        self.ida_hooks = Hooks(self.yatools, self.hash_provider, self.repo_manager)

        self.YaCoUI = YaCoUI_Hooks(self)

    yaco_menus = [
        ["yaco_toggle_rebase_push", "YaCo - Toggle YaCo auto rebase/push", toggle_auto_rebase_push, ""],
        ["yaco_create_reset", "YaCo - Force push", create_reset, ""],
        ["yaco_retrieve_reset", "YaCo - Force pull", retrieve_reset, ""],
        ["yaco_export_all_cache", "YaCo - Export database (All cores)", export_all_cache, ""],
        ["yaco_export_single_file", "YaCo - Export database (One core)", export_single_cache, ""],
    ]

    def start(self):
        self.YaCoUI.hook()

        try:
            self.ida_hooks.unhook()
            self.initial_load()
            idc.Wait()
            self.ida_hooks.hook()
        except:
            traceback.print_exc()
            self.YaCoUI.unhook()
            self.ida_hooks.unhook()
            logger.error('Error during load cache, YaCo is disabled !')

        idc.SetCharPrm(idc.INF_AUTO, False)

        for menu_item in self.yaco_menus:
            name = menu_item[0]
            text = menu_item[1]
            callback = menu_item[2]
            shortcut = menu_item[3]
            handler = YaCoHandler(self, callback)
            action = idaapi.action_desc_t(name, text, handler, shortcut, "")
            idaapi.register_action(action)
            idaapi.attach_action_to_menu("Edit/YaTools/", name, idaapi.SETMENU_APP)

        if PROFILE_YACO_LOADING:
            self.pr.disable()
            f = open("yaco-loading.profile", 'w')
            ps = pstats.Stats(self.pr, stream=f).sort_stats('time')
            ps.print_stats()
            f.close()

    def close(self):
        self.YaCoUI.unhook()
        self.ida_hooks.unhook()
        ya.StopYatools()

        for menu_item in self.yaco_menus:
            name = menu_item[0]
            idaapi.detach_action_from_menu("Edit/YaTools/", name)
            idaapi.unregister_action(name)


LOGGING_LEVEL = logging.INFO
set_console_level = None

logging_ready = False


class YaLogHandler(logging.Handler):
    def __init__(self):
        logging.Handler.__init__(self)
        self.deftype = ya.LOG_LEVEL_ERROR
        self.typemap = {
            logging.DEBUG: ya.LOG_LEVEL_DEBUG,
            logging.INFO: ya.LOG_LEVEL_INFO,
            logging.WARNING: ya.LOG_LEVEL_WARNING,
            logging.ERROR: ya.LOG_LEVEL_ERROR,
        }

    def emit(self, record):
        try:
            level = self.typemap.get(record.levelno, self.deftype)
            ya.yaco_log(level, self.format(record) + '\n')
        except:
            self.handleError(record)


yaco = None
yaco_starting = False


def start(init_logging=True):
    global yaco, yaco_starting

    if yaco_starting:
        print("YaCo is starting : skipping")
        return

    yaco_starting = True
    if yaco is None:
        print("Starting YaCo")
        yaco = YaCo()
        yaco.start()
        yaco_starting = False
        return True
    else:
        logger.warning("Not starting YaCo: already done")
        yaco_starting = False
        return False


def commit():
    global yaco
    logger.info("YaCo.commit()")
    try:
        # try to commit cache
        yaco.commit_cache()
    except Exception, e:
        traceback.print_exc()
        raise e
    logger.info("YaCo.commit() done")


def save():
    global yaco
    logger.info("YaCo.save()")
    try:
        yaco.commit_cache()
    except Exception, e:
        ex = traceback.format_exc()
        logger.error("An error occurred during YaCo commit")
        logger.error("%s", ex)
        traceback.print_exc()
        Warning("An error occured during YaCo commit : please relaunch IDA")

        raise e


def close():
    global yaco
    if yaco is None:
        print("Could not close YaCo: not loaded")
        return

    logger.info("YaCo.close()")
    try:
        # on shutdown, restoring original IDB
        if CHECKOUT_IDB_ON_CLOSE:
            yaco.repo_manager.repo_restore_idb()
    except Exception, e:
        traceback.print_exc()
        raise e
    yaco.close()
    print("YaCo.close() done")
    yaco = None
