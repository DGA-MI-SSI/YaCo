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

if idc.__EA64__:
    import YaToolsPy64 as ya
else:
    import YaToolsPy32 as ya
import hooks

logging.basicConfig()
logger = None

YACO_VERSION = ya.GitVersion

VALIDATE_EXPORTER_VISITOR = False

IDA_IS_INTERACTIVE = ya.IS_INTERACTIVE


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
        ya.export_to_ida(ya.MakeXmlDatabaseModel("cache/"), self.hash_provider)

        end_time = time.time()

        logger.debug("YaCo cache loaded in %d seconds.", (end_time - start_time))

    def toggle_auto_rebase_push(self, *args):
        self.repo_manager.toggle_repo_auto_sync()

    def export_single_cache(self, *args):
        logger.info("Exporting database using one core")
        if not os.path.isdir("database"):
            os.mkdir("database")
        exporter = ya.MakeFlatBufferExporter()
        ya.MakeModel(self.hash_provider).accept(exporter)
        with open("database/database.yadb", "wb") as fh:
            fh.write(exporter.GetBuffer())
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
        self.ida_hooks.unhook()

        self.repo_manager.sync_and_push_original_idb()

        idc.Warning("Force push complete, you can restart IDA and other YaCo users can \"Force pull\"")

        idc.Exit(0)

    def retrieve_reset(self, *args):
        if not idaapi.askyn_c(False, "All your local changes will be lost !\nDo you really want to proceed ?"):
            return

        # disable all yaco hooks
        self.ida_hooks.unhook()

        self.repo_manager.discard_and_pull_idb()

        # current idb should not be overwritten, so we have to close IDA brutally !
        idaapi.set_database_flag(idaapi.DBFL_KILL)
        idc.Warning("Force pull complete, you can restart IDA")
        idc.Exit(0)

    # ======================================================================#
    # Main
    # ======================================================================#

    def __init__(self):
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

        self.hash_provider = ya.MakeHashProvider()
        self.repo_manager = ya.MakeRepository(".", IDA_IS_INTERACTIVE)
        self.repo_manager.check_valid_cache_startup()

        self.ida_hooks = hooks.Hooks(self.hash_provider, self.repo_manager)


    yaco_menus = [
        ["yaco_toggle_rebase_push", "YaCo - Toggle YaCo auto rebase/push", toggle_auto_rebase_push, ""],
        ["yaco_create_reset", "YaCo - Resync idb & force push", create_reset, ""],
        ["yaco_retrieve_reset", "YaCo - Discard idb & force pull", retrieve_reset, ""],
        ["yaco_export_single_file", "YaCo - Export database", export_single_cache, ""],
    ]

    def start(self):
        logger.info("YaCo.start()")

        try:
            self.ida_hooks.unhook()
            self.initial_load()
            idc.Wait()
            self.ida_hooks.hook()
        except:
            traceback.print_exc()
            self.ida_hooks.unhook()
            logger.error('Error during load cache, YaCo is disabled !')

        idc.set_inf_attr(idc.INFFL_AUTO, False)

        for menu_item in self.yaco_menus:
            name = menu_item[0]
            text = menu_item[1]
            callback = menu_item[2]
            shortcut = menu_item[3]
            handler = YaCoHandler(self, callback)
            action = idaapi.action_desc_t(name, text, handler, shortcut, "")
            idaapi.register_action(action)
            idaapi.attach_action_to_menu("Edit/YaTools/", name, idaapi.SETMENU_APP)

    def close(self):
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
        yaco = YaCo()
        yaco.start()
        yaco_starting = False
        return True
    else:
        logger.warning("Not starting YaCo: already done")
        yaco_starting = False
        return False

def close():
    global yaco
    if yaco is None:
        print("Could not close YaCo: not loaded")
        return

    logger.info("YaCo.close()")
    yaco.close()
    print("YaCo.close() done")
    yaco = None
