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
import logging
import os
import shutil
import time
import traceback
import xml.dom.minidom
import yatools

if idc.__EA64__:
    import YaToolsPy64 as ya
else:
    import YaToolsPy32 as ya

try:
    import idaapi

    IDA_RUNNING = True
except:
    IDA_RUNNING = False

logger = logging.getLogger("YaCo")

REPO_AUTO_SYNC = True

DEBUG_REPO = False

REPO_AUTO_PUSH = True

MAX_GIT_COMMAND_FILE_COUNT = 50

RUN_IDA_SCRIPT_FILENAME = "run-ida.run"

IDA_IS_INTERACTIVE = True

COMMIT_RETRIES = 3


def try_and_debug(f):
    def inner(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as exc:
            logger.error("an error occured during %s call, error: %s" % (f.__name__, exc))
            traceback.print_exc()
            raise exc

    return inner


class PythonGuiPromptMergeConflict(ya.PromptMergeConflict):
    def __init__(self):
        ya.PromptMergeConflict.__init__(self)

    @try_and_debug
    def merge_attributes_callback(self, message_info, input_attribute1, input_attribute2):
        message = "%s\n" % message_info
        message += "Value from local : %s\n" % input_attribute1
        message += "Value from remote : %s\n" % input_attribute2
        output_attribute_result = idaapi.asktext(4096, input_attribute1, message)
        if output_attribute_result is None:
            output_attribute_result = ""
        return output_attribute_result
        if output_attribute_result is None:
            return ya.PROMPT_MERGE_CONFLICT_UNSOLVED
        return ya.PROMPT_MERGE_CONFLICT_SOLVED


def print_args_file(f):
    def inner(*args, **kwargs):
        for input in args:
            if type(input) in [str]:
                logger.debug("input: %r" % input)
                if os.path.exists(input) and os.path.isfile(input):
                    with open(input, "r") as finput:
                        logger.debug("%s content:" % input)
                        for line in finput.readlines():
                            logger.debug("[###]%r" % line)
        return f(*args, **kwargs)

    return inner


class PythonResolveFileConflictCallback(ya.ResolveFileConflictCallback):
    def __init__(self):
        ya.ResolveFileConflictCallback.__init__(self)
        pass

    @try_and_debug
    def callback(self, input_file1, input_file2, output_file_result):
        logger.debug("PythonResolveFileConflictCallback.callback(%s, %s, %s)" %
                     (input_file1, input_file2, output_file_result))
        if not output_file_result.endswith(".xml"):
            return True

        merger_conflict = PythonGuiPromptMergeConflict()
        merger = ya.Merger(merger_conflict, ya.OBJECT_VERSION_MERGE_PROMPT)
        merge_flag = merger.smartMerge(input_file1, input_file2, output_file_result)

        if merge_flag == ya.OBJECT_MERGE_STATUS_NOT_UPDATED:
            logger.error("PythonResolveFileConflictCallback: callback: object version was not updated")
            with open(output_file_result, 'r') as foutput:
                input_content = foutput.read()
                while True:
                    if len(input_content) >= 65536:
                        idc.Warning(
                            "[File too big to be edited, please edit manually %s then continue]" % output_file_result)
                        merged_content = open(output_file_result, 'r').read()
                    else:
                        merged_content = idaapi.asktext(len(input_content) * 2, input_content, "manual merge stuff")

                    if merged_content not in [None, ""]:
                        try:
                            xml.dom.minidom.parseString(merged_content)
                        except:
                            logger.warning("invalid xml content")
                            logger.warning(traceback.format_exc())
                            idc.Warning("invalid xml content")

                            # loop again in while
                            continue

                        with open(output_file_result, 'w') as foutput_:
                            foutput_.write(merged_content)

                        # Everything worked : stop endless while
                        break

                    else:
                        return False

        # endif merge_flag == OBJECT_MERGE_STATUS_NOT_UPDATED:

        try:
            xml.dom.minidom.parse(output_file_result)
        except:
            logger.error("invalid xml output generate by PythonResolveFileConflictCallback")
            idaapi.msg("invalid xml output generate by PythonResolveFileConflictCallback")
            return False
        return True


class YaToolRepoManager(object):
    '''
    classdocs
    '''

    def __init__(self, idb_path, ask_for_remote=True):
        '''
        Constructor
        '''
        self.native = ya.MakeRepoManager(IDA_IS_INTERACTIVE)

        self.idb_filename = os.path.basename(idb_path)
        self.idb_directory = os.path.dirname(idb_path)

        if not self.repo_exists():
            logger.warning("No repo found ! Creating repo.")
            self.repo_init(ask_for_remote)
            logger.warning('Creation done.')
        else:
            self.repo_open()
        logger.debug('Opening repo.')

        self.repo_auto_sync = REPO_AUTO_SYNC

    def ask_to_checkout_modified_files(self):
        self.repo_auto_sync = self.native.ask_to_checkout_modified_files(self.repo_auto_sync)

    def ensure_git_globals(self):
        self.native.ensure_git_globals()

    def add_auto_comment(self, ea, text):
        self.native.add_auto_comment(ea, text)

    # ==================================================================#
    # Repo
    # ==================================================================#
    def repo_exists(self):
        return self.native.repo_exists()

    def repo_init(self, ask_for_remote=True):
        self.native.repo_init(self.idb_filename, ask_for_remote)

    def repo_open(self, path="."):
        self.native.repo_open()

    def repo_get_cache_files_status(self):
        return self.native.repo_get_cache_files_status()

    def get_master_commit(self):
        return self.native.get_master_commit()

    def get_origin_master_commit(self):
        return self.native.get_origin_master_commit()

    def fetch_origin(self):
        self.native.fetch_origin()

    def fetch(self, origin):
        self.native.fetch(origin)

    def rebase_from_origin(self):
        cb = PythonResolveFileConflictCallback()
        self.native.get_repo().rebase("origin/master", "master", cb)
        return

    def rebase(self, origin, branch):
        cb = PythonResolveFileConflictCallback()
        self.native.get_repo().rebase(origin, branch, cb)
        return

    def push_origin_master(self):
        self.native.push_origin_master()

    def checkout_master(self):
        self.native.checkout_master()

    def check_valid_cache_startup(self):
        logger.debug("check_valid_cache_startup")
        if "origin" not in self.native.get_repo().get_remotes():
            logger.debug("WARNING origin not defined : ignoring origin and master sync check !")
        else:
            if self.native.get_repo().get_commit("origin/master") != self.native.get_repo().get_commit("master"):
                message = "Master and origin/master doesn't point to the same commit, please update your master."
                logger.debug(message)

        if IDA_RUNNING is True:
            try:
                os.mkdir("cache/")
            except OSError:
                pass
            idbname = os.path.basename(idc.GetIdbPath())
            idbname_prefix = os.path.splitext(idbname)[0]
            idbname_extension = os.path.splitext(idbname)[1]
            if not idbname_prefix.endswith('_local'):
                local_idb_name = "%s_local%s" % (idbname_prefix, idbname_extension)
                if not os.path.exists(local_idb_name):
                    yatools.copy_idb_to_local_file()
                if IDA_IS_INTERACTIVE:
                    message = "To use YaCo you must name your IDB with _local suffix. "
                    message += "YaCo will create one for you.\nRestart IDA and open %s." % local_idb_name
                    logger.debug(message)
                    idaapi.set_database_flag(idaapi.DBFL_KILL)
                    idc.Warning(message)
                    idc.Exit(0)

    def update_cache(self):
        logger.info("updating cache")
        if "origin" not in self.native.get_repo().get_remotes():
            return ([], [], [], [])

        try:

            # check if files has been modified in background
            self.ask_to_checkout_modified_files()

            if self.repo_auto_sync:

                for _ in range(COMMIT_RETRIES):
                    # get master commit
                    master_commit = self.get_master_commit()
                    logger.debug("Current master: %s" % master_commit)

                    # fetch remote
                    self.fetch_origin()
                    logger.debug("Fetched origin/master: %s" % self.get_origin_master_commit())

                    # rebase in master
                    try:
                        self.rebase_from_origin()
                        logger.debug("[update_cache] rebase_from_origin done")
                    except Exception as e:
                        logger.debug("[update_cache] rebase_from_origin failed")
                        # disable auto sync (when closing database)
                        message = "You have errors during rebase. You have to resolve it manually.\n"
                        message += "See git_rebase.log for details.\n"
                        message += "Then run save on IDA to complete rebase and update master"
                        logger.debug(message)
                        logger.debug("%s" % e)
                        idc.Warning(message)
                        idc.Warning("%s" % e)
                        traceback.print_exc()
                        return ([], [], [], [])

                    # get modified files from origin
                    modified_files = self.native.get_repo().get_modified_objects(master_commit)
                    deleted_files = self.native.get_repo().get_deleted_objects(master_commit)
                    new_files = self.native.get_repo().get_new_objects(master_commit)
                    for f in new_files:
                        logger.info("added    %s" % os.path.relpath(f, "cache"))
                    for f in modified_files:
                        logger.info("modified %s" % os.path.relpath(f, "cache"))
                    for f in deleted_files:
                        logger.info("deleted  %s" % os.path.relpath(f, "cache"))

                    modified_files = set(new_files).union(modified_files)

                    # if all done, we can push to origin
                    if self.repo_auto_sync:
                        try:
                            self.native.get_repo().push("master", "master")
                            logger.debug("[update_cache] push done")
                            logger.debug("Your cache was successfully sent to origin master.")
                            break
                        except Exception as e:
                            logger.debug("[update_cache] push failed")
                            # disable auto sync (when closing database)
                            self.repo_auto_sync = False
                            message = "You have errors during push to origin. You have to resolve it manually."
                            logger.debug(message)
                            logger.debug("%s" % e)
                            # idc.Warning(message)
                            # idc.Warning("%s" % e)
                            traceback.print_exc()
                            continue
                            # return ([], [], [], [])
                else:
                    message = "You have errors during push to origin. You have to resolve it manually."
                    logger.debug(message)
                    idc.Warning(message)
                    return ([], [], [], [])

                modified_objects_id = set()
                deleted_objects_id = set()

                for modified_file in modified_files:
                    modified_objects_id.add(modified_file.split(".xml")[0].split("/")[-1])

                for deleted_file in deleted_files:
                    deleted_objects_id.add(deleted_file.split(".xml")[0].split("/")[-1])

                if DEBUG_REPO:
                    logger.debug("modified object :")
                    logger.debug(modified_objects_id)

                    logger.debug("deleted object :")
                    logger.debug(deleted_objects_id)

                return (modified_objects_id, deleted_objects_id, modified_files, deleted_files)
        except Exception as e:
            message = "An error happened with git. Check error log."
            logger.debug(message)
            logger.debug("%s" % e)
            idc.Warning(message)
            idc.Warning("%s" % e)
            traceback.print_exc()

        return ([], [], [], [])

    def repo_commit(self, commit_msg=None):
        if commit_msg == None:
            commit_msg = ""
        return self.native.repo_commit(commit_msg)
