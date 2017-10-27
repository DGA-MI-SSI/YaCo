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

DEBUG_REPO = False

REPO_AUTO_PUSH = True

MAX_GIT_COMMAND_FILE_COUNT = 50

RUN_IDA_SCRIPT_FILENAME = "run-ida.run"

IDA_IS_INTERACTIVE = True

COMMIT_RETRIES = 3


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

    def ask_to_checkout_modified_files(self):
        self.native.ask_to_checkout_modified_files()

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
        self.native.rebase_from_origin()

    def rebase(self, origin, branch):
        self.native.rebase_from_origin(origin, branch)

    def push_origin_master(self):
        self.native.push_origin_master()

    def checkout_master(self):
        self.native.checkout_master()

    def check_valid_cache_startup(self):
        self.native.check_valid_cache_startup()

    def update_cache(self):
        logger.info("updating cache")
        if "origin" not in self.native.get_repo().get_remotes():
            return ([], [], [], [])

        try:

            # check if files has been modified in background
            self.ask_to_checkout_modified_files()

            if self.native.get_repo_auto_sync():

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
                    if self.native.get_repo_auto_sync():
                        try:
                            self.native.get_repo().push("master", "master")
                            logger.debug("[update_cache] push done")
                            logger.debug("Your cache was successfully sent to origin master.")
                            break
                        except Exception as e:
                            logger.debug("[update_cache] push failed")
                            # disable auto sync (when closing database)
                            self.native.set_repo_auto_sync(False)
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
