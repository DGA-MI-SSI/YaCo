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
        self.native.update_cache()

    def repo_commit(self, commit_msg=None):
        if commit_msg == None:
            commit_msg = ""
        return self.native.repo_commit(commit_msg)
