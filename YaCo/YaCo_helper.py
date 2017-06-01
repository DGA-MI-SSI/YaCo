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

import argparse
import os
import shutil
import time

from ImportExport.YaToolRepoManager import YaToolRepoManager


def rescue():
    # commit if indexed files (in case of crash)
    repo_manager.repo.index.commit("rescue update")

    # get update
    repo_manager.fetch_origin()

    # apply master
    repo_manager.rebase_from_origin()

    # push changes to origin
    repo_manager.push_local_to_origin_master()

    sync_both_branches()


def sync_both_branches():
    # sync master
    repo_manager.pull_origin_master()

    # sync local
    repo_manager.pull_origin_local()


def init():
    idb_local = IDB_LOCAL % idb_path_wo_extension

    print("Copying %s to %s..." % (idb_path, idb_local))
    shutil.copyfile(idb_path, idb_local)
    print("Done.")


def cancel():
    # backuping IDB

    idb_local = IDB_LOCAL % idb_path_wo_extension

    shutil.copyfile(idb_local, idb_path)

    repo_manager.cancel()

    init()


def reset_cache():
    idb_local = IDB_LOCAL % idb_path_wo_extension
    idb_backup = IDB_BACKUP % idb_path_wo_extension

    # backup IDB in case of failure
    shutil.copyfile(idb_local, idb_backup)

    # replace original idb
    shutil.copyfile(idb_local, idb_path)

    # add original idb to index
    repo_manager.repo.index.add([idb_path])

    # remove cache directory of repo
    repo_manager.repo.index.remove(["cache"], r=True)

    # commit
    repo_manager.repo.index.commit("reset cache")

    # push to origin
    repo_manager.push_local_to_origin_master()

    # sync all branchs
    repo_manager.pull_origin_master()

    repo_manager.pull_origin_local()

    init()

if __name__ == "__main__":

    IDB_LOCAL = "%s_local.idb"
    IDB_BACKUP = "%s_local_" + time.strftime("%Y_%m_%d_%Hh%M") + ".idb"

    parser = argparse.ArgumentParser()
    sub_parser = parser.add_subparsers(title="actions")

    rescue_parser = sub_parser.add_parser("rescue", help='Try to rescue your repo.')
    rescue_parser.set_defaults(execute=rescue)
    rescue_parser.set_defaults(command="rescue")
    rescue_parser.add_argument('idb_path', nargs=1, help='Path to the IDB')

    sync_parser = sub_parser.add_parser("sync", help='Sync local and master branches from origin master')
    sync_parser.set_defaults(execute=sync_both_branches)
    sync_parser.set_defaults(command="sync")
    sync_parser.add_argument('idb_path', nargs=1, help='Path to the IDB')

    cancel_parser = sub_parser.add_parser("cancel", help='HARD Reset your repo to origin/master')
    cancel_parser.set_defaults(execute=cancel)
    cancel_parser.set_defaults(command="cancel")
    cancel_parser.add_argument('idb_path', nargs=1, help='Path to the IDB')

    reset_cache_parser = sub_parser.add_parser(
        "reset_cache", help='Reset cache of your repo. Remove cache directory and push all to origin master')
    reset_cache_parser.set_defaults(execute=reset_cache)
    reset_cache_parser.set_defaults(command="reset_cache")
    reset_cache_parser.add_argument('idb_path', nargs=1, help='Path to the IDB')

    idkwid_parser = sub_parser.add_parser("i_dont_know_what_i_do", help='Same as reset.')
    idkwid_parser.set_defaults(execute=cancel)
    idkwid_parser.set_defaults(command="cancel")
    idkwid_parser.add_argument('idb_path', nargs=1, help='Path to the IDB')

    init_parser = sub_parser.add_parser("init", help='copy local to ... .')
    init_parser.set_defaults(execute=init)
    init_parser.set_defaults(command="init")
    init_parser.add_argument('idb_path', nargs=1, help='Path to the IDB')

    args = parser.parse_args()

    idb_path = args.idb_path.pop()
    idb_path_wo_extension = idb_path.split(".idb")[0]
    idb_local = IDB_LOCAL % idb_path_wo_extension

    repo_path = os.path.dirname(idb_path)

    repo_manager = YaToolRepoManager(None, repo_path)

    # open repo
    repo_manager.repo_open(repo_path)
    args.execute()
    print "%s successfull." % args.command
