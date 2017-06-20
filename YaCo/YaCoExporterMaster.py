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

import binascii
import exec_ida
import idc
import idaapi
import inspect
import logging
import multiprocessing
import os
import select
import shutil
import subprocess
import sys
import YaCoUtils
import stat

from multiprocessing.connection import Listener
from ImportExport.YaToolIDAModel import YaToolIDAModel
from ImportExport.YaToolIDATools import segment_get_chunks, get_local_idb_name, remove_ida_temporary_files, \
    copy_idb_to_local_file

logger = logging.getLogger("YaCo")
debug = False

"""
MAX_SLAVE_MEMORY_USAGE_MB = 1800
MAX_IDAMEMBER_T_COUNT = 30000
"""
MIN_EA_PER_JOB = 1024

COPY_WITH_HARDLINKS = False


def get_num_cpu():
    try:
        return int(os.environ['YACO_CPU'])
    except:
        return multiprocessing.cpu_count()


class MasterEaExport():
    JOB_TASK_FACTOR = 32

    def __init__(self, yatools, hash_provider, export_dir, bin_dir, ipc_address, num_cpu, disable_plugin):
        self.task_count = num_cpu if num_cpu else get_num_cpu()
        logger.info("using %d cpu(s)" % self.task_count)
        self.min_ea_count = 100
        self.ea_list = None
        self.segment_id = 0
        self.connections = {}
        self.connection_fds = {}
        self.next_worker_id = 0
        self.yatools = yatools
        self.hash_provider = hash_provider
        self.export_dir = export_dir
        self.bin_dir = bin_dir
        self.ipc_address = ipc_address
        self.disable_plugin = disable_plugin
        pass

    def launch_worker(self, create_idb=True, recycle_idb_from_id=None):
        worker_id = self.next_worker_id
        self.next_worker_id += 1
        idb_filename_for_export = get_local_idb_name(idc.GetIdbPath(),
                                                     "_cache_export_%08i" % worker_id,
                                                     self.export_dir)

        if create_idb:
            self.create_idb_for_worker(worker_id, recycle_idb_from_id)
        logger.debug("Running job %i." % worker_id)

        idaq = sys.executable
        if sys.platform == "linux2":
            idaq = "idaq"
            if idc.GetIdbPath().endswith(idaapi.IDB_EXT64):
                idaq = "idaq64"
            idaq_path = os.path.abspath(os.path.join(os.path.dirname(inspect.getsourcefile(idaapi)), '..'))
            idaq = os.path.join(idaq_path, idaq)
        ida_args = []
        if self.disable_plugin:
            ida_args += ["-Oyaco:disable_plugin"]
        if not debug:
            ida_args += ["-A"]
        cmd = exec_ida.Exec(idaq, os.path.abspath(idb_filename_for_export), *ida_args)
        cmd.set_idle(True)
        script = os.path.abspath(os.path.join(__file__, "..", "export_all.py"))
        cmd.with_script(script, "--slave", self.bin_dir)
        logger.info(str(cmd))
        cmd.start()

        process_conn = self.listener.accept()
        self.connection_fds[worker_id] = process_conn.fileno()
        self.connections[process_conn.fileno()] = (worker_id, process_conn, cmd)

    def relaunch_worker(self, worker_id):
        self.close_worker(worker_id, join=True)
        self.launch_worker(recycle_idb_from_id=worker_id)

    def create_idb_for_worker(self, worker_id, recycle_idb_from_id=None):
        if recycle_idb_from_id is not None:
            idb_filename_for_export_old = get_local_idb_name(
                idc.GetIdbPath(), "_cache_export_%08i" % (recycle_idb_from_id), self.export_dir)
            if os.path.exists(idb_filename_for_export_old):
                idb_filename_for_export_new = get_local_idb_name(
                    idc.GetIdbPath(), "_cache_export_%08i" % (worker_id), self.export_dir)
                if os.path.exists(idb_filename_for_export_new):
                    os.remove(idb_filename_for_export_new)
                os.rename(idb_filename_for_export_old, idb_filename_for_export_new)
                remove_ida_temporary_files(idb_filename_for_export_new)
            else:
                copy_idb_to_local_file("_cache_export_%08i" % (worker_id), self.export_dir)
        else:
            # copy current idb to temp idb for export
            # check if file already exists
            idb_filename_for_export = get_local_idb_name(
                idc.GetIdbPath(), "_cache_export_%08i" % (worker_id), self.export_dir)

            if os.path.exists(idb_filename_for_export):
                os.remove(idb_filename_for_export)

            logger.debug("Copying IDB file %s" % idb_filename_for_export)
            idb_filename_for_export = copy_idb_to_local_file("_cache_export_%08i" % (worker_id), self.export_dir,
                                                             use_hardlink=(
                                                                 COPY_WITH_HARDLINKS and sys.platform == "linux2"))

    def launch_workers(self):
        logger.info("Master starting to listen on %r" % (self.ipc_address,))
        self.listener = Listener(self.ipc_address)
        # listener_fd = self.listener._listener._socket.fileno()

        # copying all IDBs
        for worker_id in xrange(0, self.task_count):
            self.create_idb_for_worker(worker_id)

        for worker_id in xrange(0, self.task_count):
            self.launch_worker(create_idb=False)

    def try_recv(self, id, conn, proc):
        try:
            return conn.recv()
        except:
            err = proc.join()
            if err:
                print(err)
            raise

    def post_job(self, job_name, job):
        logger.debug("Job submitted, name=%s, len=%d, looking for worker" % (job_name, len(job)))
        sent = False
        while not sent and len(self.connection_fds) > 0:
            select_read = list(self.connection_fds.itervalues())
            readable, writable, in_error = select.select(select_read, [], [])

            if len(in_error) > 0:
                logger.error("error worker : %r" % in_error)
                for fd in in_error:
                    range_id, process_conn, = self.connections[fd]
                    logger.error("worker id : %d" % (range_id))

            while not sent and len(readable) > 0:
                range_id, process_conn, export_runner = self.connections[readable[0]]
                data = self.try_recv(range_id, process_conn, export_runner)
                if data == "READY":
                    logger.debug("worker %d READY, sending job" % range_id)
                    process_conn.send(job_name)
                    process_conn.send(job)
                    sent = True
                elif data == "OUTOFMEMORY":
                    logger.warning("Worker %d got OUTOFMEMORY : relaunching it" % range_id)
                    self.relaunch_worker(range_id)
                else:
                    logger.error("Worker %d NOT READY : received '%r'" % (range_id, data))

                del readable[0]

            if not sent:
                logger.warning("No readable connection : retrying")

        if sent:
            logger.debug("Job sent successfuly")
        else:
            logger.error("Job not sent : no readable connection")

    def join_workers(self, close_workers=False):
        logger.debug("Joining Workers (closing=%s)" % str(close_workers))
        for (fd, (range_id, process_conn, export_runner)) in self.connections.iteritems():
            logger.debug("joining on worker %d" % range_id)
            data = self.try_recv(range_id, process_conn, export_runner)
            if data == "READY":
                if close_workers:
                    logger.debug("Worker %d finished, joining" % range_id)
                    process_conn.send("FINISHED")
                    export_runner.join()
                else:
                    logger.debug("Worker %d finished : good job!" % range_id)
                    process_conn.send("NOP")
            else:
                logger.error("Worker %d sent an error : %r" % (range_id, data))
        logger.debug("Done, all workers terminated")

    def close_worker(self, worker_id, fd=None, join=True):
        if fd is None:
            fd = self.connection_fds[worker_id]
        (range_id, process_conn, export_runner) = self.connections[fd]
        process_conn.send("FINISHED")

        if join:
            logger.debug("Joining worker %d" % range_id)
            export_runner.join()
            logger.debug("Joined worker %d" % range_id)
        else:
            logger.debug("Finished worker %d" % range_id)

        try:
            del self.connection_fds[worker_id]
        except:
            pass

        try:
            del self.connections[fd]
        except:
            pass

    def close_workers(self, join=True):
        while len(self.connection_fds) > 0:
            (worker_id, fd) = self.connection_fds.popitem()
            self.close_worker(worker_id, fd=fd, join=join)

    def accept_segment(self, parent_id, seg_ea_start, seg_ea_end, export_chunks=True):
        self.post_job("ACCEPT_SEGMENT", (parent_id, seg_ea_start, seg_ea_end))
        if export_chunks:
            for (chunk_start, chunk_end) in segment_get_chunks(seg_ea_start, seg_ea_end):
                self.post_job("ACCEPT_SEGMENT_CHUNK", (seg_ea_start, seg_ea_end, chunk_start, chunk_end))

    def join(self):
        self.join_workers(close_workers=False)


def run_cmd(args):
    try:
        args = '"' + '" "'.join(args) + '"'
        subprocess.check_output(args, shell=True)
    except subprocess.CalledProcessError as e:
        logger.error('command line was %s' % args)
        logger.error('code %d output %s' % (e.returncode, e.output))
    except BaseException as e:
        logger.error('command line was %s' % args)
        logger.error('exception %s' % e)
    return 0


def merge_yadbs_to_yadb(bin_dir, output, inputs):
    app = os.path.join(bin_dir, 'yadbdbmerger')
    run_cmd([app, output] + inputs)


def rmtree(dirname):
    def del_rw(action, name, exc):
        os.chmod(name, stat.S_IWRITE)
        os.remove(name)

    shutil.rmtree(dirname, onerror=del_rw)


def master_handler(yatools, hash_provider, db_dir=".", export_dir=".", num_cpu=None, bin_dir=None,
                   disable_plugin=False):
    if not bin_dir:
        bin_dir = os.path.abspath(os.path.join(__file__, '..', '..', 'bin'))
    logger.info("Computing port with %s" % os.path.abspath(db_dir))
    ipc_port = (binascii.crc32(os.path.abspath(db_dir)) % (65536 - 2000)) + 2000
    ipc_address = ('localhost', ipc_port)
    try:
        shutil.rmtree(db_dir)
    except:
        pass
    try:
        os.mkdir(db_dir)
    except OSError:
        pass

    master = MasterEaExport(yatools, hash_provider, export_dir, bin_dir, ipc_address, num_cpu, disable_plugin)
    master.launch_workers()

    m = YaToolIDAModel(yatools, hash_provider)
    m.set_ea_exporter(master)
    m.set_descending_mode(True)
    exporter = ya.MakeFlatBufferExporter()
    m.accept(exporter)
    with open(os.path.join(db_dir, "database_master.yadb"), "wb") as fh:
        fh.write(exporter.GetBuffer())

    master.close_workers(True)
    yadbs = [os.path.join(db_dir, "database_master.yadb")]
    for range_id in xrange(0, master.next_worker_id):
        yadbs.append(os.path.join(db_dir, "database_%08i.yadb") % range_id)
    merge_yadbs_to_yadb(bin_dir, os.path.join(db_dir, "database.yadb"), yadbs)

    if not debug:
        logger.debug("cleaning up")
        for yadb in yadbs:
            os.remove(yadb)
        rmtree(export_dir)
    logger.info("done")
    return
