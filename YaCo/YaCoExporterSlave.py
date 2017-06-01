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

import os
import sys

sys.path.append(os.path.abspath("%s/../../deps/" % __file__))

import binascii
import idc
import idaapi
import logging
import traceback

if idc.__EA64__:
    import YaToolsPy64 as ya
else:
    import YaToolsPy32 as ya

from pympler import muppy
from ImportExport.YaToolIDATools import get_mem_usage
from multiprocessing.connection import Client
from ImportExport.YaToolIDAModel import YaToolIDAModel

logger = logging.getLogger("YaCo")

DATABASE_PATH = os.path.join(os.path.join(".", ".."), "database")

logger.info("Computing port with %s" % os.path.abspath(DATABASE_PATH))
IPC_PORT = (binascii.crc32(os.path.abspath(DATABASE_PATH)) % (65536 - 2000)) + 2000
IPC_ADDRESS = ('localhost', IPC_PORT)
MAX_SLAVE_MEMORY_USAGE_MB = 1800
MAX_IDAMEMBER_T_COUNT = 30000


def slave_handler(task_id, f_eas_to_export, yatools, hash_provider):
    m = YaToolIDAModel(yatools, hash_provider)
    m.set_slave_skip(True)
    # v = MakeFileXmlExporter("database/database_%08i.xml" % (task_id))
    v = ya.MakeFlatBufferExporter()
    logger.info("Computing port with %s" % os.path.abspath(DATABASE_PATH))
    logger.info("slave connecting to  %r" % (IPC_ADDRESS,))
    client = Client(IPC_ADDRESS)
    client.send("READY")

    v.visit_start()

    try:
        loop_count = 0
        data = client.recv()
        while data != "FINISHED":
            job_name = data
            if job_name == "ACCEPT_SEGMENT":
                (parent_id, seg_ea_start, seg_ea_end) = client.recv()
                logger.info("Received ACCEPT_SEGMENT job : parent:%X 0x%08X->0x%08X:%s" %
                            (parent_id, seg_ea_start, seg_ea_end, idc.SegName(seg_ea_start)))
                m.set_skip_accept_segment(False)
                m.accept_segment(v, parent_id, seg_ea_start, seg_ea_end)
                m.set_skip_accept_segment(True)
            elif job_name == "ACCEPT_SEGMENT_CHUNK":
                (seg_ea_start, seg_ea_end, chunk_start, chunk_end) = client.recv()
                logger.info("Received ACCEPT_SEGMENT_CHUNK job : 0x%08X->0x%08X in seg 0x%08X->0x%08X:%s" %
                            (chunk_start, chunk_end, seg_ea_start, seg_ea_end, idc.SegName(seg_ea_start)))
                m.set_skip_accept_segment(False)
                m.accept_segment_chunk(
                    v, chunk_start, chunk_end, seg_start=seg_ea_start, seg_end=seg_ea_end, export_eas=True)
                m.set_skip_accept_segment(True)
            elif job_name != "NOP":
                logger.error("Received bad job : %r" % job_name)
            loop_count += 1

            mem = get_mem_usage()
            out_of_memory = False
            if mem > MAX_SLAVE_MEMORY_USAGE_MB:
                logger.warning("Using %d Mb : limit reached" % mem)
                out_of_memory = True
            elif mem == 0 and loop_count % 4 == 3:
                objs = muppy.get_objects()
                obj_count = 0
                for o in objs:
                    if isinstance(o, idaapi.member_t):
                        obj_count += 1
                out_of_memory = obj_count > MAX_IDAMEMBER_T_COUNT

            if out_of_memory:
                client.send("OUTOFMEMORY")
            else:
                logger.warning("Memory limit not reached")
                client.send("READY")
            data = client.recv()
    except EOFError:
        logger.warning("Received EOF")
        traceback.print_exc()

    v.visit_end()
    with open(os.path.join(DATABASE_PATH, "database_%08i.yadb" % task_id), 'wb') as fh:
        fh.write(v.GetBuffer())
