#!/usr/bin/env python2.7
# we want to use python from ida

import argparse
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
import shutil
import traceback
import collections
from os import unlink
from multiprocessing import Queue

IDLE_PRIORITY_CLASS = 0x00000040

class Ctx:
    def __init__(self):
        self.files_to_delete = []
        self.folders_to_delete = []

def get_binary_name(ctx, name):
    if sys.platform in ["linux", "linux2"]:
        return name
    elif sys.platform == "win32":
        return name + ".exe"
    else:
        fail(ctx, "unknown platform %s" % sys.platform)

def run_ida(ctx, ida_database, script, interactive = False, clear_minidump = True, *args):
    if clear_minidump and ctx.minidump_dir is not None:
        print("Clearing minidump")
        shutil.rmtree(ctx.minidump_dir, True)
    flags = 0
    ida_exec = ctx.idaq
    if ida_database.endswith(".i64"):
        ida_exec = ctx.idaq64
    if sys.platform == "win32":
        flags = IDLE_PRIORITY_CLASS

    logfile = os.path.join(os.path.dirname(ida_database), '%s.log' % uuid.uuid4())
    ctx.files_to_delete.append(logfile)

    # there can never be enough quotes
    cmd = '-S"\\\"' + script + '\\\" \\\"' + '\\\" \\\"'.join(args) + '\\\""'
    args = ['"' + ida_exec + '"', '-L"' + logfile + '"', cmd, '"' + ida_database + '"']

    # non-interactive mode
    if not interactive:
        args.insert(1, '-A')

    logging.info("running %s" % " ".join(args))
    try:
        return subprocess.check_output(" ".join(args), creationflags=flags, shell=True)
    except subprocess.CalledProcessError as exp:
        with open(logfile, 'rb') as fh:
            print(fh.read().strip())
        print(exp.output)
        raise

def create_idb(ctx, binary_path, interactive=False):
    flags = 0
    ida_exec = ctx.idaq64
    if sys.platform == "win32":
        flags = IDLE_PRIORITY_CLASS

    logfile = os.path.join(os.path.dirname(binary_path), '%s.log' % uuid.uuid4())
    ctx.files_to_delete.append(logfile)

    # there can never be enough quotes
    args = ['"' + ida_exec + '"', '-L"' + logfile + '"', '-B', '"' + binary_path + '"']

    # non-interactive mode
    if not interactive:
        args.insert(1, '-A')

    if ctx.minidump_dir is not None:
        print("Clearing minidump")
        shutil.rmtree(ctx.minidump_dir, True)
        
    logging.info("running %s" % " ".join(args))
    try:
        subprocess.check_output(" ".join(args), creationflags=flags, shell=True)
    except subprocess.CalledProcessError as exp:
        with open(logfile, 'rb') as fh:
            print(fh.read().strip())
        print(exp.output)
        raise
    

def export_database(ctx, ida_database, interactive = False):
    database_dir = os.path.dirname(os.path.abspath(ida_database))
    yadb_path = os.path.join(database_dir, "database", "database.yadb")
    if os.path.isfile(yadb_path):
        logging.info("cache for %s is already exported." % ida_database)
        return yadb_path

    logging.info("exporting %s" % ida_database)
    script = os.path.join(ctx.yatools_dir, "YaCo", "export_all.py")
    run_ida(ctx, ida_database, script, interactive, True, os.path.join(ctx.yatools_dir, "bin"))
    if not os.path.isfile(yadb_path):
        fail(ctx, "unable to export to %s" % yadb_path)
    return yadb_path

def try_rmtree(d):
    try:
        shutil.rmtree(d)
    except:
        pass

def cleanup(ctx):
    for f in ctx.files_to_delete:
        os.unlink(f)
    for d in ctx.folders_to_delete:
        try_rmtree(d)
        try_rmtree(d)

def parse_options():
    parser = argparse.ArgumentParser(description="BinToYafb")

    parser.add_argument("binary_from",
        type = str,
        help = "IDA database file",
    )

    parser.add_argument("yafb_to",
        type = str,
        help = "Yafb directory",
    )

    parser.add_argument("vect_to",
        type = str,
        help = "vect directory",
    )

    parser.add_argument("--keepidb",
        action = "store_true",
        help = "Don't delete IDB file",
        default = False,
    )

    parser.add_argument("--createvectors",
        action = "store_true",
        help = "Don't delete IDB file",
        default = False,
    )

    parser.add_argument("--tmpdir",
        type = str, 
        help = "file where to store temporary files",
    )

    parser.add_argument("--maxsize",
        type = int, 
        help = "ignore binary files greater thant maxsize (in MB)",
    )

    parser.add_argument("--delete_failed_fb",
        action = "store_true", 
        help = "ignore binary files greater thant maxsize (in MB)",
        default = False,
    )

    parser.add_argument("--nosingle",
        action = "store_true", 
        help = "Under the hypothesis that names are on the form <hash_md5>--<binary_name>, don't convert files whose name appear only once",
        default = False,
    )

    parser.add_argument("--compressvector",
        action = "store_true", 
        help = "Compress the vector file using the LZMA (xz) algorithm",
        default = False,
    )

    parser.add_argument("-d", "--debug",
        action = "store_true",
        help = "Debug",
    )

    return parser.parse_args()

def fail(ctx, *args):
    logging.error(*args)
    sys.exit(-1)

def setup_ctx(ctx, options):
    # get ida directory
    if "IDA_DIR" not in os.environ.keys():
        fail(ctx, "missing IDA_DIR environment variable")
    ctx.ida_dir = os.path.abspath(os.environ["IDA_DIR"])
    logging.info("ida_dir = %s" % ctx.ida_dir)
    sys.path.append(os.path.join(ctx.ida_dir, "plugins", "YaTools", "bin"))

    # get idaq binary path
    idaq = os.path.join(ctx.ida_dir, get_binary_name(ctx, "idaq"))
    if os.path.isfile(idaq):
        idaq64 = os.path.join(ctx.ida_dir, get_binary_name(ctx, "idaq64"))
    elif os.path.isfile(os.path.join(ctx.ida_dir, get_binary_name(ctx, "ida"))):
        idaq = os.path.join(ctx.ida_dir, get_binary_name(ctx, "ida"))
        idaq64 = os.path.join(ctx.ida_dir, get_binary_name(ctx, "ida64"))
        if not os.path.isfile(idaq):
            fail(ctx, "%s is not a file" % idaq)
    logging.info("idaq = %s" % idaq)
    logging.info("idaq64 = %s" % idaq64)
    
    ctx.idaq = idaq
    ctx.idaq64 = idaq64
    
    if os.path.exists("/tmp"):
        ctx.minidump_dir = "/tmp/ida"
    else:
        ctx.minidump_dir = None

    # get yatools dir
    yatools_dir = os.path.join(ctx.ida_dir, "plugins", "YaTools")
    if "YATOOLS_DIR" in os.environ.keys():
        yatools_dir = os.path.abspath(os.environ["YATOOLS_DIR"])
    load_yadb = os.path.join(yatools_dir, "YaCo", "load_yadb.py")
    if not os.path.isfile(load_yadb):
        fail(ctx, "%s is not a file" % load_yadb)
    ctx.yatools_dir = yatools_dir
    logging.info("yatools_dir = %s" % yatools_dir)
    
    if options.createvectors:
        # get yadbtovector binary path
        yadbtovector = get_binary_name(ctx, os.path.join(ctx.yatools_dir, "bin", "yadbtovector"))
        if "YADBTOVECTOR_PATH" in os.environ.keys():
            yadbtovector = os.path.abspath(os.environ["YADBTOVECTOR_PATH"])
        if not os.path.isfile(yadbtovector):
            fail(ctx, "%s is not a file" % yadbtovector)
        ctx.yadbtovector = yadbtovector
        logging.info("yadiff = %s" % yadbtovector)

def convert_bin_to_yafb(ctx, options, binary_file_path, yafb):
    (dir_name, file_name) = os.path.split(binary_file_path)
    file_name_stripped = os.path.splitext(file_name)[0]
    
    if os.path.exists(yafb):
        print("Skipping file %s : already created" % binary_file_path)
        return yafb
    
    if options.tmpdir:
        tmpdir = tempfile.mkdtemp(dir=options.tmpdir)
    else:
        tmpdir = tempfile.mkdtemp()
    
    
    tmpfile = os.path.join(tmpdir, file_name)
    
    try:
        shutil.copy(binary_file_path, tmpfile)
        binary_file_path = tmpfile
        
        print("Converting file %s" % binary_file_path)
        idb = os.path.join(tmpdir, file_name + ".i64")
        create_idb(ctx, binary_file_path)
        yadb1 = export_database(ctx, idb)
        
        yadb_name = os.path.basename(yadb1)
        shutil.copy(yadb1, yafb)
    except:
        traceback.print_exc()
        yafb = None
    
    if options.keepidb is False:
        #os.unlink(idb)
        shutil.rmtree(tmpdir)
    return yafb

def create_vector_file(ctx, options, yadb, vector_file_path, vect_compress):
    logging.info("creating vector file")
    (dir_name, file_name) = os.path.split(yadb)
    file_name_stripped = os.path.splitext(file_name)[0]
    
    if os.path.exists(vector_file_path):
        print("Skipping vect %s : vector already created" % yadb)
        return vector_file_path
    
    
    if vect_compress is None:
        vect_compress = vector_file_path + ".xz"
        
    if os.path.exists(vect_compress):
        print("Skipping vect %s : XZ vector already created" % vect_compress)
        return vector_file_path
    
    vect_cmd_line = [ctx.yadbtovector, yadb, vector_file_path]
    logging.info("running %s" % " ".join(vect_cmd_line))
    subprocess.Popen(vect_cmd_line, stdout=subprocess.DEVNULL).wait()
    if not os.path.isfile(vector_file_path):
        logging.error("unable to export vectors into %s" % vector_file_path)
        if options.delete_failed_fb:
            logging.error("deleting YADB file : %s" % yadb)
            os.unlink(yadb)
        return None
    return vector_file_path

def compress_vector_file(ctx, vector_file_path, vect_compress=None):
    """ Compress vector files (that have a low entropy) with lzma algo
    """
    import lzma
    from _lzma import PRESET_EXTREME

    if not os.path.exists(vector_file_path):
        return None
    
    if vect_compress is None:
        vect_compress = vector_file_path + ".xz"
    if os.path.exists(vect_compress):
        print("Skipping  compress %s : XZ vector already created" % vect_compress)
        return vect_compress
    
    logging.info("Compressing vectors %s to %s" % (vector_file_path, vect_compress))
    
    failed = False
    try:
        with open(vector_file_path, "rb") as f_in:
            with lzma.open(vect_compress, "wb", preset=(9|PRESET_EXTREME)) as f_out:
                f_out.write(f_in.read())
                unlink(vector_file_path)
    except KeyboardInterrupt as e:
        try:
            unlink(vect_compress)
        except:
            pass
    except:
        traceback.print_exc()
        failed = True
        
    if failed:
        try:
            unlink(vect_compress)
        except:
            pass
        return None
    else:
        return vect_compress
def handle_bin(ctx, options, elf, yafb, vect, vect_compress=None):
    yadb  = convert_bin_to_yafb(ctx, options, elf, yafb)
    if options.createvectors:
        yavec = create_vector_file(ctx, options, yafb, vect, vect_compress)
        if yavec is not None and options.compressvector:
            compress_vector_file(ctx, yavec, vect_compress)

import multiprocessing, threading, queue

def get_single_files(binary_from):
    files_by_name = collections.defaultdict(lambda : set())
    
    for root, dirs, files in os.walk(binary_from):
        for name in files:
            if "--" not in name:
                print("bad name : %s" % name)
            
            #basename = os.path.splitext(name)[0]
            elf  = os.path.join(root, name)
            fhash = name[:name.find("--")]
            fname = name[2+name.find("--"):]
            files_by_name[fname].add(name)
    result = set()
    for (file_name, file_list) in files_by_name.items():
        if len(file_list) == 1:
            result.add(next(iter(file_list)))
    return result
            
def walk_dir_multithreads(ctx, options, elf_path, yafb_path, vect_path, num_worker_threads=1):
    
    def worker(queue):
        while True:
            item = queue.get()
            if item is None:
                print("Stopping thread")
                break
            try:
                (elf, yafb, vect, vect_compressed) = item
                handle_bin(ctx, options, elf, yafb, vect, vect_compressed)
            except KeyboardInterrupt as e:
                raise e
            except:
                print("Unable to convert file %s" % item[0])
                if options.debug:
                    traceback.print_exc()

    q = Queue(maxsize=4)
    threads = []
    for i in range(num_worker_threads):
        t = multiprocessing.Process(target=worker, args=(q,))
        t.start()
        threads.append(t)
    

    if options.nosingle:
        excluded_files = get_single_files(options.binary_from)
    else:
        excluded_files = set()
        

    done = set()
    for root, dirs, files in os.walk(options.binary_from):
        for name in files:
            if name not in done and name not in excluded_files:
                basename = os.path.splitext(name)[0]
                elf  = os.path.join(root, name)
                if options.maxsize and os.stat(elf).st_size > options.maxsize*1024*1024:
                    continue 
                yafb = os.path.join(yafb_path, name + ".yafb")
                vect = os.path.join(vect_path, name + ".vect")
                if options.compressvector and options.tmpdir:
                    vect = os.path.join(options.tmpdir, name + ".vect")
                    vect_compressed = os.path.join(vect_path, name + ".vect.xz")
                else:
                    vect = os.path.join(vect_path, name + ".vect")
                    vect_compressed = vect + ".xz"  
                done.add(name)
                q.put((elf, yafb, vect, vect_compressed))

    # block until all tasks are done

    # stop workers
    print("Stopping threads")
    for i in range(num_worker_threads):
        q.put(None)
    print("Waiting for threads")
    for t in threads:
        t.join()
    print("Threads stopped")

def main(options):
    max_level = logging.WARNING
    if options.debug:
        max_level = logging.DEBUG
    logging.basicConfig(level=max_level, format="%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    ctx = Ctx()
    setup_ctx(ctx, options)
    
    if os.path.isdir(options.binary_from):
        try:
            num_cpu = int(os.environ['EXPORT_CPU'])
        except:
            num_cpu = multiprocessing.cpu_count()
        
        walk_dir_multithreads(ctx, options, options.binary_from, options.yafb_to, options.vect_to, num_worker_threads=num_cpu)
    else:
        handle_bin(ctx, options, options.binary_from, options.yafb_to, options.vect_to)

if __name__ == "__main__":
    sys.exit(main(parse_options()))
