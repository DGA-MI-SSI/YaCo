#!/usr/bin/env python2.7
# we want to use python from ida

import argparse
import inspect
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile

IDLE_PRIORITY_CLASS = 0x00000040


class Ctx:
    def __init__(self):
        self.folders_to_delete = []


DEFAULT_CONFIG = b"""
<yadiff>
    <Matching>
        <option XRefOffsetMatch="true"/>
        <option XRefOffsetOrderMatch="true"/>
        
        <option XRefMatch="true"/>
        <option XRefMatch_TrustDiffingRelations="true"/>
        <option XRefMatch_XrefDirectionMode="both"/>
        <option XRefMatch_StripBasicBlocksMode="both"/>
        
        <option DoAnalyzeUntilAlgoReturn0="true"/>
        <option DoAnalyzeUntilAnalyzeReturn0="true"/>
    </Matching>
</yadiff>

"""


def get_binary_name(ctx, name):
    if sys.platform in ["linux", "linux2"]:
        return name
    elif sys.platform == "win32":
        return name + ".exe"
    else:
        fail(ctx, "unknown platform %s" % sys.platform)


def run_ida(ctx, ida_database, script, interactive=False, *args):
    ida = ctx.ida
    if ida_database.endswith(".i64"):
        ida = ctx.ida64
    ida_args = ["-Oyaco:disable_plugin"]
    if not interactive:
        ida_args += ['-A']
    sys.path.append(os.path.join(ctx.yatools_dir, "YaCo"))
    import exec_ida
    cmd = exec_ida.Exec(ida, ida_database, *ida_args)
    cmd.set_idle(True)
    cmd.with_script(script, *args)
    logging.info("running %s" % str(cmd))
    err = cmd.run()
    if err:
        fail(ctx, "unable to run ida\n%s" % err)


def export_database(ctx, ida_database, suffix, interactive=False):
    database_dir = os.path.dirname(os.path.abspath(ida_database))
    yadb_path = os.path.join(database_dir, "export." + suffix + ".yadb")
    if os.path.isfile(yadb_path):
        logging.info("%s: %s is already exported." % (ida_database, yadb_path))
        return yadb_path

    logging.info("%s: exporting %s" % (ida_database, yadb_path))
    script = os.path.join(ctx.yatools_dir, "YaCo", "export_all.py")
    run_ida(ctx, ida_database, script, interactive, os.path.join(ctx.yatools_dir, "bin"), "--output", yadb_path)
    if not os.path.isfile(yadb_path):
        fail(ctx, "unable to export to %s" % yadb_path)
    return yadb_path


def diff_databases(ctx, yadb1, idb2, yadb2, config_path):
    logging.info("diffing databases")
    cache_yadb = os.path.join(os.path.dirname(idb2), "yadiff.yadb")
    if os.path.exists(cache_yadb):
        return cache_yadb

    args = [ctx.yadiff, config_path, yadb1, yadb2, cache_yadb]
    logging.info("running %s" % " ".join(args))
    subprocess.check_call(args)
    if not os.path.isfile(cache_yadb):
        fail(ctx, "unable to export diff into %s" % cache_yadb)
    return cache_yadb


def load_yadb(ctx, idb, cache_yadb, analysis, interactive=False):
    logging.info("loading database")
    idbname = re.sub(r'\.i(db|64)$', '.yadiff_local.i\\1', idb)
    shutil.copyfile(idb, idbname)
    script = os.path.join(ctx.yatools_dir, "YaCo", "load_yadb.py")
    args = []
    if not analysis:
        args.append('--quick')
    args.append('yadiff.yadb')
    run_ida(ctx, idbname, script, interactive, os.path.join(ctx.yatools_dir, "bin"), *args)
    if not os.path.isfile(cache_yadb):
        fail(ctx, "unable to import database from %s" % cache_yadb)


def get_config():
    config_file = tempfile.NamedTemporaryFile(delete=False, suffix=".xml")
    config_file.write(DEFAULT_CONFIG)
    config_file.close()
    return config_file.name


def try_rmtree(d):
    try:
        shutil.rmtree(d)
    except:
        pass


def cleanup(ctx):
    for d in ctx.folders_to_delete:
        try_rmtree(d)
        try_rmtree(d)


def parse_options():
    parser = argparse.ArgumentParser(description="merge_idb")

    parser.add_argument("idb_from",
                        type=str,
                        help="IDA database file",
                        )

    parser.add_argument("idb_to",
                        type=str,
                        help="IDA database file",
                        )

    parser.add_argument("--config",
                        type=str,
                        default=None,
                        help="IDA database file",
                        )

    parser.add_argument("--dont-close-ida",
                        action="store_true",
                        help="Don't close IDA",
                        )

    parser.add_argument("--no-cleanup",
                        action="store_true",
                        help="Don't cleanup temporary files",
                        )

    parser.add_argument("-d", "--debug",
                        action="store_true",
                        help="Debug",
                        )

    parser.add_argument("--analysis",
                        action="store_true",
                        help="Wait for IDA auto-analysis",
                        )

    return parser.parse_args()


def fail(ctx, *args):
    logging.error(*args)
    sys.exit(-1)


def setup_ctx(ctx):
    # get ida directory
    if "IDA_DIR" not in os.environ.keys():
        fail(ctx, "missing IDA_DIR environment variable")
    ctx.ida_dir = os.path.abspath(os.environ["IDA_DIR"])
    logging.info("IDA_DIR = %s" % ctx.ida_dir)
    sys.path.append(os.path.join(ctx.ida_dir, "plugins", "YaTools", "bin"))

    # get ida binary path
    ida = os.path.join(ctx.ida_dir, get_binary_name(ctx, "ida"))
    if not os.path.isfile(ida):
        fail(ctx, "%s is not a file" % ida)
    ctx.ida = ida
    ctx.ida64 = os.path.join(ctx.ida_dir, get_binary_name(ctx, "ida64"))
    logging.info("ida = %s" % ida)
    logging.info("ida64 = %s" % ctx.ida64)

    # get yatools dir
    yatools_dir = os.path.abspath(os.path.join(inspect.getsourcefile(lambda: 0), "..", ".."))
    if "YATOOLS_DIR" in os.environ.keys():
        yatools_dir = os.path.abspath(os.environ["YATOOLS_DIR"])
    logging.info("YATOOLS_DIR = %s" % yatools_dir)

    load_yadb_path = os.path.join(yatools_dir, "YaCo", "load_yadb.py")
    if not os.path.isfile(load_yadb_path):
        fail(ctx, "%s is not a file" % load_yadb_path)
    ctx.yatools_dir = yatools_dir

    # get yadiff binary path
    yadiff = get_binary_name(ctx, os.path.join(ctx.yatools_dir, "bin", "yadiff"))
    if "YADIFF_PATH" in os.environ.keys():
        yadiff = os.path.abspath(os.environ["YADIFF_PATH"])
    logging.info("YADIFF_PATH = %s" % yadiff)
    if not os.path.isfile(yadiff):
        fail(ctx, "%s is not a file" % yadiff)
    ctx.yadiff = yadiff


def main(options):
    max_level = logging.INFO
    if options.debug:
        max_level = logging.DEBUG
    logging.basicConfig(level=max_level, format="%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    ctx = Ctx()
    setup_ctx(ctx)
    if options.config is None:
        config_path = get_config()
    else:
        config_path = options.config

    yadb_from = export_database(ctx, options.idb_from, "from", options.dont_close_ida)
    yadb_to = export_database(ctx, options.idb_to, "to", options.dont_close_ida)
    yadb_diff = diff_databases(ctx, yadb_from, options.idb_to, yadb_to, config_path)
    load_yadb(ctx, options.idb_to, yadb_diff, options.analysis, options.dont_close_ida)

    if not options.no_cleanup:
        cleanup(ctx)
    logging.info("all done")


if __name__ == "__main__":
    sys.exit(main(parse_options()))
