import argparse
import difflib
import inspect
import os
import subprocess
import sys

def sysexec(cwd, *args):
    if True:
        print(cwd + ": " + " ".join(*args))
    subprocess.check_call(*args, stderr=subprocess.STDOUT, shell=False)

def generate_yadiff_idb(args):
    root_dir = os.path.abspath(os.path.join(inspect.getsourcefile(lambda: 0), "..", ".."))
    os.environ["YATOOLS_DIR"] = args.bindir
    script = os.path.abspath(os.path.join(root_dir, "YaDiff", "merge_idb.py"))
    sysexec("", [args.python, script, args.src, args.dst])

def check_golden(golden_filename, got):
    expected_path = os.path.join(os.path.dirname(inspect.getsourcefile(lambda:0)), golden_filename)

    # Enable to update golden file
    if False:
        with open(expected_path, "wb") as fh:
            fh.write(got)

    # Read expected values
    expected = None
    with open(expected_path, "rb") as fh:
        expected = fh.read()

    if expected == got:
        return

    # Get number of line diff
    ## yadiff is not deterministic anymore
    ## so we want a small diff arbitrarily set at $max_lines lines
    max_lines = 100
    diff = "".join(difflib.unified_diff(expected.splitlines(1), got.splitlines(1), golden_filename, "got"))
    difflines = diff.splitlines(1)
    if len(difflines) < max_lines:
        return

    raise BaseException("diff: %d lines\n%s" % (len(difflines), diff))

def check_yadiff_database(args):
    sys.path.append(os.path.join(args.bindir, "bin"))
    print(os.path.join(args.bindir, "bin"))
    import yadb.Root
    data = None
    with open(os.path.abspath(os.path.join(args.dst, "..", "yadiff.yadb")), "rb") as fh:
        data = bytearray(fh.read())
    root = yadb.Root.Root.GetRootAsRoot(data, 0)
    got = []
    for i in range(0, root.BasicBlocksLength()):
        v = root.BasicBlocks(i)
        u = v.Username()
        if not u:
            continue
        line = root.Strings(u.Value()).rstrip()
        if not len(line):
            continue
        got.append(line)
    got.sort()
    got = "\n".join(got) + "\n\nsymbols: %d\n" % len(got)
    check_golden("test_yadiff." + sys.platform.lower() + ".golden", got)

def main():
    """ Main test for YaDiff """
    # Get args
    parser = argparse.ArgumentParser()
    parser.add_argument("bindir", type=os.path.abspath, help="yatools binary directory")
    parser.add_argument("python", type=os.path.abspath, help="python executable")
    parser.add_argument("src", type=os.path.abspath, help="input IDB")
    parser.add_argument("dst", type=os.path.abspath, help="output IDB")
    args = parser.parse_args()

    # Merge idb <- YaDiff
    generate_yadiff_idb(args)

    # Check
    check_yadiff_database(args)

if __name__ == '__main__':
    main()
