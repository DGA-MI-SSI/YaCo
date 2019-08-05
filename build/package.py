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

from argparse import ArgumentParser
from os import walk
from os.path import dirname, realpath, relpath, abspath, splitext, join
from subprocess import check_output, STDOUT, CalledProcessError
from zipfile import ZipFile, ZIP_DEFLATED
from shutil import copytree, rmtree

def procexec(cwd, *args):
    """ Execute args at current wroking dir """
    try:
        output = check_output(" ".join(args), cwd=cwd, stderr=STDOUT, shell=True)
        output = output.strip()
        return output, None
    except CalledProcessError as e:
        return None, e.output.decode().strip()

def walkdir(path, callback, *exts):
    """ Execute callback for all dir in `find pat` """
    for root, dirs, files in walk(path, followlinks=True):
        for fi in files:
            _, ext = splitext(fi)
            if ext in exts:
                continue
            callback(join(root, fi))

def main():
    """ Create package (release) """
    # Parse args
    parser = ArgumentParser()
    parser.add_argument("bindir", type=abspath, help="binary directory")
    parser.add_argument("outdir", type=abspath, help="output directory")
    parser.add_argument("platform", type=str, help="package platform")
    parser.add_argument("--git",  type=str, default="git", help="optional git executable")
    args = parser.parse_args()

    # Get git tag
    tag, err = procexec(args.bindir, args.git, "describe", "--tags", "--long", "--dirty")
    if err:
        raise Exception(err)
    tag = tag.decode()
    if not tag:
        raise Exception("missing tag on git %s" % args.bindir)

    # Get, Print name out
    name = "yatools-%s-%s" % (args.platform, tag)
    print("packaging %s.zip" % name)

    # Copy Yaco
    s_dir = dirname(realpath(__file__))
    s_from = realpath(s_dir + "/../YaCo")
    s_to = realpath(args.bindir + '/Yatools/YaCo')
    print('copying : ' + s_from + ' -> ' + s_to)
    rmtree(s_to)
    copytree(s_from, s_to)

    # Zip
    with ZipFile(join(args.outdir, name + ".zip"), "w", ZIP_DEFLATED) as fh:
        def callback(path):
            dst = join(name, relpath(path, args.bindir))
            print(dst)
            fh.write(path, dst)
        walkdir(args.bindir, callback, ".pyc")

if __name__ == "__main__":
    main()
