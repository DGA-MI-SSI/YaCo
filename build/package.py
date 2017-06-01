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
import subprocess
import zipfile

def procexec(cwd, *args):
    try:
        output = subprocess.check_output(" ".join(args), cwd=cwd, stderr=subprocess.STDOUT, shell=True)
        output = output.strip()
        return output, None
    except subprocess.CalledProcessError as e:
        return None, e.output.decode().strip()

def walkdir(path, callback, *exts):
    for root, dirs, files in os.walk(path, followlinks=True):
        for fi in files:
            _, ext = os.path.splitext(fi)
            if ext in exts:
                continue
            callback(os.path.join(root, fi))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bindir", type=os.path.abspath, help="binary directory")
    parser.add_argument("outdir", type=os.path.abspath, help="output directory")
    parser.add_argument("platform", type=str, help="package platform")
    parser.add_argument("--git",  type=str, default="git", help="optional git executable")
    opts = parser.parse_args()
    tag, err = procexec(opts.bindir, opts.git, "describe", "--tags", "--long", "--dirty")
    if err:
        raise Exception(err)
    tag = tag.decode()
    if not tag:
        raise Exception("missing tag on git %s" % opts.bindir)
    name = "yatools-%s-%s" % (opts.platform, tag)
    print("packaging %s.zip" % name)
    with zipfile.ZipFile(os.path.join(opts.outdir, name + ".zip"), "w", zipfile.ZIP_DEFLATED) as fh:
        def callback(path):
            dst = os.path.join(name, os.path.relpath(path, opts.bindir))
            print(dst)
            fh.write(path, dst)
        walkdir(opts.bindir, callback, ".pyc")

if __name__ == "__main__":
    main()
