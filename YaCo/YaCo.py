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

import glob
import os
import shutil
import sys
import time

sys.path.append(os.path.abspath("%s/../../bin/" % __file__))

import cProfile
import idc
import idaapi
import logging
import pstats
import traceback

if idc.__EA64__:
    import YaToolsPy64 as ya
else:
    import YaToolsPy32 as ya

IDA_IS_INTERACTIVE = ya.IS_INTERACTIVE

yaco = None
yaco_starting = False


def start():
    global yaco, yaco_starting

    if yaco_starting:
        print("YaCo is starting : skipping")
        return

    yaco_starting = True
    if yaco is None:
        yaco = ya.MakeYaCo(IDA_IS_INTERACTIVE)
        yaco.start()
        yaco_starting = False
        return True
    else:
        print("Not starting YaCo: already done")
        yaco_starting = False
        return False

def save_and_update():
    global yaco
    yaco.save_and_update()

def close():
    global yaco
    if yaco is None:
        print("Could not close YaCo: not loaded")
        return

    print("YaCo.close()")
    yaco.stop()
    print("YaCo.close() done")
    yaco = None
