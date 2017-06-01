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
import YaCo

def init(tests):
    # workaround ida 6.95 function chunks which should really be functions
    for ea in [0x6718f260, 0x671a5250]:
        numrefs = idc.GetFchunkAttr(ea, idc.FUNCATTR_REFQTY)
        if numrefs <= 1:
            continue
        for idx in range(numrefs, 0, -1):
            idc.RemoveFchunk(idc.GetFchunkReferer(ea, idx - 1), ea)
        idc.MakeFunction(ea)
    idc.Wait()
    YaCo.start()

def exit(tests):
    pass
