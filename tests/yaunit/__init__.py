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

import idaapi
import idautils
import idc
import json
import logging
import re
import yaco_plugin
import YaCo
debug = False

logger = logging.getLogger("YaCo")


def init(tests):
    YaCo.start()


def exit(tests):
    idbname = re.sub(r'\.i(db|64)$', '_' + tests + '.i\\1', idc.GetIdbPath())
    if tests == 'yatest':
        YaCo.save_and_update()
    # save intermediate bases
    if debug:
        idc.SaveBase(idbname)

# save generator as global for all tests
# and prevent potential conflicts
_functions = sorted([k for k in idautils.Functions()])
_not_functions = sorted([j for j in  (set([k for k in idautils.Heads()]) - set(_functions))])
_codes = []
_datas = []
for ea in _not_functions:
    flags = idc.GetFlags(ea)
    if idc.isCode(flags) and not idaapi.isFunc(flags):
        _codes.append(ea)
    elif idc.isData(flags):
        _datas.append(ea)

def _get_next_from_list(list_from, predicate=None):
    for i in xrange(0, len(list_from)):
        ea = list_from[i]
        if not predicate or predicate(ea):
            del list_from[i]
            return ea
    raise BaseException(idaapi.BADADDR)
    

def get_next_function(predicate=None):
    return _get_next_from_list(_functions, predicate)

def get_next_not_function(predicate=None):
    return _get_next_from_list(_not_functions, predicate)

def get_next_code(predicate=None):
    return _get_next_from_list(_codes, predicate)

def get_next_data(predicate=None):
    return _get_next_from_list(_datas, predicate)

def has_locals(ea, lvar_size=1, count_from_first_var=False):
    frame = idaapi.get_frame(ea)

    if frame is None or frame.memqty <= 1:
        return False
    
    if count_from_first_var:
        sida = frame.id
        offset = idc.GetFirstMember(sida)
        return idc.GetFrameLvarSize(ea) > lvar_size+offset
    else:
        return idc.GetFrameLvarSize(ea) > lvar_size

# save a setting between ida sessions
# keys must be unique
def save(key, value):
    with open('%s.json' % key, 'wb') as fh:
        json.dump(value, fh)


# load a setting between ida sessions
def load(key):
    with open('%s.json' % key, 'rb') as fh:
        return json.load(fh)
