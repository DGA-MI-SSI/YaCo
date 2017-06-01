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

import idautils
import idc
import time

if idc.__EA64__:
    import YaToolsPy64 as ya
else:
    import YaToolsPy32 as ya
yatools = ya.YaToolsIDANativeLib()

num_blocks = 0
num_binaries = 0
num_codes = 0
num_datas = 0
num_enum_members = 0
num_enums = 0
num_functions = 0
num_segment_chunks = 0
num_segments = 0
num_stackframe_members = 0
num_stackframes = 0
num_struct_members = 0
num_structs = 0
num_default_stackframe_members = 0

num_binaries += 1
for ea in idautils.Segments():
    num_segments += 1

def get_default_struc_member_name(is_struct, offset, base=0):
    if is_struct:
        return "field_%X" % (offset - base)
    if offset <= base:
        return "var_%X" % (base - offset)
    if offset < base + 4:
        return "var_s%d" % (offset - base)
    return "arg_%X" % (offset - base - 4)

def is_nil(value):
    return not value or not len(value)

def walk_members(ea):
    global num_stackframes, num_default_stackframe_members
    frame = idaapi.get_frame(ea)
    if not frame:
        return
    num_stackframes += 1
    sid = frame.id
    s = idaapi.get_struc(sid)
    if s is None or s == idaapi.BADADDR:
        return
    known = set()
    base = idc.GetFrameLvarSize(ea)
    for idx in xrange(0, s.memqty):
        ea = yatools.get_struc_member_by_idx(s, idx)
        if ea in known:
            continue
        m = idaapi.get_member(frame, ea)
        if not m or idaapi.is_special_member(m.id):
            continue
        is_data = m.flag == idaapi.FF_DATA
        is_default_name = idc.GetMemberName(sid, ea) == get_default_struc_member_name(False, ea, base)
        size = idaapi.get_member_size(m)
        no_comment = is_nil(idaapi.get_member_cmt(m.id, 0))
        no_repeated = is_nil(idaapi.get_member_cmt(m.id, 1))
        if not s.is_union() and is_data and size == 1 and is_default_name and no_comment and no_repeated:
            num_default_stackframe_members += 1
            continue
        if m and not idaapi.is_special_member(m.id):
            known.add(ea)
            yield m

def walk_function(ea):
    global num_functions, num_blocks, num_stackframe_members
    func = idaapi.get_func(ea)
    num_functions += 1
    for offset in walk_members(ea):
        num_stackframe_members += 1
    flow = idaapi.qflow_chart_t()
    flow.create('', func, func.startEA, func.endEA, idaapi.FC_NOEXT)
    for i in range(flow.size()):
        block = flow.__getitem__(i)
        if block.startEA != block.endEA:
            num_blocks += 1
    return func.endEA

def get_code_block_end(ea, func):
    while ea != idaapi.BADADDR:
        flags = idaapi.getFlags(ea)
        if not idaapi.isCode(flags):
            return ea
        elif idaapi.isData(flags):
            return ea
        elif idaapi.isUnknown(flags):
            return ea
        if idaapi.isFunc(flags):
            return ea
        if idaapi.isCode(flags) and func is not None:
            return ea
        ea = idaapi.get_item_end(ea)
    return ea

skip_ea = None
max_count = 0x10000
count = max_count
last = time.clock()
for ea in idautils.Heads():
    count += 1
    if count >= max_count:
        count = 0
        now = time.clock()
        d = now - last
        print hex(ea), hex(idc.SegEnd(ea)), '%d ms' % (d * 1000), '%d khead/s' % int(max_count / d / 1000)
        last = now
    if skip_ea is not None and ea < skip_ea:
        continue
    flags = idaapi.getFlags(ea)
    func = idaapi.get_func(ea)
    if idaapi.isFunc(flags):
        skip_ea = walk_function(ea)
        continue
    if func is None and idaapi.isCode(flags):
        skip_ea = get_code_block_end(ea, func)
        num_codes += 1
        continue
    if idaapi.isData(flags):
        skip_ea = idaapi.next_not_tail(ea)
        num_datas += 1
        continue

def walk_enum(eid):
    def get_enums(bmask):
        value = idc.GetFirstConst(eid, bmask)
        while value != idaapi.BADADDR:
            yield value, bmask
            value = idc.GetNextConst(eid, value, bmask)
    # iterate on every bmask
    bmask = idc.GetFirstBmask(eid)
    while bmask != idaapi.BADADDR:
        for v, m in get_enums(bmask):
            yield v, m
        bmask = idc.GetNextBmask(eid, bmask)
    # iterate on regular constants
    for v, m in get_enums(-1):
        yield v, m

for idx in range(0, idaapi.get_enum_qty()):
    num_enums += 1
    eid = idaapi.getn_enum(idx)
    for (value, bmask) in walk_enum(eid):
        num_enum_members += 1

for (idx, sid, name) in idautils.Structs():
    num_structs += 1
    for (offset, name, size) in idautils.StructMembers(sid):
        num_struct_members += 1

print "blocks", num_blocks
print "binaries", num_binaries
print "codes", num_codes
print "datas", num_datas
print "enum_members", num_enum_members
print "enums", num_enums
print "functions", num_functions
print "segment_chunks", num_segment_chunks
print "segments", num_segments
print "stackframe_members", num_stackframe_members
print "stackframes", num_stackframes
print "struct_members", num_struct_members
print "structs", num_structs
print "default_stackframe_members", num_default_stackframe_members
