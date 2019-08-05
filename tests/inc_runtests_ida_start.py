import idaapi
import idautils
import idc
import sys

sys.path.append(idc.ARGV[1])
sys.path.append(idc.ARGV[2])
if idc.__EA64__:
    import YaToolsPy64 as ya
else:
    import YaToolsPy32 as ya

def dump_type(ea):
    flags = idaapi.get_flags(ea)
    if idc.is_code(flags):
        return "block" if idaapi.get_func(ea) else "code"
    if idc.is_data(flags):
        return "data"
    return "unexplored"

# MS_CLS
type_flags = {
    ida_bytes.FF_CODE: "code",
    ida_bytes.FF_DATA: "data",
    ida_bytes.FF_TAIL: "tail",
    ida_bytes.FF_UNK:  "unkn",
}

# MS_CODE
code_flags = {
    ida_bytes.FF_FUNC: "func",
    ida_bytes.FF_IMMD: "immd",
    ida_bytes.FF_JUMP: "jump",
}

# DT_TYPE
data_flags = {
    ida_bytes.FF_BYTE:     "byte",
    ida_bytes.FF_WORD:     "word",
    ida_bytes.FF_DWORD:    "dword",
    ida_bytes.FF_QWORD:    "qword",
    ida_bytes.FF_TBYTE:    "tbyte",
    ida_bytes.FF_STRLIT:   "strlit",
    ida_bytes.FF_STRUCT:   "struct",
    ida_bytes.FF_OWORD:    "oword",
    ida_bytes.FF_FLOAT:    "float",
    ida_bytes.FF_DOUBLE:   "double",
    ida_bytes.FF_PACKREAL: "packreal",
    ida_bytes.FF_ALIGN:    "align",
    ida_bytes.FF_CUSTOM:   "custom",
    ida_bytes.FF_YWORD:    "yword",
    ida_bytes.FF_ZWORD:    "zword",
}

# MS_COMM
comm_flags = {
    ida_bytes.FF_COMM:   "comm",
    ida_bytes.FF_REF:    "ref",
    ida_bytes.FF_LINE:   "line",
    ida_bytes.FF_NAME:   "name",
    ida_bytes.FF_LABL:   "labl",
    ida_bytes.FF_FLOW:   "flow",
    ida_bytes.FF_SIGN:   "sign",
    ida_bytes.FF_BNOT:   "bnot",
    ida_bytes.FF_UNUSED: "unused",
}

# MS_0TYPE
op0_flags = {
    ida_bytes.FF_0NUMH: "0:numh",
    ida_bytes.FF_0NUMD: "0:numd",
    ida_bytes.FF_0CHAR: "0:char",
    ida_bytes.FF_0SEG:  "0:seg",
    ida_bytes.FF_0OFF:  "0:off",
    ida_bytes.FF_0NUMB: "0:numb",
    ida_bytes.FF_0NUMO: "0:numo",
    ida_bytes.FF_0ENUM: "0:enum",
    ida_bytes.FF_0FOP:  "0:fop",
    ida_bytes.FF_0STRO: "0:stro",
    ida_bytes.FF_0STK:  "0:stk",
    ida_bytes.FF_0FLT:  "0:flt",
    ida_bytes.FF_0CUST: "0:cust",
}

# MS_1TYPE
op1_flags = {
    ida_bytes.FF_1NUMH: "1:numh",
    ida_bytes.FF_1NUMD: "1:numd",
    ida_bytes.FF_1CHAR: "1:char",
    ida_bytes.FF_1SEG:  "1:seg",
    ida_bytes.FF_1OFF:  "1:off",
    ida_bytes.FF_1NUMB: "1:numb",
    ida_bytes.FF_1NUMO: "1:numo",
    ida_bytes.FF_1ENUM: "1:enum",
    ida_bytes.FF_1FOP:  "1:fop",
    ida_bytes.FF_1STRO: "1:stro",
    ida_bytes.FF_1STK:  "1:stk",
    ida_bytes.FF_1FLT:  "1:flt",
    ida_bytes.FF_1CUST: "1:cust",
}

def dump_flags(ea):
    flags = idaapi.get_flags(ea)
    reply = []
    for k in type_flags:
        if (flags & ida_bytes.MS_CLS) == (k & 0xFFFFFFFF):
            reply.append(type_flags[k])
    if ida_bytes.is_code(flags):
        for k in code_flags:
            if (flags & ida_bytes.MS_CODE) & k:
                reply.append(code_flags[k])
    if ida_bytes.is_data(flags):
        for k in data_flags:
            if (flags & ida_bytes.DT_TYPE) == (k & 0xFFFFFFFF):
                reply.append(data_flags[k])
    for k in comm_flags:
        if (flags & ida_bytes.MS_COMM) & k:
            reply.append(comm_flags[k])
    for k in op0_flags:
        if (flags & ida_bytes.MS_0TYPE) == (k & 0xFFFFFFFF):
            reply.append(op0_flags[k])
    for k in op1_flags:
        if (flags & ida_bytes.MS_1TYPE) == (k & 0xFFFFFFFF):
            reply.append(op1_flags[k])
    return " ".join(reply)

def export_range(start, end):
    data = ""
    count = 0
    for ea in ya.get_all_items(start, end):
        type = idc.get_type(ea)
        type = " " + type if type else ""
        name = idaapi.get_name(ea)
        name = " " + name if name else ""
        data += "0x%x: %s: %s\\n" % (ea, dump_type(ea), dump_flags(ea))
        count += 1
    if count > 100:
        data += "%d item(s)" % count
    return data

idc.Wait()
