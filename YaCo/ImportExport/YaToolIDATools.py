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

import ctypes
import idaapi
import idc
import logging
import os
import string
import sys
import zlib

from ctypes.util import find_library
# from YaToolObjectVersionElement import YaToolObjectVersionElement
from ImportExport import HandlerBuilders
# from ImportExport.YaToolPrototypeParser import YaToolPrototypeParser

LEN_ = idc.ASCSTR_LEN2

if idc.__EA64__:
    import YaToolsPy64 as ya
else:
    import YaToolsPy32 as ya

logger = logging.getLogger("YaCo")
_yatools_ida = ya.YaToolsIDANativeLib()

MAX_COMMENT_LINES = 255
RV_MIN_ADDR = 0x1000
RV_MAX_ADDR = idc.BADADDR

OBJECT_WITH_COMMENTS = set([ya.OBJECT_TYPE_BASIC_BLOCK, ya.OBJECT_TYPE_CODE, ya.OBJECT_TYPE_DATA])

TID_MASK = None

if idc.BADADDR == 0xFFFFFFFFFFFFFFFF:
    TID_MASK = 0xff00000000000000
else:
    TID_MASK = 0xff000000


def isFuncStart(F):
    return idc.isCode(F) and (F & idc.FF_FUNC) == idc.FF_FUNC


def hasAnyName(flags):
    return (flags & idc.FF_ANYNAME) != 0


def GetNameFlags(name, ea):
    flags = 0
    # we don't know what name_value is...
    name_value, _name_value = idaapi.get_name_value(ea, name)

    # 	if(addr != ea):
    # 		if(addr == (ea | 0x100000000) or addr == (ea & 0xFFFFFFFF)):
    # 			logger.warn("(IDA bug) get_name_value returned bad address : 0x%016X (instead of 0x%016X)" % (addr, ea))
    # 		else:
    # 			logger.warn("get_name_value returned bad address : "\
    # "0x%016X (instead of 0x%016X), using idc.SN_CHECK" % (addr, ea))
    # return default value used by MakeName
    # 			return idc.SN_CHECK

    if name_value == idaapi.NT_LOCAL:
        # see name.hpp : LOCAL names can not be public nor weak, and are not listed
        flags |= idaapi.SN_LOCAL | idaapi.SN_NON_PUBLIC | idaapi.SN_NON_WEAK | idaapi.SN_NOLIST
    else:
        if idaapi.is_public_name(ea):
            flags |= idaapi.SN_PUBLIC
        else:
            flags |= idaapi.SN_NON_PUBLIC

        if idaapi.is_weak_name(ea):
            flags |= idaapi.SN_WEAK
        else:
            flags |= idaapi.SN_NON_WEAK

        if idaapi.is_in_nlist(ea) is False:
            flags |= idaapi.SN_NOLIST

    ida_flags = idc.GetFlags(ea)

    if idaapi.has_user_name(ida_flags) or idc.hasUserName(ida_flags):
        flags |= idc.SN_NON_AUTO
    elif idaapi.has_auto_name(ida_flags):
        flags |= idc.SN_AUTO
    elif idaapi.has_dummy_name(ida_flags):
        # names like "dword_XXXX"
        flags |= idc.SN_AUTO
    else:
        logger.debug("name is not user nor auto?? at 0x%016X : 0x%08X" % (ea, ida_flags))

    return flags


latest_str_type = None


def check_and_set_str_type(new_type):
    global latest_str_type
    if latest_str_type != new_type:
        latest_str_type = new_type
        if idc.GetCharPrm(idc.INF_STRTYPE) != new_type:
            idc.SetCharPrm(idc.INF_STRTYPE, new_type)


def is_default_name(name, address):
    suff = "%X" % address
    if name.endswith(suff):
        name_start = name[:-(len(suff) + 1)]
        if ya.IsDefaultName(name_start):
            return True
    return False


STRING_CHAR_SIZE = {
    idc.ASCSTR_TERMCHR: 1,  # Character-terminated ASCII string
    idc.ASCSTR_C: 1,  # C-string, zero terminated
    idc.ASCSTR_PASCAL: 1,  # Pascal-style ASCII string (length byte)
    LEN_: 2,  # Pascal-style, length is 2 bytes
    idc.ASCSTR_UNICODE: 2,  # Unicode string
    idc.ASCSTR_LEN4: 4,  # Delphi string, length is 4 bytes
    idc.ASCSTR_ULEN2: 2,  # Pascal-style Unicode, length is 2 bytes
    idc.ASCSTR_ULEN4: 4,  # Pascal-style Unicode, length is 4 bytes
}


def get_char_size(str_type):
    return STRING_CHAR_SIZE[str_type]


def get_field_size(field_type, tid=0):
    field_type = field_type & idc.DT_TYPE
    if field_type == idc.FF_BYTE:
        return 1
    if field_type == idc.FF_ASCI:
        return get_char_size(tid)
    elif field_type == idc.FF_WORD:
        return 2
    elif field_type == idc.FF_DWRD:
        return 4
    elif field_type == idc.FF_QWRD:
        return 8
    elif field_type == idc.FF_OWRD:
        return 16
    elif field_type == idc.FF_FLOAT:
        return 4
    elif field_type == idc.FF_DOUBLE:
        return 8
    else:
        return 1


def LastSegEnd():
    start = idc.NextSeg(0)
    end = idc.SegEnd(start)
    while idc.NextSeg(start + 1) != idc.BADADDR:
        start = idc.NextSeg(end - 1)
        end = idc.SegEnd(start)
    return end


def decodeInstruction(InstructionAddress, ida_instruction_bytes_cache):
    # try to decode instruction
    if idaapi.decode_insn(InstructionAddress) == 0:
        logger.warning("Invalid instruction at %x." % (InstructionAddress))
        sys.exit(-1)

    # create a hash with operands type
    ophash = ''
    for op in idaapi.cmd.Operands:
        op_type = op.type
        if op_type != idaapi.o_void:
            ophash += ("%x" % op_type)

    # get intructions type
    itype = idaapi.cmd.itype

    return ((ida_instruction_bytes_cache[0], "%x" % itype + ophash), idaapi.cmd.size)


def getInvariantsBytes(InstructionAddress, Size, ida_instruction_bytes_cache):
    # while no instruction
    currentEa = InstructionAddress
    while not idaapi.isCode(idaapi.get_flags_novalue(currentEa)):
        currentEa += idc.ItemSize(currentEa)
        if currentEa >= (InstructionAddress + Size):
            return (('', ''), currentEa - InstructionAddress)

    FirstInstructionOffset = currentEa - InstructionAddress

    (hashes, instruction_size) = decodeInstruction(InstructionAddress +
                                                   FirstInstructionOffset,
                                                   ida_instruction_bytes_cache[FirstInstructionOffset:])

    # concac hash of code and instruction id
    return (hashes, instruction_size + FirstInstructionOffset)


def create_basic_block_sig(basic_block):
    FirstBytesCrc = ''
    OpcodesHashCrc = ''
    i = 0

    basic_block_start_ea = basic_block['startEA']
    basic_block_size = basic_block['endEA'] - basic_block['startEA']
    ida_function_bytes_cache = idc.GetManyBytes(basic_block_start_ea, basic_block_size)

    # for each instruction
    while i < basic_block_size:
        # get invariant bytes of instruction, we skeep data
        ((firstbyte_hash, opcode_hash), Offset) = getInvariantsBytes(
            basic_block_start_ea + i, basic_block_size - i, ida_function_bytes_cache[i:])
        FirstBytesCrc += firstbyte_hash
        OpcodesHashCrc += opcode_hash
        i += Offset

    return (zlib.crc32(FirstBytesCrc), zlib.crc32(OpcodesHashCrc))


def createSig(basic_blocks):
    FirstBytesCrc = ''
    OpcodesHashCrc = ''

    for basic_block in basic_blocks:

        i = 0
        basic_block_start_ea = basic_block['startEA']
        basic_block_size = basic_block['endEA'] - basic_block['startEA']
        ida_function_bytes_cache = idc.GetManyBytes(basic_block_start_ea, basic_block_size)

        # for each instruction
        while i < basic_block_size:
            # get invariant bytes of instruction, we skeep data
            ((firstbyte_hash, opcode_hash), Offset) = getInvariantsBytes(
                basic_block_start_ea + i, basic_block_size - i, ida_function_bytes_cache[i:])
            FirstBytesCrc += firstbyte_hash
            OpcodesHashCrc += opcode_hash
            i += Offset

    return (zlib.crc32(FirstBytesCrc), zlib.crc32(OpcodesHashCrc))


def createStringSig(string_to_hash):
    filter_string = ""
    for c in string_to_hash:
        c = c.upper()
        if c in string.uppercase + string.digits:
            filter_string += c

    return zlib.crc32(filter_string)


OFFSET_TYPE_MAP = {
    str.lower("OFF8"): 0,  # 8bit full offset
    str.lower("OFF16"): 1,  # 16bit full offset
    str.lower("OFF32"): 2,  # 32bit full offset
    str.lower("LOW8"): 3,  # low 8bits of 16bit offset
    str.lower("LOW16"): 4,  # low 16bits of 32bit offset
    str.lower("HIGH8"): 5,  # high 8bits of 16bit offset
    str.lower("HIGH16"): 6,  # high 16bits of 32bit offset
    str.lower("VHIGH"): 7,  # high ph.high_fixup_bits of 32bit offset
    str.lower("VLOW"): 8,  # low  ph.high_fixup_bits of 32bit offset
    str.lower("OFF64"): 9,  # 64bit full offset
}

OFFSET_TYPE_MAP_NAMES = {
    0: str.lower("OFF8"),  # 8bit full offset
    1: str.lower("OFF16"),  # 16bit full offset
    2: str.lower("OFF32"),  # 32bit full offset
    3: str.lower("LOW8"),  # low 8bits of 16bit offset
    4: str.lower("LOW16"),  # low 16bits of 32bit offset
    5: str.lower("HIGH8"),  # high 8bits of 16bit offset
    6: str.lower("HIGH16"),  # high 16bits of 32bit offset
    7: str.lower("VHIGH"),  # high ph.high_fixup_bits of 32bit offset
    8: str.lower("VLOW"),  # low  ph.high_fixup_bits of 32bit offset
    9: str.lower("OFF64"),  # 64bit full offset
}


def getOperandView(ea):
    operands = list()
    fl = idaapi.get_flags_novalue(ea)
    flags = [idaapi.get_optype_flags0(fl), idaapi.get_optype_flags1(fl) >> 4]
    for i in xrange(0, len(flags)):
        if flags[i] != 0:
            if (flags[i] & idaapi.FF_0STRO) != idaapi.FF_0STRO:
                # Offset property is independent : handle it first
                if flags[i] == idaapi.FF_0OFF:
                    ti = idaapi.opinfo_t()
                    if idaapi.get_opinfo(ea, i, fl, ti):
                        try:
                            offset_name = "-" + OFFSET_TYPE_MAP_NAMES[ti.ri.flags]
                        except KeyError:
                            logger.error(
                                "OperandView at 0x%08X : no valid offset found for flags 0x%08X" % (ea, ti.ri.flags))
                            offset_name = ""
                        operands.append((i, "offset" + offset_name))
                elif flags[i] == idaapi.FF_0NUMD:
                    value = ""
                    operand = i
                    if idaapi.is_invsign(ea, fl, i):
                        value = "signeddecimal"
                    else:
                        value = "unsigneddecimal"
                    operands.append((operand, value))
                elif flags[i] == idaapi.FF_0NUMH:
                    if idaapi.is_invsign(ea, fl, i):
                        operands.append((i, "signedhexadecimal"))
                    else:
                        operands.append((i, "unsignedhexadecimal"))
                elif flags[i] == idaapi.FF_0CHAR:
                    operands.append((i, "char"))
                elif flags[i] == idaapi.FF_0NUMB:
                    operands.append((i, "binary"))
                elif flags[i] == idaapi.FF_0NUMO:
                    operands.append((i, "octal"))

    return operands


def getRegistersView(eaCodeBlockStart, eaCodeBlockEnd, func):
    """
            IDAPython broken !!!! regvars only return the first regvar !

              regvar_t *regvars;   // array of register variables
                                               // this array is sorted by: startEA
                                               // use ...regvar...() functions to access this array

            We have to find a workaround !
    """
    registers = {}

    if func.regvarqty > 0:
        regs_text = set()
        # learn register name of this architecture
        ea = eaCodeBlockStart
        while ea < eaCodeBlockEnd:
            reg0 = idc.GetOpnd(ea, 0)
            reg1 = idc.GetOpnd(ea, 1)
            regs_text.add(reg0)
            regs_text.add(reg1)
            ea += idc.ItemSize(ea)

        # for each register name
        for reg_text in regs_text:
            # try to get regvar_t
            # regvar_canon = idaapi.find_regvar(func, eaCodeBlockStart, eaCodeBlockEnd, reg_text, None)
            regvar_user = idaapi.find_regvar(func, eaCodeBlockStart, eaCodeBlockEnd, None, reg_text)

            if regvar_user is not None:
                offset = regvar_user.startEA - eaCodeBlockStart
                # if offset < 0, it's already treated by an other BB
                if offset >= 0:
                    try:
                        register_offset = registers[offset]
                    except KeyError:
                        register_offset = []
                        registers[offset] = register_offset

                    register_offset.append((regvar_user.canon, regvar_user.endEA - eaCodeBlockStart, regvar_user.user))

        # check if we have found all modified regvars
        if (
                (len(registers) != func.regvarqty) and
                not ((eaCodeBlockStart == func.startEA) and (eaCodeBlockEnd == func.endEA))
        ):
            # if we don't find all regvars, search on whole function (some regvars are in other basic blocks)
            for (regvar_offset, regvar_info) in getRegistersView(func.startEA, func.endEA, func).iteritems():
                registers[regvar_offset] = regvar_info

    return registers


def GetItemContaining(ea):
    previous_item = idc.PrevHead(ea)
    if previous_item is not idc.BADADDR:
        previous_item_size = idc.ItemSize(previous_item)
        if previous_item_size > 0 and ea < previous_item + previous_item_size:
            return previous_item
    return ea


def get_function_xrefs_at_ea(base_address, ea, function_xrefs, minSegAddress, maxSegAddress):
    # TODO: we should look at the operand number
    xrefCode = idc.Rfirst0(ea)
    # code xref
    while xrefCode != idc.BADADDR:
        if (idc.GetFlags(xrefCode) & idc.FF_FUNC) == idc.FF_FUNC:
            function_xrefs[ea - base_address] = GetItemContaining(xrefCode)
        xrefCode = idc.Rnext0(ea, xrefCode)


def get_data_xrefs_at_ea(base_address, ea, data_xrefs, function_xrefs, minSegAddress, maxSegAddress):
    # TODO: we should look at the operand number
    xrefData = idc.Dfirst(ea)
    # data xref
    while xrefData != idc.BADADDR:
        # strangely, xrefs to structure offsets are coded as addresses in 0xFFxxxxxx
        # ignore them
        if xrefData < maxSegAddress and xrefData >= minSegAddress:
            fl = idc.GetFlags(xrefData)
            if idc.isCode(fl):
                if (fl & idc.FF_FUNC) == idc.FF_FUNC:
                    # this deals with the following snippets : reg = load(code_address), call(reg)
                    # in this case, the load instruction has a DATA Xref to code_address,
                    # where code_address is the beginning of a function
                    # surprisingly, [bne regA,regB,addr] is considered as a data Xref to addr. This is why we test if
                    # the crossref is at the beginning of a function
                    function_xrefs[ea - base_address] = GetItemContaining(xrefData)
            else:
                data_xrefs[ea - base_address] = GetItemContaining(xrefData)
        xrefData = idc.Dnext(ea, xrefData)


def get_hidden_area_at_ea(base_address, ea, hidden_area):
    hidden_area[ea - base_address] = set()
    ha = idaapi.get_hidden_area(ea)
    if ha is not None:
        # keep only start on hidden area
        if ha.startEA == ea:
            size = ha.endEA - ha.startEA
            hidden_area[ea - base_address].add((size, ha.description))

    return hidden_area


def update_bookmarks():
    _yatools_ida.update_bookmarks()


def get_comments_at_ea(ea):
    return _yatools_ida.get_comments_at_ea(ea)

def add_comments_at_ea(base_address, ea, comments):
    line_comment = get_comments_at_ea(ea)
    if len(line_comment) > 0:
        comments[ea - base_address] = line_comment


def delete_comment_at_ea(ea, comment_type):
    logger.debug("Deleting comment at 0x%08X / %d" % (ea, comment_type))
    if comment_type == ya.COMMENT_REPEATABLE:
        idc.MakeRptCmt(ea, "")
        # TODO: remove the test with "comment" (temporary fix because of cache incoherency)
    elif comment_type == ya.COMMENT_NON_REPEATABLE or comment_type == "comment":
        idc.MakeComm(ea, "")
    elif comment_type == ya.COMMENT_ANTERIOR:
        for i in xrange(0, idaapi.get_first_free_extra_cmtidx(ea, idaapi.E_PREV)):
            idaapi.del_extra_cmt(ea, idaapi.E_PREV + i)
    elif comment_type == ya.COMMENT_POSTERIOR:
        for i in xrange(0, idaapi.get_first_free_extra_cmtidx(ea, idaapi.E_NEXT)):
            idaapi.del_extra_cmt(ea, idaapi.E_NEXT + i)
    elif comment_type == ya.COMMENT_BOOKMARK:
        # parse marked position
        for i in xrange(1, 1024):
            if idc.GetMarkedPos(i) == idc.BADADDR:
                break
            elif idc.GetMarkedPos(i) == ea:
                idc.MarkPosition(ea, 0, 0, 0, i, "")


def get_reference_xrefs_at_ea(base_address, ea, references):
    #
    # REFERENCE
    #
    # we consider we have 2 operands max
    for op_index in xrange(0, 2):
        ti = idaapi.opinfo_t()
        f = idc.GetFlags(ea)
        if idaapi.get_opinfo(ea, op_index, f, ti):
            if ti.ri.type() != 0 and ti.ri.base != 0:
                if ea - base_address not in references:
                    references[ea - base_address] = list()
                s = {'flags': ti.ri.flags}
                references[ea - base_address].append((op_index, s, ti.ri.base))


def tid_is_enum(tid):
    # get_enum_name return name for struc or enum
    tid_name = idaapi.get_enum_name(tid)

    if idaapi.get_enum(tid_name) != idc.BADADDR:
        return True

    return False


def tid_is_struc(tid):
    # get_struc_name return name for struc or enum
    tid_name = idaapi.get_struc_name(tid)

    if idaapi.get_struc_id(tid_name) != idc.BADADDR:
        return True

    return False


def isEnum(F, op_index):
    if op_index == 0:
        return idc.isEnum0(F)
    elif op_index == 1:
        return idc.isEnum1(F)
    else:
        return False


def isStroff(F, op_index):
    if op_index == 0:
        return idc.isStroff0(F)
    elif op_index == 1:
        return idc.isStroff1(F)
    else:
        return False


def get_struc_enum_xrefs_at_ea(base_address, ea, strucs, enums, stackframe, func):
    # structures
    # TODO: fix use a lot of CPU !!!! (call twice)
    if idaapi.decode_insn(ea) == 0:
        logger.warning("Invalid instruction at %x." % (ea))
        # TODO: check that it is a good thing not to exit
        """
        Code Example :
.text:000000010003D73A E8 CD FB 01+                call    _CxxThrowException
.text:000000010003D73A 00          ; ---------------------------------------------------------------------------
.text:000000010003D73F CC                          db 0CCh
.text:000000010003D73F             sub_10003D6D8   endp
.text:000000010003D73F
.text:000000010003D740 CC CC CC CC+                db 8 dup(0CCh)
.text:000000010003D748 90 90 90 90+                align 10h
        0xCC can be used as padding : it  is recognized as an illegal instruction by IDA
        The instruction should be just ignored, no need to exit
        """
        # sys.exit(-1)
    else:
        # TODO: add 2 xrefs instead of one in struc operands
        """
        following instruction :
        cmp     eax, struc_1.field_1
        should add 2 xrefs : (in XML format)
<xrefs offset="0x0000004A" operand="0x00000001" delta="X">UUID(struc_1)</xrefstrucs>
<xrefs offset="0x0000004A" operand="0x00000001">UUID(struc_1.field_1)</xrefstrucs>
        This way, if field_1 is moved inside struc_1 (between 2 different versions of
        binary), it will still be identified
        """
        op_index = 0
        for op in idaapi.cmd.Operands:
            if op.type != idaapi.o_void:
                ti = idaapi.opinfo_t()
                f = idc.GetFlags(ea)
                if isEnum(f, op_index):
                    if idaapi.get_opinfo(ea, op_index, f, ti):
                        name = idc.GetEnumName(ti.ec.tid)
                        if name is not None:
                            # name can be None if the enum was deleted
                            try:
                                ll = enums[ea - base_address]
                            except KeyError:
                                ll = list()
                                enums[ea - base_address] = ll
                            ll.append((op_index, ti.ec.tid, name))
                elif isStroff(f, op_index):
                    if idaapi.get_opinfo(ea, op_index, f, ti):
                        struc_path = ti.path.ids
                        struc_delta = ti.path.delta
                        path_len = ti.path.len

                        try:
                            struc_xrefs = strucs[ea - base_address]
                        except KeyError:
                            struc_xrefs = list()
                            strucs[ea - base_address] = struc_xrefs

                        for path_idx in xrange(0, path_len):
                            field_id = struc_path[path_idx]
                            if path_len > 1:
                                logger.debug("adding path_idx=%d, id=0x%08X, name=%s" % (
                                    path_idx, field_id, idaapi.get_struc_name(field_id)))
                            struc_dict = None
                            if struc_delta != 0:
                                struc_dict = {'delta': "0x%08X" % struc_delta}
                            if path_idx != 0:
                                if struc_dict is None:
                                    struc_dict = {'path_idx': "0x%08X" % path_idx}
                                else:
                                    struc_dict['path_idx'] = "0x%08X" % path_idx
                            struc_xrefs.append((op_index, struc_dict, field_id))
                #
                # STACK VARIABLE
                #
                # check if op if var stack
                if func is not None and (
                    ((op_index == 0) and idaapi.isStkvar0(f)) or
                    ((op_index == 1) and idaapi.isStkvar1(f))
                ):
                    t = idaapi.get_stkvar(op, op.addr)
                    if t is not None:
                        (member, actval) = t
                        if ea - base_address not in stackframe:
                            stackframe[ea - base_address] = list()
                        stackframe[ea - base_address].append((op_index, member, idaapi.get_spd(func, ea)))

                op_index += 1


def createBasicBlockXRefsTo(startAddress, endAddress,
                            minSegAddress, maxSegAddress, func=None):
    function_xrefs = {}
    data_xrefs = {}
    comments = {}
    strucs = {}
    stackframe = {}
    operand_view = {}
    hidden_areas = {}
    references = {}
    enums = {}

    ea = startAddress
    while ea < endAddress:
        get_function_xrefs_at_ea(startAddress, ea, function_xrefs, minSegAddress, maxSegAddress)
        get_data_xrefs_at_ea(startAddress, ea, data_xrefs, function_xrefs, minSegAddress, maxSegAddress)
        add_comments_at_ea(startAddress, ea, comments)
        get_hidden_area_at_ea(startAddress, ea, hidden_areas)
        get_struc_enum_xrefs_at_ea(startAddress, ea, strucs, enums, stackframe, func)
        get_reference_xrefs_at_ea(startAddress, ea, references)

        #
        # OPERAND VIEW
        #
        operand_view[ea - startAddress] = getOperandView(ea)

        # next instruction
        # (a, size) = getInvariantsBytes(ea, ida_function_bytes_cache[ea - startAddress:])
        ea += idc.ItemSize(ea)

    return (function_xrefs, data_xrefs, comments, strucs, enums, operand_view, hidden_areas, stackframe, references)


SEGATTR_MAP = {
    'start_ea': idc.SEGATTR_START,
    'end_ea': idc.SEGATTR_END,
    'org_base': idc.SEGATTR_ORGBASE,
    'align': idc.SEGATTR_ALIGN,
    'comb': idc.SEGATTR_COMB,
    'perm': idc.SEGATTR_PERM,
    'bitness': idc.SEGATTR_BITNESS,
    'flags': idc.SEGATTR_FLAGS,
    'sel': idc.SEGATTR_SEL,
    # TODO: find another way to handle these flags
    # 'es'       : SEGATTR_ES     ,
    # 'cs'       : SEGATTR_CS     ,
    # 'ss'       : SEGATTR_SS     ,
    # 'ds'       : SEGATTR_DS     ,
    # 'fs'       : SEGATTR_FS     ,
    # 'gs'       : SEGATTR_GS     ,
    'type': idc.SEGATTR_TYPE,
    'color': idc.SEGATTR_COLOR
}

SEGATTR_MAP_IDS = {
    # TODO: find another way to handle these flags
    idc.SEGATTR_START: 'start_ea',
    idc.SEGATTR_END: 'end_ea',
    idc.SEGATTR_ORGBASE: 'org_base',
    idc.SEGATTR_ALIGN: 'align',
    idc.SEGATTR_COMB: 'comb',
    idc.SEGATTR_PERM: 'perm',
    idc.SEGATTR_BITNESS: 'bitness',
    idc.SEGATTR_FLAGS: 'flags',
    idc.SEGATTR_SEL: 'sel',
    # SEGATTR_ES      : 'es'       ,
    # SEGATTR_CS      : 'cs'       ,
    # SEGATTR_SS      : 'ss'       ,
    # SEGATTR_DS      : 'ds'       ,
    # SEGATTR_FS      : 'fs'       ,
    # SEGATTR_GS      : 'gs'       ,
    idc.SEGATTR_TYPE: 'type',
    idc.SEGATTR_COLOR: 'color'
}

union_member_object_ids = {}
member_struc_ids = {}


def register_union_member_object_id(struc_id, member_id, object_id):
    union_member_object_ids[member_id] = object_id
    member_struc_ids[member_id] = struc_id


def get_struc_id_from_member_if(member_id):
    try:
        return member_struc_ids[member_id]
    except KeyError:

        idx = idc.GetFirstStrucIdx()
        while idx != idc.BADADDR:
            struc_id = idc.GetStrucId(idx)
            if idc.IsUnion(struc_id):
                offset = idc.GetFirstMember(struc_id)

                while offset != idc.BADADDR:
                    smember_id = idc.GetMemberId(struc_id, offset)
                    if smember_id == member_id:
                        member_struc_ids[member_id] = struc_id
                        return struc_id
                    offset = idc.GetStrucNextOff(struc_id, offset)
            idx = idc.GetNextStrucIdx(idx)
        logger.error("Could not find struc id from member id 0x%08X (name=%s)" %
                     (member_id, idaapi.get_struc_name(member_id)))
        return None


def get_object_id_of_union_member_id(hash_provider, member_id):
    try:
        return union_member_object_ids[member_id]
    except KeyError:

        idx = idc.GetFirstStrucIdx()
        while idx != idc.BADADDR:
            struc_id = idc.GetStrucId(idx)
            struc_name = idc.GetStrucName(struc_id)
            if idc.IsUnion(struc_id):

                offset = idc.GetFirstMember(struc_id)

                while offset != idc.BADADDR:
                    smember_id = idc.GetMemberId(struc_id, offset)
                    if smember_id == member_id:
                        name = idc.GetMemberName(struc_id, offset)
                        if name is not None:
                            logger.debug("found member id 0x%016X in union %s/%s" % (member_id, struc_name, name))
                            return hash_provider.get_struc_member_id(struc_id, offset, struc_name)

                    # next member
                    offset = idc.GetStrucNextOff(struc_id, offset)
            idx = idc.GetNextStrucIdx(idx)

        logger.error("Could not find member id 0x%016X in unions" % member_id)

        return None

def get_original_idb_name(local_idb_name, suffix=None):
    idbname = os.path.basename(local_idb_name)
    idbname_prefix = os.path.splitext(idbname)[0]
    idbname_extension = os.path.splitext(idbname)[1]
    if suffix is None:
        suffix = "_local"
    orig_file_name = "%s%s" % (idbname_prefix.replace(suffix, ""), idbname_extension)
    return orig_file_name


def get_local_idb_name(original_idb_name, suffix=None, subdir=None):
    idbname = os.path.basename(original_idb_name)
    idbname_prefix = os.path.splitext(idbname)[0]
    idbname_extension = os.path.splitext(idbname)[1]
    if suffix is None:
        suffix = "_local"
    local_file_name = "%s%s%s" % (idbname_prefix, suffix, idbname_extension)

    if subdir is not None:
        (head, tail) = os.path.split(local_file_name)
        local_file_name = os.path.join(head, subdir, tail)
        # create directory if necessary
        (head, tail) = os.path.split(local_file_name)
        if os.path.exists(head) is False:
            os.mkdir(head)

    return local_file_name


def remove_ida_temporary_files(idb_path):
    dot = idb_path.rfind(".")
    file_name = idb_path[:dot]
    for del_ext in ["id0", "id1", "id2", "nam", "til"]:
        try:
            os.remove(file_name + "." + del_ext)
        except:
            pass


def copy_idb_to_local_file(suffix=None, subdir=None, use_hardlink=False):
    local_file_name = get_local_idb_name(idc.GetIdbPath(), suffix)
    if subdir is not None:
        (head, tail) = os.path.split(local_file_name)
        local_file_name = os.path.join(head, subdir, tail)
        (head, tail) = os.path.split(local_file_name)
        if os.path.exists(head) is False:
            os.mkdir(head)

    if use_hardlink:
        (idb_dir, idb_name) = os.path.split(idc.GetIdbPath())
        original_idb_name = os.path.splitext(idb_name)[0]
        new_idb_name = os.path.splitext(local_file_name)[0]
        (head, tail) = os.path.split(local_file_name)
        logger.info("looking for copy-possible files in %s" % head)
        for f in os.listdir(head):
            (list_file_name, list_file_ext) = os.path.splitext(f)
            logger.info("checking if %s:%s is to be copied to %s as source name" % (
                list_file_name, list_file_ext, original_idb_name))
            if (list_file_name == original_idb_name and
                    (
                        list_file_ext in set([".nam", ".til"]) or
                        (list_file_ext.startswith(".id") and list_file_ext[-1:].isdigit()))):
                new_name = os.path.join(idb_dir, new_idb_name + list_file_ext)
                f = os.path.join(idb_dir, f)
                logger.info("Linking %s to %s" % (f, new_name))

                try:
                    os.remove(new_name)
                except:
                    pass
                os.system("/bin/cp --reflink=auto %s %s" % (f, new_name))
    else:
        idc.SaveBase(local_file_name)
        remove_ida_temporary_files(local_file_name)
    return local_file_name


def copy_idb_to_original_file(suffix=None):
    orig_file_name = get_original_idb_name(idc.GetIdbPath(), suffix)
    idc.SaveBase(orig_file_name)
    remove_ida_temporary_files(orig_file_name)
    return orig_file_name


def struc_member_list(struc_id, is_union):
    current_idx = 0
    struc = idaapi.get_struc(struc_id)
    if struc is None or struc == idc.BADADDR:
        return []

    offsets = dict()
    for current_idx in xrange(0, struc.memqty):
        offset = _yatools_ida.get_struc_member_by_idx(struc, current_idx)
        if offset not in offsets:
            name = idc.GetMemberName(struc_id, offset)
            if name is not None:
                offsets[offset] = name

    return sorted(offsets.items())


def enum_member_iterate_all(enum_id):
    const_value = idc.GetFirstConst(enum_id, -1)
    while const_value != idc.BADADDR:
        serial = 0
        const_id = idc.GetConstEx(enum_id, const_value, serial, -1)
        while const_id != idc.BADADDR:
            yield (const_id, const_value, idc.BADADDR)

            serial += 1
            const_id = idc.GetConstEx(enum_id, const_value, serial, -1)
        const_value = idc.GetNextConst(enum_id, const_value, -1)

    bmask = idc.GetFirstBmask(enum_id)
    while bmask != idc.BADADDR:
        const_value = idc.GetFirstConst(enum_id, bmask)
        while const_value != idc.BADADDR:
            # TODO must implement serial for bitfield
            const_id = idc.GetConstEx(enum_id, const_value, 0, bmask)
            yield (const_id, const_value, bmask)
            const_value = idc.GetNextConst(enum_id, const_value, bmask)
        bmask = idc.GetNextBmask(enum_id, bmask)


def SetStrucmember(struc_id, member_name, offset, flag, typeid, nitems, member_type=ya.OBJECT_TYPE_STRUCT_MEMBER,
                   name_offset=0):
    if member_name is None:
        member_name = get_default_struc_member_name(member_type, offset, name_offset)

    ret = idc.SetMemberName(struc_id, offset, member_name)
    if not ret:
        logger.debug("Error while naming sub strucmember (struc) : " +
                     "%d (struc=%s, member=%s, offset=0x%08X"
                     % (ret, idc.GetStrucName(struc_id), member_name, offset))
    else:
        ret = idc.SetMemberType(struc_id, offset, flag, typeid, nitems)
        if ret == 0:
            logger.debug("Error while setting sub strucmember type (struc) :" +
                         " %d (struc=%s, member=%s, offset=0x%08X, mflags=%d, nitems=%d, tid=0x%016X" %
                         (ret, idc.GetStrucName(struc_id), member_name, offset, flag, nitems, typeid))


address_range_get_items_cache = {}


def address_range_items_clear_cache(ea_start, ea_end=idc.BADADDR):
    try:
        del address_range_get_items_cache[(ea_start, ea_end)]
    except KeyError:
        pass


def address_range_get_items(ea_start, ea_end=idc.BADADDR):
    try:
        return address_range_get_items_cache[(ea_start, ea_end)]
    except KeyError:
        pass

    items = _yatools_ida.address_range_get_items(ea_start, ea_end)
    address_range_get_items_cache[(ea_start, ea_end)] = items
    return items


def segment_get_chunks(seg_start, seg_end):
    chunks = []
    ea = seg_start
    while ea + ya.SEGMENT_CHUNK_MAX_SIZE < seg_end:
        chunk_end = min(ea + ya.SEGMENT_CHUNK_MAX_SIZE, seg_end)
        chunks.append((ea, chunk_end))

        ea += ya.SEGMENT_CHUNK_MAX_SIZE

    chunks.append((ea, seg_end))
    return chunks


"""
returns chunks of the segment that contain the given ea list
"""


def segment_get_chunks_for_eas(seg_start, seg_end, ea_list):
    chunks = []
    for ea in ea_list:
        rel_ea = ea - seg_start
        chunk_off = rel_ea % ya.SEGMENT_CHUNK_MAX_SIZE
        chunk_start = ea - chunk_off
        chunk_end = min(chunk_start + ya.SEGMENT_CHUNK_MAX_SIZE, seg_end)
        chunks.append((chunk_start, chunk_end))
    return chunks


def get_segment_chunk_for_ea(seg_ea_start, ea, seg_end=None):
    if seg_end is None:
        seg_end = idc.SegEnd(ea)
    rel_ea = ea - seg_ea_start
    chunk_off = rel_ea % ya.SEGMENT_CHUNK_MAX_SIZE
    chunk_start = ea - chunk_off

    chunk_end = min(chunk_start + ya.SEGMENT_CHUNK_MAX_SIZE, seg_end)
    return (chunk_start, chunk_end)


idaname = "ida64" if idc.__EA64__ else "ida"
if sys.platform == "win32":
    dll = ctypes.windll[idaname + ".wll"]
elif sys.platform == "linux2":
    dll = ctypes.cdll["lib" + idaname + ".so"]
elif sys.platform == "darwin":
    dll = ctypes.cdll["lib" + idaname + ".dylib"]

if sys.platform == "linux2":
    def get_mem_usage():
        status_path = "/proc/%i/status" % os.getpid()
        f_status = open(status_path, 'r')
        lines = f_status.readlines()
        for line in lines:
            if "VmHWM" in line.split(':')[0]:
                s_kmem = line.split(':')[1].split()[0]
                return (int(s_kmem) / 1024)

else:
    from win32.get_process_memory import get_memory_usage

    def get_mem_usage():
        return get_memory_usage() / (1024 * 1024)


def ctypes_get_many_bytes_ex(ea, size):
    buf1 = ctypes.create_string_buffer(size)
    buf2 = ctypes.create_string_buffer((size + 7) / 8)
    if idc.__EA64__:
        ea = ctypes.c_int64(ea)
    dll.get_many_bytes_ex(ea, buf1, size, buf2)
    return (buf1.raw, bytearray(buf2.raw))


def address_range_get_blobs(ea_start, ea_end=idc.BADADDR):
    if ea_end == idc.BADADDR:
        ea_end = idc.SegEnd(ea_start)

    (bytes_data, bytes_mask) = ctypes_get_many_bytes_ex(ea_start, ea_end - ea_start)

    current_ea = ea_start
    current_pos = 0
    ea_mask = 0x01
    mask_offset = 0
    current_buffer = None
    buffer_start = 0x0

    blobs = {}

    while current_ea < ea_end:
        if bytes_mask[mask_offset] == 0xFF:
            # 8 bytes present
            if current_buffer is None:
                # start of area : init buffer
                buffer_start = current_ea
                current_buffer = bytearray()

            current_buffer += bytes_data[current_pos:current_pos + 8]
            current_ea += 8
            current_pos += 8
            mask_offset += 1

        elif bytes_mask[mask_offset] == 0x00:
            # 8 bytes not present
            if current_buffer is not None:
                # end of area : save buffer
                blobs[buffer_start] = current_buffer
                buffer_start = 0x0
                current_buffer = None

            current_ea += 8
            current_pos += 8
            mask_offset += 1

        else:
            if (bytes_mask[mask_offset] & ea_mask) != 0x0:
                # byte is present
                if current_buffer is None:
                    # start of area : init buffer
                    buffer_start = current_ea
                    current_buffer = bytearray()

                current_buffer += bytes_data[current_pos]

            else:
                # byte is not present
                if current_buffer is not None:
                    # end of area : save buffer
                    blobs[buffer_start] = current_buffer
                    buffer_start = 0x0
                    current_buffer = None

            if ea_mask == 0x80:
                ea_mask = 0x01
                mask_offset += 1
            else:
                ea_mask = ea_mask << 1

            current_ea += 1
            current_pos += 1

    if current_buffer is not None:
        # last buffer not recorded
        blobs[buffer_start] = current_buffer
        buffer_start = 0x0
        current_buffer = None
    return blobs


def is_userdefined_name(name, ea_name):
    suffix = "_%X" % ea_name
    return not name.endswith(suffix) or not ya.IsDefaultName(name)


def get_function_chunks(funcea):
    chunks = list()
    func = idaapi.get_func(funcea)
    fci = idaapi.func_tail_iterator_t(func, funcea)
    if fci.main():
        ch = fci.chunk()
        ea_start = ch.startEA
        ea_end = ch.endEA

        chunks.append((ea_start, ea_end))
        while fci.next():
            ch = fci.chunk()
            chunks.append((ch.startEA, ch.endEA))
    else:
        logger.error("No function chunk found at address 0x%08X" % funcea)

    return chunks


function_basic_block_cache = {}


def get_function_basic_blocks(funcea, func=None):
    try:
        cached = function_basic_block_cache[funcea]
        # 			logger.debug("function basic block cache hit for %s" % (self.yatools.address_to_hex_string(funcea)))
        return cached
    except KeyError:
        # 			logger.debug("function basic block cache miss for %s" % (self.yatools.address_to_hex_string(funcea)))
        pass

    basic_blocks = list()

    if func is None:
        func = idaapi.get_func(funcea)

    start_ea = func.startEA
    end_ea = func.endEA
    flow_chart = idaapi.qflow_chart_t()
    flow_chart.create("", func, start_ea, end_ea, 0)
    size = flow_chart.size()
    for i in range(size):
        block = flow_chart.__getitem__(i)
        block_startEA = block.startEA
        block_endEA = block.endEA
        if block_startEA != block_endEA:
            block_type = flow_chart.calc_block_type(i)
            basic_blocks.append({
                'funcEA': funcea,
                'startEA': block_startEA,
                'endEA': block_endEA,
                'block_type': block_type,
            })
    basic_blocks.sort(key=lambda x: x["startEA"])
    function_basic_block_cache[funcea] = basic_blocks
    return basic_blocks


def clear_function_basic_block_cache():
    function_basic_block_cache.clear()


def get_basic_block_at_ea(ea, funcea=None, func=None):
    if func is None:
        func = idaapi.get_func(ea)

    if funcea is None:
        funcea = func.startEA

    basic_blocks = get_function_basic_blocks(funcea, func)
    for basic_block in basic_blocks:
        startEA = basic_block['startEA']
        endEA = basic_block['endEA']
        if ea >= startEA and ea < endEA:
            return basic_block

    return None


def get_default_struc_member_name(object_type, offset, name_offset=0):
    if object_type == ya.OBJECT_TYPE_STRUCT_MEMBER:
        return "field_%X" % (offset - name_offset)
    elif object_type == ya.OBJECT_TYPE_STACKFRAME_MEMBER:
        if offset > name_offset:

            if offset - name_offset < 4:
                name = "var_s%d" % (offset - name_offset)
            else:
                name = "arg_%X" % (offset - (name_offset + 4))
            #             logger.debug("get_default_struc_member_name: offset=0x%08X, name_offset=0x%08X, retval=%s ",
            #                          offset, name_offset, name
            #                          )
            return name
        else:
            #             logger.debug("get_default_struc_member_name: offset=0x%08X, name_offset=0x%08X, retval=%s ",
            #                          offset, name_offset, "var_%X" % (name_offset-offset))
            return "var_%X" % (name_offset - offset)
    else:
        logger.warning("get_default_struc_member_name: bad object_type: %r" % (object_type))
        return None
