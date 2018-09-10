//  Copyright (C) 2017 The YaCo Authors
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include "YaTypes.hpp"
#include "Ida.h"
#include "YaHelpers.hpp"
#include "Helpers.h"
#include "Strucs.hpp"

#include "Hash.hpp"

#include <algorithm>

#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("ya", (FMT), ## __VA_ARGS__)

namespace
{
    char back(const qstring& v)
    {
        return v[v.length() - 1];
    }

    void to_string(qstring& buf, const tinfo_t& tif, const char* name, const char* cmt)
    {
        buf.qclear();
        const auto ok = tif.print(&buf, name, 0, 0, 0, nullptr, cmt);
        if(!ok)
            return;
        while(!buf.empty() && back(buf) == ' ')
            buf.resize(buf.length() - 1);
    }

    const struct { cm_t cc; const_string_ref name; } cc_names[] =
    {
#define DECL_CC_NAME(VALUE, NAME) {VALUE, {NAME, sizeof NAME - 1}},
        DECL_CC_NAME(CM_CC_CDECL,       "__cdecl")
        DECL_CC_NAME(CM_CC_STDCALL,     "__stdcall")
        DECL_CC_NAME(CM_CC_PASCAL,      "__pascal")
        DECL_CC_NAME(CM_CC_FASTCALL,    "__fastcall")
        DECL_CC_NAME(CM_CC_THISCALL,    "__thiscall")
        DECL_CC_NAME(CM_CC_SPECIAL,     "__usercall")
        DECL_CC_NAME(CM_CC_SPECIALE,    "__usercall")
        DECL_CC_NAME(CM_CC_SPECIALP,    "__usercall")
#undef DECL_CC_NAME
    };
    const const_string_ref empty_string = {nullptr, 0};

    const const_string_ref& get_calling_convention(cm_t cc)
    {
        for(const auto& it : cc_names)
            if(it.cc == cc)
                return it.name;
        return empty_string;
    }

    void add_suffix(qstring& dst, const const_string_ref& suffix)
    {
        if(!suffix.value || !*suffix.value)
            return;
        if(!dst.empty() && back(dst) != '*' && back(dst) != ' ' && back(dst) != '/')
            dst += ' ';
        dst.append(suffix.value, suffix.size);
    }

    const qstring arglog_prefix = "@<";

    void append_location(qstring& dst, cm_t cc, char* buffer, size_t bufsize, const argloc_t& loc)
    {
        if(cc != CM_CC_SPECIAL && cc != CM_CC_SPECIALE && cc != CM_CC_SPECIALP)
            return;
        if(loc.is_badloc())
            return;
        const auto size = print_argloc(buffer, bufsize, loc);
        if(!size)
            return;
        dst += arglog_prefix;
        dst.append(buffer, size);
        dst += '>';
    }

    void simple_tif_to_string(qstring& dst, ya::TypeToStringMode_e mode, ya::Deps* deps, const tinfo_t& tif, const const_string_ref& name)
    {
        to_string(dst, tif, name.value, nullptr);
        if(mode == ya::NO_HEURISTIC)
            return;
        
        auto subtif = tif;
        while(subtif.remove_ptr_or_array())
            continue;

        qstring subtype;
        const auto ok = subtif.get_type_name(&subtype);
        if(!ok)
            return;

        const auto subtid = node2ea(netnode(subtype.c_str()));
        if(subtid == BADADDR)
            return;

        const auto subid = get_struc(subtid) ?
            strucs::hash(subtid) :
            hash::hash_enum(ya::to_string_ref(subtype));
        if(deps)
            deps->push_back({subid, subtid});
    }

    #define DECLARE_REF(name, value)\
    const char name ## _txt[] = value;\
    const const_string_ref name = {name ## _txt, sizeof name ## _txt - 1};
    DECLARE_REF(hidden_suffix, "__hidden");
    DECLARE_REF(return_ptr_suffix, "__return_ptr");
    DECLARE_REF(struct_ptr_suffix, "__struct_ptr");
    DECLARE_REF(default_function_name, "sub");
#undef DECLARE_REF

    const qstring comma_separator = ", ";
    const qstring ellipsis_argument = ", ...";

    const_string_ref skip_leading_underscores(const const_string_ref& txt)
    {
        if(!txt.size)
            return txt;
        size_t skip = 0;
        while(txt.value[skip] == ' ')
            skip++;
        while(txt.value[skip] == '_')
            skip++;
        return {&txt.value[skip], txt.size - skip};
    }

    void tif_to_string(qstring& dst, ya::TypeToStringMode_e mode, ya::Deps* deps, const tinfo_t& tif, const const_string_ref& name)
    {
        if(!tif.is_func())
            return simple_tif_to_string(dst, mode, deps, tif, name);

        func_type_data_t fi;
        auto ok = tif.get_func_details(&fi);
        if(!ok)
            ok = tif.get_func_details(&fi, GTD_NO_ARGLOCS);
        if(!ok)
            return to_string(dst, tif, name.value, nullptr);

        // build type manually
        const auto rettype = tif.get_rettype();
        print_type(dst, mode, deps, rettype, {});
        
        const auto cc = tif.get_cc();
        add_suffix(dst, get_calling_convention(cc));
        add_suffix(dst, name.size ? name : default_function_name);

        // append return type usercall *after* function name
        char buffer[256];
        append_location(dst, cc, buffer, sizeof buffer, fi.retloc);

        size_t i = 0;
        std::string argname;
        qstring arg;
        dst += '(';
        for(const auto& it : fi)
        {
            arg.qclear();
            if(it.flags & FAI_HIDDEN)
                add_suffix(arg, hidden_suffix);
            if(it.flags & FAI_RETPTR)
                add_suffix(arg, return_ptr_suffix);
            if(it.flags & FAI_STRUCT)
                add_suffix(arg, struct_ptr_suffix);
            // FIXME ida remove leading underscores on argument names...
            add_suffix(arg, skip_leading_underscores(ya::to_string_ref(it.name)));
            append_location(arg, cc, buffer, sizeof buffer, it.argloc);
            if(i++)
                dst += comma_separator;
            argname.assign(arg.c_str(), arg.length());
            print_type(arg, mode, deps, it.type, make_string_ref(argname));
            dst += arg;
        }
        if(cc == CM_CC_ELLIPSIS || cc == CM_CC_SPECIALE)
            dst += ellipsis_argument;
        dst += ')';
    }
}

namespace ya
{
    bool operator==(const ya::Dependency& a, const ya::Dependency& b)
    {
        return a.id == b.id;
    }

    bool operator<(const ya::Dependency& a, const ya::Dependency& b)
    {
        return a.id < b.id;
    }
}

void ya::print_type(qstring& dst, TypeToStringMode_e mode, Deps* deps, const tinfo_t& tif, const const_string_ref& name)
{
    tif_to_string(dst, mode, deps, tif, name);
    if(deps)
        ya::dedup(*deps);
}

namespace
{
    tinfo_t get_tinfo_from_struct_tid(tid_t tid)
    {
        tinfo_t tif;
        const auto struc = get_struc(tid);
        if(!struc)
            return tif;

        if(struc->ordinal == -1)
            return tif;

        const auto ok = tif.get_numbered_type(get_idati(), struc->ordinal);
        if(!ok)
            tif.clear();

        return tif;
    }

    tinfo_t get_tinfo_from_enum_tid(tid_t tid)
    {
        tinfo_t tif;
        const auto guess = guess_tinfo(&tif, tid);
        if(guess != GUESS_FUNC_OK)
            tif.clear();

        return tif;
    }

    using FlagName = struct { uint32_t mask; uint32_t value; char name[32]; };

    static const FlagName g_codeflags[] =
    {
        {MS_CODE, FF_FUNC, "function"},
        {MS_CODE, FF_IMMD, "immediate_value"},
        {MS_CODE, FF_JUMP, "jump"},
    };

    static const FlagName g_dataflags[] = 
    {
        {DT_TYPE,   FF_BYTE,        "byte"},
        {DT_TYPE,   FF_WORD,        "word"},
        {DT_TYPE,   FF_DWORD,       "dword"},
        {DT_TYPE,   FF_QWORD,       "qword"},
        {DT_TYPE,   FF_TBYTE,       "tbyte"},
        {DT_TYPE,   FF_STRLIT,      "ascii"},
        {DT_TYPE,   FF_STRUCT,      "struct"},
        {DT_TYPE,   FF_OWORD,       "oword"},
        {DT_TYPE,   FF_FLOAT,       "float"},
        {DT_TYPE,   FF_DOUBLE,      "double"},
        {DT_TYPE,   FF_PACKREAL,    "packreal"},
        {DT_TYPE,   FF_ALIGN,       "align"},
        {DT_TYPE,   FF_CUSTOM,      "custom"},
        {DT_TYPE,   FF_YWORD,        "yword"},
#ifdef FF_ZWORD
        {DT_TYPE,   FF_ZWORD,        "zword"},
#endif
    };

    static const FlagName g_commonflags[] =
    {
        {MS_COMM,   FF_COMM,        "has_comments"},
        {MS_COMM,   FF_REF,         "has_references"},
        //{MS_COMM,   FF_LINE,        "has_next_or_prev_lines"},
        {MS_COMM,   FF_NAME,        "has_name"},
        {MS_COMM,   FF_LABL,        "has_dummy_name"},
        {MS_COMM,   FF_FLOW,        "exec_flow_from_prev_instruction"},
        {MS_COMM,   FF_SIGN,        "inverted_sign_of_operands"},
        {MS_COMM,   FF_BNOT,        "bitwise_negation_of_operands"},
        {MS_COMM,   FF_UNUSED,      "unused"},
    };

    static const FlagName g_operandflags[] =
    {
        //{MS_0TYPE,  FF_0VOID,       "void.0"},
        {MS_0TYPE,  FF_0NUMH,       "hexadecimal.0"},
        {MS_0TYPE,  FF_0NUMD,       "decimal.0"},
        {MS_0TYPE,  FF_0CHAR,       "char.0"},
        {MS_0TYPE,  FF_0SEG,        "segment.0"},
        {MS_0TYPE,  FF_0OFF,        "offset.0"},
        {MS_0TYPE,  FF_0NUMB,       "binary.0"},
        {MS_0TYPE,  FF_0NUMO,       "octal.0"},
        {MS_0TYPE,  FF_0ENUM,       "enumeration.0"},
        {MS_0TYPE,  FF_0FOP,        "forced_operand.0"},
        {MS_0TYPE,  FF_0STRO,       "struct_offset.0"},
        {MS_0TYPE,  FF_0STK,        "stack_variable.0"},
        {MS_0TYPE,  FF_0FLT,        "float.0"},
        {MS_0TYPE,  FF_0CUST,       "custom.0"},
        //{MS_1TYPE,  FF_1VOID,       "void.1"},
        {MS_1TYPE,  FF_1NUMH,       "hexadecimal.1"},
        {MS_1TYPE,  FF_1NUMD,       "decimal.1"},
        {MS_1TYPE,  FF_1CHAR,       "char.1"},
        {MS_1TYPE,  FF_1SEG,        "segment.1"},
        {MS_1TYPE,  FF_1OFF,        "offset.1"},
        {MS_1TYPE,  FF_1NUMB,       "binary.1"},
        {MS_1TYPE,  FF_1NUMO,       "octal.1"},
        {MS_1TYPE,  FF_1ENUM,       "enumeration.1"},
        {MS_1TYPE,  FF_1FOP,        "forced_operand.1"},
        {MS_1TYPE,  FF_1STRO,       "struct_offset.1"},
        {MS_1TYPE,  FF_1STK,        "stack_variable.1"},
        {MS_1TYPE,  FF_1FLT,        "float.1"},
        {MS_1TYPE,  FF_1CUST,       "custom.1"},
    };

    static const FlagName g_valueflags[] = 
    {
        {FF_IVL,    FF_IVL,         "byte_has_value"},
    };

    static const FlagName g_types[] =
    {
        {MS_CLS,    FF_CODE,    "code"},
        {MS_CLS,    FF_DATA,    "data"},
        {MS_CLS,    FF_TAIL,    "tail"},
        {MS_CLS,    FF_UNK,     "unknown"},
    };
}

std::string ya::dump_flags(flags_t flags)
{
    std::string reply;
    bool first = true;
    const auto add = [&](const char* value)
    {
        if(!first)
            reply += ", ";
        reply += value;
        first = false;
    };
    for(const auto it : g_types)
        if((flags & it.mask) == it.value)
            add(it.name);
    if(is_code(flags))
        for(const auto it : g_codeflags)
            if(flags & it.mask & it.value)
                add(it.name);
    if(is_data(flags))
        for(const auto it : g_dataflags)
            if((flags & it.mask) == it.value)
                add(it.name);
    for(const auto it : g_commonflags)
        if(flags & it.mask & it.value)
            add(it.name);
    for(const auto it : g_operandflags)
        if((flags & it.mask) == it.value)
            add(it.name);
    for(const auto it : g_valueflags)
        if((flags & it.mask) == it.value)
            add(it.name);
    return reply;
}

tinfo_t ya::get_tinfo_from_op(flags_t flags, const opinfo_t* op)
{
    tinfo_t empty;
    if(!op)
        return empty;

    if(is_struct(flags))
        return get_tinfo_from_struct_tid(op->tid);

    if(is_enum0(flags))
        return get_tinfo_from_enum_tid(op->ec.tid);

    return empty;
}

tinfo_t ya::get_tinfo(ea_t ea)
{
#ifdef _DEBUG
    const auto dump = dump_flags(get_flags(ea));
    UNUSED(dump);
#endif

    tinfo_t tif;
    auto ok = get_tinfo(&tif, ea);
    if(ok)
        return tif;

    // try harder
    opinfo_t op;
    const auto flags = get_flags(ea);
    const auto has_op = get_opinfo(&op, ea, 0, flags);
    return get_tinfo_from_op(flags, has_op ? &op : nullptr);
}

std::string ya::get_type(ea_t ea)
{
    // print_tinfo has bugs, instead we regenerate type ourselves
    const auto tif = get_tinfo(ea);
    if(tif.empty())
        return {};

    // do NOT include function name in prototype
    // - names are set elsewhere
    // - mangled c++ names are rejected as prototype
    qstring buf;
    print_type(buf, ya::NO_HEURISTIC, nullptr, tif, {nullptr, 0});
    return to_string(buf);
}

#ifdef __EA64__
#define PRIXEA "llX"
#define PRIuEA "llu"
#else
#define PRIXEA "X"
#define PRIuEA "u"
#endif

namespace
{
    // use a macro & ensure compiler statically check snprintf
    #define TO_FMT(FMT, VALUE)\
        [&](char* buf, size_t szbuf) { return snprintf(buf, szbuf, FMT, VALUE); }
}

const_string_ref ya::get_default_name(qstring& buffer, ea_t offset, func_t* func)
{
    buffer.resize(std::max(buffer.size(), static_cast<size_t>(32)));
    if(!func)
        return ya::read_string_from(buffer, TO_FMT("field_%" PRIXEA, offset));
    if(offset <= func->frsize)
        return ya::read_string_from(buffer, TO_FMT("var_%" PRIXEA, func->frsize - offset));
    if(offset < func->frsize + 4 + func->frregs)
        return ya::read_string_from(buffer, TO_FMT("var_s%" PRIuEA, offset - func->frsize));
    return ya::read_string_from(buffer, TO_FMT("arg_%" PRIXEA, offset - func->frsize - 4 - func->frregs));
}

namespace ya
{
    range_t get_range_item(ea_t ea)
    {
        return range_t{get_item_head(ea), get_item_end(ea)};
    }

    range_t get_range_code(ea_t ea, ea_t min, ea_t max)
    {
        const auto seg = getseg(ea);
        if(!seg)
            return range_t();

        min = std::max(min, seg->start_ea);
        max = std::min(max, seg->end_ea);

        const auto item = get_range_item(ea);
        auto start = item.start_ea;
        const auto func = get_func(item.start_ea);
        while(true)
        {
            const auto prev = get_range_item(start - 1);
            if(!is_code(get_flags(prev.start_ea)) || get_func(prev.start_ea) != func)
                break;
            if(prev.start_ea < min)
                break;
            start = prev.start_ea;
        }
        auto end = item.end_ea;
        while(end < max)
        {
            const auto next = get_range_item(end);
            if(!is_code(get_flags(next.start_ea)) || get_func(next.start_ea) != func)
                break;
            end = next.end_ea;
        }
        return range_t{start, end};
    }

    std::vector<ea_t> get_all_items(ea_t start, ea_t end)
    {
        std::vector<ea_t> items;

        // add previous overlapped item
        auto ea = start;
        const auto curr = ya::get_range_item(ea);
        if(curr.contains(ea))
            ea = curr.start_ea;

        const auto allowed = range_t{start, end};
        const auto add_ea = [&](ea_t x)
        {
            const auto flags = get_flags(x);
            if(is_code(flags) || ya::is_item(flags))
                if(allowed.contains(x))
                    items.emplace_back(x);
        };

        // find all interesting items
        while(ea != BADADDR && ea < end)
        {
            const auto flags = get_flags(ea);
            if(is_code(flags))
            {
                const auto func = get_func(ea);
                const auto code = ya::get_range_code(ea, start, end);
                if(func)
                    add_ea(func->start_ea);
                else if(code.contains(ea))
                    add_ea(code.start_ea);
                ea = code.end_ea;
                continue;
            }
            add_ea(ea);
            ea = next_not_tail(ea);
        }

        dedup(items);
        return items;
    }

    bool is_item(flags_t flags)
    {
        return has_cmt(flags)
            || has_xref(flags)
            || has_extra_cmts(flags)
            || has_any_name(flags)
            || !!(flags & FF_SIGN)
            || !!(flags & FF_BNOT)
            || is_defarg0(flags)
            || is_defarg1(flags)
            || (is_data(flags) && !is_byte(flags));
    }
}
