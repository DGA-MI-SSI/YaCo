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

#include "Ida.h"
#include "YaHelpers.hpp"

#include "YaToolsHashProvider.hpp"
#include "../Helpers.h"
#include "StringFormat.hpp"

#include <algorithm>

#ifdef _MSC_VER
#define itoa _itoa
#endif

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
#define DECL_CC_NAME(VALUE, NAME) {VALUE, NAME, sizeof NAME - 1},
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
        const auto size = print_argloc(buffer, bufsize, loc);
        if(!size)
            return;
        dst += arglog_prefix;
        dst.append(buffer, size);
        dst += '>';
    }

    void append_int(qstring& dst, int value)
    {
        char buf[65];
        itoa(value, buf, 10);
        dst += buf;
    }

    const qstring comment_prefix = "/*%";
    const qstring comment_suffix = "%*/";

    void simple_tif_to_string(qstring& dst, YaToolsHashProvider* provider, ya::Deps* deps, const tinfo_t& tif, const tinfo_t& subtif, const const_string_ref& name)
    {
        to_string(dst, tif, name.value, nullptr);
        if(!provider)
            return;

        qstring type;
        const auto ok = subtif.get_type_name(&type);
        if(!ok)
            return;

        const auto subtid = static_cast<tid_t>(netnode(type.c_str()));
        if(subtid == BADADDR)
            return;

        const auto subid = provider->get_struc_enum_object_id(subtid, ya::to_string(type), true);
        if(deps)
            deps->push_back({subid, tif, subtid});

        type.insert(0, comment_prefix);
        type += '#';
        append_uint64(type, subid);
        type += comment_suffix;
        auto comment_size = type.length();
        const auto has_name = name.value && *name.value;
        if(has_name)
        {
            type += ' ';
            comment_size += 1;
            type.append(name.value, name.size);
        }

        to_string(dst, tif, type.c_str(), nullptr);

        // move back pointers after dependency comment
        const auto pos = dst.find(type);
        if(pos == qstring::npos)
            return;

        bool first = !has_name;
        while(pos > 1 && dst[pos - 1] == '*')
        {
            dst.remove(pos - 1, 1);
            dst.insert(pos - 1 + comment_size, first ? " *" : "*");
            first = false;
        }
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

    void tif_to_string(qstring& dst, YaToolsHashProvider* provider, ya::Deps* deps, const tinfo_t& tif, const const_string_ref& name)
    {
        if(!tif.is_func())
            return simple_tif_to_string(dst, provider, deps, tif, tif, name);

        func_type_data_t fi;
        auto ok = tif.get_func_details(&fi);
        if(!ok)
            ok = tif.get_func_details(&fi, GTD_NO_ARGLOCS);
        if(!ok)
            return to_string(dst, tif, name.value, nullptr);

        // build type manually
        const auto rettype = tif.get_rettype();
        print_type(dst, provider, deps, rettype, {});
        
        const auto cc = tif.get_cc();
        add_suffix(dst, get_calling_convention(cc));

        char buffer[256];
        append_location(dst, cc, buffer, sizeof buffer, fi.retloc);
        add_suffix(dst, name.size ? name : default_function_name);

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
            print_type(arg, provider, deps, it.type, make_string_ref(argname));
            dst += arg;
        }
        if(cc == CM_CC_ELLIPSIS || cc == CM_CC_SPECIALE)
            dst += ellipsis_argument;
        dst += ')';
    }
}

namespace std
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

namespace
{
    void cleanup_deps(ya::Deps& deps)
    {
        std::sort(deps.begin(), deps.end());
        deps.erase(std::unique(deps.begin(), deps.end()), deps.end());
    }
}

void ya::print_type(qstring& dst, YaToolsHashProvider* provider, Deps* deps, const tinfo_t& tif, const const_string_ref& name)
{
    tif_to_string(dst, provider, deps, tif, name);
    if(deps)
        cleanup_deps(*deps);
}

namespace
{
    tinfo_t get_tinfo_from_struct_tid(tid_t tid)
    {
        tinfo_t tif;
        const auto struc = get_struc(tid);
        if(!struc)
            return tif;

        if(struc->ordinal == BADADDR)
            return tif;

        const auto ok = tif.get_numbered_type(idati, struc->ordinal);
        if(!ok)
            tif.clear();

        return tif;
    }

    tinfo_t get_tinfo_from_enum_tid(tid_t tid)
    {
        tinfo_t tif;
        const auto guess = guess_tinfo2(tid, &tif);
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
        {DT_TYPE,   FF_DWRD,        "dword"},
        {DT_TYPE,   FF_QWRD,        "qword"},
        {DT_TYPE,   FF_TBYT,        "tbyte"},
        {DT_TYPE,   FF_ASCI,        "ascii"},
        {DT_TYPE,   FF_STRU,        "struct"},
        {DT_TYPE,   FF_OWRD,        "oword"},
        {DT_TYPE,   FF_FLOAT,       "float"},
        {DT_TYPE,   FF_DOUBLE,      "double"},
        {DT_TYPE,   FF_PACKREAL,    "packreal"},
        {DT_TYPE,   FF_ALIGN,       "align"},
        {DT_TYPE,   FF_3BYTE,       "3byte"},
        {DT_TYPE,   FF_CUSTOM,      "custom"},
        {DT_TYPE,   FF_YWRD,        "yword"},
        {DT_TYPE,   FF_ZWRD,        "zword"},
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
        {MS_COMM,   FF_VAR,         "is_variable_byte"},
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
    if(isCode(flags))
        for(const auto it : g_codeflags)
            if(flags & it.mask & it.value)
                add(it.name);
    if(isData(flags))
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

tinfo_t ya::get_tinfo(flags_t flags, const opinfo_t* op)
{
    tinfo_t empty;
    if(!op)
        return empty;

    if(isStruct(flags))
        return get_tinfo_from_struct_tid(op->tid);

    if(isEnum0(flags))
        return get_tinfo_from_enum_tid(op->ec.tid);

    return empty;
}

tinfo_t ya::get_tinfo(ea_t ea)
{
#ifdef _DEBUG
    const auto dump = dump_flags(getFlags(ea));
    UNUSED(dump);
#endif

    tinfo_t tif;
    auto ok = get_tinfo2(ea, &tif);
    if(ok)
        return tif;

    // try harder
    opinfo_t op;
    const auto flags = getFlags(ea);
    const auto has_op = get_opinfo(ea, 0, flags, &op);
    return get_tinfo(flags, has_op ? &op : nullptr);
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
    print_type(buf, nullptr, nullptr, tif, {nullptr, 0});
    return to_string(buf);
}
