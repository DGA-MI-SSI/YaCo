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

#include <YaTypes.hpp>
#include "Ida.h"

#include "IDANativeModel.hpp"
#include "YaToolsHashProvider.hpp"

#include <Logger.h>
#include <Yatools.h>
#include "../Helpers.h"

#include <regex>

#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("IDANativeModel", (FMT), ## __VA_ARGS__)

#ifdef __EA64__
#define EA_FMT  "%llx"
#else
#define EA_FMT  "%x"
#endif

#define FAIL_AND_RETURN(FMT, ...) do {\
    LOG(ERROR, FMT, __VA_ARGS__);\
    return {};\
} while(0)

namespace
{
    std::string to_string(const qstring& q)
    {
        return {q.c_str(), q.length()};
    }

    std::string to_string(const tinfo_t& tif, const char* name)
    {
        qstring out;
        const auto ok = tif.print(&out, name);
        if(!ok)
            return {};
        auto value = to_string(out);
        while(!value.empty() && value.back() == ' ')
            value.resize(value.size() - 1);
        return value;
    }

    std::string get_calling_convention(cm_t cc)
    {
        switch(cc)
        {
            case CM_CC_CDECL:       return "__cdecl";
            case CM_CC_STDCALL:     return "__stdcall";
            case CM_CC_PASCAL:      return "__pascal";
            case CM_CC_FASTCALL:    return "__fastcall";
            case CM_CC_THISCALL:    return "__thiscall";
            case CM_CC_SPECIAL:     return "__usercall";
            case CM_CC_SPECIALE:    return "__usercall";
            case CM_CC_SPECIALP:    return "__usercall";
            default:                return "";
        }
    }

    void add_suffix(std::string& dst, const std::string& suffix)
    {
        if(suffix.empty())
            return;
        if(!dst.empty() && dst.back() != '*' && dst.back() != ' ')
            dst += " ";
        dst += suffix;
    }

    void append_location(std::string& dst, cm_t cc, char* buffer, size_t bufsize, const argloc_t& loc)
    {
        if(cc != CM_CC_SPECIAL && cc != CM_CC_SPECIALE && cc != CM_CC_SPECIALP)
            return;
        const auto size = print_argloc(buffer, bufsize, loc);
        if(!size)
            return;
        dst += "@<" + std::string{buffer, size} + ">";
    }

    std::regex r_leading_underscores {"^\\s*_+"};

    std::string get_type_from(const tinfo_t& tif, const char* name)
    {
        if(!tif.is_func())
            return to_string(tif, name);

        func_type_data_t fi;
        auto ok = tif.get_func_details(&fi);
        if(!ok)
            ok = tif.get_func_details(&fi, GTD_NO_ARGLOCS);
        if(!ok)
            return to_string(tif, name);

        // build type manually
        char buffer[256];
        auto type = get_type_from(tif.get_rettype(), nullptr);
        const auto cc = tif.get_cc();
        add_suffix(type, get_calling_convention(cc));
        append_location(type, cc, buffer, sizeof buffer, fi.retloc);
        if(type.back() != '*')
            type += " ";
        type += "sub(";

        size_t i = 0;
        for(const auto& it : fi)
        {
            std::string it_name;
            if(it.flags & FAI_HIDDEN)
                add_suffix(it_name, "__hidden");
            if(it.flags & FAI_RETPTR)
                add_suffix(it_name, "__return_ptr");
            if(it.flags & FAI_STRUCT)
                add_suffix(it_name, "__struct_ptr");
            // FIXME ida remove leading underscores on argument names...
            auto argname = to_string(it.name);
            argname = std::regex_replace(argname, r_leading_underscores, "");
            add_suffix(it_name, argname);
            append_location(it_name, cc, buffer, sizeof buffer, it.argloc);
            if(i++)
                type += ", ";
            type += get_type_from(it.type, it_name.data());
        }
        if(cc == CM_CC_ELLIPSIS || cc == CM_CC_SPECIALE)
            type += ", ...";
        return type + ")";
    }
}

std::string IDANativeModel::get_type(ea_t ea)
{
    // print_tinfo has bugs, instead we regenerate type ourselves
    tinfo_t tif;
    auto ok = get_tinfo2(ea, &tif);
    if(!ok)
        return {};

    // do NOT include function name in prototype
    // - names are set elsewhere
    // - mangled c++ names are rejected as prototype
    auto type = get_type_from(tif, nullptr);
    return type;
}

void IDANativeModel::start_object(IModelVisitor& v, YaToolObjectType_e type, YaToolObjectId id, YaToolObjectId parent, ea_t ea)
{
    v.visit_start_reference_object(type);
    v.visit_id(id);
    v.visit_start_object_version();
    if(parent)
        v.visit_parent_id(parent);
    v.visit_address(ea);
}

namespace
{
    const char               gEq[] = "equipment";
    const char               gOs[] = "os";
    const const_string_ref   gEqRef = {gEq, sizeof gEq - 1};
    const const_string_ref   gOsRef = {gOs, sizeof gOs - 1};

    const int DEFAULT_NAME_FLAGS = 0;
}

void IDANativeModel::visit_system(IModelVisitor& v, ea_t ea)
{
    v.visit_start_matching_systems();
    v.visit_start_matching_system(ea);
    v.visit_matching_system_description(gEqRef, eqref_);
    v.visit_matching_system_description(gOsRef, osref_);
    v.visit_end_matching_system();
    v.visit_end_matching_systems();
}

template<typename T>
static std::string to_py_hex(T value)
{
    std::stringstream ss;
    ss << "0x" << std::hex << value << "L";
    return ss.str();
}

void IDANativeModel::accept_enum_member(IModelVisitor& v, YaToolsHashProvider* provider, YaToolObjectId parent, uint64_t veid, uint64_t vconst_id)
{
    const auto eid = static_cast<enum_t>(veid);
    const auto const_id = static_cast<const_t>(vconst_id);

    qstring const_name;
    get_enum_member_name(&const_name, const_id);
    const auto bmask = get_enum_member_bmask(const_id);
    const auto const_value = get_enum_member_value(const_id);
    const auto enum_name = get_enum_name(eid);
    const auto id = provider->get_enum_member_id(eid, to_string(enum_name), const_id, to_string(const_name), to_py_hex(const_value), bmask, true);
    start_object(v, OBJECT_TYPE_ENUM_MEMBER, id, parent, const_value);
    v.visit_size(0);
    v.visit_name({const_name.c_str(), const_name.length()}, DEFAULT_NAME_FLAGS);
    if(bmask != BADADDR)
        v.visit_flags(static_cast<flags_t>(bmask));

    std::vector<char> buffer(64);
    for(const auto rpt : {false, true})
    {
        while(true)
        {
            const auto n = get_enum_member_cmt(const_id, rpt, &buffer[0], buffer.size());
            if(n < 0)
                break;
            if(n + 1 < static_cast<ssize_t>(buffer.size()))
            {
                v.visit_header_comment(rpt, {&buffer[0], static_cast<size_t>(n)});
                break;
            }
            // retry with bigger buffer
            buffer.resize(buffer.size() * 2);
        }
    }
    visit_system(v, const_value);
    v.visit_end_object_version();
    v.visit_end_reference_object();
}

void IDANativeModel::set_system(const const_string_ref& eq, const const_string_ref& os)
{
    eq_ = make_string(eq);
    eqref_ = make_string_ref(eq_);
    os_ = make_string(os);
    osref_ = make_string_ref(os_);
}
