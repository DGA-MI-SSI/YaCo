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

#ifdef _MSC_VER
#   include <optional.hpp>
using namespace nonstd;
#else
#   include <experimental/optional>
using namespace std::experimental;

#endif
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
    const int DEFAULT_OPERAND = 0;
}

void IDANativeModel::set_system(const const_string_ref& eq, const const_string_ref& os)
{
    eq_ = make_string(eq);
    eqref_ = make_string_ref(eq_);
    os_ = make_string(os);
    osref_ = make_string_ref(os_);
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

namespace
{
    template<typename T>
    std::string to_py_hex(T value)
    {
        std::stringstream ss;
        ss << "0x" << std::hex << value << "L";
        return ss.str();
    }

    template<typename T>
    optional<size_t> read_string_from(qstring& buffer, const T& read)
    {
        while(true)
        {
            const auto n = read();
            if(n < 0)
                return nullopt;
            if(n + 1 < static_cast<ssize_t>(buffer.size()))
                return n;
            buffer.resize(buffer.size() * 2);
        }
    }

    template<typename T>
    void visit_header_comments(IModelVisitor& v, qstring& buffer, const T& read)
    {
        for(const auto rpt : {false, true})
        {
            while(true)
            {
                const auto n = read(rpt, &buffer[0], buffer.size());
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
    }

    template<typename T>
    void walk_enum_members_with_bmask(enum_t eid, bmask_t bmask, const T& operand)
    {
        const_t first_cid;
        uchar serial;
        for(auto value = get_first_enum_member(eid, bmask); value != BADADDR; value = get_next_enum_member(eid, value, bmask))
            for(auto cid = first_cid = get_first_serial_enum_member(eid, value, &serial, bmask); cid != BADADDR; cid = get_next_serial_enum_member(first_cid, &serial))
                operand(cid, value, bmask);
    }

    template<typename T>
    void walk_enum_members(enum_t eid, const T& operand)
    {
        walk_enum_members_with_bmask(eid, DEFMASK, operand);
        for(auto fmask = get_first_bmask(eid); fmask != BADADDR; fmask = get_next_bmask(eid, fmask))
            walk_enum_members_with_bmask(eid, fmask, operand);
    }

    struct EnumMember
    {
        YaToolObjectId  id;
        const_t         const_id;
        qstring         const_name;
        uval_t          const_value;
        bmask_t         bmask;
    };
}

YaToolObjectId IDANativeModel::accept_enum(IModelVisitor& visitor, YaToolsHashProvider* provider, uint64_t eid)
{
    qstring buffer;
    buffer.resize(64);

    const auto enum_id = static_cast<enum_t>(eid);
    qstring enum_name;
    get_enum_name(&enum_name, enum_id);
    const auto id = provider->get_struc_enum_object_id(enum_id, to_string(enum_name), true);
    const auto idx = get_enum_idx(enum_id);
    start_object(visitor, OBJECT_TYPE_ENUM, id, 0, idx);
    visitor.visit_size(get_enum_width(enum_id));
    visitor.visit_name({enum_name.c_str(), enum_name.length()}, DEFAULT_NAME_FLAGS);
    const auto flags = get_enum_flag(enum_id);
    const auto bitfield = is_bf(enum_id) ? ENUM_FLAGS_IS_BF : 0;
    visitor.visit_flags(flags | bitfield);
    visit_header_comments(visitor, buffer, [&](bool repeated, char* buf, size_t szbuf)
    {
        return get_enum_cmt(enum_id, repeated, buf, szbuf);
    });

    visitor.visit_start_xrefs();
    std::vector<EnumMember> members;
    walk_enum_members(enum_id, [&](const_t const_id, uval_t const_value, bmask_t bmask)
    {
        get_enum_member_name(&buffer, const_id);
        const auto member_id = provider->get_enum_member_id(enum_id, to_string(enum_name), const_id, to_string(buffer), to_py_hex(const_value), bmask, true);
        visitor.visit_start_xref(0, member_id, DEFAULT_OPERAND);
        visitor.visit_end_xref();
        members.push_back({member_id, const_id, buffer, const_value, bmask});
    });
    visitor.visit_end_xrefs();

    visit_system(visitor, idx);
    visitor.visit_end_object_version();
    visitor.visit_end_reference_object();

    for(const auto& m : members)
    {
        start_object(visitor, OBJECT_TYPE_ENUM_MEMBER, m.id, id, m.const_value);
        visitor.visit_size(0);
        visitor.visit_name({m.const_name.c_str(), m.const_name.length()}, DEFAULT_NAME_FLAGS);
        if(m.bmask != BADADDR)
            visitor.visit_flags(static_cast<flags_t>(m.bmask));
        visit_header_comments(visitor, buffer, [&](bool repeated, char* buf, size_t szbuf)
        {
            return get_enum_member_cmt(m.const_id, repeated, buf, szbuf);
        });
        visit_system(visitor, m.const_value);
        visitor.visit_end_object_version();
        visitor.visit_end_reference_object();
    }

    return id;
}