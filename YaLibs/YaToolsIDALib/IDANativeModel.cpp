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
#include "YaHelpers.hpp"

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
    std::string to_string(const tinfo_t& tif, const char* name)
    {
        qstring out;
        const auto ok = tif.print(&out, name);
        if(!ok)
            return {};
        auto value = ya::to_string(out);
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
            auto argname = ya::to_string(it.name);
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

    const char               gEq[] = "equipment";
    const char               gOs[] = "os";
    const char               gEmpty[] = "";
    const const_string_ref   gEqRef = {gEq, sizeof gEq - 1};
    const const_string_ref   gOsRef = {gOs, sizeof gOs - 1};
    const const_string_ref   gEmptyRef = {gEmpty, sizeof gEmpty - 1};

    const int DEFAULT_NAME_FLAGS = 0;
    const int DEFAULT_OPERAND = 0;
}

IDANativeModel::IDANativeModel()
    : provider_(nullptr)
    , eqref_(gEmptyRef)
    , osref_(gEmptyRef)
{
}

void IDANativeModel::set_system(const const_string_ref& eq, const const_string_ref& os)
{
    eq_ = make_string(eq);
    eqref_ = make_string_ref(eq_);
    os_ = make_string(os);
    osref_ = make_string_ref(os_);
}

void IDANativeModel::set_provider(YaToolsHashProvider* provider)
{
    provider_ = provider;
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

void IDANativeModel::finish_object(IModelVisitor& v, ea_t ea)
{
    v.visit_start_matching_systems();
    v.visit_start_matching_system(ea);
    v.visit_matching_system_description(gEqRef, eqref_);
    v.visit_matching_system_description(gOsRef, osref_);
    v.visit_end_matching_system();
    v.visit_end_matching_systems();
    v.visit_end_object_version();
    v.visit_end_reference_object();
}

namespace
{
    template<typename T>
    void visit_header_comments(IModelVisitor& v, qstring& buffer, const T& read)
    {
        for(const auto rpt : {false, true})
        {
            ya::read_string_from(buffer, [&]
            {
                return read(rpt);
            });
            if(!buffer.empty())
                v.visit_header_comment(rpt, ya::to_string_ref(buffer));
        }
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

YaToolObjectId IDANativeModel::accept_enum(IModelVisitor& visitor, uint64_t eid)
{
    qstring buffer;
    buffer.resize(64);

    const auto enum_id = static_cast<enum_t>(eid);
    qstring enum_name;
    get_enum_name(&enum_name, enum_id);
    const auto id = provider_->get_struc_enum_object_id(enum_id, ya::to_string(enum_name), true);
    const auto idx = get_enum_idx(enum_id);
    start_object(visitor, OBJECT_TYPE_ENUM, id, 0, idx);
    visitor.visit_size(get_enum_width(enum_id));
    visitor.visit_name(ya::to_string_ref(enum_name), DEFAULT_NAME_FLAGS);
    const auto flags = get_enum_flag(enum_id);
    const auto bitfield = is_bf(enum_id) ? ENUM_FLAGS_IS_BF : 0;
    visitor.visit_flags(flags | bitfield);
    visit_header_comments(visitor, buffer, [&](bool repeated)
    {
        return get_enum_cmt(enum_id, repeated, &buffer[0], buffer.size());
    });

    visitor.visit_start_xrefs();
    std::vector<EnumMember> members;
    ya::walk_enum_members(enum_id, [&](const_t const_id, uval_t const_value, uchar /*serial*/, bmask_t bmask)
    {
        get_enum_member_name(&buffer, const_id);
        const auto member_id = provider_->get_enum_member_id(enum_id, ya::to_string(enum_name), const_id, ya::to_string(buffer), ya::to_py_hex(const_value), bmask, true);
        visitor.visit_start_xref(0, member_id, DEFAULT_OPERAND);
        visitor.visit_end_xref();
        members.push_back({member_id, const_id, buffer, const_value, bmask});
    });
    visitor.visit_end_xrefs();

    finish_object(visitor, idx);

    for(const auto& m : members)
    {
        start_object(visitor, OBJECT_TYPE_ENUM_MEMBER, m.id, id, m.const_value);
        visitor.visit_size(0);
        visitor.visit_name(ya::to_string_ref(m.const_name), DEFAULT_NAME_FLAGS);
        if(m.bmask != BADADDR)
            visitor.visit_flags(static_cast<flags_t>(m.bmask));
        visit_header_comments(visitor, buffer, [&](bool repeated)
        {
            return get_enum_member_cmt(m.const_id, repeated, &buffer[0], buffer.size());
        });
        finish_object(visitor, m.const_value);
    }

    return id;
}

static YaToolObjectId get_segment_id(YaToolsHashProvider* provider, qstring& buffer, segment_t* seg)
{
    ya::read_string_from(buffer, [&]
    {
        return get_true_segm_name(seg, &buffer[0], buffer.size());
    });
    const auto value = "segment-" + ya::to_string(buffer) + std::to_string(seg->startEA);
    return provider->hash_local_string(value);
}

YaToolObjectId IDANativeModel::accept_binary(IModelVisitor& visitor)
{
    const auto id = provider_->hash_local_string("binary");
    const auto base = get_imagebase();
    start_object(visitor, OBJECT_TYPE_BINARY, id, 0, base);
    const auto first = get_first_seg();
    if(first)
        visitor.visit_size(get_last_seg()->endEA - first->startEA);

    qstring buffer;
    buffer.resize(64);
    ya::read_string_from(buffer, [&]
    {
        return get_root_filename(&buffer[0], buffer.size());
    });
    if(!buffer.empty())
        visitor.visit_name(ya::to_string_ref(buffer), DEFAULT_NAME_FLAGS);

    visitor.visit_start_xrefs();
    for(auto seg = first; seg; seg = get_next_seg(seg->endEA - 1))
    {
        const auto seg_id = get_segment_id(provider_, buffer, seg);
        visitor.visit_start_xref(seg->startEA - base, seg_id, DEFAULT_OPERAND);
        visitor.visit_end_xref();
    }
    visitor.visit_end_xrefs();

    finish_object(visitor, base);
    return id;
}
