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
