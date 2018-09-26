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

#include "IdaDeleter.hpp"
#include "HVersion.hpp"
#include "Yatools.hpp"
#include "Helpers.h"
#include "YaHelpers.hpp"
#include "Strucs.hpp"

#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("ida_deleter", (FMT), ## __VA_ARGS__)

namespace
{
    void delete_local_type_from(int32_t ord, const char* name)
    {
        if(ord <= 0)
        {
            LOG(ERROR, "unable to delete missing local type '%s'\n", name);
            return;
        }

        local_types::remove(name);
        const auto ok = del_numbered_type(nullptr, ord);
        if(!ok)
            LOG(ERROR, "unable to delete local type '%s'\n", name);
    }

    void delete_struc(const HVersion& hver)
    {
        const auto name = make_string(hver.username());
        const auto struc = get_struc(get_struc_id(name.data()));
        if(!struc)
        {
            LOG(ERROR, "unable to delete missing struc '%s'\n", name.data());
            return;
        }
        strucs::remove(struc->id);
        const auto ok = del_struc(struc);
        if(!ok)
            LOG(ERROR, "unable to delete struc '%s'\n", name.data());
    }

    void delete_local_type(const HVersion& hver)
    {
        const auto name = make_string(hver.username());
        const auto ord = get_type_ordinal(nullptr, name.data());
        delete_local_type_from(ord, name.data());
    }

    void delete_enum(const HVersion& hver)
    {
        const auto name = make_string(hver.username());
        const auto eid = get_enum(name.data());
        if(eid == BADADDR)
        {
            LOG(ERROR, "unable to delete missing enum '%s'\n", name.data());
            return;
        }

        enums::remove(eid);
        del_enum(eid);
    }

    void delete_enum_member(const HVersion& hver)
    {
        const auto name = make_string(hver.username());
        const auto cid = get_enum_member_by_name(name.data());
        if(cid == BADADDR)
        {
            LOG(ERROR, "unable to delete missing enum member '%s'\n", name.data());
            return;
        }
        const auto eid = get_enum_member_enum(cid);
        const auto value = get_enum_member_value(cid);
        const auto serial = get_enum_member_serial(cid);
        const auto bmask = get_enum_member_bmask(cid);
        const auto ok = del_enum_member(eid, value, serial, bmask);
        if(!ok)
            LOG(ERROR, "unable to delete enum member '%s'\n", name.data());
    }

    void delete_function(const HVersion& hver)
    {
        const auto ea = static_cast<ea_t>(hver.address());
        const auto ok = del_func(ea);
        if(!ok)
            LOG(ERROR, "unable to delete func 0x%0" EA_SIZE PRIXEA "\n", ea);
    }

    void reset_ea(ea_t ea, int nmax)
    {
        const auto flags = get_flags(ea);
        for(const auto repeatable : {false, true})
            set_cmt(ea, "", repeatable);
        del_extra_cmt(ea, E_PREV);
        del_extra_cmt(ea, E_NEXT);
        for(int n = 0; n < nmax; ++n)
        {
            if(is_invsign(ea, flags, n))
                toggle_sign(ea, n);
            if(is_bnot(ea, flags, n))
                toggle_bnot(ea, n);
        }
    }

    void delete_chunk(const HVersion& hver, const char* where, int nmax)
    {
        const auto ea   = static_cast<ea_t>(hver.address());
        const auto end  = static_cast<ea_t>(ea + hver.size());
        for(auto it = ea; it < end; it = get_item_end(it))
            reset_ea(it, nmax);
        const auto ok = del_items(ea, DELIT_EXPAND, static_cast<asize_t>(hver.size()));
        if(!ok)
            LOG(ERROR, "unable to delete %s 0x%0" EA_SIZE PRIXEA "\n", where, ea);
    }

    void delete_object(const HVersion& hver)
    {
        switch(hver.type())
        {
            default:
                break;

            case OBJECT_TYPE_STRUCT:
                delete_struc(hver);
                break;

            case OBJECT_TYPE_LOCAL_TYPE:
                delete_local_type(hver);
                break;

            case OBJECT_TYPE_ENUM:
                delete_enum(hver);
                break;

            case OBJECT_TYPE_ENUM_MEMBER:
                delete_enum_member(hver);
                break;

            case OBJECT_TYPE_FUNCTION:
                delete_function(hver);
                break;

            case OBJECT_TYPE_DATA:
                delete_chunk(hver, "data", 1);
                break;

            case OBJECT_TYPE_CODE:
                delete_chunk(hver, "code", 2);
                break;

            case OBJECT_TYPE_BASIC_BLOCK:
                delete_chunk(hver, "block", 2);
                break;
        }
    }
}

void delete_from_model(const IModel& model)
{
    model.walk([](const HVersion& hver)
    {
        ::delete_object(hver);
        return WALK_CONTINUE;
    });
}