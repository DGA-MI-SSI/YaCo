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

#include <Ida.h>
#include "YaSwig.hpp"

#include <YaCo.hpp>
#include <Yatools.h>
#include <IdaModel.hpp>
#include <IdaVisitor.hpp>
#include <YaHelpers.hpp>

namespace yaswig
{
    Private make_yaco()
    {
        return {::MakeYaCo()};
    }

    void Private::sync_and_push_idb()
    {
        yaco->sync_and_push_idb(IDA_NOT_INTERACTIVE);
    }

    void Private::discard_and_pull_idb()
    {
        yaco->discard_and_pull_idb(IDA_NOT_INTERACTIVE);
    }

    void export_from_ida(const std::string& idb_wo_ext, const std::string& dst)
    {
        const auto yatools = MakeYatools(idb_wo_ext.data());
        ::export_from_ida(dst);
    }

    void import_to_ida(const std::string& idb_wo_ext, const std::string& src)
    {
        const auto yatools = MakeYatools(idb_wo_ext.data());
        ::import_to_ida(src);
    }

    std::string export_xml(ea_t ea, int type_mask)
    {
        return ::export_xml(ea, type_mask);
    }
    
    std::string export_xml_enum(const std::string& name)
    {
        return ::export_xml_enum(name);
    }
    
    std::string export_xml_struc(const std::string& name)
    {
        return ::export_xml_struc(name);
    }
    
    std::string export_xml_strucs()
    {
        return ::export_xml_strucs();
    }

    std::string get_type(ea_t ea)
    {
        return ya::get_type(ea);
    }

    bool set_type_at(ea_t ea, const std::string& prototype)
    {
        return ::set_type_at(ea, prototype);
    }

    bool set_struct_member_type_at(ea_t ea, const std::string& prototype)
    {
        return ::set_struct_member_type_at(ea, prototype);
    }

    std::vector<ea_t> get_all_items(ea_t start, ea_t end)
    {
        return ::get_all_items(start, end);
    }
}
