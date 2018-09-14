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

#pragma once

#include <memory>
#include <string>
#include <vector>

#include <YaEnums.hpp>

struct IYaCo;

namespace yaswig
{
    // swig need to see object definitions  in order to properly delete them
    // if we return shared_ptr<IYaCo> directly, swig *must* see IYaCo definition
    // use a trampoline struc instead and keep IYaCo out of swig tentacles
    struct Private
    {
        std::shared_ptr<IYaCo> yaco;

        bool is_started();
        void sync_and_push_idb();
        void discard_and_pull_idb();
    };
    Private make_yaco();

    void export_from_ida(const std::string& idb_wo_ext, const std::string& dst);
    void import_to_ida  (const std::string& idb_wo_ext, const std::string& src);

    // for tests
    std::string export_xml(ea_t ea, int type_mask);
    std::string export_xml_enum(const std::string& name);
    std::string export_xml_struc(const std::string& name);
    std::string export_xml_strucs();
    std::string export_xml_local_types();
    std::string export_xml_local_type(const std::string& name);

    std::string         get_type                    (ea_t ea);
    bool                set_type_at                 (ea_t ea, const std::string& prototype);
    bool                set_struct_member_type_at   (ea_t ea, const std::string& prototype);
    std::vector<ea_t>   get_all_items               (ea_t start, ea_t end);
    void                enable_testing_mode         ();
}
