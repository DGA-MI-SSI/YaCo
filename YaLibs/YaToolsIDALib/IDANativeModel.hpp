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

#include "IModelVisitor.hpp"
#include "YaTypes.hpp"

namespace std { template<typename T> class shared_ptr; }
class YaToolObjectVersion;
struct YaToolsHashProvider;

struct IDANativeModel
{
    std::string get_type(ea_t ea);

    YaToolObjectId accept_binary    (IModelVisitor& visitor, YaToolsHashProvider* provider);
    YaToolObjectId accept_enum      (IModelVisitor& visitor, YaToolsHashProvider* provider, uint64_t eid);

    // intermediate native methods
    void set_system(const const_string_ref& eq, const const_string_ref& os);
    void start_object(IModelVisitor& visitor, YaToolObjectType_e type, YaToolObjectId id, YaToolObjectId parent, ea_t ea);
    void visit_system(IModelVisitor& visitor, ea_t ea);

#ifndef SWIG
private:
    std::string eq_;
    const_string_ref eqref_;
    std::string os_;
    const_string_ref osref_;
#endif
};
