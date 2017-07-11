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

#include "YaTypes.hpp"

class IModelVisitor;
struct HVersion;

struct IPluginModel
{
    virtual ~IPluginModel() {}

    virtual void accept_block   (IModelVisitor& v, ea_t ea) = 0;
    virtual void accept_function(IModelVisitor& v, ea_t ea) = 0;
};

std::shared_ptr<IPluginModel> MakeArmPluginModel();

struct IPluginVisitor
{
    virtual ~IPluginVisitor() {}

    virtual void make_basic_block_enter (const HVersion& version, ea_t ea) = 0;
    virtual void make_basic_block_exit  (const HVersion& version, ea_t ea) = 0;
    virtual void make_function_enter    (const HVersion& version, ea_t ea) = 0;
    virtual void make_function_exit     (const HVersion& version, ea_t ea) = 0;
};

std::shared_ptr<IPluginVisitor> MakeArmPluginVisitor();