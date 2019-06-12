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

// Declare implicit structure (to avoid including Repository.hpp)
struct IRepository;

// Interface for ida events callbacks
struct IEvents
{
    virtual ~IEvents() = default;

    virtual void touch_struc(tid_t struc_id) = 0;
    virtual void touch_enum (enum_t enum_id) = 0;
    virtual void touch_func (ea_t ea) = 0;
    virtual void touch_code (ea_t ea) = 0;
    virtual void touch_data (ea_t ea) = 0;
    virtual void touch_ea   (ea_t ea) = 0;
    virtual void touch_types() = 0;

    virtual void save               () = 0;
    virtual void update             () = 0;
    virtual void touch              () = 0;
};

// Create & Return event object (shared_ptr)
std::shared_ptr<IEvents> MakeEvents(IRepository& repo);
