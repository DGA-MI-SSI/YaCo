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

// Forward declarations
struct IYaCo;
struct IHashProvider;
struct IRepository;

struct IHooks
{
    virtual void hook() = 0;
    virtual void unhook() = 0;
};

std::shared_ptr<IHooks> MakeHooks(IYaCo& yaco, IHashProvider& hash_provider, IRepository& repo_manager);
