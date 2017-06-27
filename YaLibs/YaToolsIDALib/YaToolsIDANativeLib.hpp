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

#include <stdint.h>

#include <struct.hpp>

#include <vector>
#include <map>


struct YaToolsIDANativeLib
{
    YaToolsIDANativeLib();

    ea_t get_struc_member_by_idx(const struc_t *sptr, uint32_t idx);

    std::map<ea_t, std::vector<std::pair<CommentType_e, std::string>>> get_comments_in_area(ea_t ea_start, ea_t ea_end);

    void clear_extra_comment(ea_t ea, int from);
    void make_extra_comment(ea_t ea, const char* comment, int from);

    void delete_comment_at_ea(ea_t ea, CommentType_e comment_type);
};

