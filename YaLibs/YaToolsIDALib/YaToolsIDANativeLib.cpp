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

#include "YaToolsIDANativeLib.hpp"

#include <Logger.h>
#include <Yatools.h>
#include "../Helpers.h"
#include "YaHelpers.hpp"

#include <algorithm>


#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("IDANativeLib", (FMT), ## __VA_ARGS__)

YaToolsIDANativeLib::YaToolsIDANativeLib()
{
}

ea_t YaToolsIDANativeLib::get_struc_member_by_idx(const struc_t *sptr, uint32_t idx)
{
    if(!sptr)
        return BADADDR;
    if(!sptr->members)
        return BADADDR;
    if(idx > sptr->memqty)
        return BADADDR;
    return sptr->members[idx].soff;
}

static const int MAX_COMMENT_SIZE = 1024;

static std::string get_extra_comment(ea_t ea, int from)
{
    std::string comment;
    int idx = get_first_free_extra_cmtidx(ea, from);
    if(idx == from)
        return comment;

    char tmp[MAX_COMMENT_SIZE];
    for(int i = from; i < idx; i++)
    {
        get_extra_cmt(ea, i, tmp, sizeof tmp);
        comment.append(tmp);
        comment.append("\n");
    }
    if(!comment.empty())
        comment.resize(comment.length() - 1);
    return comment;
}

void YaToolsIDANativeLib::clear_extra_comment(ea_t ea, int from)
{
    for(int i = get_first_free_extra_cmtidx(ea, from) - 1; i >= from; i--)
        del_extra_cmt(ea, i);
}

void YaToolsIDANativeLib::make_extra_comment(ea_t ea, const char* comment, int from)
{
    clear_extra_comment(ea, from);

    std::stringstream istream(comment);
    std::string line;
    while(std::getline(istream, line))
        update_extra_cmt(ea, from++, line.data());

    // matches "doExtra" call from idapython
    setFlbits(ea, FF_LINE);
}

static std::vector<std::pair<CommentType_e, std::string>> get_comments_at_ea(ea_t ea)
{
    std::vector<std::pair<CommentType_e, std::string>> line_comments;

    char tmp[MAX_COMMENT_SIZE];
    for(const auto rpt : {false, true})
        if(get_cmt(ea, rpt, tmp, sizeof tmp) > 0)
            line_comments.emplace_back(rpt ? COMMENT_REPEATABLE : COMMENT_NON_REPEATABLE, tmp);

    // check if anterior/posterior comment exists
    const auto flags = getFlags(ea);
    if(hasExtra(flags))
    {
        // anterior comments
        std::string comment;
        comment = get_extra_comment(ea, E_PREV);
        if(!comment.empty())
            line_comments.emplace_back(COMMENT_ANTERIOR, comment);

        comment = get_extra_comment(ea, E_NEXT);
        if(!comment.empty())
            line_comments.emplace_back(COMMENT_POSTERIOR, comment);
    }

    char bookmark_buf[MAX_COMMENT_SIZE];
    ya::walk_bookmarks([&](int i, ea_t loc_ea, curloc& loc)
    {
        if(ea != loc_ea)
            return;
        loc.markdesc(i, bookmark_buf, sizeof bookmark_buf);
        line_comments.emplace_back(COMMENT_BOOKMARK, bookmark_buf);
    });

    return line_comments;
}

std::map<ea_t, std::vector<std::pair<CommentType_e, std::string>>> YaToolsIDANativeLib::get_comments_in_area(ea_t ea_start, ea_t ea_end)
{
    std::map<ea_t, std::vector<std::pair<CommentType_e, std::string>>> comments;
    for(auto ea = ea_start; ea != BADADDR && ea < ea_end; ea = get_item_end(ea))
    {
        auto v = get_comments_at_ea(ea);
        if(!v.empty())
            comments[ea] = v;
    }
    return comments;
}

static bool try_delete_comment_at_ea(YaToolsIDANativeLib& lib, ea_t ea, CommentType_e comment_type)
{
    LOG(DEBUG, "delete_comment: 0x%" PRIXEA " %s\n", ea, get_comment_type_string(comment_type));
    switch(comment_type)
    {
        case COMMENT_REPEATABLE:
            return set_cmt(ea, "", 1);

        case COMMENT_NON_REPEATABLE:
            return set_cmt(ea, "", 0);

        case COMMENT_ANTERIOR:
            lib.clear_extra_comment(ea, E_PREV);
            return true;

        case COMMENT_POSTERIOR:
            lib.clear_extra_comment(ea, E_NEXT);
            return true;

        case COMMENT_BOOKMARK:
            ya::walk_bookmarks([&](int i, ea_t locea, curloc& loc)
            {
                if(locea == ea)
                    loc.mark(i, "", "");
            });
            return true;

        case COMMENT_UNKNOWN:
        case COMMENT_COUNT:
            break;
    }
    return false;
}

void YaToolsIDANativeLib::delete_comment_at_ea(ea_t ea, CommentType_e comment_type)
{
    const auto ok = try_delete_comment_at_ea(*this, ea, comment_type);
    if(!ok)
        LOG(ERROR, "delete_comment: 0x%" PRIXEA " unable to delete comment type %d %s\n", ea, comment_type, get_comment_type_string(comment_type));
}
