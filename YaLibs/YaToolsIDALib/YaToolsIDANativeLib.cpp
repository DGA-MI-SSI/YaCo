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

#include <algorithm>


#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("IDANativeLib", (FMT), ## __VA_ARGS__)

YaToolsIDANativeLib::YaToolsIDANativeLib()
{
}

bool YaToolsIDANativeLib::is_exportable_data(ea_t address)
{
    UNUSED(address);
#if 0
    const auto flags = getFlags(address);
    if(isData(flags))
        return true;

    // some unknown bytes still have a name : export them
    if(isUnknown(flags) && has_name(flags))
        return true;

    const auto prev = prevaddr(address);
    if(prev == BADADDR || prev == address || !isData(getFlags(prev)))
        return false;

    return is_exportable_data(prev);
#endif
    return true;
}

ea_t YaToolsIDANativeLib::get_code_chunk_end_addr(ea_t ea_start, ea_t ea_max)
{
    ea_t ea = ea_start;
    while(ea != BADADDR && ea < ea_max)
    {
        const auto flags = getFlags(ea);
        if(!isCode(flags))
            return ea;
        else if(isData(flags))
            return ea;
        else if(isUnknown(flags))
            return ea;
        if(isFunc(flags))
            return ea;
        if(isCode(flags) && get_func(ea))
            return ea;
        ea = get_item_end(ea);
    }
    return ea;
}

ea_t YaToolsIDANativeLib::get_code_chunk_start_addr(ea_t ea_start, ea_t ea_min)
{
    ea_t ea = ea_start;
    while(ea != BADADDR && ea >= ea_min)
    {
        const auto ea_before = get_item_head(ea - 1);
        if(ea_before == BADADDR)
            break;

        const auto flags = getFlags(ea_before);
        if(!isCode(flags))
            return ea;
        else if(isData(flags))
            return ea;
        else if(isUnknown(flags))
            return ea;
        if(isFunc(flags))
            return ea;
        if(isCode(flags) && get_func(ea_before))
            return ea;
        ea = ea_before;
    }
    return BADADDR;
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

std::vector<ea_t> YaToolsIDANativeLib::address_range_get_items(ea_t ea_start, ea_t ea_end)
{
    std::vector<ea_t> items;

    // first, find all function entry points
    auto ea = ea_start;
    while(ea != BADADDR && ea < ea_end)
    {
        const auto flags = getFlags(ea);
        if(isFunc(flags) || isCode(flags))
        {
            const auto func = get_func(ea);
            if(func)
            {
                const auto eaFunc = func->startEA;
                if(eaFunc >= ea_start && eaFunc < ea_end)
                    items.push_back(eaFunc);
            }
        }
        const auto func = get_next_func(ea);
        ea = func ? func->startEA : BADADDR;
    }

    // try to add previous overlapped item
    ea = ea_start;
    const auto previous_item = prev_head(ea, 0);
    if(previous_item != BADADDR)
    {
        const auto previous_item_size = get_item_end(ea) - ea;
        if(previous_item_size > 0 && ea < previous_item + previous_item_size)
            ea = previous_item;
    }

    // iterate on every ea
    while(ea != BADADDR && ea < ea_end)
    {
        const auto flags = getFlags(ea);
        if(isData(flags))
        {
            if(ea >= ea_start && ea < ea_end)
                items.push_back(ea);
            ea = next_not_tail(ea);
            continue;
        }

        auto size = BADADDR;
        const auto func = isFunc(flags) || isCode(flags) ? get_func(ea) : nullptr;
        if(func)
        {
            const auto chunk = get_fchunk(ea);
            if(chunk)
                size = chunk->endEA - ea;
        }
        else if(isCode(flags))
        {
            size = get_code_chunk_end_addr(ea, ea_end) - ea;
            const auto chunk_start_ea = get_code_chunk_start_addr(ea, ea_start);
            if(chunk_start_ea != BADADDR && chunk_start_ea >= ea_start && ea < ea_end)
                items.push_back(ea);
        }
        else if(has_any_name(flags) && hasRef(flags))
        {
            if(ea >= ea_start && ea < ea_end)
                items.push_back(ea);
        }

        if(size == 0 || size == 1)
        {
            if(!flags || hasValue(flags))
                ea = next_not_tail(ea);
            else
                ++ea;
        }
        else if(size == BADADDR)
        {
            ea = next_not_tail(ea);
        }
        else
        {
            // TODO: check if we should use next_head or get_item_end
            // next_head is FAR faster (we skip bytes that belong to no items) but may miss
            // some elements
            // end = idaapi.get_item_end(ea)
            const auto end = next_not_tail(ea);
            if(ea + size < end)
                ea = end;
            else
                ea += size;
        }
    }

    std::sort(items.begin(), items.end());
    items.erase(std::unique(items.begin(), items.end()), items.end());
    return items;
}

static const int MAX_COMMENT_SIZE = 1024;

template<typename T>
static void walk_bookmarks(const T& operand)
{
    curloc loc;
    for(int i = 1; i < 1024; ++i)
    {
        const auto ea = loc.markedpos(&i);
        if(ea == BADADDR)
            return;
        operand(i, ea, loc);
    }
}

void YaToolsIDANativeLib::update_bookmarks()
{
    bookmarks.clear();
    char bookmark_buf[MAX_COMMENT_SIZE];
    walk_bookmarks([&](int i, ea_t ea, curloc& loc)
    {
        loc.markdesc(i, bookmark_buf, sizeof bookmark_buf);
        bookmarks[ea] = bookmark_buf;
    });
}

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

std::vector<std::pair<CommentType_e, std::string>> YaToolsIDANativeLib::get_comments_at_ea(ea_t ea)
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

    const auto it = bookmarks.find(ea);
    if(it != bookmarks.end())
        line_comments.emplace_back(COMMENT_BOOKMARK, it->second);

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
            walk_bookmarks([&](int i, ea_t locea, curloc& loc)
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
