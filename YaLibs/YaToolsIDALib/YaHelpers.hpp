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
#include "BinHex.hpp"

#include <vector>

namespace ya
{
    struct Dependency
    {
        YaToolObjectId  id;
        tid_t           tid;
    };
    using Deps = std::vector<Dependency>;

    enum TypeToStringMode_e
    {
        NO_HEURISTIC,
        USE_HEURISTIC,
    };

    void                print_type(qstring& dst, TypeToStringMode_e mode, Deps* deps, const tinfo_t& tif, const const_string_ref& name);
    tinfo_t             get_tinfo(flags_t flags, const opinfo_t* op);
    tinfo_t             get_tinfo(ea_t ea);
    std::string         get_type(ea_t ea);
    std::string         dump_flags(flags_t flags);
    const_string_ref    get_default_name(qstring& buffer, ea_t offset, func_t* func);

    // wrap an ida api call & clear output buffer on errors
    template<typename... Args>
    void wrap(ssize_t (*fn)(qstring*, Args...), qstring& buf, Args... args)
    {
        const auto n = fn(&buf, args...);
        if(n <= 0)
            buf.qclear();
    }

    // call void(const_t const_id, uval_t value, uchar serial, bmask_t bmask) on every enum member with specified bmask
    template<typename T>
    void walk_enum_members_with_bmask(enum_t eid, bmask_t bmask, const T& operand)
    {
        const_t first_cid;
        uchar serial = 0;
        for(auto value = get_first_enum_member(eid, bmask); value != BADADDR; value = get_next_enum_member(eid, value, bmask))
            for(auto cid = first_cid = get_first_serial_enum_member(&serial, eid, value, bmask); cid != BADADDR; cid = get_next_serial_enum_member(&serial, first_cid))
                operand(cid, value, serial, bmask);
    }

    // call void(const_t const_id, uval_t value, uchar serial, bmask_t bmask) on every enum member
    template<typename T>
    void walk_enum_members(enum_t eid, const T& operand)
    {
        walk_enum_members_with_bmask(eid, DEFMASK, operand);
        for(auto fmask = get_first_bmask(eid); fmask != BADADDR; fmask = get_next_bmask(eid, fmask))
            walk_enum_members_with_bmask(eid, fmask, operand);
    }

    // call void(area_t area) on every function chunks
    template<typename T>
    bool walk_function_chunks(ea_t ea, const T& operand)
    {
        const auto func = get_func(ea);
        if(!func)
            return false;

        func_tail_iterator_t fti{func, ea};
        for(auto ok = fti.first(); ok; ok = fti.next())
            operand(fti.chunk());

        return true;
    }

    // call void(int i, ea_t locea, const lochist_entry_t& loc, const qstring& desc) on every bookmarks
    template<typename T>
    void walk_bookmarks(const T& operand)
    {
        idaplace_t place;
        renderer_info_t rinfo;
        lochist_entry_t loc(&place, rinfo);
        qstring desc;
        for(uint32_t i = 0; i < bookmarks_t::size(loc, nullptr); ++i)
        {
            const auto ok = bookmarks_t::get(&loc, &desc, &i, nullptr);
            if(!ok)
                continue;
            operand(i, loc.place()->toea(), loc, desc);
        }
    }

    // call read which return size_t & grow buffer if necessary
    template<typename T>
    const_string_ref read_string_from(qstring& buffer, const T& read)
    {
        if(buffer.empty())
            buffer.resize(32);
        while(true)
        {
            const auto n = read(&buffer[0], buffer.size());
            if(n < 0)
                return {nullptr, 0};
            if(n + 1 < static_cast<ssize_t>(buffer.size()))
                return {buffer.c_str(), static_cast<size_t>(n)};
            // retry with bigger buffer
            buffer.resize(buffer.size() * 2);
        }
    }

    inline std::string to_string(const qstring& q)
    {
        return {q.c_str(), q.length()};
    }

    inline const_string_ref to_string_ref(const qstring& q)
    {
        return {q.c_str(), q.length()};
    }


    template<typename Ctx, typename T>
    void walk_comments(Ctx& ctx, ea_t ea, flags_t flags, const T& operand)
    {
        const auto qbuf = ctx.qpool_.acquire();
        for(const auto repeat : {false, true})
        {
            ya::wrap(&get_cmt, *qbuf, ea, repeat);
            if(!qbuf->empty())
                operand(ya::to_string_ref(*qbuf), repeat ? COMMENT_REPEATABLE : COMMENT_NON_REPEATABLE);
        }

        auto& b = ctx.buffer_;
        b.clear();
        if(has_extra_cmts(flags))
            for(const auto from : {E_PREV, E_NEXT})
            {
                const auto end = get_first_free_extra_cmtidx(ea, from);
                for(int i = from; i < end; ++i)
                {
                    ya::wrap(&get_extra_cmt, *qbuf, ea, i);
                    if(qbuf->empty())
                        continue;
                    const auto extra = ya::to_string_ref(*qbuf);
                    const auto size = b.size();
                    b.resize(size + extra.size);
                    memcpy(&b[size], extra.value, extra.size);
                    b.push_back('\n');
                }
                if(b.empty())
                    continue;
                const auto cmt = const_string_ref{reinterpret_cast<char*>(&b[0]), b.size() - 1};
                operand(cmt, from == E_PREV ? COMMENT_ANTERIOR : COMMENT_POSTERIOR);
                b.clear();
            }

        int i = -1;
        for(const auto& it : ctx.bookmarks_)
        {
            ++i;
            if(ea != it.ea)
                return;
            if(!it.value.empty())
                operand(make_string_ref(it.value), COMMENT_BOOKMARK);
        }
    }

    template<uint32_t flags = 0, typename T>
    void append_uint64(T& dst, uint64_t x)
    {
        char buf[sizeof x * 2];
        const auto str = to_hex<flags>(buf, x);
        dst.append(str.value, str.size);
    }
}
