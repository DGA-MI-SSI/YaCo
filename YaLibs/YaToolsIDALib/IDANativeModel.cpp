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

#include "IDANativeModel.hpp"
#include "IModelAccept.hpp"
#include "IModelVisitor.hpp"
#include <MultiplexerDelegatingVisitor.hpp>
#include "YaToolsHashProvider.hpp"
#include "YaHelpers.hpp"
#include "../Helpers.h"
#include "Pool.hpp"
#include "StringFormat.hpp"
#include "PluginModel.hpp"

#include <Logger.h>
#include <Yatools.h>

#include <algorithm>
#include <unordered_set>

extern "C"
{
    // ugly, we extract crc32 function from git2/deps/zlib
    typedef int64_t git_off_t;
    #define INCLUDE_common_h__
    #include <zlib.h>
}

#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("ida_model", (FMT), ## __VA_ARGS__)

#ifdef __EA64__
#define EA_PREFIX "ll"
#define EA_SIZE   "16"
#else
#define EA_PREFIX ""
#define EA_SIZE   "8"
#endif
#define EA_FMT      "%" EA_PREFIX "x"
#define XMLEA_FMT   "%0" EA_SIZE EA_PREFIX "X"

std::string get_type(ea_t ea)
{
    return ya::get_type(ea);
}

void pool_item_clear(qstring& item)
{
    item.qclear();
}

namespace
{
    const bool EMULATE_PYTHON_MODEL_BEHAVIOR = true; // FIXME set to false & remove

    const int DEFAULT_NAME_FLAGS = 0;
    const int DEFAULT_OPERAND = 0;
    const int SEGMENT_CHUNK_MAX_SIZE = 0x10000;
    const int MAX_BLOB_TAG_LEN = 0x1000;

#define DECLARE_REF(name, value)\
    const char name ## _txt[] = value;\
    const const_string_ref name = {name ## _txt, sizeof name ## _txt - 1};

    DECLARE_REF(g_eq, "equipment");
    DECLARE_REF(g_os, "os");
    DECLARE_REF(g_empty, "");
    DECLARE_REF(g_stack_lvars, "stack_lvars");
    DECLARE_REF(g_stack_regvars, "stack_regvars");
    DECLARE_REF(g_stack_args, "stack_args");
    DECLARE_REF(g_none, "None");
    DECLARE_REF(g_serial, "serial");
    DECLARE_REF(g_size, "size");
    DECLARE_REF(g_udec, "unsigneddecimal");
    DECLARE_REF(g_sdec, "signeddecimal");
    DECLARE_REF(g_uhex, "unsignedhexadecimal");
    DECLARE_REF(g_shex, "signedhexadecimal");
    DECLARE_REF(g_char, "char");
    DECLARE_REF(g_binary, "binary");
    DECLARE_REF(g_octal, "octal");
    DECLARE_REF(g_offset, "offset");
    DECLARE_REF(g_path_idx, "path_idx");

#undef DECLARE_REF

    template<typename T>
    const_string_ref str_hex(char* buf, size_t /*szbuf*/, T x)
    {
        return to_hex<LowerCase, RemovePadding>(buf, x);
    }

    const_string_ref str_crc32(char* buf, size_t /*szbuf*/, uint32_t x)
    {
        return to_hex(buf, x);
    }

    const_string_ref str_defname(char* buf, size_t /*szbuf*/, ea_t ea)
    {
        // make sure we have one byte to put '-'
        const auto str = to_hex<UpperCase, RemovePadding>(buf + 1, ea);
        auto ptr = buf + (str.value - buf - 1);
        *ptr = '_';
        return {ptr, 1 + str.size};
    }

#define DECLARE_STRINGER(NAME, FMT, VALUE_TYPE)\
    const_string_ref NAME(char* buf, size_t szbuf, VALUE_TYPE value)\
    {\
        const auto n = snprintf(buf, szbuf, (FMT), value);\
        if(n <= 0)\
            return {nullptr, 0};\
        return {buf, static_cast<size_t>(n)};\
    }
    DECLARE_STRINGER(str_ea, "%" EA_PREFIX "u", ea_t);
    DECLARE_STRINGER(str_uchar, "%hhd", uchar)
    DECLARE_STRINGER(str_ushort, "%hd", ushort)
    DECLARE_STRINGER(str_bgcolor, "%u", bgcolor_t)
    DECLARE_STRINGER(str_hexpath, "0x%08X", int)

#undef DECLARE_STRINGER

    struct Parent
    {
        YaToolObjectId  id;
        ea_t            ea;
    };

    struct EnumMember
    {
        YaToolObjectId  id;
        const_t         const_id;
        uval_t          value;
        bmask_t         bmask;
    };

    struct Bookmark
    {
        std::string value;
        ea_t        ea;
    };
    using Bookmarks = std::vector<Bookmark>;

    struct RefInfo
    {
        YaToolObjectId  id;
        ea_t            offset;
        int             opidx;
        flags_t         flags;
        ea_t            base;
    };
    using RefInfos = std::vector<RefInfo>;

    bool operator<(const RefInfo& a, const RefInfo& b)
    {
        return std::make_tuple(a.offset, a.opidx) < std::make_tuple(b.offset, b.opidx);
    }

    bool operator==(const RefInfo& a, const RefInfo& b)
    {
        return std::make_tuple(a.offset, a.opidx, a.flags, a.base) == std::make_tuple(b.offset, b.opidx, b.flags, b.base);
    }

    struct Xref
    {
        offset_t        offset;
        YaToolObjectId  id;
        operand_t       operand;
        int             path_idx;
    };
    using Xrefs = std::vector<Xref>;

    bool operator<(const Xref& a, const Xref& b)
    {
        return std::make_tuple(a.offset, a.operand, a.path_idx, a.id) < std::make_tuple(b.offset, b.operand, b.path_idx, b.id);
    }

    bool operator==(const Xref& a, const Xref& b)
    {
        return std::make_tuple(a.offset, a.operand, a.id, a.path_idx) == std::make_tuple(b.offset, b.operand, b.id, b.path_idx);
    }

    template<typename Parent>
    struct Ctx
    {
        static const bool is_incremental = Parent::is_incremental;

        Ctx(YaToolsHashProvider& provider, Parent& parent)
            : provider_ (provider)
            , parent_   (parent)
            , qpool_    (4)
        {
            if(!strncmp(inf.procName, "ARM", sizeof inf.procName))
                plugin_ = MakeArmPluginModel();
        }

        inline bool skip_id(YaToolObjectId id) { return Parent::is_incremental ? parent_.skip_id(id) : false; }

        YaToolsHashProvider&            provider_;
        Parent&                         parent_;
        Pool<qstring>                   qpool_;
        std::vector<uint8_t>            buffer_;
        Bookmarks                       bookmarks_;
        Xrefs                           xrefs_;
        RefInfos                        refs_;
        std::shared_ptr<PluginModel>    plugin_;
    };

    offset_t offset_from_ea(ea_t offset)
    {
        // FIXME sign-extend to 64-bits because offset_t is unsigned...
        return sizeof offset == 4 ? int64_t(int32_t(offset)) : offset;
    }

    void start_object(IModelVisitor& v, YaToolObjectType_e type, YaToolObjectId id, YaToolObjectId parent, ea_t ea)
    {
        v.visit_start_reference_object(type);
        v.visit_id(id);
        v.visit_start_object_version();
        if(parent)
            v.visit_parent_id(parent);
        v.visit_address(offset_from_ea(ea));
    }

    void finish_object(IModelVisitor& v, ea_t offset)
    {
        v.visit_start_matching_systems();
        v.visit_start_matching_system(offset_from_ea(offset));
        v.visit_matching_system_description(g_eq, g_none);
        v.visit_matching_system_description(g_os, g_none);
        v.visit_end_matching_system();
        v.visit_end_matching_systems();
        v.visit_end_object_version();
        v.visit_end_reference_object();
    }

    template<typename T>
    void visit_header_comments(IModelVisitor& v, qstring& buffer, const T& read)
    {
        for(const auto rpt : {false, true})
        {
            const auto comment = ya::read_string_from(buffer, [&](char* buf, size_t szbuf)
            {
                return read(buf, szbuf, rpt);
            });
            if(comment.size)
                v.visit_header_comment(rpt, comment);
        }
    }

    template<typename Ctx>
    void accept_enum_member(Ctx& ctx, IModelVisitor& v, const Parent& parent, const EnumMember& em)
    {
        start_object(v, OBJECT_TYPE_ENUM_MEMBER, em.id, parent.id, em.value);
        const auto qbuf = ctx.qpool_.acquire();
        get_enum_member_name(&*qbuf, em.const_id);
        v.visit_name(ya::to_string_ref(*qbuf), DEFAULT_NAME_FLAGS);
        if(em.bmask != BADADDR)
            v.visit_flags(static_cast<flags_t>(em.bmask));
        visit_header_comments(v, *qbuf, [&](char* buf, size_t szbuf, bool repeated)
        {
            return get_enum_member_cmt(em.const_id, repeated, buf, szbuf);
        });
        finish_object(v, em.value);
    }

    template<typename Ctx>
    void accept_enum(Ctx& ctx, IModelVisitor& v, enum_t eid)
    {
        const auto enum_name = ctx.qpool_.acquire();
        get_enum_name(&*enum_name, eid);
        const auto id = ctx.provider_.get_struc_enum_object_id(eid, ya::to_string_ref(*enum_name), true);
        if(ctx.skip_id(id))
            return;

        const auto idx = get_enum_idx(eid);
        start_object(v, OBJECT_TYPE_ENUM, id, 0, idx);
        v.visit_size(get_enum_width(eid));
        v.visit_name(ya::to_string_ref(*enum_name), DEFAULT_NAME_FLAGS);
        const auto flags = get_enum_flag(eid);
        const auto bitfield = is_bf(eid) ? ENUM_FLAGS_IS_BF : 0;
        v.visit_flags(flags | bitfield);

        const auto qbuf = ctx.qpool_.acquire();
        visit_header_comments(v, *qbuf, [&](char* buf, size_t szbuf, bool repeated)
        {
            return get_enum_cmt(eid, repeated, buf, szbuf);
        });

        v.visit_start_xrefs();
        std::vector<EnumMember> members;
        const auto qval = ctx.qpool_.acquire();
        ya::walk_enum_members(eid, [&](const_t const_id, uval_t value, uchar /*serial*/, bmask_t bmask)
        {
            get_enum_member_name(&*qbuf, const_id);
            to_py_hex(*qval, value);
            const auto member_id = ctx.provider_.get_enum_member_id(eid, ya::to_string_ref(*enum_name), const_id, ya::to_string_ref(*qbuf), ya::to_string_ref(*qval), bmask, true);
            v.visit_start_xref(0, member_id, DEFAULT_OPERAND);
            v.visit_end_xref();
            members.push_back({member_id, const_id, value, bmask});
        });
        v.visit_end_xrefs();

        finish_object(v, idx);

        for(const auto& it : members)
            accept_enum_member(ctx, v, {id, 0}, it);
    }

    template<typename Ctx>
    void accept_enums(Ctx& ctx, IModelVisitor& v)
    {
        for(size_t i = 0, end = get_enum_qty(); i < end; ++i)
            accept_enum(ctx, v, getn_enum(i));
    }

    const_string_ref to_fmt(qstring& buffer, const char* fmt, int64_t value)
    {
        return ya::read_string_from(buffer, [&](char* buf, size_t szbuf)
        {
            return snprintf(buf, szbuf, fmt, value);
        });
    }

    const_string_ref get_default_name(qstring& buffer, ea_t offset, func_t* func)
    {
        buffer.resize(std::max(buffer.size(), 32u));
        if(!func)
            return to_fmt(buffer, "field_%X", offset);
        if(offset <= func->frsize)
            return to_fmt(buffer, "var_%X", func->frsize - offset);
        if(offset < func->frsize + 4)
            return to_fmt(buffer, "var_s%d", offset - func->frsize);
        return to_fmt(buffer, "arg_%X", offset - func->frsize - 4);
    }

    struct MemberType
    {
        tinfo_t tif;
        bool    guess;
    };

    MemberType get_member_type(member_t* member, opinfo_t* pop)
    {
        tinfo_t tif;
        auto ok = get_member_tinfo2(member, &tif);
        if(ok)
            return {tif, false};

        tif = ya::get_tinfo(member->flag, pop);
        if(!tif.empty())
            return {tif, true};

        const auto guess = guess_tinfo2(member->id, &tif);
        if(guess == GUESS_FUNC_OK)
            return {tif, true};

        return {tinfo_t(), true};
    }

    bool is_trivial_member_type(const MemberType& mtype)
    {
        const auto& tif = mtype.tif;
        if(tif.empty())
            return true;

        if(tif.has_details())
            return false;

        if(tif.is_array())
            return false;

        if(!mtype.guess && tif.get_size() != 1)
            return false;

        // FIXME is_unsigned && is_integral && !is_bool ?
        return tif.is_arithmetic();
    }

    bool is_default_member(qstring& buffer, struc_t* struc, member_t* member, const_string_ref member_name)
    {
        if(struc->is_union())
            return false;

        if(!isData(member->flag))
            return false;

        if(get_member_size(member) != 1)
            return false;

        for(const auto rpt : {false, true})
        {
            const auto cmt = ya::read_string_from(buffer, [&](char* buf, size_t szbuf)
            {
                return get_member_cmt(member->id, rpt, buf, szbuf);
            });
            if(cmt.size)
                return false;
        }

        const auto func = get_func(get_func_by_frame(struc->id));
        const auto defname = get_default_name(buffer, member->soff, func);
        if(defname.size != member_name.size)
            return false;
        if(strncmp(defname.value, member_name.value, defname.size))
            return false;

        opinfo_t op;
        const auto ok = retrieve_member_info(member, &op);
        const auto mtype = get_member_type(member, ok ? &op : nullptr);
        return is_trivial_member_type(mtype);
    }

    template<typename T>
    const_string_ref to_hex_ref(qstring* qbuf, T value)
    {
        *qbuf = "0x";
        append_uint64(*qbuf, value);
        return ya::to_string_ref(*qbuf);
    }

    template<typename Ctx>
    void visit_member_type(Ctx& ctx, IModelVisitor& v, ya::Deps& deps, member_t* member)
    {
        opinfo_t op;
        const auto flags = member->flag;
        const auto is_ascii = isASCII(flags);
        const auto has_op = !!retrieve_member_info(member, &op);
        if(is_ascii && has_op && op.strtype > 0)
            v.visit_string_type(op.strtype);

        const auto mtype = get_member_type(member, has_op ? &op : nullptr);
        if(mtype.tif.empty())
            LOG(WARNING, "accept_struct_member: 0x" EA_FMT " unable to get member type info\n", member->id);

        const auto qbuf = ctx.qpool_.acquire();
        // FIXME is_ascii vs visit_prototype confusion
        if((!EMULATE_PYTHON_MODEL_BEHAVIOR || !is_ascii) && !is_trivial_member_type(mtype))
            ya::print_type(*qbuf, &ctx.provider_, &deps, mtype.tif, {nullptr, 0});
        if(!qbuf->empty())
            v.visit_prototype(ya::to_string_ref(*qbuf));
        v.visit_flags(flags);

        // do not put xrefs on struct pointers else exporter will try to apply the pointed struct
        // FIXME get rid of ids hidden in prototype comments
        // add xrefs and use offset = -1 or another mechanism
        if(mtype.tif.is_ptr())
            return;

        // FIXME add missing dependencies?
        const auto size = deps.size();
        if(size > 1)
            LOG(WARNING, "accept_struct_member: 0x" EA_FMT " ignoring %d dependencies\n", member->id, size);

        if(size != 1)
            return;

        v.visit_start_xrefs();
        v.visit_start_xref(0, deps.front().id, 0);

        if(has_op && isEnum0(flags))
        {
            const auto seref = op.ec.serial ? to_hex_ref(&*qbuf, op.ec.serial) : g_empty;
            if(seref.size)
                v.visit_xref_attribute(g_serial, seref);
        }

        v.visit_end_xref();
        v.visit_end_xrefs();
    }

    // forward declaration due to circular dependency on structs & struct members
    template<typename Ctx>
    void accept_dependency(Ctx& ctx, IModelVisitor& v, const ya::Dependency dep);

    template<typename Ctx>
    void accept_dependencies(Ctx& ctx, IModelVisitor& v, const ya::Deps& deps)
    {
        if(Ctx::is_incremental)
            for(const auto& dep : deps)
                accept_dependency(ctx, v, dep);
    }

    template<typename Ctx>
    void accept_struct_member(Ctx& ctx, IModelVisitor& v, const Parent& parent, struc_t* struc, func_t* func, member_t* member)
    {
        if(func && is_special_member(member->id))
            return;

        const auto sid = struc->id;
        const auto offset = member->soff;
        const auto qbuf = ctx.qpool_.acquire();
        get_struc_name(&*qbuf, sid);
        const auto id = func ?
            ctx.provider_.get_stackframe_member_object_id(sid, member->soff, func->startEA) :
            ctx.provider_.get_struc_member_id(sid, offset, ya::to_string_ref(*qbuf));
        if(ctx.skip_id(id))
            return;

        get_member_name2(&*qbuf, member->id);

        // we need to skip default members else we explode on structures with thousand of default fields
        const auto obtype = func ? OBJECT_TYPE_STACKFRAME_MEMBER : OBJECT_TYPE_STRUCT_MEMBER;
        if(is_default_member(*ctx.qpool_.acquire(), struc, member, ya::to_string_ref(*qbuf)))
        {
            v.visit_start_default_object(obtype);
            v.visit_id(id);
            v.visit_end_default_object();
            return;
        }

        start_object(v, obtype, id, parent.id, offset);
        const auto size = get_member_size(member);
        v.visit_size(size);
        v.visit_name(ya::to_string_ref(*qbuf), DEFAULT_NAME_FLAGS);

        ya::Deps deps;
        visit_member_type(ctx, v, deps, member);

        visit_header_comments(v, *qbuf, [&](char* buf, size_t szbuf, bool repeat)
        {
            return get_member_cmt(member->id, repeat, buf, szbuf);
        });
        finish_object(v, offset);
        accept_dependencies(ctx, v, deps);
    }

    template<typename Ctx>
    YaToolObjectId accept_struct(Ctx& ctx, IModelVisitor& v, const Parent& parent, struc_t* struc, func_t* func)
    {
        const auto struc_name = ctx.qpool_.acquire();
        const auto sid = struc->id;
        get_struc_name(&*struc_name, sid);
        const auto id = func ?
            ctx.provider_.get_stackframe_object_id(sid, func->startEA) :
            ctx.provider_.get_struc_enum_object_id(sid, ya::to_string_ref(*struc_name), true);
        if(ctx.skip_id(id))
            return id;

        const auto ea = func ? func->startEA : 0;
        start_object(v, func ? OBJECT_TYPE_STACKFRAME : OBJECT_TYPE_STRUCT, id, parent.id, ea);
        const auto size = get_struc_size(struc);
        v.visit_size(size);
        v.visit_name(ya::to_string_ref(*struc_name), DEFAULT_NAME_FLAGS);
        if(struc->is_union())
            v.visit_flags(1); // FIXME constant

        const auto qbuf = ctx.qpool_.acquire();
        visit_header_comments(v, *qbuf, [&](char* buf, size_t szbuf, bool repeated)
        {
            return get_struc_cmt(sid, repeated, buf, szbuf);
        });

        v.visit_start_xrefs();
        for(auto i = 0u, end = struc->memqty; i < end; ++i)
        {
            const auto member = &struc->members[i];
            const auto off = member->soff;
            if(func && is_special_member(member->id))
                continue;

            get_member_name2(&*qbuf, member->id);
            if(qbuf->empty())
                continue;

            const auto mid = func ?
                ctx.provider_.get_stackframe_member_object_id(sid, off, func->startEA) :
                ctx.provider_.get_struc_member_id(sid, off, ya::to_string_ref(*struc_name));
            v.visit_start_xref(struc->is_union() ? 0 : off, mid, DEFAULT_OPERAND);
            v.visit_end_xref();
        }
        v.visit_end_xrefs();

        // add custom frame attributes
        if(func)
        {
            char buf[64];
            const auto int_to_ref = [&](uint64_t value)
            {
                const auto n = snprintf(buf, sizeof buf, "0x" XMLEA_FMT, (ea_t) value);
                return const_string_ref{buf, static_cast<size_t>(std::max(0, n))};
            };
            v.visit_attribute(g_stack_lvars,    int_to_ref(func->frsize));
            v.visit_attribute(g_stack_regvars,  int_to_ref(func->frregs));
            v.visit_attribute(g_stack_args,     int_to_ref(func->argsize));
        }

        finish_object(v, 0);

        for(auto i = 0u, end = struc->memqty; i < end; ++i)
        {
            const auto member = &struc->members[i];
            accept_struct_member(ctx, v, {id, member->soff}, struc, func, member);
        }

        return id;
    }

    template<typename Ctx>
    void accept_dependency(Ctx& ctx, IModelVisitor& v, const ya::Dependency dep)
    {
        if(get_struc(dep.tid))
            accept_struct(ctx, v, {}, get_struc(dep.tid), nullptr);
        else
            accept_enum(ctx, v, dep.tid);
    }

    template<typename Ctx>
    void accept_structs(Ctx& ctx, IModelVisitor& v)
    {
        for(auto idx = get_first_struc_idx(); idx != BADADDR; idx = get_next_struc_idx(idx))
        {
            const auto tid = get_struc_by_idx(idx);
            const auto struc = get_struc(tid);
            if(!struc)
            {
                LOG(ERROR, "accept_struc: 0x" EA_FMT " missing struct at index " EA_FMT "\n", tid, idx);
                continue;
            }
            accept_struct(ctx, v, {}, struc, nullptr);
        }
    }

#ifdef _DEBUG
    void assert_bitmap_is_initialized(const uint8_t* bitmap, size_t from, size_t to)
    {
        for(; from < to; ++from)
            assert(bitmap[from >> 3] & (1 << (from & 7)));
    }
#else
    #define assert_bitmap_is_initialized(a, b, c) do { UNUSED(a); UNUSED(b); UNUSED(c); } while(0)
#endif

    void accept_blob_chunks(IModelVisitor& v, const uint8_t* buffer, size_t from, size_t to)
    {
        for(size_t k = 0; from + k < to; k += MAX_BLOB_TAG_LEN)
        {
            const auto size = std::min(static_cast<size_t>(MAX_BLOB_TAG_LEN), to - from - k);
            v.visit_blob(from + k, &buffer[from + k], size);
        }
    }

    struct Buffer
    {
        const uint8_t*  pdata;
        size_t          size;
        const uint8_t*  pbitmap;
        size_t          bitmap_size;
        bool            valid;
        bool            full;
    };

    template<typename Ctx>
    Buffer read_buffer(Ctx& ctx, const char* where, ea_t ea, ea_t end)
    {
        const auto size = static_cast<size_t>(end - ea);
        // bitmap_size has one more bit to simplify chunking
        const auto bitmap_size = (size + 1 + 7) >> 3;
        ctx.buffer_.resize(size + bitmap_size);
        if(!size)
            return {};

        // set last unreachable bit to zero
        ctx.buffer_.back() = 0;
        auto* pbuf = &ctx.buffer_[0];
        auto* pbitmap = &ctx.buffer_[size];
        const auto err = get_many_bytes_ex(ea, pbuf, size, pbitmap);
        if(err < 0)
        {
            LOG(ERROR, "%s: 0x" EA_FMT " unable to get %d bytes\n", where, ea, size);
            return {};
        }

        return {pbuf, size, pbitmap, bitmap_size, true, err == 1};
    }

    template<typename T>
    void walk_contiguous_chunks(const Buffer& buf, const T& operand)
    {
        if(!buf.valid)
            return;

        // complete read, no need to check bitmap
        if(buf.full)
        {
            assert_bitmap_is_initialized(buf.pbitmap, 0, buf.size);
            operand(buf.pdata, 0, buf.size);
            return;
        }

        // slow & naive but correct version which handle single byte blobs
        // we added one byte to bitmap to handle end of buffer directly in loop
        size_t last = 0;
        for(size_t i = 0; i < buf.size + 1; ++i)
            if(!(buf.pbitmap[i >> 3] & (1 << (i & 7))))
            {
                if(last != i)
                {
                    assert_bitmap_is_initialized(buf.pbitmap, last, i);
                    operand(buf.pdata, last, i);
                }
                last = i + 1;
            }
    }

    template<typename Ctx>
    void accept_blobs(Ctx& ctx, IModelVisitor& v, ea_t ea, ea_t end)
    {
        const auto buf = read_buffer(ctx, "accept_blobs", ea, end);
        walk_contiguous_chunks(buf, [&](const uint8_t* chunk, size_t from, size_t to)
        {
            accept_blob_chunks(v, chunk, from, to);
        });
    }

    template<typename Ctx>
    void accept_signature(Ctx& ctx, IModelVisitor& v, uint32_t crc)
    {
        const auto qbuf = ctx.qpool_.acquire();
        qbuf->resize(std::max(qbuf->size(), 32u));
        v.visit_signature(SIGNATURE_FIRSTBYTE, SIGNATURE_ALGORITHM_CRC32, str_crc32(&(*qbuf)[0], qbuf->size(), crc));
    }

    template<typename T>
    static uint32_t std_crc32(uint32_t crc, const T* data, size_t szdata)
    {
        return crc32(crc, reinterpret_cast<const Bytef*>(data), szdata);
    }

    template<typename Ctx>
    void accept_string(Ctx& ctx, IModelVisitor& v, ea_t ea, flags_t flags)
    {
        if(!isASCII(flags))
            return;

        opinfo_t op;
        auto ok = !!get_opinfo(ea, 0, flags, &op);
        if(!ok)
            return;

        const auto strtype = op.strtype == -1 ? ASCSTR_C : op.strtype;
        if(strtype > 0)
            v.visit_string_type(strtype);

        const auto n = get_max_ascii_length(ea, strtype, ALOPT_IGNHEADS);
        if(!n)
            return;

        auto& buf = ctx.buffer_;
        buf.resize(n + 1);
        auto* pbuf = &buf[0];
        memset(pbuf, 0, buf.size());
        ok = get_ascii_contents2(ea, n, strtype, pbuf, buf.size());
        if(!ok)
        {
            LOG(ERROR, "accept_string_type: 0x" EA_FMT " unable to get ascii contents %d bytes %x strtype\n", ea, n, strtype);
            return;
        }

        // remove invalid characters
        buf.erase(std::remove_if(buf.begin(), buf.end(), [](uint8_t c)
        {
            return !((c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9'));
        }), buf.end());

        // convert to uppercase
        for(auto& value : buf)
            value = static_cast<uint8_t>(toupper(value));

        v.visit_start_signatures();
        accept_signature(ctx, v, std_crc32(0, pbuf, buf.size()));
        v.visit_end_signatures();
    }

    flags_t get_name_flags(ea_t ea, const char* name, flags_t ea_flags)
    {
        flags_t flags = 0;
        if(has_user_name(ea_flags))
            flags |= SN_NON_AUTO;
        else if(has_auto_name(ea_flags))
            flags |= SN_AUTO;
        else if(has_dummy_name(ea_flags))
            flags |= SN_AUTO;
        else if(ea_flags && name && *name)
            LOG(WARNING, "get_name_flags: 0x" EA_FMT " unhandled name flags %x on %s\n", ea, ea_flags, name);
        uval_t ignore = 0;
        const auto code = get_name_value(ea, name, &ignore);
        if(code == NT_LOCAL)
            return flags | SN_LOCAL | SN_NON_PUBLIC | SN_NON_WEAK | SN_NOLIST;
        flags |= is_public_name(ea) ? SN_PUBLIC : SN_NON_PUBLIC;
        flags |= is_weak_name(ea) ? SN_WEAK : SN_NON_WEAK;
        flags |= is_in_nlist(ea) ? 0 : SN_NOLIST;
        return flags;
    }

    void accept_data_xrefs(IModelVisitor& v, const ya::Deps& deps, ea_t /*ea*/)
    {
        if(deps.size() != 1)
            return;

        const auto& dep = deps.front();
        if(!get_struc(dep.tid))
            return;

        if(dep.tid == BADADDR)
            return;

        v.visit_start_xrefs();
        v.visit_start_xref(0, dep.id, DEFAULT_OPERAND);
        v.visit_end_xref();
        v.visit_end_xrefs();
    }

    enum NamePolicy_e
    {
        BasicBlockNamePolicy,
        DataNamePolicy,
    };

    template<typename Ctx>
    void accept_name(Ctx& ctx, IModelVisitor& v, ea_t ea, flags_t flags, NamePolicy_e epolicy)
    {
        const auto qbuf = ctx.qpool_.acquire();
        const auto ok = !!get_long_name(&*qbuf, ea, GN_LOCAL);
        if(!ok)
            return;

        // FIXME python version does not check for default names on datas...
        if(!EMULATE_PYTHON_MODEL_BEHAVIOR || epolicy != DataNamePolicy)
        {
            ctx.buffer_.resize(32);
            const auto nameref = ya::to_string_ref(*qbuf);
            const auto defref = str_defname(reinterpret_cast<char*>(&ctx.buffer_[0]), ctx.buffer_.size(), ea);
            if(nameref.size >=  defref.size)
                if(!strncmp(nameref.value + nameref.size - defref.size, defref.value, defref.size))
                    if(IsDefaultName(nameref))
                        return;
        }

        v.visit_name(ya::to_string_ref(*qbuf), get_name_flags(ea, qbuf->c_str(), flags));
    }

    template<typename Ctx, typename T>
    void walk_comments(Ctx& ctx, ea_t ea, flags_t flags, const T& operand)
    {
        const auto qbuf = ctx.qpool_.acquire();
        for(const auto repeat : {false, true})
        {
            const auto cmt = ya::read_string_from(*qbuf, [&](char* buf, size_t szbuf)
            {
                return get_cmt(ea, repeat, buf, szbuf);
            });
            if(cmt.size)
                operand(cmt, repeat ? COMMENT_REPEATABLE : COMMENT_NON_REPEATABLE);
        }

        auto& b = ctx.buffer_;
        b.clear();
        if(hasExtra(flags))
            for(const auto from : {E_PREV, E_NEXT})
            {
                const auto end = get_first_free_extra_cmtidx(ea, from);
                for(int i = from; i < end; ++i)
                {
                    const auto extra = ya::read_string_from(*qbuf, [&](char* buf, size_t szbuf)
                    {
                        return get_extra_cmt(ea, i, buf, szbuf);
                    });
                    if(!extra.size)
                        continue;
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

    template<typename Ctx>
    void accept_comments(Ctx& ctx, IModelVisitor& v, ea_t ea, ea_t root, flags_t flags)
    {
        const auto offset = ea - root;
        walk_comments(ctx, ea, flags, [&](const const_string_ref& cmt, CommentType_e type)
        {
            v.visit_offset_comments(offset, type, cmt);
        });
    }

    template<typename Ctx>
    void accept_data(Ctx& ctx, IModelVisitor& v, const Parent& parent, ea_t ea)
    {
        const auto flags = getFlags(ea);
        const auto id = ctx.provider_.get_hash_for_ea(ea);
        if(ctx.skip_id(id))
            return;

        start_object(v, OBJECT_TYPE_DATA, id, parent.id, ea);
        const auto size = get_item_end(ea) - ea;
        v.visit_size(size);
        accept_name(ctx, v, ea, flags, DataNamePolicy);

        ya::Deps deps;
        const auto tif = ya::get_tinfo(ea);
        const auto qbuf = ctx.qpool_.acquire();
        ya::print_type(*qbuf, &ctx.provider_, &deps, tif, {nullptr, 0});
        if(!qbuf->empty())
            v.visit_prototype(ya::to_string_ref(*qbuf));
        v.visit_flags(flags);
        accept_string(ctx, v, ea, flags);
        v.visit_start_offsets();
        accept_comments(ctx, v, ea, ea, flags);
        v.visit_end_offsets();
        accept_data_xrefs(v, deps, ea);
        finish_object(v, ea - parent.ea);
        accept_dependencies(ctx, v, deps);
    }

    qflow_chart_t get_flow(func_t* func)
    {
        // FIXME maybe use a cache or a buffer
        qflow_chart_t flow(nullptr, func, func->startEA, func->endEA, 0);
        auto& blocks = flow.blocks;
        // sort blocks in increasing offset order
        std::sort(blocks.begin(), blocks.end(), [](const auto& a, const auto& b)
        {
            return a.startEA < b.startEA;
        });
        // remove empty blocks
        blocks.erase(std::remove_if(blocks.begin(), blocks.end(), [](const auto& a)
        {
            return !a.size();
        }), blocks.end());
        return flow;
    }

    struct Crcs
    {
        uint32_t firstbyte;
        uint32_t operands;
    };

    template<typename Ctx>
    void get_crcs(Ctx& ctx, const char* where, Crcs* crcs, ea_t ea_func, area_t block)
    {
        char hexbuf[32];
        const auto buf = read_buffer(ctx, "accept_function", block.startEA, block.endEA);
        walk_contiguous_chunks(buf, [&](const uint8_t* buffer, size_t from, size_t to)
        {
            const auto end = block.startEA + to;
            auto ea = block.startEA + from;
            while(ea < end)
            {
                // skip non-code bytes
                for(; !isCode(get_flags_novalue(ea)); ea = get_item_end(ea))
                    if(ea >= end)
                        return;
                const auto err = decode_insn(ea);
                if(!err)
                {
                    LOG(WARNING, "%s: 0x" EA_FMT " invalid instruction at offset 0x" EA_FMT "\n", where, ea_func, ea);
                    return;
                }
                crcs->firstbyte = std_crc32(crcs->firstbyte, buffer, 1);
                const auto itypehex = str_hex(hexbuf, sizeof hexbuf, cmd.itype);
                crcs->operands = std_crc32(crcs->operands, itypehex.value, itypehex.size);
                for(const auto& op : cmd.Operands)
                {
                    if(op.type == o_void)
                        continue;
                    const auto ophex = str_hex(hexbuf, sizeof hexbuf, op.type);
                    crcs->operands = std_crc32(crcs->operands, ophex.value, ophex.size);
                }
                ea += cmd.size;
            }
        });
    }

    template<typename Ctx>
    void accept_function_xrefs(Ctx& ctx, IModelVisitor& v, ea_t ea, struc_t* frame, const qflow_chart_t::blocks_t& blocks)
    {
        v.visit_start_xrefs();
        if(frame)
        {
            const auto sid = ctx.provider_.get_stackframe_object_id(frame->id, ea);
            v.visit_start_xref(BADADDR, sid, DEFAULT_OPERAND);
            v.visit_end_xref();
        }
        const auto qbuf = ctx.qpool_.acquire();
        for(const auto& block : blocks)
        {
            const auto bid = ctx.provider_.get_function_basic_block_hash(block.startEA, ea);
            const auto offset = block.startEA - ea;
            // FIXME a block does not necessarily start after the first function basic block
            // in which case offset is negative but offset_t is unsigned...
            // for now, keep compatibility with python version
            // & make sure offset is sign-extended to 64-bits
            const int64_t iea = sizeof ea == 4 ? int64_t(int32_t(offset)) : offset;
            v.visit_start_xref(iea, bid, DEFAULT_OPERAND);
            v.visit_xref_attribute(g_size, to_hex_ref(&*qbuf, block.size()));
            v.visit_end_xref();
        }
        v.visit_end_xrefs();
    }

    static const struct { char type[8]; reftype_t offset; } offset_types[] =
    {
        {"off8",    REF_OFF8},
        {"off16",   REF_OFF16},
        {"off32",   REF_OFF32},
        {"low8",    REF_LOW8},
        {"low16",   REF_LOW16},
        {"high8",   REF_HIGH8},
        {"high16",  REF_HIGH16},
        {"vhigh",   REF_VHIGH},
        {"vlow",    REF_VLOW},
        {"off64",   REF_OFF64},
    };

    static const_string_ref get_offset_type(reftype_t value)
    {
        for(const auto& it : offset_types)
            if(it.offset == value)
                return make_string_ref(it.type);
        return get_offset_type(REF_OFF32);
    }

    const_string_ref get_off_value(qstring* qbuf, ea_t ea, int i, flags_t flags, opinfo_t* pop)
    {
        const auto ok = get_opinfo(ea, i, flags, pop);
        if(!ok)
            return {nullptr, 0};

        *qbuf = "offset-";
        const auto offtype = get_offset_type(pop->ri.type());
        qbuf->insert(qbuf->size(), offtype.value, offtype.size);
        return ya::to_string_ref(*qbuf);
    }

    template<typename Ctx>
    void accept_value_views(Ctx& ctx, IModelVisitor& v, ea_t ea, ea_t root, flags_t flags)
    {
        int i = -1;
        const auto offset = ea - root;
        const_string_ref value;
        opinfo_t op;
        const auto qbuf = ctx.qpool_.acquire();
        for(const auto opflags : {get_optype_flags0(flags), get_optype_flags1(flags) >> 4})
        {
            ++i;
            switch(opflags)
            {
            case 0:
            case FF_0STRO:
                continue;

            default:
                // FIXME log error?
                continue;

            case FF_0OFF:
                value = get_off_value(&*qbuf, ea, i, flags, &op);
                if(!value.size)
                    continue;
                break;

            case FF_0NUMD:
                value = is_invsign(ea, flags, i) ? g_sdec : g_udec;
                break;

            case FF_0NUMH:
                value = is_invsign(ea, flags, i) ? g_shex : g_uhex;
                break;

            case FF_0CHAR:
                value = g_char;
                break;

            case FF_0NUMB:
                value = g_binary;
                break;

            case FF_0NUMO:
                value = g_octal;
                break;
            }
            v.visit_offset_valueview(offset, i, value);
        }
    }

    ea_t get_root_item(ea_t ea)
    {
        const auto prev = prev_head(ea, 0);
        if(prev == BADADDR)
            return ea;

        const auto end = get_item_end(prev);
        if(ea >= end)
            return ea;

        return prev;
    }

    template<typename Ctx>
    void accept_from_xrefs(Ctx& ctx, ea_t ea, ea_t root)
    {
        xrefblk_t xb;
        for(auto ok = xb.first_from(ea, XREF_FAR); ok; ok = xb.next_from())
        {
            const auto xflags = get_flags_novalue(xb.to);
            // xref.to must point to a segment because ida also put internal struc ids as xb.to
            // FIXME maybe we could use to struct ids here instead of accept_insn_xrefs
            const auto is_valid = getseg(xb.to) && (!isCode(xflags) || isFunc(xflags));
            //const auto dump = ya::dump_flags(xflags);
            if(!is_valid)
                continue;
            const auto xref = Xref{ea - root, ctx.provider_.get_hash_for_ea(get_root_item(xb.to)), DEFAULT_OPERAND, 0};
            ctx.xrefs_.push_back(xref);
        }
    }

    template<typename Ctx>
    void accept_bb_xrefs(Ctx& ctx, func_t* func, ea_t start, ea_t end)
    {
        if(!func)
            return;

        const auto next = prev_not_tail(end);
        for(auto ea = get_first_cref_from(next); ea != BADADDR; ea = get_next_cref_from(next, ea))
        {
            const auto id = ctx.provider_.get_function_basic_block_hash(ea, func->startEA);
            ctx.xrefs_.push_back({ea - start, id, DEFAULT_OPERAND, 0});
        }
    }

    template<typename Ctx>
    void accept_enum_operand(Ctx& ctx, ea_t ea, ea_t root, ya::Deps* deps, flags_t flags, int opidx, opinfo_t* pop)
    {
        const auto ok = get_opinfo(ea, opidx, flags, pop);
        if(!ok)
            return;

        const auto qbuf = ctx.qpool_.acquire();
        get_enum_name(&*qbuf, pop->ec.tid);
        const auto xid = ctx.provider_.get_struc_enum_object_id(pop->ec.tid, ya::to_string_ref(*qbuf), true);

        deps->push_back({xid, pop->ec.tid});
        ctx.xrefs_.push_back({ea - root, xid, opidx, 0});
    }

    template<typename Ctx>
    void accept_struc_operand(Ctx& ctx, ea_t ea, ea_t root, ya::Deps* deps, flags_t flags, int opidx, opinfo_t* pop)
    {
        const auto ok = get_opinfo(ea, opidx, flags, pop);
        if(!ok)
            return;

        if(pop->path.len < 1)
            return;

        const auto struc = get_struc(pop->path.ids[0]);
        if(!struc)
            return;

        const auto tid = pop->path.ids[0];
        const auto qbuf = ctx.qpool_.acquire();
        get_struc_name(&*qbuf, tid);
        const auto xid = ctx.provider_.get_struc_enum_object_id(tid, ya::to_string_ref(*qbuf), true);

        deps->push_back({xid, tid});
        ctx.xrefs_.push_back({ea - root, xid, opidx, 0});

        for(int i = 1; i < pop->path.len; ++i)
        {
            const auto mid = pop->path.ids[i];
            get_member_fullname(&*qbuf, mid);
            struc_t* mstruc = nullptr;
            const auto member = get_member_by_fullname(qbuf->c_str(), &mstruc);
            if(!member)
                break;

            get_member_name2(&*qbuf, mid);
            const auto xmid = ctx.provider_.get_struc_member_id(mstruc->id, member->soff, ya::to_string_ref(*qbuf));
            ctx.xrefs_.push_back({ea - root, xmid, opidx, i});
        }
    }

    template<typename Ctx>
    void accept_stackframe_operand(Ctx& ctx, ea_t ea, ea_t root, func_t* func, struc_t* frame, const op_t& operand, int opidx)
    {
        sval_t val = 0;
        const auto member = get_stkvar(operand, operand.addr, &val);
        if(!member)
            return;

        // FIXME we are adding special stack members, which are not into stackframe_members
        const auto qbuf = ctx.qpool_.acquire();
        if(!EMULATE_PYTHON_MODEL_BEHAVIOR)
        {
            if(is_special_member(member->id))
                return;

            get_member_name2(&*qbuf, member->id);
            if(is_default_member(*ctx.qpool_.acquire(), frame, member, ya::to_string_ref(*qbuf)))
                return;
        }

        const auto xid = ctx.provider_.get_stackframe_member_object_id(frame->id, member->soff, func->startEA);
        ctx.xrefs_.push_back({ea - root, xid, opidx, 0});
    }

    template<typename Ctx>
    void accept_insn_xrefs(Ctx& ctx, ea_t ea, ea_t root, ya::Deps* deps, flags_t flags, func_t* func, struc_t* frame, opinfo_t* pop)
    {
        // check for content before decoding
        if(!isEnum0(flags)
        && !isEnum1(flags)
        && !isStkvar0(flags)
        && !isStkvar1(flags)
        && !isStroff0(flags)
        && !isStroff1(flags))
            return;

        // FIXME memoize decode instructions
        const auto insn_size = decode_insn(ea);
        if(!insn_size)
            return;

        for(size_t i = 0; i < 2; ++i)
            if(cmd.Operands[i].type == o_void)
                continue;
            else if(isEnum(flags, i))
                accept_enum_operand(ctx, ea, root, deps, flags, i, pop);
            else if(isStroff(flags, i))
                accept_struc_operand(ctx, ea, root, deps, flags, i, pop);
            else if(func && isStkvar(flags, i))
                accept_stackframe_operand(ctx, ea, root, func, frame, cmd.Operands[i], i);
    }

    template<typename Ctx>
    void accept_references(Ctx& ctx, ea_t ea, ea_t root, flags_t flags, opinfo_t* pop)
    {
        // FIXME max 2 operands
        int i = -1;
        for(const auto opflags : {get_optype_flags0(flags), get_optype_flags1(flags) >> 4})
        {
            ++i;
            if(opflags != FF_0OFF)
                continue;
            const auto ok = get_opinfo(ea, i, flags, pop);
            if(!ok)
                continue;
            if(!pop->ri.base)
                continue;
            const auto offset = ea - root;
            const auto rflags = pop->ri.flags;
            const auto base = pop->ri.base;
            const auto id = ctx.provider_.get_reference_info_hash(ea, base);
            ctx.xrefs_.push_back({offset, id, i, 0});
            ctx.refs_.push_back({id, offset, i, rflags, base});
        }
    }

    template<typename Ctx>
    void accept_hiddenareas(Ctx& /*ctx*/, IModelVisitor& v, ea_t ea, ea_t root)
    {
        const auto area = get_hidden_area(ea);
        if(!area)
            return;
        if(area->startEA != ea)
            return;
        v.visit_offset_hiddenarea(ea - root, area->size(), make_string_ref(area->description));
    }

    void accept_registerviews(IModelVisitor& v, ea_t block_start, area_t insn, func_t* func)
    {
        for(int i = 0; func && func->regvars && i < func->regvarqty; ++i)
        {
            const auto& r = func->regvars[i];
            if(!r.user)
                continue;
            // handled by another instruction
            if(!insn.contains(r.startEA))
                continue;
            v.visit_offset_registerview(r.startEA - block_start, r.endEA - block_start, make_string_ref(r.canon), make_string_ref(r.user));
        }
    }

    template<typename Ctx>
    void accept_offsets(Ctx& ctx, IModelVisitor& v, ya::Deps* deps, ea_t start, ea_t end)
    {
        opinfo_t op;

        const auto func = get_func(start);
        const auto frame = get_frame(func);
        accept_bb_xrefs(ctx, func, start, end);

        v.visit_start_offsets();
        for(auto ea = start, ea_end = BADADDR; ea < end; ea = ea_end)
        {
            ea_end = get_item_end(ea);
            const auto flags = get_flags_novalue(ea);
            accept_comments(ctx, v, ea, start, flags);
            accept_registerviews(v, start, {ea, ea_end}, func);
            accept_hiddenareas(ctx, v, ea, start);
            accept_value_views(ctx, v, ea, start, flags);
            accept_from_xrefs(ctx, ea, start);
            accept_insn_xrefs(ctx, ea, start, deps, flags, func, frame, &op);
            accept_references(ctx, ea, start, flags, &op);
        }
        v.visit_end_offsets();
    }

    template<typename T>
    void dedup(T& d)
    {
        // sort & remove duplicates
        std::sort(d.begin(), d.end());
        d.erase(std::unique(d.begin(), d.end()), d.end());
    }

    template<typename Ctx>
    void accept_xrefs(Ctx& ctx, IModelVisitor& v)
    {
        dedup(ctx.xrefs_);
        v.visit_start_xrefs();
        const auto qbuf = ctx.qpool_.acquire();
        qbuf->resize(std::max(qbuf->size(), 32u));
        for(const auto& it : ctx.xrefs_)
        {
            v.visit_start_xref(it.offset, it.id, it.operand);
            if(it.path_idx)
                v.visit_xref_attribute(g_path_idx, str_hexpath(&(*qbuf)[0], qbuf->size(), it.path_idx));
            v.visit_end_xref();
        }
        v.visit_end_xrefs();
        ctx.xrefs_.clear();
    }

    template<typename Ctx>
    void accept_reference_infos(Ctx& ctx, IModelVisitor& v)
    {
        dedup(ctx.refs_);
        for(const auto& r : ctx.refs_)
        {
            start_object(v, OBJECT_TYPE_REFERENCE_INFO, r.id, 0, 0);
            v.visit_flags(r.flags);
            finish_object(v, r.base);
        }
        ctx.refs_.clear();
    }

    bool is_code_end(ea_t ea)
    {
        const auto flags = get_flags_novalue(ea);
        if(!isCode(flags))
            return true;
        else if(isData(flags))
            return true;
        else if(isUnknown(flags))
            return true;
        if(isFunc(flags))
            return true;
        if(isCode(flags) && get_func(ea))
            return true;
        return false;
    }

    ea_t get_code_end(ea_t start, ea_t end)
    {
        auto ea = start;
        while(ea < end && ea != BADADDR)
            if(is_code_end(ea))
                return ea;
            else
                ea = get_item_end(ea);
        return ea;
    }

    ea_t get_code_start(ea_t start, ea_t ea_min)
    {
        auto ea = start;
        while(ea != BADADDR && ea >= ea_min)
        {
            const auto ea_before = get_item_head(ea - 1);
            if(ea_before == BADADDR)
                break; // FIXME return ea ?
            if(is_code_end(ea_before))
                return ea;
            ea = ea_before;
        }
        // FIXME return ea ?
        return BADADDR;
    }

    template<typename Ctx>
    void accept_code(Ctx& ctx, IModelVisitor& v, const Parent& parent, ea_t ea)
    {
        const auto id = ctx.provider_.get_hash_for_ea(ea);
        if(ctx.skip_id(id))
            return;

        start_object(v, OBJECT_TYPE_CODE, id, parent.id, ea);
        const auto seg = getseg(ea);
        const auto end = get_code_end(ea, seg ? seg->endEA : BADADDR);
        const auto size = end - ea;
        v.visit_size(size);
        const auto flags = get_flags_novalue(ea);
        accept_name(ctx, v, ea, flags, BasicBlockNamePolicy);

        ya::Deps deps;
        accept_offsets(ctx, v, &deps, ea, end);
        accept_xrefs(ctx, v);

        finish_object(v, ea - parent.ea);
        accept_reference_infos(ctx, v);
        accept_dependencies(ctx, v, deps);
    }

    template<typename Ctx>
    void accept_block(Ctx& ctx, IModelVisitor& v, const Parent& parent, const qflow_chart_t& flow, size_t idx, area_t block)
    {
        const auto ea = block.startEA;
        const auto id = ctx.provider_.get_function_basic_block_hash(ea, parent.ea);
        if(ctx.skip_id(id))
            return;

        start_object(v, OBJECT_TYPE_BASIC_BLOCK, id, parent.id, ea);
        v.visit_size(block.size());

        accept_name(ctx, v, ea, get_flags_novalue(ea), BasicBlockNamePolicy);

        const auto type = flow.calc_block_type(idx);
        v.visit_flags(type);

        // FIXME maybe reuse crc computed from accept_function
        v.visit_start_signatures();
        Crcs crcs = {};
        get_crcs(ctx, "accept_block", &crcs, parent.ea, block);
        // FIXME use ops hash but tell firstbyte...
        accept_signature(ctx, v, crcs.operands);
        v.visit_end_signatures();

        ya::Deps deps;
        accept_offsets(ctx, v, &deps, block.startEA, block.endEA);
        accept_xrefs(ctx, v);

        if(ctx.plugin_)
            ctx.plugin_->accept_block(v, ea);
        finish_object(v, ea - parent.ea);
        accept_reference_infos(ctx, v);
        accept_dependencies(ctx, v, deps);
    }

    template<typename Ctx>
    void accept_function(Ctx& ctx, IModelVisitor& v, const Parent& parent, func_t* func, ea_t block_ea)
    {
        const auto ea = func->startEA;
        const auto id = ctx.provider_.get_hash_for_ea(ea);
        if(ctx.skip_id(id))
            return;

        asize_t size = 0;
        Crcs crcs = {};
        const auto flow = get_flow(func);
        for(const auto& block : flow.blocks)
        {
            size += block.size();
            get_crcs(ctx, "accept_functions", &crcs, ea, block);
        }

        start_object(v, OBJECT_TYPE_FUNCTION, id, parent.id, ea);
        v.visit_size(size);

        ya::Deps deps;
        const auto tif = ya::get_tinfo(ea);
        const auto qbuf = ctx.qpool_.acquire();
        ya::print_type(*qbuf, &ctx.provider_, &deps, tif, {nullptr, 0});
        if(!qbuf->empty())
            v.visit_prototype(ya::to_string_ref(*qbuf));
        v.visit_flags(func->flags);

        v.visit_start_signatures();
        // FIXME use ops hash but tell firstbyte...
        accept_signature(ctx, v, crcs.operands);
        v.visit_end_signatures();

        for(const auto repeat : {false, true})
        {
            const auto cmt = get_func_cmt(func, repeat);
            if(!cmt)
                continue;
            v.visit_header_comment(repeat, make_string_ref(cmt));
            qfree(cmt);
        }

        const auto frame = get_frame(func);
        accept_function_xrefs(ctx, v, func->startEA, frame, flow.blocks);

        if(ctx.plugin_)
            ctx.plugin_->accept_function(v, ea);
        finish_object(v, ea - parent.ea);

        if(frame)
            accept_struct(ctx, v, {id, ea}, frame, func);
        accept_dependencies(ctx, v, deps);

        size_t i = 0;
        UNUSED(block_ea);
        for(const auto& block : flow.blocks)
        {
            ++i;
            // accept only one block in incremental mode
            if(Ctx::is_incremental && !block.contains(block_ea))
                continue;
            accept_block(ctx, v, {id, ea}, flow, i - 1, block);
            if(Ctx::is_incremental)
                break;
        }
    }

    template<typename Ctx>
    void accept_ea(Ctx& ctx, IModelVisitor& v, const Parent& parent, ea_t ea)
    {
        const auto flags = getFlags(ea);
        const auto func = get_func(ea);
        if(func)
            accept_function(ctx, v, parent, func, ea);
        else if(isCode(flags))
            accept_code(ctx, v, parent, ea);
        else
            accept_data(ctx, v, parent, ea);
    }
}

std::vector<ea_t> get_all_items(ea_t start, ea_t end)
{
    std::vector<ea_t> items;

    // first, find all function entry points
    auto ea = start;
    while(ea != BADADDR && ea < end)
    {
        const auto flags = get_flags_novalue(ea);
        if(isCode(flags) || isFunc(flags))
        {
            const auto func = get_func(ea);
            if(func)
            {
                const auto eaFunc = func->startEA;
                if(eaFunc >= start && eaFunc < end)
                    items.push_back(eaFunc);
            }
        }
        const auto func = get_next_func(ea);
        ea = func ? func->startEA : BADADDR;
    }

    // try to add previous overlapped item
    ea = start;
    const auto previous_item = prev_head(ea, 0);
    if(previous_item != BADADDR)
    {
        const auto previous_item_size = get_item_end(ea) - ea;
        if(previous_item_size > 0 && ea < previous_item + previous_item_size)
            ea = previous_item;
    }

    // iterate on every ea
    while(ea != BADADDR && ea < end)
    {
        const auto flags = get_flags_novalue(ea);
        if(isData(flags))
        {
            if(ea >= start && ea < end)
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
            size = get_code_end(ea, end) - ea;
            const auto chunk_start_ea = get_code_start(ea, start);
            if(chunk_start_ea != BADADDR && chunk_start_ea >= start && ea < end)
                items.push_back(ea);
        }
        else if(has_any_name(flags) && hasRef(flags))
        {
            if(ea >= start && ea < end)
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
            const auto tail_end = next_not_tail(ea);
            if(ea + size < tail_end)
                ea = tail_end;
            else
                ea += size;
        }
    }

    dedup(items);
    return items;
}

namespace
{
    template<typename Ctx>
    Parent accept_segment_chunk(Ctx& ctx, IModelVisitor& v, const Parent& parent, ea_t ea, ea_t end)
    {
        const auto id = ctx.provider_.get_segment_chunk_id(parent.id, ea, end);
        const auto current = Parent{id, ea};
        if(ctx.skip_id(id))
            return current;

        start_object(v, OBJECT_TYPE_SEGMENT_CHUNK, id, parent.id, ea);
        v.visit_size(end - ea);

        v.visit_start_xrefs();
        const auto eas = get_all_items(ea, end);
        for(const auto item_ea : eas)
        {
            const auto offset = item_ea - ea;
            const auto item_id = ctx.provider_.get_hash_for_ea(item_ea);
            v.visit_start_xref(offset, item_id, DEFAULT_OPERAND);
            v.visit_end_xref();
        }
        v.visit_end_xrefs();

        accept_blobs(ctx, v, ea, end);
        finish_object(v, ea - parent.ea);

        if(Ctx::is_incremental)
            return current;

        for(const auto item_ea : eas)
            accept_ea(ctx, v, current, item_ea);
        return current;
    }

    template<typename T>
    void walk_segment_chunks(const segment_t* seg, const T& operand)
    {
        // do not chunk empty loader segments
        if(!isEnabled(seg->startEA))
            return;
        for(auto ea = seg->startEA; ea < seg->endEA; ea += SEGMENT_CHUNK_MAX_SIZE)
        {
            const auto end = std::min(ea + SEGMENT_CHUNK_MAX_SIZE, seg->endEA);
            operand(ea, end);
        }
    }

    template<typename Ctx>
    void accept_segment_chunks(Ctx& ctx, IModelVisitor& v, const Parent& parent, segment_t* seg)
    {
        walk_segment_chunks(seg, [&](ea_t ea, ea_t end)
        {
            accept_segment_chunk(ctx, v, parent, ea, end);
        });
    }

    enum SegAttribute
    {
        SEG_ATTR_START,
        SEG_ATTR_END,
        SEG_ATTR_BASE,
        SEG_ATTR_ALIGN,
        SEG_ATTR_COMB,
        SEG_ATTR_PERM,
        SEG_ATTR_BITNESS,
        SEG_ATTR_FLAGS,
        SEG_ATTR_SEL,
        SEG_ATTR_ES,
        SEG_ATTR_CS,
        SEG_ATTR_SS,
        SEG_ATTR_DS,
        SEG_ATTR_FS,
        SEG_ATTR_GS,
        SEG_ATTR_TYPE,
        SEG_ATTR_COLOR,
        SEG_ATTR_COUNT,
    };

    // copied from _SEGATTRMAP in idc.py...
    enum RegAttribute
    {
        REG_ATTR_ES,
        REG_ATTR_CS,
        REG_ATTR_SS,
        REG_ATTR_DS,
        REG_ATTR_FS,
        REG_ATTR_GS,
        REG_ATTR_COUNT,
    };

    const char g_seg_attributes[][12] =
    {
        "start_ea",
        "end_ea",
        "org_base",
        "align",
        "comb",
        "perm",
        "bitness",
        "flags",
        "sel",
        "es",
        "cs",
        "ss",
        "ds",
        "fs",
        "gs",
        "type",
        "color",
    };

    static_assert(COUNT_OF(g_seg_attributes) == SEG_ATTR_COUNT, "invalid number of g_seg_attributes entries");

    void accept_segment_attributes(IModelVisitor& v, const segment_t* seg)
    {
        const auto get_key = [](auto attr)
        {
            return const_string_ref{g_seg_attributes[attr], sizeof g_seg_attributes[attr]};
        };
        char buf[32];
        v.visit_attribute(get_key(SEG_ATTR_BASE), str_ea(buf, sizeof buf, get_segm_base(seg)));
        v.visit_attribute(get_key(SEG_ATTR_COMB), str_uchar(buf, sizeof buf, seg->comb));
        if(seg->color != DEFCOLOR)
            v.visit_attribute(get_key(SEG_ATTR_COLOR), str_bgcolor(buf, sizeof buf, seg->color));
        v.visit_attribute(get_key(SEG_ATTR_ALIGN), str_uchar(buf, sizeof buf, seg->align));
        v.visit_attribute(get_key(SEG_ATTR_START), str_ea(buf, sizeof buf, seg->startEA));
        v.visit_attribute(get_key(SEG_ATTR_PERM), str_uchar(buf, sizeof buf, seg->perm));
        v.visit_attribute(get_key(SEG_ATTR_BITNESS), str_uchar(buf, sizeof buf, seg->bitness));
        v.visit_attribute(get_key(SEG_ATTR_FLAGS), str_ushort(buf, sizeof buf, seg->flags));
        v.visit_attribute(get_key(SEG_ATTR_END), str_ea(buf, sizeof buf, seg->endEA));
        v.visit_attribute(get_key(SEG_ATTR_SEL), str_ea(buf, sizeof buf, seg->sel));
        v.visit_attribute(get_key(SEG_ATTR_TYPE), str_uchar(buf, sizeof buf, seg->type));

        // FIXME flaky link between REG_ATTR, SEG_ATTR & defsr...
        for(size_t i = 0; i < REG_ATTR_COUNT; ++i)
            if(seg->defsr[i] != BADADDR)
                v.visit_attribute(get_key(SEG_ATTR_ES + i), str_ea(buf, sizeof buf, seg->defsr[i]));
    }

    template<typename Ctx>
    Parent accept_segment(Ctx& ctx, IModelVisitor& v, const Parent& parent, segment_t* seg)
    {
        const auto segname = ya::read_string_from(*ctx.qpool_.acquire(), [&](char* buf, size_t szbuf)
        {
            return get_true_segm_name(seg, buf, szbuf);
        });
        const auto id = ctx.provider_.get_segment_id(segname, seg->startEA);
        const auto current = Parent{id, seg->startEA};
        if(ctx.skip_id(id))
            return current;

        start_object(v, OBJECT_TYPE_SEGMENT, id, parent.id, seg->startEA);
        v.visit_size(seg->endEA - seg->startEA);
        v.visit_name(segname, DEFAULT_NAME_FLAGS);

        v.visit_start_xrefs();
        walk_segment_chunks(seg, [&](ea_t ea, ea_t end)
        {
            const auto chunk_id = ctx.provider_.get_segment_chunk_id(id, ea, end);
            v.visit_start_xref(ea - seg->startEA, chunk_id, DEFAULT_OPERAND);
            v.visit_end_xref();

        });
        v.visit_end_xrefs();

        accept_segment_attributes(v, seg);
        finish_object(v, seg->startEA - parent.ea);

        if(Ctx::is_incremental)
            return current;

        accept_segment_chunks(ctx, v, current, seg);
        return current;
    }

    template<typename Ctx>
    void accept_segments(Ctx& ctx, IModelVisitor& v, const Parent& parent)
    {
        v.visit_segments_start();
        for(auto seg = get_first_seg(); seg; seg = get_next_seg(seg->endEA - 1))
            accept_segment(ctx, v, parent, seg);
        v.visit_segments_end();
    }

    template<typename Ctx>
    Parent accept_binary(Ctx& ctx, IModelVisitor& v)
    {
        const auto qbuf = ctx.qpool_.acquire();
        const auto id = ctx.provider_.get_binary_id();
        const auto base = get_imagebase();
        const auto current = Parent{id, base};
        if(ctx.skip_id(id))
            return current;

        start_object(v, OBJECT_TYPE_BINARY, id, 0, base);
        const auto first = get_first_seg();
        if(first)
            v.visit_size(get_last_seg()->endEA - first->startEA);

        const auto filename = ya::read_string_from(*qbuf, [&](char* buf, size_t szbuf)
        {
            return get_root_filename(buf, szbuf);
        });
        if(filename.size)
            v.visit_name(filename, DEFAULT_NAME_FLAGS);

        v.visit_start_xrefs();
        for(auto seg = first; seg; seg = get_next_seg(seg->endEA - 1))
        {
            const auto segname = ya::read_string_from(*qbuf, [&](char* buf, size_t szbuf)
            {
                return get_true_segm_name(seg, buf, szbuf);
            });
            const auto seg_id = ctx.provider_.get_segment_id(segname, seg->startEA);
            v.visit_start_xref(seg->startEA - base, seg_id, DEFAULT_OPERAND);
            v.visit_end_xref();
        }
        v.visit_end_xrefs();

        finish_object(v, base);

        if(Ctx::is_incremental)
            return current;

        accept_enums(ctx, v);
        accept_structs(ctx, v);
        accept_segments(ctx, v, current);
        return current;
    }

    template<typename Ctx>
    void accept(Ctx& ctx, IModelVisitor& v)
    {
        const auto qbuf = ctx.qpool_.acquire();
        ya::walk_bookmarks([&](int i, ea_t ea, const curloc& loc)
        {
            const auto value = ya::read_string_from(*qbuf, [&](char* buf, size_t szbuf)
            {
                return loc.markdesc(i, buf, szbuf);
            });
            ctx.bookmarks_.push_back({make_string(value), ea});
        });
        v.visit_start();
        accept_binary(ctx, v);
        v.visit_end();
    }
}

namespace
{
    struct Model
        : public IModelAccept
    {
        static const bool is_incremental = false;

        Model(YaToolsHashProvider* provider);

        inline bool skip_id(YaToolObjectId) const { return false; }

        // IModelAccept methods
        void accept(IModelVisitor& v) override;

        Ctx<Model> ctx_;
    };

    struct ModelIncremental
        : public IModelIncremental
    {
        static const bool is_incremental = true;

        ModelIncremental(YaToolsHashProvider* provider);

        // IModelIncremental methods
        void export_id(YaToolObjectId id) override;
        void unexport_id(YaToolObjectId id) override;
        bool is_exported(YaToolObjectId id) const override;

        // IModelIncremental accept methods
        void accept_enum(IModelVisitor& v, ea_t enum_id) override;
        void accept_struct(IModelVisitor& v, ea_t struc_id, ea_t func_ea) override;
        void accept_struct_member(IModelVisitor& v, ea_t func_ea, ea_t member_id) override;
        void accept_function(IModelVisitor& v, ea_t ea) override;
        void accept_ea(IModelVisitor& v, ea_t ea) override;
        void accept_segment(IModelVisitor& v, ea_t ea) override;

        // IModelIncremental delete methods
        void delete_enum(IModelVisitor& v, ea_t enum_id) override;
        void delete_struct(IModelVisitor& v, ea_t struc_id) override;
        void delete_struct_member(IModelVisitor& v, ea_t struc_id, ea_t offset, ea_t func_ea) override;

        // Ctx methods
        bool skip_id(YaToolObjectId);

        Ctx<ModelIncremental>               ctx_;
        std::unordered_set<YaToolObjectId>  ids_;
    };
}

Model::Model(YaToolsHashProvider* provider)
    : ctx_(*provider, *this)
{
}

std::shared_ptr<IModelAccept> MakeModel(YaToolsHashProvider* provider)
{
    return std::make_shared<Model>(provider);
}

void Model::accept(IModelVisitor& v)
{
    ::accept(ctx_, v);
}

ModelIncremental::ModelIncremental(YaToolsHashProvider* provider)
    : ctx_(*provider, *this)
{
}

std::shared_ptr<IModelIncremental> MakeModelIncremental(YaToolsHashProvider* provider)
{
    return std::make_shared<ModelIncremental>(provider);
}

void ModelIncremental::export_id(YaToolObjectId id)
{
    ids_.emplace(id);
}

void ModelIncremental::unexport_id(YaToolObjectId id)
{
    ids_.erase(id);
}

bool ModelIncremental::is_exported(YaToolObjectId id) const
{
    return !!ids_.count(id);
}

void ModelIncremental::accept_enum(IModelVisitor& v, ea_t enum_id)
{
    ::accept_enum(ctx_, v, enum_id);
}

bool ModelIncremental::skip_id(YaToolObjectId id)
{
    return !ids_.emplace(id).second;
}

namespace
{
    template<typename Ctx>
    Parent get_parent_function(Ctx& ctx, ea_t func_ea, func_t* func)
    {
        if(!func)
            return {};
        const auto id = ctx.provider_.get_hash_for_ea(func_ea);
        return {id, func_ea};
    }
}

void ModelIncremental::accept_struct(IModelVisitor& v, ea_t func_ea, ea_t struc_id)
{
    const auto struc = get_struc(struc_id);
    if(!struc)
    {
        LOG(ERROR, "accept_struct: 0x" EA_FMT " unable to get struct\n", struc_id);
        return;
    }

    const auto func = get_func(func_ea);
    ::accept_struct(ctx_, v, get_parent_function(ctx_, func_ea, func), struc, func);
}

void ModelIncremental::accept_struct_member(IModelVisitor& v, ea_t func_ea, ea_t member_id)
{
    struc_t* struc = nullptr;
    const auto member = get_member_by_id(member_id, &struc);
    if(!member)
    {
        LOG(ERROR, "accept_member: 0x" EA_FMT " unable to get member or struc (m %p s %p)\n", member_id, member, struc);
        return;
    }
    const auto func = get_func(func_ea);
    const auto struct_id = ::accept_struct(ctx_, v, get_parent_function(ctx_, func_ea, func), struc, func);
    ::accept_struct_member(ctx_, v, {struct_id, member->soff}, struc, func, member);
}

namespace
{
    template<typename Ctx>
    Parent accept_binary_to_chunk(Ctx& ctx, IModelVisitor& v, segment_t* seg, ea_t ea)
    {
        const auto binary = ::accept_binary(ctx, v);
        const auto segment = ::accept_segment(ctx, v, binary, seg);
        const auto chunk_start = ea - ((ea - seg->startEA) % SEGMENT_CHUNK_MAX_SIZE);
        const auto chunk_end = std::min(chunk_start + SEGMENT_CHUNK_MAX_SIZE, seg->endEA);
        return ::accept_segment_chunk(ctx, v, segment, chunk_start, chunk_end);
    }
}

void ModelIncremental::accept_function(IModelVisitor& v, ea_t ea)
{
    // owner function may not belong to the same segment chunk as ea
    const auto func = get_func(ea);
    if(!func)
    {
        LOG(ERROR, "accept_function: 0x" EA_FMT " unable to get function\n", ea);
        return;
    }

    const auto seg = getseg(func->startEA);
    if(!seg)
    {
        LOG(ERROR, "accept_function: 0x" EA_FMT " unable to get segment\n", func->startEA);
        return;
    }

    const auto chunk = accept_binary_to_chunk(ctx_, v, seg, func->startEA);
    ::accept_function(ctx_, v, chunk, func, ea);
}

void ModelIncremental::accept_ea(IModelVisitor& v, ea_t ea)
{
    // owner function may not belong to the same segment chunk as ea
    const auto func = get_func(ea);
    if(func)
        return accept_function(v, ea);

    const auto seg = getseg(ea);
    if(!seg)
    {
        LOG(ERROR, "accept_ea: 0x" EA_FMT " unable to get segment\n", ea);
        return;
    }

    const auto chunk = accept_binary_to_chunk(ctx_, v, seg, ea);
    ::accept_ea(ctx_, v, chunk, ea);
}

void ModelIncremental::accept_segment(IModelVisitor& v, ea_t ea)
{
    const auto seg = getseg(ea);
    if(!seg)
    {
        LOG(ERROR, "accept_segment: 0x" EA_FMT " unable to get segment\n", ea);
        return;
    }

    const auto binary = ::accept_binary(ctx_, v);
    const auto segment = ::accept_segment(ctx_, v, binary, seg);
    // called on new segments only, so we need to accept chunks too
    ::accept_segment_chunks(ctx_, v, segment, seg);
}

namespace
{
    void delete_id(IModelVisitor& v, YaToolObjectType_e type, YaToolObjectId id)
    {
        v.visit_start_deleted_object(type);
        v.visit_id(id);
        v.visit_end_deleted_object();
    }
}

void ModelIncremental::delete_struct(IModelVisitor& v, ea_t struc_id)
{
    const auto id = ctx_.provider_.get_struc_enum_object_id(struc_id, g_empty, true);
    delete_id(v, OBJECT_TYPE_STRUCT, id);
}

void ModelIncremental::delete_enum(IModelVisitor& v, ea_t enum_id)
{
    const auto id = ctx_.provider_.get_struc_enum_object_id(enum_id, g_empty, true);
    delete_id(v, OBJECT_TYPE_ENUM, id);
}

void ModelIncremental::delete_struct_member(IModelVisitor& v, ea_t func_ea, ea_t struc_id, ea_t offset)
{
    const auto func = get_func(func_ea);
    if(func)
    {
        const auto id = ctx_.provider_.get_stackframe_member_object_id(struc_id, offset, func_ea);
        delete_id(v, OBJECT_TYPE_STACKFRAME_MEMBER, id);
        return;
    }

    const auto qbuf = ctx_.qpool_.acquire();
    get_struc_name(&*qbuf, struc_id);
    const auto id = ctx_.provider_.get_struc_member_id(struc_id, offset, ya::to_string_ref(*qbuf));
    delete_id(v, OBJECT_TYPE_STRUCT_MEMBER, id);
}
