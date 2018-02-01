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

#include "IDANativeExporter.hpp"

#include "YaToolsHashProvider.hpp"
#include "IObjectListener.hpp"
#include "HVersion.hpp"
#include "HObject.hpp"
#include "IModel.hpp"
#include "Logger.h"
#include "Yatools.h"
#include "../Helpers.h"
#include "YaHelpers.hpp"
#include "StringFormat.hpp"
#include "Pool.hpp"
#include "Plugins.hpp"
#include "FlatBufferDatabaseModel.hpp"
#include "Utils.hpp"

#include <algorithm>
#include <string>
#include <iostream>
#include <functional>
#include <set>
#include <chrono>
#include <regex>
#include <unordered_map>

#ifdef _MSC_VER
#   include <optional.hpp>
using namespace nonstd;
#else
#   include <experimental/optional>
using namespace std::experimental;
#endif

#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("ida_exporter", (FMT), ## __VA_ARGS__)

#ifdef __EA64__
#define PRIxEA "llx"
#define PRIXEA "llX"
#define PRIuEA "llu"
#define EA_SIZE "16"
#else
#define PRIxEA "x"
#define PRIXEA "X"
#define PRIuEA "u"
#define EA_SIZE "8"
#endif

namespace
{
    #define DECLARE_REF(name, value)\
        const char name ## _txt[] = value;\
        const const_string_ref name = {name ## _txt, sizeof name ## _txt - 1};
    DECLARE_REF(g_empty, "");
    DECLARE_REF(g_start_ea, "start_ea");
    DECLARE_REF(g_end_ea, "end_ea");
    DECLARE_REF(g_sel, "sel");
    DECLARE_REF(g_align, "align");
    DECLARE_REF(g_comb, "comb");
    DECLARE_REF(g_find, "find");
    DECLARE_REF(g_path_idx, "path_idx");
    DECLARE_REF(g_stack_lvars, "stack_lvars");
    DECLARE_REF(g_stack_regvars, "stack_regvars");
    DECLARE_REF(g_stack_args, "stack_args");
    #undef DECLARE_REF

    using RefInfos = std::unordered_map<YaToolObjectId, refinfo_t>;

    struct Tid
    {
        Tid(ea_t tid, asize_t size, YaToolObjectType_e type)
            : tid(tid)
            , size(size)
            , type(type)
        {
        }
        ea_t                tid;
        asize_t             size;
        YaToolObjectType_e  type;
    };

    struct Bookmark
    {
        std::string value;
        ea_t        ea;
    };
    using Bookmarks = std::vector<Bookmark>;

    enum UseStacks
    {
        SKIP_STACKS,
        USE_STACKS,
    };

    using Enums = std::map<YaToolObjectId, enum_t>;

    struct Exporter
        : public IObjectListener
    {
        Exporter(IHashProvider& provider, UseStacks use_stacks);

        // IObjectListener
        void on_object (const HObject& object) override;
        void on_deleted(YaToolObjectId id) override;
        void on_default(YaToolObjectId id) override;

        void on_version(const HVersion& version);

        using TidMap = std::unordered_map<YaToolObjectId, Tid>;
        using Members = std::multimap<YaToolObjectId, YaToolObjectId>;
        using EnumMemberMap = std::unordered_map<uint64_t, enum_t>;

        IHashProvider&                  provider_;
        RefInfos                        refs_;
        Members                         members_;
        TidMap                          tids_;
        std::shared_ptr<IPluginVisitor> plugin_;
        std::vector<uint8_t>            buffer_;
        Pool<qstring>                   qpool_;
        Bookmarks                       bookmarks_;
        Enums                           enums_;
        bool                            use_stacks_;
    };

    const char ARM_txt[] = "ARM";
}

Exporter::Exporter(IHashProvider& provider, UseStacks use_stacks)
    : provider_(provider)
    , qpool_(4)
    , use_stacks_(use_stacks == USE_STACKS)
{
    static_assert(sizeof ARM_txt <= sizeof inf.procname, "procname size mismatch");
    if(!memcmp(inf.procname, ARM_txt, sizeof ARM_txt))
        plugin_ = MakeArmPluginVisitor();

    const auto qbuf = qpool_.acquire();
    ya::walk_bookmarks([&](int, ea_t ea, const auto&, const qstring& desc)
    {
        bookmarks_.push_back({ya::to_string(desc), ea});
    });

    for(size_t i = 0, end = get_enum_qty(); i < end; ++i)
    {
        const auto eid = getn_enum(i);
        ya::wrap(&get_enum_name, *qbuf, eid);
        const auto id = provider_.get_enum_id(ya::to_string_ref(*qbuf));
        enums_.emplace(id, eid);
    }
}

namespace
{
    void make_name(Exporter& exporter, const HVersion& version, ea_t ea)
    {
        const auto name = version.username();
        const auto strname = make_string(name);
        const auto qbuf = exporter.qpool_.acquire();
        ya::wrap(&get_ea_name, *qbuf, ea, 0, (getname_info_t*) NULL);
        const auto ok = set_name(ea, "");
        if(!ok)
            LOG(DEBUG, "make_name: 0x%" PRIxEA " unable to reset name\n", ea);

        if(!name.size || is_default_name(name))
        {
            LOG(DEBUG, "make_name: 0x%" PRIxEA " resetting name %s\n", ea, strname.data());
            return;
        }

        auto flags = version.username_flags();
        if(!flags)
            flags = SN_CHECK;
        const auto ok_ = set_name(ea, strname.data(), flags | SN_NOWARN);
        if(ok_)
            return;

        LOG(WARNING, "make_name: 0x%" PRIxEA " unable to set name flags 0x%08x '%s'\n", ea, flags, strname.data());
        set_name(ea, qbuf->c_str(), SN_CHECK | SN_NOWARN);
    }

    void add_bookmark(ea_t ea, const std::string& comment_text)
    {
        const auto title = make_string_ref(comment_text);
        ya::walk_bookmarks([&](int i, ea_t locea, const auto& loc, const qstring& desc)
        {
            LOG(DEBUG, "add_bookmark: 0x%" PRIxEA " found bookmark[%d]\n", ea, i);
            if(locea != ea)
                return;

            if(ya::to_string_ref(desc) == title)
                return;

            LOG(DEBUG, "add_bookmark: 0x%" PRIxEA " bookmark[%d] = %s\n", ea, i, title.value);
            bookmarks_t::mark(loc, i, title.value, title.value, nullptr);
        });
        // FIXME add to bookmarks_ ?
    }

    void clear_extra_comment(ea_t ea, int from)
    {
        for(int i = get_first_free_extra_cmtidx(ea, from) - 1; i >= from; i--)
            del_extra_cmt(ea, i);
    }

    bool try_delete_comment(CommentType_e comment_type, ea_t ea)
    {
        LOG(DEBUG, "delete_comment: 0x%" PRIXEA " %s\n", ea, get_comment_type_string(comment_type));
        switch(comment_type)
        {
            case COMMENT_REPEATABLE:
                return set_cmt(ea, "", true);

            case COMMENT_NON_REPEATABLE:
                return set_cmt(ea, "", false);

            case COMMENT_ANTERIOR:
                clear_extra_comment(ea, E_PREV);
                return true;

            case COMMENT_POSTERIOR:
                clear_extra_comment(ea, E_NEXT);
                return true;

            case COMMENT_BOOKMARK:
                ya::walk_bookmarks([&](uint32_t i, ea_t locea, const auto& loc, const qstring&)
                {
                    if(locea == ea)
                        bookmarks_t::erase(loc, i, nullptr);
                });
                return true;

            case COMMENT_UNKNOWN:
            case COMMENT_COUNT:
                break;
        }
        return false;
    }

    void delete_comment(CommentType_e comment_type, ea_t ea)
    {
        const auto ok = try_delete_comment(comment_type, ea);
        if(!ok)
            LOG(ERROR, "delete_comment: 0x%" PRIXEA " unable to delete %s comment\n", ea, get_comment_type_string(comment_type));
    }

    void make_extra_comment(ea_t ea, const std::string& comment, int from)
    {
        clear_extra_comment(ea, from);

        std::stringstream istream(comment);
        std::string line;
        while(std::getline(istream, line))
            update_extra_cmt(ea, from++, line.data());
    }

    void make_comments(Exporter& exporter, const HVersion& version, ea_t ea)
    {
        std::set<std::tuple<offset_t, CommentType_e, std::string>> comments;
        version.walk_comments([&](offset_t offset, CommentType_e type, const const_string_ref& comment)
        {
            const auto comment_ea = static_cast<ea_t>(ea + offset);
            const auto strcmt = make_string(comment);
            comments.emplace(offset, type, strcmt);
            switch(type)
            {
                case COMMENT_REPEATABLE:
                    if(!set_cmt(comment_ea, strcmt.data(), 1))
                        LOG(ERROR, "make_comments: 0x%" PRIxEA " unable to set repeatable comment '%s'\n", comment_ea, strcmt.data());
                    break;
                case COMMENT_NON_REPEATABLE:
                    if(!set_cmt(comment_ea, strcmt.data(), 0))
                        LOG(ERROR, "make_comments: 0x%" PRIxEA " unable to set non-repeatable comment '%s'\n", comment_ea, strcmt.data());
                    break;
                case COMMENT_ANTERIOR:
                    make_extra_comment(comment_ea, strcmt.data(), E_PREV);
                    break;
                case COMMENT_POSTERIOR:
                    make_extra_comment(comment_ea, strcmt.data(), E_NEXT);
                    break;
                case COMMENT_BOOKMARK:
                    add_bookmark(comment_ea, strcmt);
                    break;
                default:
                    LOG(ERROR, "make_comments: 0x%" PRIxEA " unknown %s comment\n", comment_ea, get_comment_type_string(type));
                    break;
            }
            return WALK_CONTINUE;
        });
        // delete obsolete comments
        for(ea_t it = ea, end = static_cast<ea_t>(ea + version.size()); it != BADADDR && it < end; it = get_item_end(it))
            ya::walk_comments(exporter, it, get_flags(it), [&](const const_string_ref& cmt, CommentType_e type)
            {
                if(!comments.count(std::make_tuple(it - ea, type, make_string(cmt))))
                    delete_comment(type, it);
            });
    }

    // use a macro & ensure compiler statically check sscanf...
    #define MAKE_TO_TYPE_FUNCTION(NAME, TYPE, FMT)\
    TYPE NAME(const char* value)\
    {\
        TYPE reply = {};\
        sscanf(value, FMT, &reply);\
        return reply;\
    }

    MAKE_TO_TYPE_FUNCTION(to_ea,      ea_t,             "%" PRIuEA);
    MAKE_TO_TYPE_FUNCTION(to_uchar,   uchar,            "%hhu");
    MAKE_TO_TYPE_FUNCTION(to_ushort,  ushort,           "%hu");
    MAKE_TO_TYPE_FUNCTION(to_int,     int,              "%d");
    MAKE_TO_TYPE_FUNCTION(to_sel,     sel_t,            "%" PRIuEA);
    MAKE_TO_TYPE_FUNCTION(to_bgcolor, bgcolor_t,        "%u");
    MAKE_TO_TYPE_FUNCTION(to_yaid,    YaToolObjectId,   "%" PRIx64);
    MAKE_TO_TYPE_FUNCTION(to_path,    uint32_t,         "0x%08X");
    MAKE_TO_TYPE_FUNCTION(to_xmlea,   ea_t,             "0x%0" EA_SIZE PRIXEA);

    template<typename T>
    int find_int(const T& data, const char* key)
    {
        const auto it = data.find(key);
        if(it == data.end())
            return 0;
        return to_int(it->second.data());
    }

    segment_t* check_segment(ea_t ea, ea_t end)
    {
        const auto segment = getseg(ea);
        if(!segment)
            return nullptr;

        if(segment->start_ea != ea || segment->end_ea != end)
            return nullptr;

        return segment;
    }

    segment_t* add_seg(ea_t start, ea_t end, ea_t base, int bitness, int align, int comb)
    {
        segment_t seg;
        seg.start_ea = start;
        seg.end_ea = end;
        seg.sel = setup_selector(base);
        seg.bitness = static_cast<uchar>(bitness);
        seg.align = static_cast<uchar>(align);
        seg.comb = static_cast<uchar>(comb);
        const auto ok = add_segm_ex(&seg, nullptr, nullptr, ADDSEG_NOSREG);
        if(!ok)
            return nullptr;

        return getseg(start);
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
        REG_ATTR_ES = 0,
        REG_ATTR_CS = 1,
        REG_ATTR_SS = 2,
        REG_ATTR_DS = 3,
        REG_ATTR_FS = 4,
        REG_ATTR_GS = 5,
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

    SegAttribute get_segment_attribute(const char* value)
    {
        for(size_t i = 0; i < COUNT_OF(g_seg_attributes); ++i)
            if(!strcmp(g_seg_attributes[i], value))
                return static_cast<SegAttribute>(i);
        return SEG_ATTR_COUNT;
    }

    bool set_segment_attribute(segment_t* seg, const char* key, const char* value)
    {
        ea_t        ea      = 0;
        uchar       uc      = 0;
        ushort      us      = 0;
        sel_t       sel     = 0;
        int         ival    = 0;
        bgcolor_t   bg      = 0;

        switch(get_segment_attribute(key))
        {
            case SEG_ATTR_START:
                ea = to_ea(value);
                std::swap(seg->start_ea, ea);
                return ea != seg->start_ea;

            case SEG_ATTR_END:
                ea = to_ea(value);
                std::swap(seg->end_ea, ea);
                return ea != seg->end_ea;

            case SEG_ATTR_BASE:
                ea = to_ea(value);
                if(ea == seg->orgbase)
                    return false;
                return set_segm_base(seg, ea);

            case SEG_ATTR_ALIGN:
                uc = to_uchar(value);
                std::swap(seg->align, uc);
                return seg->align != uc;

            case SEG_ATTR_COMB:
                uc = to_uchar(value);
                std::swap(seg->comb, uc);
                return seg->comb != uc;

            case SEG_ATTR_PERM:
                uc = to_uchar(value);
                std::swap(seg->perm, uc);
                return seg->perm != uc;

            case SEG_ATTR_BITNESS:
                ival = to_int(value);
                if(seg->bitness == ival)
                    return false;
                return set_segm_addressing(seg, ival);

            case SEG_ATTR_FLAGS:
                us = to_ushort(value);
                std::swap(seg->flags, us);
                return seg->flags != us;

            case SEG_ATTR_SEL:
                sel = to_sel(value);
                std::swap(seg->sel, sel);
                return seg->sel != sel;

            case SEG_ATTR_ES:
                sel = to_sel(value);
                std::swap(seg->defsr[REG_ATTR_ES], sel);
                return seg->defsr[REG_ATTR_ES] != sel;

            case SEG_ATTR_CS:
                sel = to_sel(value);
                std::swap(seg->defsr[REG_ATTR_CS], sel);
                return seg->defsr[REG_ATTR_CS] != sel;

            case SEG_ATTR_SS:
                sel = to_sel(value);
                std::swap(seg->defsr[REG_ATTR_SS], sel);
                return seg->defsr[REG_ATTR_SS] != sel;

            case SEG_ATTR_DS:
                sel = to_sel(value);
                std::swap(seg->defsr[REG_ATTR_DS], sel);
                return seg->defsr[REG_ATTR_DS] != sel;

            case SEG_ATTR_FS:
                sel = to_sel(value);
                std::swap(seg->defsr[REG_ATTR_FS], sel);
                return seg->defsr[REG_ATTR_FS] != sel;

            case SEG_ATTR_GS:
                sel = to_sel(value);
                std::swap(seg->defsr[REG_ATTR_GS], sel);
                return seg->defsr[REG_ATTR_GS] != sel;

            case SEG_ATTR_TYPE:
                uc = to_uchar(value);
                std::swap(seg->type, uc);
                return seg->type != uc;

            case SEG_ATTR_COLOR:
                bg = to_bgcolor(value);
                std::swap(seg->color, bg);
                return seg->color != bg;

            case SEG_ATTR_COUNT:
                return false;
        }

        return false;
    }

    void make_segment(const HVersion& version, ea_t ea)
    {
        const auto size = version.size();
        const auto name = version.username();
        const auto end  = static_cast<ea_t>(ea + size);

        int align = 0;
        int comb = 0;
        version.walk_attributes([&](const const_string_ref& key, const const_string_ref& val)
        {
            if(g_align == key)
                align = to_int(val.value);
            else if(g_comb == key)
                comb = to_int(val.value);
            return WALK_CONTINUE;
        });

        auto seg = check_segment(ea, end);
        if(!seg)
        {
            seg = add_seg(ea, end, 0, 1, align, comb);
            if(!seg)
            {
                LOG(ERROR, "make_segment: 0x%" PRIxEA " unable to add segment [0x%" PRIxEA ", 0x%" PRIxEA "] align:%d comb:%d\n", ea, ea, end, align, comb);
                return;
            }
        }

        if(name.size)
        {
            qstring curname;
            ya::wrap(&::get_segm_name, curname, const_cast<const segment_t*>(seg), 0);
            const auto strname = make_string(name);
            const auto ok = ya::to_string_ref(curname) == name || set_segm_name(seg, strname.data());
            if(!ok)
                LOG(ERROR, "make_segment: 0x%" PRIxEA " unable to set name %s\n", ea, strname.data());
        }

        static const const_string_ref read_only_attributes[] =
        {
            g_start_ea,
            g_end_ea,
            g_sel,
        };
        bool updated = false;
        version.walk_attributes([&](const const_string_ref& key, const const_string_ref& val)
        {
            for(const auto& it : read_only_attributes)
                if(it == key)
                    return WALK_CONTINUE;

            const auto strkey = make_string(key);
            const auto strval = make_string(val);
            updated |= set_segment_attribute(seg, strkey.data(), strval.data());
            return WALK_CONTINUE;
        });
        if(!updated)
            return;

        const auto ok = seg->update();
        if(!ok)
            LOG(ERROR, "make_segment: 0x%" PRIxEA " unable to update segment\n", ea);
    }

    void make_segment_chunk(Exporter& exporter, const HVersion& version, ea_t ea)
    {
        // TODO : now that we have enough precision, we could delete elements
        // that are in the base but not in our segment_chunk
        version.walk_blobs([&](offset_t offset, const void* pbuf, size_t szbuf)
        {
            if(!szbuf)
                return WALK_CONTINUE;

            const auto blob_ea = static_cast<ea_t>(ea + offset);
            exporter.buffer_.resize(szbuf);
            auto ok = get_bytes(&exporter.buffer_[0], szbuf, blob_ea, GMB_READALL);
            if(!ok)
            {
                LOG(ERROR, "make_segment_chunk: 0x%" PRIxEA " unable to read %zd bytes\n", blob_ea, szbuf);
                return WALK_CONTINUE;
            }
            if(!memcmp(&exporter.buffer_[0], pbuf, szbuf))
                return WALK_CONTINUE;

            // put_many_bytes does not return any error code...
            put_bytes(blob_ea, pbuf, szbuf);
            ok = get_bytes(&exporter.buffer_[0], szbuf, blob_ea, GMB_READALL);
            if(!ok || memcmp(&exporter.buffer_[0], pbuf, szbuf))
                LOG(ERROR, "make_segment_chunk: 0x%" PRIxEA " unable to write %zd bytes\n", blob_ea, szbuf);

            return WALK_CONTINUE;
        });
    }

    Tid get_tid(const Exporter& exporter, YaToolObjectId id)
    {
        const auto it = exporter.tids_.find(id);
        if(it == exporter.tids_.end())
            return {BADADDR, 0, OBJECT_TYPE_UNKNOWN};
        return it->second;
    }

    void set_tid(Exporter& exporter, YaToolObjectId id, ea_t tid, offset_t size, YaToolObjectType_e type)
    {
        exporter.tids_.insert({id, {tid, static_cast<asize_t>(size), type}});
    }

    const std::regex r_trailing_identifier{"\\s*<?[a-zA-Z_0-9]+>?\\s*$"}; // match c/c++ identifiers
    const std::regex r_type_id{"/\\*%(.+?)#([A-F0-9]{16})%\\*/"};         // match yaco ids /*%name:ID%*/
    const std::regex r_trailing_comma{"\\s*;\\s*$"};                      // match trailing ;
    const std::regex r_trailing_whitespace{"\\s+$"};                      // match trailing whitespace
    const std::regex r_leading_whitespace{"^\\s+"};                       // match leading whitespace
    const std::regex r_trailing_const_pointer{"\\*\\s*const\\s*$"};       // match trailing * const
    const std::regex r_trailing_pointer{"\\*\\s*$"};                      // match trailing *

    void replace_inline(std::string& value, const std::string& pattern, const std::string& replace)
    {
        size_t pos = 0;
        while(true)
        {
            pos = value.find(pattern, pos);
            if(pos == std::string::npos)
                break;

            value.replace(pos, pattern.size(), replace);
            pos += replace.size();
        }
    }

    std::string patch_prototype(const Exporter& exporter, const std::string& src, ea_t ea)
    {
        // remove/patch struct ids
        auto dst = src;
        qstring buffer;
        for(std::sregex_iterator it = {src.begin(), src.end(), r_type_id}, end; it != end; ++it)
        {
            const auto id = it->str(2);
            const auto name = it->str(1);
            // always remove special struct comment
            replace_inline(dst, "/*%" + name + "#" + id + "%*/", "");
            const auto k = exporter.tids_.find(to_yaid(id.data()));
            if(k == exporter.tids_.end())
            {
                LOG(WARNING, "make_prototype: 0x%" PRIxEA " unknown struct %s id %s\n", ea, name.data(), id.data());
                continue;
            }
            if(k->second.type != OBJECT_TYPE_STRUCT)
                continue;
            const auto tid = static_cast<tid_t>(k->second.tid);
            ya::wrap(&get_struc_name, buffer, tid);
            // replace struct name with new name
            replace_inline(dst, name, buffer.c_str());
        }

        // remove trailing whitespace
        dst = std::regex_replace(dst, r_trailing_whitespace, "");
        return dst;
    }

    tinfo_t make_simple_type(type_t type)
    {
        tinfo_t tif;
        tif.create_simple_type(type);
        return tif;
    }

    tinfo_t try_find_type(const char* value)
    {
        tinfo_t tif;
        std::string decl = value;
        auto ok = parse_decl(&tif, nullptr, nullptr, (decl + ";").data(), PT_SIL);
        if(ok)
            return tif;

        tif.clear();
        ok = tif.get_named_type(get_idati(), value);
        if(ok)
            return tif;

        tif.clear();
        return tif;
    }

    std::vector<bool> remove_pointers(std::string* value)
    {
        std::vector<bool> pointers;
        while(true)
        {
            auto dst = std::regex_replace(*value, r_trailing_const_pointer, "");
            const auto is_const = dst != *value;
            if(!is_const)
                dst = std::regex_replace(*value, r_trailing_pointer, "");
            dst = std::regex_replace(dst, r_trailing_whitespace, "");
            if(dst == *value)
                break;
            *value = dst;
            pointers.push_back(is_const);
         }
        return pointers;
    }

    tinfo_t add_back_pointers(const tinfo_t& tif, const std::vector<bool>& pointers)
    {
        tinfo_t work = tif;
        for(const auto is_const_ptr : pointers)
        {
            tinfo_t next;
            next.create_ptr(work);
            if(is_const_ptr)
                next.set_const();
            work = next;
        }
        return work;
    }

    tinfo_t find_single_type(const std::string& input)
    {
        // special case 'void' type because ida doesn't want to parse it...
        if(input == "void")
            return make_simple_type(BT_VOID);

        std::string value = input;
        auto tif = try_find_type(value.data());
        if(!tif.empty())
            return tif;

        value = std::regex_replace(value, r_trailing_comma, "");
        value = std::regex_replace(value, r_trailing_whitespace, "");
        auto pointers = remove_pointers(&value);
        tif = try_find_type(value.data());
        if(!tif.empty())
            return add_back_pointers(tif, pointers);

        // remove left-most identifier, which is possibly a variable name
        value = std::regex_replace(value, r_trailing_identifier, "");
        value = std::regex_replace(value, r_trailing_whitespace, "");
        pointers = remove_pointers(&value);
        tif = try_find_type(value.data());
        if(!tif.empty())
            return add_back_pointers(tif, pointers);

        return tinfo_t();
    }

    const std::regex r_varargs {"\\s*\\.\\.\\.\\s*\\)$"};

    cm_t get_calling_convention(const std::string& value, const std::string& args)
    {
        const auto has_varargs = std::regex_match(args, r_varargs);
        if(value == "__cdecl")
            return has_varargs ? CM_CC_ELLIPSIS : CM_CC_CDECL;
        if(value == "__stdcall")
            return CM_CC_STDCALL;
        if(value == "__pascal")
            return CM_CC_PASCAL;
        if(value == "__thiscall")
            return CM_CC_THISCALL;
        if(value == "__usercall")
            return has_varargs ? CM_CC_SPECIALE : CM_CC_SPECIAL;
        return CM_CC_UNKNOWN;
    }

    std::vector<std::string> split_args(const std::string& value)
    {
        std::vector<std::string> args;
        int in_templates = 0;
        int in_parens = 0;
        int in_comments = 0;
        size_t previous = 0;
        char cprev = 0;

        const auto add_arg = [&](size_t i)
        {
            auto arg = value.substr(previous, i - previous);
            arg = std::regex_replace(arg, r_leading_whitespace, "");
            arg = std::regex_replace(arg, r_trailing_whitespace, "");
            args.emplace_back(arg);
            previous = i + 1;
        };

        // ugly & broken way to determine where to split on ','
        for(size_t i = 0, end = value.size(); i < end; ++i)
        {
            const auto c = value[i];

            in_templates += c == '<';
            in_parens += c == '(';
            in_comments += c == '*' && cprev == '/';

            in_templates -= c == '>';
            in_parens -= c == ')';
            in_comments -= c == '/' && cprev == '*';

            // we have a ','
            cprev = c;
            if(c != ',')
                continue;
            if(in_templates || in_parens || in_comments)
                continue;
            add_arg(i);
        }
        if(!value.empty())
            add_arg(value.size());

        return args;
    }

    const std::regex r_function_definition  {"^(.+?)\\s*(__\\w+)\\s+sub\\((.*)\\)$"};

    tinfo_t try_find_type(ea_t ea, const std::string& input)
    {
        auto tif = find_single_type(input);
        if(!tif.empty())
            return tif;

        std::smatch match;
        auto ok = std::regex_match(input, match, r_function_definition);
        if(!ok)
            return tinfo_t();

        // we have a function definition
        const auto return_type = match.str(1);
        const auto calling_convention = match.str(2);
        const auto args = match.str(3);

        func_type_data_t ft;
        ft.rettype = try_find_type(ea, return_type);
        if(ft.rettype.empty())
            return tinfo_t();

        ft.cc = get_calling_convention(calling_convention, args);
        for(const auto& token : split_args(args))
        {
            funcarg_t arg;
            arg.type = try_find_type(ea, token);
            if(arg.type.empty())
                return tinfo_t();

            // FIXME try to parse argument name, it often work but is fundamentally broken
            std::string argname;
            const auto stripped = std::regex_replace(token, r_trailing_identifier, "");
            tif = try_find_type(ea, "typedef " + token + " a b");
            if(tif.empty())
                argname = token.substr(stripped.size());
            argname = std::regex_replace(argname, r_leading_whitespace, "");
            argname = std::regex_replace(argname, r_trailing_whitespace, "");

            arg.name = {argname.data(), argname.size()};
            ft.push_back(arg);
        }

        tif.clear();
        ok = tif.create_func(ft);
        if(!ok)
            return tinfo_t();

        return tif;
    }

    template<typename T>
    bool try_set_type(const Exporter* exporter, ea_t ea, const std::string& value, const T& operand)
    {
        if(value.empty())
            return false;

        const auto patched = exporter ? patch_prototype(*exporter, value, ea) : value;
        const auto tif = try_find_type(ea, patched.data());
        if(tif.empty())
        {
            LOG(ERROR, "set_type: 0x%" PRIxEA " unknown type %s\n", ea, patched.data());
            return false;
        }

        const auto ok = operand(tif);
        if(!ok)
            LOG(ERROR, "set_type: 0x%" PRIxEA " unable to set type %s\n", ea, patched.data());
        return ok;
    }

    bool set_type(const Exporter* exporter, ea_t ea, const std::string& value)
    {
        return try_set_type(exporter, ea, value, [&](const tinfo_t& tif)
        {
            return apply_tinfo(ea, tif, TINFO_DEFINITE);
        });
    }

    bool set_struct_member_type(const Exporter* exporter, ea_t ea, const std::string& value)
    {
        return try_set_type(exporter, ea, value, [&](const tinfo_t& tif)
        {
            struc_t* s = nullptr;
            auto* m = get_member_by_id(ea, &s);
            if(!s || !m)
                return false;
            const auto err = set_member_tinfo(s, m, 0, tif, 0);
            static_assert(SMT_FAILED == 0, "smt_code_t has been modified");
            return err > SMT_FAILED;
        });
    }

    void clear_function(const HVersion& version, ea_t ea)
    {
        version.walk_xrefs([&](offset_t offset, operand_t /*operand*/, YaToolObjectId /*id*/, const XrefAttributes* attrs)
        {
            bool has_size = false;
            version.walk_xref_attributes(attrs, [&](const const_string_ref& key, const const_string_ref& /*val*/)
            {
                has_size = g_find == key;
                return has_size ? WALK_STOP : WALK_CONTINUE;
            });
            if(!has_size)
                return WALK_CONTINUE;

            const auto xref_ea = static_cast<ea_t>(ea + offset);
            const auto func = get_func(xref_ea);
            if(!func)
                return WALK_CONTINUE;
            if(func->start_ea != ea)
                return WALK_CONTINUE;

            const auto ok = remove_func_tail(func, ea);
            if(!ok)
                LOG(ERROR, "clear_function: 0x%" PRIxEA " unable to remove func tail at %" PRIxEA "\n", ea, xref_ea);
            // FIXME check if we need for i in xrange(ea, ea + size): idc.MakeUnkn(i)
            return WALK_CONTINUE;
        });
    }

    bool set_function_flags(ea_t ea, YaToolFlag_T flags)
    {
        auto func = get_func(ea);
        if(!func)
            return false;
        func->flags = static_cast<ushort>(flags);
        return update_func(func);
    }

    bool add_function(ea_t ea, const HVersion& version, func_t* func)
    {
        const auto flags = get_flags(ea);
        if(is_func(flags) && func && func->start_ea == ea)
            return true;

        LOG(DEBUG, "make_function: 0x%" PRIxEA " flags 0x%08X current flags 0x%08x\n", ea, version.flags(), flags);
        if(func)
            LOG(DEBUG, "make_function: 0x%" PRIxEA " func [0x%" PRIxEA ", 0x%" PRIxEA "] size 0x%08" PRIX64 "\n", ea, func->start_ea, func->end_ea, version.size());

        auto ok = add_func(ea, BADADDR);
        if(ok)
            return true;

        if(!has_value(flags))
        {
            LOG(ERROR, "make_function: 0x%" PRIxEA " unable to add function, missing data\n", ea);
            return false;
        }

        clear_function(version, ea);
        return add_func(ea, BADADDR);
    }

    void make_function(const Exporter& exporter, const HVersion& version, ea_t ea)
    {
        const auto func = get_func(ea);
        auto ok = add_function(ea, version, func);
        if(!ok)
            LOG(ERROR, "make_function: 0x%" PRIxEA " unable to add function\n", ea);

        const auto flags = version.flags();
        if(flags)
            if(!set_function_flags(ea, flags))
                LOG(ERROR, "make_function: 0x%" PRIxEA " unable to set function flags 0x%08x\n", ea, flags);

        set_type(&exporter, ea, make_string(version.prototype()));

        for(const auto repeat : {false, true})
        {
            const auto cmt = version.header_comment(repeat);
            const auto strcmt = make_string(cmt);
            ok = set_func_cmt(func, strcmt.data(), repeat);
            if(!ok)
                LOG(ERROR, "make_function: 0x%" PRIxEA " unable to set %s comment to '%s'\n", ea, repeat ? "repeatable" : "non-repeatable", strcmt.data());
        }
    }

    bool begins_with_offset(const std::string& value)
    {
        static const char offset_prefix[] = "offset";
        return !strncmp(value.data(), offset_prefix, sizeof offset_prefix - 1);
    }

    const struct { char type[8]; reftype_t offset; } offset_types[] =
    {
        {"OFF8",    REF_OFF8},
        {"OFF16",   REF_OFF16},
        {"OFF32",   REF_OFF32},
        {"LOW8",    REF_LOW8},
        {"LOW16",   REF_LOW16},
        {"HIGH8",   REF_HIGH8},
        {"HIGH16",  REF_HIGH16},
        {"VHIGH",   V695_REF_VHIGH},
        {"VLOW",    V695_REF_VLOW},
        {"OFF64",   REF_OFF64},
    };

    reftype_t get_offset_type(const char* value)
    {
        for(const auto& it : offset_types)
            if(!stricmp(it.type, value))
                return it.offset;
        return REF_OFF32;
    }

    enum SignToggle_e
    {
        UNSIGNED,
        SIGNED,
    };

    bool set_sign(ea_t ea, operand_t operand, SignToggle_e toggle)
    {
        if(is_invsign(ea, get_flags(ea), operand) == !!toggle)
            return true;
        return toggle_sign(ea, operand);
    }

    bool try_make_valueview(ea_t ea, operand_t operand, const std::string& view)
    {
        if(view == "signeddecimal")
            return op_dec(ea, operand) && set_sign(ea, operand, SIGNED);
        if(view == "unsigneddecimal")
            return op_dec(ea, operand) && set_sign(ea, operand, UNSIGNED);
        if(view == "signedhexadecimal")
            return op_hex(ea, operand) && set_sign(ea, operand, SIGNED);
        if(view == "unsignedhexadecimal")
            return op_hex(ea, operand) && set_sign(ea, operand, UNSIGNED);
        if(view == "char")
            return op_chr(ea, operand);
        if(view == "binary")
            return op_bin(ea, operand);
        if(view == "octal")
            return op_oct(ea, operand);
        if(begins_with_offset(view))
        {
            const auto dash = view.find('-');
            auto op_type = REF_OFF32;
            if(dash != std::string::npos)
                op_type = get_offset_type(&view.data()[dash+1]);
            refinfo_t ri;
            ri.init(op_type);
            return !!op_offset_ex(ea, operand, &ri);
        }

        LOG(ERROR, "make_valueview: 0x%" PRIxEA " unexpected value view type %s\n", ea, view.data());
        return false;
    }

    void make_valueview(ea_t ea, operand_t operand, const std::string& view)
    {
        const auto ok = try_make_valueview(ea, operand, view);
        if(!ok)
            LOG(ERROR, "make_valueview: 0x%" PRIxEA " unable to make value view\n", ea);
    }

    void make_registerview(ea_t ea, offset_t offset, const std::string& name, offset_t end, const std::string& newname)
    {
        const auto func = get_func(ea);
        if(!func)
        {
            LOG(ERROR, "make_registerview: 0x%" PRIxEA " missing function\n", ea);
            return;
        }

        const auto ea0 = static_cast<ea_t>(func->start_ea + offset);
        const auto ea1 = static_cast<ea_t>(func->start_ea + end);
        const auto regvar = find_regvar(func, ea0, ea1, name.data(), newname.data());
        if(regvar)
        {
            if(regvar->start_ea == ea0 && regvar->end_ea == ea1)
                return;

            const auto err = del_regvar(func, ea0, ea1, regvar->canon);
            if(err)
                LOG(ERROR, "make_registerview: 0x%" PRIxEA " unable to del regvar 0x%p 0x%" PRIxEA "-0x%" PRIxEA " %s -> %s error %d\n",
                    ea, func, ea0, ea1, name.data(), newname.data(), err);
        }

        const auto err = add_regvar(func, ea0, ea1, name.data(), newname.data(), nullptr);
        if(err)
            LOG(ERROR, "make_registerview: 0x%" PRIxEA " unable to add regvar 0x%p 0x%" PRIxEA "-0x%" PRIxEA " %s -> %s error %d\n",
                ea, func, ea0, ea1, name.data(), newname.data(), err);
    }

    void make_hiddenarea(ea_t ea, offset_t offset, offset_t offset_end, const std::string& value)
    {
        const auto start = static_cast<ea_t>(ea + offset);
        const auto end = static_cast<ea_t>(ea + offset_end);
        const auto ok = add_hidden_range(start, end, value.data(), nullptr, nullptr, ~0u);
        if(!ok)
            LOG(ERROR, "make_hiddenarea: 0x%" PRIxEA " unable to set hidden area %" PRIxEA "-%" PRIxEA " %s\n", ea, start, end, value.data());
    }

    void clear_register_views(const HVersion& version, ea_t ea)
    {
        const auto func = get_func(ea);
        if(!func)
            return;

        const range_t range{ea, ea + static_cast<ea_t>(version.size())};
        for(int i = 0; i < func->regvarqty; ++i)
        {
            const auto regvar = &func->regvars[i];
            if(!range.contains(regvar->start_ea))
                continue;
            const auto err = del_regvar(func, regvar->start_ea, regvar->end_ea, regvar->canon);
            if(err != REGVAR_ERROR_OK)
                LOG(ERROR, "make_basic_block: 0x%" PRIxEA " unable to delete regvar %s 0x%" PRIxEA "-0x%" PRIxEA "\n", ea, regvar->canon, regvar->start_ea, regvar->end_ea);
            else
                --i;
        }
    }

    void clear_applied_enums(const HVersion& version, ea_t ea)
    {
        const auto end = ea + version.size();
        for(auto it = ea; it < end; it = get_item_end(it))
        {
            const auto flags = get_flags(it);
            for(int n = 0; n < UA_MAXOP; ++n)
                if(is_enum(flags, n))
                    clr_op_type(it, n);
        }
    }

    void make_views(const HVersion& version, ea_t ea)
    {
        clear_applied_enums(version, ea);
        clear_register_views(version, ea);
        version.walk_value_views([&](offset_t offset, operand_t operand, const const_string_ref& value)
        {
            make_valueview(static_cast<ea_t>(ea + offset), operand, make_string(value));
            return WALK_CONTINUE;
        });
        version.walk_register_views([&](offset_t offset, offset_t end, const const_string_ref& name, const const_string_ref& newname)
        {
            make_registerview(ea, offset, make_string(name), end, make_string(newname));
            return WALK_CONTINUE;
        });
        version.walk_hidden_areas([&](offset_t offset, offset_t offset_end, const const_string_ref& value)
        {
            make_hiddenarea(ea, offset, offset_end, make_string(value));
            return WALK_CONTINUE;
        });
    }

    void make_code(Exporter& exporter, const HVersion& version, ea_t ea)
    {
        del_func(ea);
        create_insn(ea);
        make_name(exporter, version, ea);
        make_views(version, ea);
    }

    void set_data_type(const Exporter& exporter, const HVersion& version, ea_t ea)
    {
        const auto size = static_cast<size_t>(version.size());
        if(!size)
        {
            const auto ok = del_items(ea, DELIT_EXPAND);
            if(!ok)
                LOG(ERROR, "make_data: 0x%" PRIxEA " unable to set unknown\n", ea);
            return;
        }

        const auto flags = version.flags();
        if(!flags)
        {
            const auto ok = create_byte(ea, static_cast<asize_t>(size));
            if(!ok)
                LOG(ERROR, "make_data: 0x%" PRIxEA " unable to set data size %zd\n", ea, size);
            return;
        }

        if(is_strlit(flags))
        {
            const auto strtype = version.string_type();
            auto ok = create_strlit(ea, size, strtype == UINT8_MAX ? STRTYPE_C : strtype);
            if(!ok)
                LOG(ERROR, "make_data: 0x%" PRIxEA " unable to make ascii string size %zd type %d\n", ea, size, strtype);
            return;
        }

        if(is_struct(flags))
        {
            bool found = false;
            version.walk_xrefs([&](offset_t /*offset*/, operand_t /*operand*/, YaToolObjectId id, const XrefAttributes* /*attrs*/)
            {
                const auto fi = exporter.tids_.find(id);
                if(fi == exporter.tids_.end())
                    return WALK_CONTINUE;

                del_items(ea, DELIT_DELNAMES, static_cast<asize_t>(size));
                auto ok = create_struct(ea, static_cast<asize_t>(size), fi->second.tid);
                if(!ok)
                    LOG(ERROR, "make_data: 0x%" PRIxEA " unable to set struct %016" PRIx64 " size %zd\n", ea, id, size);
                found = true;
                return WALK_CONTINUE;
            });
            if(!found)
                LOG(ERROR, "make_data: 0x%" PRIxEA " unknown struct %016" PRIx64 " %s\n", ea, version.id(), make_string(version.username()).data());
            return;
        }

        const auto type_flags = flags & (DT_TYPE | get_optype_flags0(~0u));
        const auto ok = create_data(ea, type_flags, static_cast<asize_t>(size), 0);
        if(!ok)
            LOG(ERROR, "make_data: 0x%" PRIxEA " unable to set data type 0x%" PRIx64 " size %zd\n", ea, static_cast<uint64_t>(type_flags), size);
    }

    void make_data(Exporter& exporter, const HVersion& version, ea_t ea)
    {
        set_data_type(exporter, version, ea);
        make_name(exporter, version, ea);
        set_type(&exporter, ea, make_string(version.prototype()));
    }

    bool is_member(const Exporter& exporter, YaToolObjectId parent, YaToolObjectId id)
    {
        const auto range = exporter.members_.equal_range(parent);
        for(auto it = range.first; it != range.second; ++it)
            if(it->second == id)
                return true;
        return false;
    }

    enum_t try_get_enum(const HVersion& version, const std::string& name)
    {
        auto eid = get_enum(name.data());
        if(eid != BADADDR)
            return eid;

        // when renaming an enum, we delete the previous one
        // in order to prevent orphan ordinals
        // we try to retrieve the previous one
        tinfo_t tif;
        const auto idati = get_idati();
        const auto ok = tif.get_numbered_type(idati, static_cast<uint32_t>(version.address()));
        if(!ok)
            return BADADDR;

        qstring ename;
        tif.get_type_name(&ename);
        if(is_autosync(ename.c_str(), tif))
            return BADADDR;

        return import_type(idati, -1, ename.c_str());
    }

    void make_enum(Exporter& exporter, const HVersion& version, ea_t ea)
    {
        const auto id = version.id();
        const auto flags = version.flags();
        const auto name = make_string(version.username());
        auto eid = try_get_enum(version, name);
        if(eid == BADADDR)
            eid = add_enum(~0u, name.data(), flags & ~0x1);
        if(eid == BADADDR)
        {
            LOG(ERROR, "make_enum: 0x%" PRIxEA " unable to create enum", ea);
            return;
        }

        if(!set_enum_name(eid, name.data()))
            LOG(ERROR, "make_enum: 0x%" PRIxEA " unable to set name %s\n", ea, name.data());

        if(!set_enum_bf(eid, flags & 0x1))
            LOG(ERROR, "make_enum: 0x%" PRIxEA " unable to set as bitfield\n", ea);

        const auto width = version.size();
        if(width)
            if(!set_enum_width(eid, static_cast<int>(width)))
                LOG(ERROR, "make_enum: 0x%" PRIxEA " unable to set width %" PRId64 "\n", ea, width);

        for(const auto rpt : {false, true})
        {
            const auto cmt = make_string(version.header_comment(rpt));
            if(!set_enum_cmt(eid, cmt.data(), rpt))
                LOG(ERROR, "make_enum: 0x%" PRIxEA " unable to set %s comment to %s\n", ea, rpt ? "repeatable" : "non-repeatable", cmt.data());
        }

        // remember our childs
        version.walk_xrefs([&](offset_t /*offset*/, operand_t /*operand*/, YaToolObjectId xref_id, const XrefAttributes* /*attrs*/)
        {
            exporter.members_.emplace(id, xref_id);
            return WALK_CONTINUE;
        });

        const auto qbuf = exporter.qpool_.acquire();
        ya::walk_enum_members(eid, [&](const_t cid, uval_t value, uchar serial, bmask_t bmask)
        {
            ya::wrap(&get_enum_member_name, *qbuf, cid);
            const auto yaid = exporter.provider_.get_enum_member_id(id, ya::to_string_ref(*qbuf));
            if(is_member(exporter, id, yaid))
                return;

            if(!del_enum_member(eid, value, serial, bmask))
                LOG(ERROR, "make_enum: 0x%" PRIxEA ": unable to delete member %" PRIxEA " %" PRIxEA " %x %" PRIxEA "\n", ea, cid, value, serial, bmask);
        });

        set_tid(exporter, id, eid, 0, OBJECT_TYPE_ENUM);
    }

    void make_enum_member(Exporter& exporter, const HVersion& version, ea_t ea)
    {
        const auto parent_id = version.parent_id();
        const auto it = exporter.tids_.find(parent_id);
        if(it == exporter.tids_.end())
        {
            LOG(ERROR, "make_enum_member: 0x%" PRIxEA " unable to find parent enum %016" PRIx64 "\n", ea, parent_id);
            return;
        }

        const auto id = version.id();
        const auto name = version.username();
        const auto strname = make_string(name);
        if(!is_member(exporter, parent_id, id))
        {
            LOG(ERROR, "make_enum_member: %016" PRIx64 " %s: invalid member for struct %016" PRIx64 "\n", id, strname.data(), parent_id);
            return;
        }

        const auto eid = it->second.tid;
        const auto bmask = is_bf(eid) ? version.flags() : DEFMASK;
        auto mid = get_enum_member(eid, ea, 0, bmask);
        if(mid == BADADDR)
        {
            const auto err = add_enum_member(eid, strname.data(), ea, bmask);
            if(err)
                LOG(ERROR, "make_enum_member: 0x%" PRIxEA " unable to add enum member %s bmask 0x%" PRIxEA "\n", ea, strname.data(), bmask);
            mid = get_enum_member(eid, ea, 0, bmask);
        }

        if(!set_enum_member_name(mid, strname.data()))
            LOG(ERROR, "make_enum_member: 0x%" PRIxEA " unable to set enum member name to %s\n", ea, strname.data());

        for(const auto rpt : {false, true})
        {
            const auto cmt = make_string(version.header_comment(rpt));
            if(!set_enum_member_cmt(mid, cmt.data(), rpt))
                LOG(ERROR, "make_enum_member: 0x%" PRIxEA " unable to set %s comment to %s\n", ea, rpt ? "repeatable" : "non-repeatable", cmt.data());
        }
    }

    void make_reference_info(Exporter& exporter, const HVersion& version, ea_t ea)
    {
        const auto id = version.id();
        const auto flags = version.flags();
        refinfo_t ref;
        ref.init(flags, ea);
        exporter.refs_.emplace(id, ref);
    }

    void set_stackframe_member_operand(ea_t ea, offset_t offset, operand_t operand)
    {
        const auto ok = op_stkvar(static_cast<ea_t>(ea + offset), operand);
        if(!ok)
            LOG(ERROR, "make_basic_block: 0x%" PRIxEA " unable to set stackframe member at offset %" PRId64 " operand %d\n", ea, offset, operand);
    }

    void set_enum_operand(ea_t ea, offset_t offset, operand_t operand, enum_t enum_id)
    {
        // FIXME serial
        const auto ok = op_enum(static_cast<ea_t>(ea + offset), operand, enum_id, 0);
        if(!ok)
            LOG(ERROR, "make_basic_block: 0x%" PRIxEA " unable to set enum 0x%" PRIxEA " at offset %" PRId64 " operand %d\n", ea, enum_id, offset, operand);
    }

    void set_reference_info(RefInfos& refs, ea_t ea, offset_t offset, operand_t operand, YaToolObjectId id)
    {
        const auto it_ref = refs.find(id);
        if(it_ref == refs.end())
            return;
        const auto& ref = it_ref->second;
        const auto ok = op_offset_ex(static_cast<ea_t>(ea + offset), operand, &ref);
        if(!ok)
            LOG(ERROR, "make_basic_block: 0x%" PRIxEA " unable to set reference info %" PRIxEA ":%x at offset %" PRId64 " operand %d\n", ea, ref.base, ref.flags, offset, operand);
    }

    struct PathItem
    {
        tid_t    tid;
        uint32_t idx;
    };

    struct Path
    {
        offset_t                offset;
        operand_t               operand;
        std::vector<PathItem>   types;
    };

    using Paths = std::vector<Path>;
    using IdaPath = std::vector<tid_t>;

    Path& get_path_at(Paths& paths, offset_t offset, operand_t operand)
    {
        const auto it = std::find_if(paths.begin(), paths.end(), [&](const auto& item)
        {
            return item.offset == offset && item.operand == operand;
        });
        if(it != paths.end())
            return *it;

        paths.push_back({offset, operand, {}});
        return paths.back();
    }

    void fill_path(Paths& paths, tid_t tid, offset_t offset, operand_t operand, const HVersion& version, const XrefAttributes* attrs)
    {
        auto& path = get_path_at(paths, offset, operand);
        uint32_t path_idx = 0;
        version.walk_xref_attributes(attrs, [&](const const_string_ref& key, const const_string_ref& val)
        {
            if(!(g_path_idx == key))
                return WALK_CONTINUE;
            const auto strval = make_string(val);
            path_idx = to_path(strval.data());
            return WALK_STOP;
        });
        path.types.push_back({tid, path_idx});
    }

    void set_path(Path& path, ea_t ea)
    {
        insn_t insn;
        if(path.types.empty())
            return;

        std::sort(path.types.begin(), path.types.end(), [](const auto& a, const auto b)
        {
            return a.idx < b.idx;
        });
        IdaPath ida_path;
        ida_path.clear();
        ida_path.reserve(path.types.size());
        for(const auto& it : path.types)
            ida_path.emplace_back(it.tid);
        auto ok = decode_insn(&insn, static_cast<ea_t>(ea + path.offset));
        if(!ok)
            return;

        ok = op_stroff(insn, path.operand, &ida_path[0], static_cast<int>(ida_path.size()), 0);
        if(ok)
            return;

        std::string pathstr;
        bool first = true;
        for(const auto tid : ida_path)
        {
            if(!first)
                pathstr += ":";
            pathstr += std::to_string(tid);
        }
        LOG(ERROR, "make_basic_block: 0x%" PRIxEA " unable to set path %s at offset %" PRId64 " operand %d\n", ea, pathstr.data(), path.offset, path.operand);
    }

    void make_basic_block(Exporter& exporter, const HVersion& version, ea_t ea)
    {
        Paths paths;
        make_name(exporter, version, ea);
        make_views(version, ea);
        version.walk_xrefs([&](offset_t offset, operand_t operand, YaToolObjectId xref_id, const XrefAttributes* attrs)
        {
            const auto key = get_tid(exporter, xref_id);
            switch(key.type)
            {
                case OBJECT_TYPE_UNKNOWN:
                case OBJECT_TYPE_BINARY:
                case OBJECT_TYPE_DATA:
                case OBJECT_TYPE_CODE:
                case OBJECT_TYPE_FUNCTION:
                case OBJECT_TYPE_ENUM_MEMBER:
                case OBJECT_TYPE_BASIC_BLOCK:
                case OBJECT_TYPE_SEGMENT:
                case OBJECT_TYPE_SEGMENT_CHUNK:
                case OBJECT_TYPE_REFERENCE_INFO:
                case OBJECT_TYPE_COUNT:
                    break;

                case OBJECT_TYPE_STRUCT:
                case OBJECT_TYPE_STACKFRAME:
                case OBJECT_TYPE_STRUCT_MEMBER:
                    fill_path(paths, key.tid, offset, operand, version, attrs);
                    break;

                case OBJECT_TYPE_STACKFRAME_MEMBER:
                    set_stackframe_member_operand(ea, offset, operand);
                    break;

                case OBJECT_TYPE_ENUM:
                    set_enum_operand(ea, offset, operand, key.tid);
                    break;
            }
            set_reference_info(exporter.refs_, ea, offset, operand, xref_id);
            return WALK_CONTINUE;
        });
        for(auto& path : paths)
            set_path(path, ea);
    }

    void set_struct_member(qstring& buffer, const char* where, struc_t* struc, const const_string_ref& name, ea_t ea, asize_t size, func_t* func, const opinfo_t* pop)
    {
        if(!name.size)
        {
            const auto defname = ya::get_default_name(buffer, ea, func);
            const auto ok = set_member_name(struc, ea, defname.value);
            if(!ok)
                LOG(ERROR, "%s: 0x%" PRIxEA ":%" PRIxEA " unable to set member name %s\n", where, struc->id, ea, defname.value);
        }
        const auto ok = set_member_type(struc, ea, FF_BYTE, pop, size);
        if(!ok)
            LOG(ERROR, "%s: 0x%" PRIxEA ":%" PRIxEA " unable to set member type to 0x%" PRIxEA " bytes\n", where, struc->id, ea, size);
    }

    void clear_struct_fields(Exporter& exporter, const char* where, const HVersion& version, ea_t struct_id)
    {
        begin_type_updating(UTP_STRUCT);

        const auto size = version.size();
        const auto struc = get_struc(struct_id);
        const auto last_offset = get_struc_last_offset(struc);
        const auto func_ea = get_func_by_frame(struct_id);
        const auto func = get_func(func_ea);

        // get existing members
        std::set<offset_t> fields;
        const auto vid = version.id();
        version.walk_xrefs([&](offset_t offset, operand_t /*operand*/, YaToolObjectId xid, const XrefAttributes* /*attrs*/)
        {
            fields.emplace(offset);
            exporter.members_.emplace(vid, xid);
            return WALK_CONTINUE;
        });

        // create missing members first & prevent deleting all members
        std::set<offset_t> new_fields;
        qstring member_name;
        for(const auto offset : fields)
        {
            const auto aoff = static_cast<asize_t>(offset);
            auto member = get_member(struc, aoff);
            if(member && member->soff < offset)
            {
                set_member_type(struc, member->soff, FF_BYTE, nullptr, 1);
                member = get_member(struc, aoff);
            }
            if(member && get_member_name(&member_name, member->id) > 0)
                continue;

            new_fields.insert(offset);
            const auto defname = ya::get_default_name(member_name, aoff, func);
            const auto field_size = offset == last_offset && offset == size ? 0 : 1;
            const auto err = add_struc_member(struc, defname.value, aoff, FF_BYTE, nullptr, field_size);
            if(err != STRUC_ERROR_MEMBER_OK)
                LOG(ERROR, "clear_%s: 0x%" PRIxEA ":%" PRIx64 " unable to add member %s size %d\n", where, struct_id, offset, defname.value, field_size);
        }

        for(size_t i = 0; i < struc->memqty; ++i)
        {
            // ignore new fields
            auto& m = struc->members[i];
            const auto offset = m.soff;
            const auto is_new = new_fields.count(offset);
            if(is_new)
                continue;

            // remove unknown fields
            const auto is_known = fields.count(offset);
            if(!is_known)
            {
                // ignore special stack frame members
                if(func_ea != BADADDR && is_special_member(m.id))
                    continue;
                const auto ok = del_struc_member(struc, offset);
                if(!ok)
                    LOG(ERROR, "clear_%s: 0x%" PRIxEA ":%" PRIxEA " unable to delete member\n", where, struct_id, offset);
                else
                    --i;
                continue;
            }

            // reset known fields
            const auto field_size = offset == last_offset && offset == size ? 0 : 1;
            const auto id = exporter.provider_.get_member_id(vid, offset);
            const auto key = get_tid(exporter, id);
            // skip fields which have already been exported
            if(key.tid != BADADDR)
                continue;

            set_struct_member(member_name, where, struc, g_empty, offset, field_size, func, nullptr);
            for(const auto repeat : {false, true})
            {
                const auto ok = set_member_cmt(&m, g_empty.value, repeat);
                if(!ok)
                    LOG(ERROR, "clear_%s: 0x%" PRIxEA ":%" PRIxEA " unable to reset %s comment\n", where, struct_id, offset, repeat ? "repeatable" : "non-repeatable");
            }
        }

        end_type_updating(UTP_STRUCT);
    }

    struc_t* get_or_add_frame(const HVersion& version, ea_t func_ea)
    {
        auto frame = get_frame(func_ea);
        if(frame)
            return frame;

        const auto func = get_func(func_ea);
        if(!func)
            return nullptr;

        ea_t lvars = 0;
        ushort regvars = 0;
        ea_t args = 0;
        version.walk_attributes([&](const const_string_ref& key, const const_string_ref& val)
        {
            if(key == g_stack_lvars)
                lvars = to_xmlea(make_string(val).data());
            else if(key == g_stack_regvars)
                regvars = static_cast<ushort>(to_xmlea(make_string(val).data()));
            else if(key == g_stack_args)
                args = to_xmlea(make_string(val).data());
            return WALK_CONTINUE;
        });
        const auto ok = add_frame(func, lvars, regvars, args);
        if(!ok)
            set_frame_size(func, lvars, regvars, args);
        return get_frame(func);
    }

    void make_stackframe(Exporter& exporter, const HVersion& version, ea_t ea)
    {
        const auto frame = get_or_add_frame(version, ea);
        if(!frame)
        {
            LOG(ERROR, "make_stackframe: 0x%" PRIxEA " unable to create function\n", ea);
            return;
        }

        const auto id = version.id();
        set_tid(exporter, id, frame->id, version.size(), OBJECT_TYPE_STACKFRAME);
        clear_struct_fields(exporter, "stackframe_fields", version, frame->id);
    }

    optional<YaToolObjectId> get_xref_at(const HVersion& version, offset_t offset, operand_t operand)
    {
        optional<YaToolObjectId> reply;
        version.walk_xrefs([&](offset_t off, operand_t op, YaToolObjectId xref_id, const XrefAttributes* /*attrs*/)
        {
            if(off != offset || op != operand)
                return WALK_CONTINUE;

            reply = xref_id;
            return WALK_CONTINUE;
        });
        return reply;
    }

    const opinfo_t* get_member_info(opinfo_t* pop, asize_t& size, const Exporter& exporter, const HVersion& version, flags_t flags)
    {
        if(is_strlit(flags))
        {
            pop->strtype = version.string_type();
            if(pop->strtype == UINT8_MAX)
                pop->strtype = STRTYPE_C;
            return pop;
        }

        // if the sub field is a struct/enum then the first xref field is the struct/enum object id
        const auto xref_id = get_xref_at(version, 0, 0);
        if(!xref_id)
            return nullptr;

        const auto xref = get_tid(exporter, *xref_id);
        if(xref.tid == BADADDR)
            return nullptr;

        if(is_struct(flags))
        {
            const auto struc = get_struc(xref.tid);
            if(!struc)
                return nullptr;

            // as members are updated without ordering
            // target struct may not have its final size
            // yet IDA MUST be given a struct size multiple
            // so we must use the current structure size here
            const auto current_size = get_struc_size(struc);
            if(xref.size > 0 && current_size > 0)
            {
                size *= current_size;
                size /= xref.size;
            }
            pop->tid = struc->id;
            return pop;
        }

        if(is_enum0(flags))
        {
            pop->ec.serial = 0; // FIXME ?
            pop->ec.tid = xref.tid;
            return pop;
        }

        return nullptr;
    }

    void make_struct_member(Exporter& exporter, const char* where, const HVersion& version, ea_t ea)
    {
        const auto id = version.id();
        const auto name = make_string(version.username());
        const auto parent_id = version.parent_id();
        const auto parent = get_tid(exporter, parent_id);
        if(parent.tid == BADADDR)
        {
            LOG(ERROR, "make_%s: %016" PRIx64 " %s: missing parent struct %016" PRIx64 "\n", where, id, name.data(), parent_id);
            return;
        }

        if(!is_member(exporter, parent_id, id))
        {
            LOG(ERROR, "make_%s: %016" PRIx64 " %s: invalid member for struct %016" PRIx64 "\n", where, id, name.data(), parent_id);
            return;
        }

        const auto struc = get_struc(parent.tid);
        if(!struc)
        {
            LOG(ERROR, "make_%s: %016" PRIx64 " %s: missing struct id %016" PRIx64 " tid_t %" PRIxEA "\n", where, id, name.data(), parent_id, parent.tid);
            return;
        }

        const auto sname = exporter.qpool_.acquire();
        ya::wrap(&get_struc_name, *sname, parent.tid);
        const auto qbuf = exporter.qpool_.acquire();
        const auto func = get_func(get_func_by_frame(struc->id));
        for(auto it = get_struc_last_offset(struc); struc->is_union() && it != BADADDR && it < ea; ++it)
        {
            const auto offset = it + 1;
            const auto defname = ya::get_default_name(*qbuf, offset, func);
            const auto err = add_struc_member(struc, defname.value, BADADDR, FF_BYTE | FF_DATA, nullptr, 1);
            if(err != STRUC_ERROR_MEMBER_OK)
                LOG(ERROR, "make_%s: %s:%" PRIxEA ": unable to add member %s %" PRIxEA " (error %d)\n", where, sname->c_str(), ea, defname.value, offset, err);
        }

        if(!name.empty())
        {
            const auto ok = set_member_name(struc, ea, name.data());
            if(!ok)
                LOG(ERROR, "make_%s: %s:%" PRIxEA ": unable to set member name %s\n", where, sname->c_str(), ea, name.data());
        }

        opinfo_t op;
        const auto flags = version.flags();
        auto size = static_cast<asize_t>(version.size());
        const auto pop = get_member_info(&op, size, exporter, version, flags);
        auto ok = set_member_type(struc, ea, (flags & DT_TYPE) | FF_DATA, pop, size);
        const auto is_struct_applied = ok && is_struct(flags);
        if(!ok)
            LOG(ERROR, "make_%s: %s.%s: unable to set member type %x to %" PRIuEA " bytes\n", where, sname->c_str(), name.data(), flags, size);

        const auto member = get_member(struc, ea);
        if(!member)
        {
            LOG(ERROR, "make_%s: %s.%s: missing member\n", where, sname->c_str(), name.data());
            return;
        }

        for(const auto repeat : {false, true})
        {
            const auto cmt = version.header_comment(repeat);
            const auto strcmt = make_string(cmt);
            ok = set_member_cmt(member, strcmt.data(), repeat);
            if(!ok)
                LOG(ERROR, "make_%s: %s.%s: unable to set %s comment to '%s'\n", where, sname->c_str(), name.data(), repeat ? "repeatable" : "non-repeatable", strcmt.data());
        }

        const auto prototype = version.prototype();
        // do not reapply prototype if struct member was already applied
        if(prototype.size && !is_struct_applied)
        {
            const auto strtype = make_string(prototype);
            ok = set_struct_member_type(&exporter, member->id, strtype);
            if(!ok)
                LOG(ERROR, "make_%s: %s.%s: unable to set prototype '%s'\n", where, sname->c_str(), name.data(), strtype.data());
        }
        set_tid(exporter, version.id(), member->id, 0, struc->props & SF_FRAME ? OBJECT_TYPE_STACKFRAME_MEMBER : OBJECT_TYPE_STRUCT_MEMBER);
    }

    struc_t* get_struc_from_name(const char* name)
    {
        return get_struc(netnode(name));
    }

    struc_t* get_or_add_struct(const HVersion& version, ea_t ea, const char* name)
    {
        const auto struc = get_struc_from_name(name);
        if(struc)
            return struc;

        const auto is_union = !!(version.flags() & 1); // fixme use constant
        const auto ok = add_struc(BADADDR, name, is_union);
        if(!ok)
        {
            LOG(ERROR, "make_struct: 0x%" PRIxEA " unable to add struct\n", ea);
            return nullptr;
        }

        return get_struc_from_name(name);
    }

    void make_struct(Exporter& exporter, const HVersion& version, ea_t ea)
    {
        const auto name = make_string(version.username());
        const auto struc = get_or_add_struct(version, ea, name.data());
        if(!struc)
        {
            LOG(ERROR, "make_struct: 0x%" PRIxEA " missing struct %s\n", ea, name.data());
            return;
        }

        const auto id = version.id();
        set_tid(exporter, id, struc->id, version.size(), OBJECT_TYPE_STRUCT);

        for(const auto repeat : {false, true})
        {
            const auto cmt = version.header_comment(repeat);
            const auto strcmt = make_string(cmt);
            const auto ok = set_struc_cmt(struc->id, strcmt.data(), repeat);
            if(!ok)
                LOG(ERROR, "make_struct: 0x%" PRIxEA " unable to set %s comment to '%s'\n", ea, repeat ? "repeatable" : "non-repeatable", strcmt.data());
        }

        clear_struct_fields(exporter, "struct_fields", version, struc->id);
    }
}

void Exporter::on_version(const HVersion& version)
{
    const auto ea = static_cast<ea_t>(version.address());
    switch(version.type())
    {
        case OBJECT_TYPE_UNKNOWN:
        case OBJECT_TYPE_BINARY:
        case OBJECT_TYPE_COUNT:
            break;

        case OBJECT_TYPE_STRUCT:
            make_struct(*this, version, ea);
            break;

        case OBJECT_TYPE_STACKFRAME:
            if(use_stacks_)
                make_stackframe(*this, version, ea);
            break;

        case OBJECT_TYPE_ENUM:
            make_enum(*this, version, ea);
            break;

        case OBJECT_TYPE_CODE:
            make_code(*this, version, ea);
            make_comments(*this, version, ea);
            break;

        case OBJECT_TYPE_FUNCTION:
            if(plugin_)
                plugin_->make_function_enter(version, ea);
            make_function(*this, version, ea);
            if(plugin_)
                plugin_->make_function_exit(version, ea);
            break;

        case OBJECT_TYPE_BASIC_BLOCK:
            if(plugin_)
                plugin_->make_basic_block_enter(version, ea);
            make_basic_block(*this, version, ea);
            make_comments(*this, version, ea);
            if(plugin_)
                plugin_->make_basic_block_exit(version, ea);
            break;

        case OBJECT_TYPE_STRUCT_MEMBER:
            make_struct_member(*this, "struct_member", version, ea);
            break;

        case OBJECT_TYPE_ENUM_MEMBER:
            make_enum_member(*this, version, ea);
            break;

        case OBJECT_TYPE_STACKFRAME_MEMBER:
            if(use_stacks_)
                make_struct_member(*this, "stackframe_member", version, ea);
            break;

        case OBJECT_TYPE_DATA:
            make_data(*this, version, ea);
            make_comments(*this, version, ea);
            break;

        case OBJECT_TYPE_SEGMENT:
            make_segment(version, ea);
            break;

        case OBJECT_TYPE_SEGMENT_CHUNK:
            make_segment_chunk(*this, version, ea);
            break;

        case OBJECT_TYPE_REFERENCE_INFO:
            make_reference_info(*this, version, ea);
            break;
    }
}

void Exporter::on_object(const HObject& object)
{
    object.walk_versions([&](const HVersion& version)
    {
        on_version(version);
        return WALK_CONTINUE;
    });
}

void Exporter::on_deleted(YaToolObjectId id)
{
    const auto it_enum = enums_.find(id);
    if(it_enum != enums_.end())
    {
        del_enum(it_enum->second);
        enums_.erase(it_enum);
    }
}

void Exporter::on_default(YaToolObjectId id)
{
    // FIXME ?
    UNUSED(id);
}

bool set_type_at(ea_t ea, const std::string& prototype)
{
    return set_type(nullptr, ea, prototype);
}

bool set_struct_member_type_at(ea_t ea, const std::string& prototype)
{
    return set_struct_member_type(nullptr, ea, prototype);
}

namespace
{
    void import_to_ida(IModelAccept& model, IHashProvider& provider, UseStacks use_stacks)
    {
        const auto prev = inf.is_auto_enabled();
        inf.set_auto_enabled(false);
        Exporter exporter{provider, use_stacks};
        model.accept(*MakeVisitorFromListener(exporter));
        inf.set_auto_enabled(prev);
    }
}

void import_to_ida(IModelAccept& model, IHashProvider& provider)
{
    import_to_ida(model, provider, USE_STACKS);
}

void import_to_ida(const std::string& filename)
{
    import_to_ida(*MakeFlatBufferDatabaseModel(filename), *MakeHashProvider(), SKIP_STACKS);
}