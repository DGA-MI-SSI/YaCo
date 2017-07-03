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

#include "YaToolsIDANativeLib.hpp"
#include "YaToolsHashProvider.hpp"
#include <YaToolObjectVersion.hpp>
#include <MultiplexerDelegatingVisitor.hpp>
#include "Logger.h"
#include "Yatools.h"
#include "../Helpers.h"
#include "YaHelpers.hpp"
#include "StringFormat.hpp"

#include <string>
#include <iostream>
#include <set>
#include <chrono>
#include <regex>

#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("ida_exporter", (FMT), ## __VA_ARGS__)

#ifdef __EA64__
#define EA_FMT  "%llx"
#define EA_DECIMAL_FMT "%llu"
#define SEL_FMT "%lld"
#else
#define EA_FMT  "%x"
#define EA_DECIMAL_FMT "%u"
#define SEL_FMT "%d"
#endif

namespace
{
    using RefInfos = std::unordered_map<YaToolObjectId, refinfo_t>;

    struct Exporter
        : public IExporter
    {
        Exporter(YaToolsHashProvider* provider);

        // IExporter methods
        bool set_type               (ea_t ea, const std::string& prototype) override;
        bool set_struct_member_type (ea_t ea, const std::string& prototype) override;
        void set_tid                (YaToolObjectId id, ea_t tid, YaToolObjectType_e type) override;
        Tid  get_tid                (YaToolObjectId id) override;
        void analyze_function       (ea_t ea) override;
        void make_function          (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea) override;
        void make_views             (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea) override;
        void make_code              (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea) override;
        void make_data              (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea) override;
        void make_enum              (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea) override;
        void make_enum_member       (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea) override;
        void make_name              (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea, bool is_in_func) override;
        void make_comments          (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea) override;
        void make_header_comments   (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea) override;
        void make_segment           (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea) override;
        void make_segment_chunk     (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea) override;
        void make_basic_block       (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea) override;
        void make_reference_info    (std::shared_ptr<YaToolObjectVersion>& version, ea_t ea) override;
        void clear_struct_fields    (std::shared_ptr<YaToolObjectVersion>& version, ea_t struct_id) override;

        //
        std::string patch_prototype(const std::string& prototype, ea_t ea);
        using TidMap = std::unordered_map<YaToolObjectId, Tid>;
        using EnumMemberMap = std::unordered_map<uint64_t, enum_t>;

        YaToolsHashProvider&    provider;
        EnumMemberMap           enum_members;
        YaToolsIDANativeLib     tools;
        RefInfos                refs;
        TidMap                  tids;
    };
}

std::shared_ptr<IExporter> MakeExporter(YaToolsHashProvider* provider)
{
    return std::make_shared<Exporter>(provider);
}

Exporter::Exporter(YaToolsHashProvider* provider)
    : provider(*provider)
{
}

void Exporter::make_name(std::shared_ptr<YaToolObjectVersion>& version, ea_t ea, bool is_in_func)
{
    const auto& name = version->get_name();
    auto flags = version->get_name_flags();
    if(!flags)
        flags = SN_CHECK;

    const auto reset_flags = SN_CHECK | (is_in_func ? SN_LOCAL : 0);
    const auto previous = get_true_name(ea);
    set_name(ea, "", reset_flags);
    if(name.empty() || IsDefaultName(make_string_ref(name)))
    {
        LOG(DEBUG, "make_name: 0x" EA_FMT " resetting name %s\n", ea, name.data());
        return;
    }

    const auto ok = set_name(ea, name.data(), flags | SN_NOWARN);
    if(ok)
        return;

    LOG(WARNING, "make_name: 0x" EA_FMT " unable to set name flags 0x%08x '%s'\n", ea, flags, name.data());
    set_name(ea, previous.c_str(), SN_CHECK | SN_NOWARN);
}

namespace
{
    void add_bookmark(ea_t ea, std::string comment_text)
    {
        char buffer[1024];
        ya::walk_bookmarks([&](int i, ea_t locea, curloc loc)
        {
            LOG(DEBUG, "add_bookmark: 0x" EA_FMT " found bookmark[%d]\n", ea, i);
            if(locea != ea)
                return;

            loc.markdesc(i, buffer, sizeof buffer);
            if(comment_text == buffer)
                return;

            LOG(DEBUG, "add_bookmark: 0x" EA_FMT " bookmark[%d] = %s\n", ea, i, comment_text.data());
            loc.ea = ea;
            loc.x = 0;
            loc.y = 0;
            loc.lnnum = 0;
            loc.mark(i, comment_text.data(), comment_text.data());
        });
    }

    // FIXME useless ?
    const std::string& sanitize_comment_to_ascii(const std::string& comment)
    {
        return comment;
    }
}

void Exporter::make_comments(std::shared_ptr<YaToolObjectVersion>& version, ea_t address)
{
    const auto current_comments = tools.get_comments_in_area(address, static_cast<ea_t>(address + version->get_size()));
    const auto new_comments = version->get_offset_comments();
    for(const auto& current_cmt : current_comments)
    {
        const auto comment_offset = current_cmt.first - address;
        for(const auto& one_comment : current_cmt.second)
        {
            const auto comment_type = one_comment.first;
            const auto& current_comment_text = one_comment.second;
            const auto it = new_comments.find(std::make_pair(static_cast<offset_t>(comment_offset), comment_type));
            if(it != new_comments.end() && it->second == current_comment_text)
                continue;
            tools.delete_comment_at_ea(address + current_cmt.first, comment_type);
        }
    }

    for(const auto& new_comment : new_comments)
    {
        const auto comment_offset = new_comment.first.first;
        const auto ea = static_cast<ea_t>(address + comment_offset);
        const auto comment_type = new_comment.first.second;
        const auto& comment_text = sanitize_comment_to_ascii(new_comment.second);
        LOG(DEBUG, "make_comments: 0x" EA_FMT " adding comment type %d\n", ea, comment_type);
        switch(comment_type)
        {
            case COMMENT_REPEATABLE:
                set_cmt(ea, comment_text.c_str(), 1);
                break;
            case COMMENT_NON_REPEATABLE:
                set_cmt(ea, comment_text.c_str(), 0);
                break;
            case COMMENT_ANTERIOR:
                tools.make_extra_comment(ea, comment_text.data(), E_PREV);
                break;
            case COMMENT_POSTERIOR:
                tools.make_extra_comment(ea, comment_text.data(), E_NEXT);
                break;
            case COMMENT_BOOKMARK:
                add_bookmark(ea, comment_text);
                break;
            default:
                LOG(ERROR, "make_comments: 0x" EA_FMT " unknown comment type %d\n", ea, comment_type);
                break;
        }
    }
}

namespace
{
    // use a macro & ensure compiler statically check sscanf...
    #define MAKE_TO_TYPE_FUNCTION(NAME, TYPE, FMT)\
    TYPE NAME(const char* value)\
    {\
        TYPE reply = {};\
        sscanf(value, FMT, &reply);\
        return reply;\
    }

    MAKE_TO_TYPE_FUNCTION(to_ea,      ea_t,             EA_DECIMAL_FMT);
    MAKE_TO_TYPE_FUNCTION(to_uchar,   uchar,            "%hhd");
    MAKE_TO_TYPE_FUNCTION(to_ushort,  ushort,           "%hd");
    MAKE_TO_TYPE_FUNCTION(to_int,     int,              "%d");
    MAKE_TO_TYPE_FUNCTION(to_sel,     sel_t,            SEL_FMT);
    MAKE_TO_TYPE_FUNCTION(to_bgcolor, bgcolor_t,        "%u");
    MAKE_TO_TYPE_FUNCTION(to_yaid,    YaToolObjectId,   "%llx");
    MAKE_TO_TYPE_FUNCTION(to_path,    int,              "0x%08X")

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

        if(segment->startEA != ea || segment->endEA != end)
            return nullptr;

        return segment;
    }

    segment_t* add_seg(ea_t start, ea_t end, ea_t base, int bitness, int align, int comb)
    {
        segment_t seg;
        seg.startEA = start;
        seg.endEA = end;
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

    void set_segment_attribute(segment_t* seg, const char* key, const char* value)
    {
        switch(get_segment_attribute(key))
        {
            case SEG_ATTR_START:
                seg->startEA = to_ea(value);
                break;

            case SEG_ATTR_END:
                seg->endEA = to_ea(value);
                break;

            case SEG_ATTR_BASE:
                set_segm_base(seg, to_ea(value));
                break;

            case SEG_ATTR_ALIGN:
                seg->align = to_uchar(value);
                break;

            case SEG_ATTR_COMB:
                seg->comb = to_uchar(value);
                break;

            case SEG_ATTR_PERM:
                seg->perm = to_uchar(value);
                break;

            case SEG_ATTR_BITNESS:
                set_segm_addressing(seg, to_int(value));
                break;

            case SEG_ATTR_FLAGS:
                seg->flags = to_ushort(value);
                break;

            case SEG_ATTR_SEL:
                seg->sel = to_sel(value);
                break;

            case SEG_ATTR_ES:
                seg->defsr[REG_ATTR_ES] = to_sel(value);
                break;

            case SEG_ATTR_CS:
                seg->defsr[REG_ATTR_CS] = to_sel(value);
                break;

            case SEG_ATTR_SS:
                seg->defsr[REG_ATTR_SS] = to_sel(value);
                break;

            case SEG_ATTR_DS:
                seg->defsr[REG_ATTR_DS] = to_sel(value);
                break;

            case SEG_ATTR_FS:
                seg->defsr[REG_ATTR_FS] = to_sel(value);
                break;

            case SEG_ATTR_GS:
                seg->defsr[REG_ATTR_GS] = to_sel(value);
                break;

            case SEG_ATTR_TYPE:
                seg->type = to_uchar(value);
                break;

            case SEG_ATTR_COLOR:
                seg->color = to_bgcolor(value);
                break;

            case SEG_ATTR_COUNT:
                break;
        }
    }
}

void Exporter::make_segment(std::shared_ptr<YaToolObjectVersion>& version, ea_t ea)
{
    const auto size = version->get_size();
    const auto name = version->get_name();
    const auto attributes = version->get_attributes();
    const auto end  = static_cast<ea_t>(ea + size);

    auto seg = check_segment(ea, end);
    if(!seg)
    {
        const auto align = find_int(attributes, "align");
        const auto comb = find_int(attributes, "comb");
        seg = add_seg(ea, end, 0, 1, align, comb);
        if(!seg)
        {
            LOG(ERROR, "make_segment: 0x" EA_FMT " unable to add segment [0x" EA_FMT ", 0x" EA_FMT "] align:%d comb:%d\n", ea, ea, end, align, comb);
            return;
        }
    }

    if(!name.empty())
    {
        const auto ok = set_segm_name(seg, "%s", name.data());
        if(!ok)
            LOG(ERROR, "make_segment: 0x" EA_FMT " unable to set name %s\n", ea, name.data());
    }

    const auto is_readonly = [](const std::string& key)
    {
        static const char read_only_attributes[][12] =
        {
            "start_ea",
            "end_ea",
            "sel",
        };
        for(const auto& it : read_only_attributes)
            if(key == it)
                return true;
        return false;
    };

    bool updated = false;
    for(const auto& p : attributes)
    {
        if(is_readonly(p.first))
            continue;
        set_segment_attribute(seg, p.first.data(), p.second.data());
        updated = true;
    }
    if(!updated)
        return;

    const auto ok = seg->update();
    if(!ok)
        LOG(ERROR, "make_segment: 0x" EA_FMT " unable to update segment\n", ea);
}

void Exporter::make_segment_chunk(std::shared_ptr<YaToolObjectVersion>& version, ea_t ea)
{
    // TODO : now that we have enough precision, we could delete elements
    // that are in the base but not in our segment_chunk
    std::vector<uint8_t> buffer;
    for(const auto& it : version->get_blobs())
    {
        const auto offset = static_cast<ea_t>(ea + it.first);
        const auto& data = it.second;
        buffer.resize(data.size());
        auto ok = get_many_bytes(offset, &buffer[0], data.size());
        if(!ok)
        {
            LOG(ERROR, "make_segment_chunk: 0x" EA_FMT " unable to read %d bytes\n", offset, data.size());
            continue;
        }
        if(data == buffer)
            continue;

        // put_many_bytes does not return any error code...
        put_many_bytes(offset, &data[0], data.size());
        ok = get_many_bytes(offset, &buffer[0], data.size());
        if(!ok || data != buffer)
            LOG(ERROR, "make_segment_chunk: 0x" EA_FMT " unable to write %d bytes\n", offset, data.size());
    }
}

Tid Exporter::get_tid(YaToolObjectId id)
{
    const auto it = tids.find(id);
    if(it == tids.end())
        return {BADADDR, OBJECT_TYPE_UNKNOWN};
    return it->second;
}

void Exporter::set_tid(YaToolObjectId id, ea_t tid, YaToolObjectType_e type)
{
    tids.insert({id, {tid, type}});
}

namespace
{
    const std::regex r_trailing_identifier{"\\s*<?[a-zA-Z_0-9]+>?\\s*$"};     // match c/c++ identifiers
    const std::regex r_type_id{"/\\*%(.+?)#([A-F0-9]{16})%\\*/"}; // match yaco ids /*%name:ID%*/
    const std::regex r_trailing_comma{"\\s*;\\s*$"};                     // match trailing ;
    const std::regex r_trailing_whitespace{"\\s+$"};                          // match trailing whitespace
    const std::regex r_leading_whitespace{"^\\s+"};                          // match leading whitespace
    const std::regex r_trailing_pointer{"\\*\\s*$"};                       // match trailing *

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
}

std::string Exporter::patch_prototype(const std::string& src, ea_t ea)
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
        const auto k = tids.find(to_yaid(id.data()));
        if(k == tids.end())
        {
            LOG(WARNING, "make_prototype: 0x" EA_FMT " unknown struct %s id %s\n", ea, name.data(), id.data());
            continue;
        }
        if(k->second.type != OBJECT_TYPE_STRUCT)
            continue;
        const auto tid = static_cast<tid_t>(k->second.tid);
        get_struc_name(&buffer, tid);
        // replace struct name with new name
        replace_inline(dst, name, buffer.c_str());
    }

    // remove trailing whitespace
    dst = std::regex_replace(dst, r_trailing_whitespace, "");
    return dst;
}

namespace
{
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
        auto ok = parse_decl2(idati, (decl + ";").data(), nullptr, &tif, PT_SIL);
        if(ok)
            return tif;

        tif.clear();
        ok = tif.get_named_type(idati, value);
        if(ok)
            return tif;

        tif.clear();
        return tif;
    }

    size_t remove_pointers(std::string* value)
    {
        size_t count = 0;
        while(true)
        {
            auto dst = std::regex_replace(*value, r_trailing_pointer, "");
            dst = std::regex_replace(dst, r_trailing_whitespace, "");
            if(dst == *value)
                break;
            *value = dst;
            count++;
         }
        return count;
    }

    tinfo_t add_back_pointers(const tinfo_t& tif, size_t num_pointers)
    {
        tinfo_t work = tif;
        for(size_t i = 0; i < num_pointers; ++i)
        {
            tinfo_t next;
            next.create_ptr(work);
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
        auto num_pointers = remove_pointers(&value);
        tif = try_find_type(value.data());
        if(!tif.empty())
            return add_back_pointers(tif, num_pointers);

        // remove left-most identifier, which is possibly a variable name
        value = std::regex_replace(value, r_trailing_identifier, "");
        value = std::regex_replace(value, r_trailing_whitespace, "");
        num_pointers = remove_pointers(&value);
        tif = try_find_type(value.data());
        if(!tif.empty())
            return add_back_pointers(tif, num_pointers);

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

    tinfo_t find_type(ea_t ea, const std::string& input);

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
        ft.rettype = find_type(ea, return_type);
        if(ft.rettype.empty())
            return tinfo_t();

        ft.cc = get_calling_convention(calling_convention, args);
        for(const auto& token : split_args(args))
        {
            funcarg_t arg;
            arg.type = find_type(ea, token);
            if(arg.type.empty())
                return tinfo_t();

            // FIXME try to parse argument name, it often work but is fundamentally broken
            std::string argname;
            const auto stripped = std::regex_replace(token, r_trailing_identifier, "");
            tif = find_type(ea, "typedef " + token + " a b");
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

    tinfo_t find_type(ea_t ea, const std::string& input)
    {
        tinfo_t tif = try_find_type(ea, input);
        if(tif.empty())
            LOG(ERROR, "find_type: 0x" EA_FMT " unable to guess type for %s\n", ea, input.data());
        return tif;
    }

    template<typename T>
    bool try_set_type(Exporter& exporter, ea_t ea, const std::string& value, const T& operand)
    {
        if(value.empty())
            return false;

        const auto patched = exporter.patch_prototype(value, ea);
        const auto tif = find_type(ea, patched.data());
        const auto ok = operand(tif);
        if(!ok)
            LOG(ERROR, "set_type: 0x" EA_FMT " unable to set type %s\n", ea, patched.data());
        return ok;
    }
}

bool Exporter::set_type(ea_t ea, const std::string& value)
{
    return try_set_type(*this, ea, value, [&](const tinfo_t& tif)
    {
        return apply_tinfo2(ea, tif, TINFO_DEFINITE);
    });
}

bool Exporter::set_struct_member_type(ea_t ea, const std::string& value)
{
    return try_set_type(*this, ea, value, [&](const tinfo_t& tif)
    {
        struc_t* s = nullptr;
        auto* m = get_member_by_id(ea, &s);
        return s && m && set_member_tinfo2(s, m, 0, tif, 0);
    });
}

namespace
{
    bool set_function_comment(ea_t ea, const char* comment, bool repeatable)
    {
        const auto func = get_func(ea);
        if(!func)
            return false;
        return set_func_cmt(func, comment, repeatable);
    }

    bool set_struct_comment(const Exporter::TidMap& tids, YaToolObjectId id, const char* comment, bool repeatable)
    {
        const auto it = tids.find(id);
        if(it == tids.end())
            return false;
        return set_struc_cmt(it->second.tid, comment, repeatable);
    }

    bool set_struct_member_comment(const Exporter::TidMap& tids, YaToolObjectId id, const char* comment, bool repeatable)
    {
        const auto it = tids.find(id);
        if(it == tids.end())
            return false;
        const auto member = get_member_by_id(it->second.tid);
        if(!member)
            return false;
        return set_member_cmt(member, comment, repeatable);
     }
}

void Exporter::make_header_comments(std::shared_ptr<YaToolObjectVersion>& version, ea_t ea)
{
    const auto type = version->get_type();
    const auto id = version->get_id();
    for(const auto rpt : {false, true})
    {
        const auto comment = version->get_header_comment(rpt);
        auto ok = false;
        switch(type)
        {
            case OBJECT_TYPE_FUNCTION:
                ok = set_function_comment(ea, comment.data(), rpt);
                break;

            case OBJECT_TYPE_STRUCT:
                ok = set_struct_comment(tids, id, comment.data(), rpt);
                break;

            case OBJECT_TYPE_STRUCT_MEMBER:
                ok = set_struct_member_comment(tids, id, comment.data(), rpt);
                break;

            case OBJECT_TYPE_ENUM:              // done in make_enum
            case OBJECT_TYPE_ENUM_MEMBER:       // done in make_enum_member
                ok = true;
                break;

            // unsupported yet
            case OBJECT_TYPE_UNKNOWN:
            case OBJECT_TYPE_BINARY:
            case OBJECT_TYPE_DATA:
            case OBJECT_TYPE_CODE:
            case OBJECT_TYPE_BASIC_BLOCK:
            case OBJECT_TYPE_SEGMENT:
            case OBJECT_TYPE_SEGMENT_CHUNK:
            case OBJECT_TYPE_STACKFRAME:
            case OBJECT_TYPE_STACKFRAME_MEMBER:
            case OBJECT_TYPE_REFERENCE_INFO:
            case OBJECT_TYPE_COUNT:
                ok = comment.empty();
                break;
        }
        if(!ok)
            LOG(ERROR, "make_header_comments: 0x" EA_FMT " unable to set %s %s comment: %s\n", ea, get_object_type_string(type), rpt ? "repeatable" : "non-repeatable", comment.data());
    }
}

void Exporter::analyze_function(ea_t ea)
{
    const auto ok = ya::walk_function_chunks(ea, [=](area_t area)
    {
        if(!analyze_area(area.startEA, area.endEA))
            LOG(ERROR, "analyze_function: 0x" EA_FMT " unable to analyze area " EA_FMT "-" EA_FMT "\n", ea, area.startEA, area.endEA);
    });
    if(!ok)
        LOG(ERROR, "analyze_function: 0x" EA_FMT " missing function\n", ea);
}

namespace
{
    void clear_function(const YaToolObjectVersion& version, ea_t ea)
    {
        for(const auto& it : version.get_xrefed_id_map())
            for(const auto& ju : it.second)
            {
                const auto itsize = ju.attributes.find("size");
                if(itsize == ju.attributes.end())
                    continue;

                const auto xref_ea = static_cast<ea_t>(ea + it.first.first);
                const auto func = get_func(xref_ea);
                if(!func)
                    continue;
                if(func->startEA == ea)
                    continue;

                const auto ok = remove_func_tail(func, ea);
                if(!ok)
                    LOG(ERROR, "clear_function: 0x" EA_FMT " unable to remove func tail at " EA_FMT "\n", ea, xref_ea);
                // FIXME check if we need for i in xrange(ea, ea + size): idc.MakeUnkn(i)
            }
    }

    bool set_function_flags(ea_t ea, ObjectVersionFlag_T flags)
    {
        auto func = get_func(ea);
        if(!func)
            return false;
        func->flags = static_cast<ushort>(flags);
        return update_func(func);
    }

    bool add_function(ea_t ea, const YaToolObjectVersion& version)
    {
        const auto flags = getFlags(ea);
        const auto func = get_func(ea);
        if(isFunc(flags) && func && func->startEA == ea)
            return true;

        LOG(DEBUG, "make_function: 0x" EA_FMT " flags 0x%08X current flags 0x%08x\n", ea, version.get_object_flags(), flags);
        if(func)
            LOG(DEBUG, "make_function: 0x" EA_FMT " func [0x" EA_FMT ", 0x" EA_FMT "] size 0x%08llX\n", ea, func->startEA, func->endEA, version.get_size());

        auto ok = add_func(ea, BADADDR);
        if(ok)
            return true;

        if(!hasValue(flags))
        {
            LOG(ERROR, "make_function: 0x" EA_FMT " unable to add function, missing data\n", ea);
            return false;
        }

        clear_function(version, ea);
        return add_func(ea, BADADDR);
    }
}

void Exporter::make_function(std::shared_ptr<YaToolObjectVersion>& version, ea_t ea)
{
    auto ok = add_function(ea, *version);
    if(!ok)
        LOG(ERROR, "make_function: 0x" EA_FMT " unable to add function\n", ea);

    ok = !!analyze_area(ea, ea + 1);
    if(!ok)
        LOG(ERROR, "make_function: 0x" EA_FMT " unable to analyze area\n", ea);

    const auto flags = version->get_object_flags();
    if(flags)
        if(!set_function_flags(ea, flags))
            LOG(ERROR, "make_function: 0x" EA_FMT " unable to set function flags 0x%08x\n", ea, flags);

    set_type(ea, version->get_prototype());
}

namespace
{
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
        {"VHIGH",   REF_VHIGH},
        {"VLOW",    REF_VLOW},
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
        if(is_invsign(ea, getFlags(ea), operand) == !!toggle)
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

        LOG(ERROR, "make_valueview: 0x" EA_FMT " unexpected value view type %s\n", ea, view.data());
        return false;
    }

    void make_valueview(ea_t ea, operand_t operand, const std::string& view)
    {
        const auto ok = try_make_valueview(ea, operand, view);
        if(!ok)
            LOG(ERROR, "make_valueview: 0x" EA_FMT " unable to make value view\n", ea);
    }

    void make_registerview(ea_t ea, offset_t offset, const std::string& name, offset_t end, const std::string& newname)
    {
        const auto func = get_func(ea);
        if(!func)
        {
            LOG(ERROR, "make_registerview: 0x" EA_FMT " missing function\n", ea);
            return;
        }

        const auto ea0 = static_cast<ea_t>(func->startEA + offset);
        const auto ea1 = static_cast<ea_t>(func->startEA + end);
        const auto regvar = find_regvar(func, ea0, ea1, name.data(), newname.data());
        if(regvar)
        {
            if(regvar->startEA == ea0 && regvar->endEA == ea1)
                return;

            const auto err = del_regvar(func, ea0, ea1, regvar->canon);
            if(err)
                LOG(ERROR, "make_registerview: 0x" EA_FMT " unable to del regvar 0x%p 0x" EA_FMT "-0x" EA_FMT " %s -> %s error %d\n",
                    ea, func, ea0, ea1, name.data(), newname.data(), err);
        }

        const auto err = add_regvar(func, ea0, ea1, name.data(), newname.data(), nullptr);
        if(err)
            LOG(ERROR, "make_registerview: 0x" EA_FMT " unable to add regvar 0x%p 0x" EA_FMT "-0x" EA_FMT " %s -> %s error %d\n",
                ea, func, ea0, ea1, name.data(), newname.data(), err);
    }

    void make_hiddenarea(ea_t ea, offset_t offset, offset_t offset_end, const std::string& value)
    {
        const auto start = static_cast<ea_t>(ea + offset);
        const auto end = static_cast<ea_t>(ea + offset_end);
        const auto ok = add_hidden_area(start, end, value.data(), nullptr, nullptr, ~0u);
        if(!ok)
            LOG(ERROR, "make_hiddenarea: 0x" EA_FMT " unable to set hidden area " EA_FMT "-" EA_FMT " %s\n", ea, start, end, value.data());
    }
}

void Exporter::make_views(std::shared_ptr<YaToolObjectVersion>& version, ea_t ea)
{
    for(const auto& it : version->get_offset_valueviews())
        make_valueview(static_cast<ea_t>(ea + it.first.first), it.first.second, it.second);
    for(const auto& it : version->get_offset_registerviews())
        make_registerview(ea, it.first.first, it.first.second, it.second.first, it.second.second);
    for(const auto& it : version->get_offset_hiddenareas())
        make_hiddenarea(ea, it.first.first, it.first.second, it.second);
}

void Exporter::make_code(std::shared_ptr<YaToolObjectVersion>& version, ea_t ea)
{
    del_func(ea);
    create_insn(ea);
    make_name(version, ea, false);
    make_views(version, ea);
}

namespace
{
    void set_data_type(ea_t ea, YaToolObjectVersion& version, const Exporter::TidMap& struct_ids)
    {
        const auto size = static_cast<size_t>(version.get_size());
        if(!size)
        {
            const auto ok = do_unknown(ea, DOUNK_EXPAND);
            if(!ok)
                LOG(ERROR, "make_data: 0x" EA_FMT " unable to set unknown\n", ea);
            return;
        }

        const auto flags = version.get_object_flags();
        if(!flags)
        {
            const auto ok = doByte(ea, size);
            if(!ok)
                LOG(ERROR, "make_data: 0x" EA_FMT " unable to set data size %zd\n", ea, size);
            return;
        }

        if(isASCII(flags))
        {
            const auto strtype = version.get_string_type();
            auto ok = make_ascii_string(ea, size, strtype);
            if(!ok)
                LOG(ERROR, "make_data: 0x" EA_FMT " unable to make ascii string size %zd type %d\n", ea, size, strtype);
            setFlags(ea, flags);
            return;
        }

        if(isStruct(flags))
        {
            bool found = false;
            for(const auto& it : version.get_xrefed_id_map())
                for(const auto& xref : it.second)
                {
                    const auto fi = struct_ids.find(xref.object_id);
                    if(fi == struct_ids.end())
                        continue;

                    do_unknown_range(ea, size, DOUNK_DELNAMES);
                    const auto prev = inf.s_auto;
                    inf.s_auto = true;
                    autoWait();
                    auto ok = doStruct(ea, size, fi->second.tid);
                    inf.s_auto = prev;
                    if(!ok)
                        LOG(ERROR, "make_data: 0x" EA_FMT " unable to set struct %016llx size %d\n", ea, xref.object_id, size);
                    found = true;
                }
            if(!found)
                LOG(ERROR, "make_data: 0x" EA_FMT " unknown struct %016llx %s\n", ea, version.get_id(), version.get_name().data());
            return;
        }

        const auto type_flags = flags & (DT_TYPE | get_optype_flags0(~0u));
        const auto ok = do_data_ex(ea, type_flags, size, 0);
        if(!ok)
            LOG(ERROR, "make_data: 0x" EA_FMT " unable to set data type 0x%llx size %zd\n", ea, static_cast<uint64_t>(type_flags), size);
    }
}

void Exporter::make_data(std::shared_ptr<YaToolObjectVersion>& version, ea_t ea)
{
    set_data_type(ea, *version, tids);
    make_name(version, ea, false);
    set_type(ea, version->get_prototype());
}

void Exporter::make_enum(std::shared_ptr<YaToolObjectVersion>& version, ea_t ea)
{
    const auto name = version->get_name();
    const auto flags = version->get_object_flags();
    auto eid = get_enum(name.data());
    if(eid == BADADDR)
        eid = add_enum(~0u, name.data(), flags & ~ENUM_FLAGS_IS_BF);

    if(!set_enum_bf(eid, flags & ENUM_FLAGS_IS_BF))
        LOG(ERROR, "make_enum: 0x" EA_FMT " unable to set as bitfield\n", ea);

    const auto width = version->get_size();
    if(width)
        if(!set_enum_width(eid, static_cast<int>(width)))
            LOG(ERROR, "make_enum: 0x" EA_FMT " unable to set width %lld\n", ea, width);

    for(const auto rpt : {false, true})
        if(!set_enum_cmt(eid, sanitize_comment_to_ascii(version->get_header_comment(rpt)).data(), rpt))
        {
            LOG(ERROR, "make_enum: 0x" EA_FMT " unable to set %s comment to %s\n", ea, rpt ? "repeatable" : "non-repeatable", version->get_header_comment(rpt).data());
        }

    const auto xref_ids = version->get_xrefed_ids();
    qstring const_name;
    qstring const_value;
    ya::walk_enum_members(eid, [&](const_t cid, uval_t value, uchar serial, bmask_t bmask)
    {
        const auto it = enum_members.find(cid);
        if(it != enum_members.end() && it->second == eid)
            return;

        get_enum_member_name(&const_name, cid);
        to_py_hex(const_value, value);
        const auto yaid = provider.get_enum_member_id(eid, make_string_ref(name), cid, ya::to_string_ref(const_name), ya::to_string_ref(const_value), bmask, true);
        if(xref_ids.count(yaid))
            return;

        if(!del_enum_member(eid, value, serial, bmask))
            LOG(ERROR, "make_enum: 0x" EA_FMT ": unable to delete member " EA_FMT " " EA_FMT " %x " EA_FMT "\n", ea, cid, value, serial, bmask);
    });

    const auto id = version->get_id();
    tids.insert({id, {eid, OBJECT_TYPE_ENUM}});
    provider.put_hash_struc_or_enum(eid, id, false);
}

void Exporter::make_enum_member(std::shared_ptr<YaToolObjectVersion>& version, ea_t ea)
{
    const auto parent_id = version->get_parent_object_id();
    const auto it = tids.find(parent_id);
    if(it == tids.end())
    {
        LOG(ERROR, "make_enum_member: 0x" EA_FMT " unable to find parent enum %016llx\n", ea, parent_id);
        return;
    }

    const auto eid = it->second.tid;
    const auto ename = get_enum_name(eid);
    const auto name = version->get_name();
    const auto id = version->get_id();
    provider.put_hash_enum_member(ya::to_string_ref(ename), make_string_ref(name), ea, id, false);

    const auto bmask = is_bf(eid) ? version->get_object_flags() : DEFMASK;
    auto mid = get_enum_member(eid, ea, 0, bmask);
    if(mid == BADADDR)
    {
        const auto err = add_enum_member(eid, name.data(), ea, bmask);
        if(err)
            LOG(ERROR, "make_enum_member: 0x" EA_FMT " unable to add enum member %s bmask 0x" EA_FMT "\n", ea, name.data(), bmask);
        mid = get_enum_member(eid, ea, 0, bmask);
    }

    if(!set_enum_member_name(mid, name.data()))
        LOG(ERROR, "make_enum_member: 0x" EA_FMT " unable to set enum member name to %s\n", ea, name.data());

    for(const auto rpt : {false, true})
        if(!set_enum_member_cmt(mid, sanitize_comment_to_ascii(version->get_header_comment(rpt)).data(), rpt))
        {
            LOG(ERROR, "make_enum_member: 0x" EA_FMT " unable to set %s comment to %s\n", ea, rpt ? "repeatable" : "non-repeatable", version->get_header_comment(rpt).data());
        }

    enum_members.emplace(mid, eid);
}

void Exporter::make_reference_info(std::shared_ptr<YaToolObjectVersion>& version, ea_t ea)
{
    const auto id = version->get_id();
    const auto flags = version->get_object_flags();
    refinfo_t ref;
    ref.init(flags, ea);
    refs.emplace(id, ref);
}

namespace
{
    void set_stackframe_member_operand(ea_t ea, offset_t offset, operand_t operand)
    {
        const auto ok = op_stkvar(static_cast<ea_t>(ea + offset), operand);
        if(!ok)
            LOG(ERROR, "make_basic_block: 0x" EA_FMT " unable to set stackframe member at offset %lld operand %d\n", ea, offset, operand);
    }

    void set_enum_operand(ea_t ea, offset_t offset, operand_t operand, enum_t enum_id)
    {
        // FIXME serial
        const auto ok = op_enum(static_cast<ea_t>(ea + offset), operand, enum_id, 0);
        if(!ok)
            LOG(ERROR, "make_basic_block: 0x" EA_FMT " unable to set enum 0x" EA_FMT " at offset %lld operand %d\n", ea, enum_id, offset, operand);
    }

    void set_reference_info(RefInfos& refs, ea_t ea, offset_t offset, operand_t operand, YaToolObjectId id)
    {
        const auto it_ref = refs.find(id);
        if(it_ref == refs.end())
            return;
        const auto& ref = it_ref->second;
        const auto ok = op_offset_ex(static_cast<ea_t>(ea + offset), operand, &ref);
        if(!ok)
            LOG(ERROR, "make_basic_block: 0x" EA_FMT " unable to set reference info " EA_FMT ":%x at offset %lld operand %d\n", ea, ref.base, ref.flags, offset, operand);
    }

    struct PathValue
    {
        tid_t   tid;
        int     idx;
    };
    using Path = std::vector<PathValue>;
    using IdaPath = std::vector<tid_t>;

    void fill_path(Path& path, tid_t tid, const XrefedId_T& xref)
    {
        int path_idx = 0;
        const auto it_path_idx = xref.attributes.find("path_idx");
        if(it_path_idx != xref.attributes.end())
            path_idx = to_path(it_path_idx->second.data());
        path.push_back({tid, path_idx});
    }

    void set_path(Path& path, IdaPath& ida_path, ea_t ea, offset_t offset, operand_t operand)
    {
        if(path.empty())
            return;

        std::sort(path.begin(), path.end(), [](const auto& a, const auto b)
        {
            return a.idx < b.idx;
        });
        ida_path.clear();
        ida_path.reserve(path.size());
        for(const auto& it : path)
            ida_path.emplace_back(it.tid);
        const auto ok = op_stroff(static_cast<ea_t>(ea + offset), operand, &ida_path[0], ida_path.size(), 0);
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
        LOG(ERROR, "make_basic_block: 0x" EA_FMT " unable to set path %s at offset %lld operand %d\n", ea, pathstr.data(), offset, operand);
    }
}

void Exporter::make_basic_block(std::shared_ptr<YaToolObjectVersion>& version, ea_t ea)
{
    Path path;
    IdaPath ida_path;
    make_name(version, ea, true);
    make_views(version, ea);
    for(const auto& xrefs : version->get_xrefed_id_map())
    {
        const auto offset = xrefs.first.first;
        const auto operand = xrefs.first.second;
        path.clear();
        for(const auto& xref : xrefs.second)
        {
            const auto key = get_tid(xref.object_id);
            switch(key.type)
            {
                case OBJECT_TYPE_STRUCT:
                case OBJECT_TYPE_STACKFRAME:
                case OBJECT_TYPE_STRUCT_MEMBER:
                    fill_path(path, key.tid, xref);
                    break;

                case OBJECT_TYPE_STACKFRAME_MEMBER:
                    set_stackframe_member_operand(ea, offset, operand);
                    break;

                case OBJECT_TYPE_ENUM:
                    set_enum_operand(ea, offset, operand, key.tid);
                    break;
            }
            set_path(path, ida_path, ea, offset, operand);
            set_reference_info(refs, ea, offset, operand, xref.object_id);
        }
    }
}

namespace
{
#define DECLARE_REF(name, value)\
    const char name ## _txt[] = value;\
    const const_string_ref name = {name ## _txt, sizeof name ## _txt - 1};
    DECLARE_REF(g_empty, "");
#undef DECLARE_REF
}

void Exporter::clear_struct_fields(std::shared_ptr<YaToolObjectVersion>& version, ea_t struct_id)
{
    begin_type_updating(UTP_STRUCT);

    const auto size = version->get_size();
    const auto struc = get_struc(struct_id);
    const auto last_offset = get_struc_last_offset(struc);

    // get existing members
    std::set<offset_t> fields;
    for(const auto& xref : version->get_xrefed_id_map())
        fields.emplace(xref.first.first);

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
        if(member && get_member_name2(&member_name, member->id) > 0)
            continue;

        new_fields.insert(offset);
        const auto func_ea = get_func_by_frame(struct_id);
        const auto func = get_func(func_ea);
        const auto defname = ya::get_default_name(member_name, aoff, func);
        const auto field_size = offset == last_offset && offset == size ? 0 : 1;
        member_name.resize(defname.size);
        const auto err = add_struc_member(struc, defname.value, aoff, FF_BYTE, nullptr, field_size);
        if(err != STRUC_ERROR_MEMBER_OK)
            LOG(ERROR, "clear_struct_fields: 0x" EA_FMT ":%llx unable to add member %s size %d\n", struct_id, offset, defname.value, field_size);
    }

    for(size_t i = 0; i < struc->memqty; ++i)
    {
        auto& m = struc->members[i];
        const auto offset = m.soff;
        const auto is_known = fields.count(m.soff);
        const auto is_new = new_fields.count(m.soff);
        const auto func_ea = get_func_by_frame(struct_id);
        if(is_known && !is_new)
        {
            const auto field_size = offset == last_offset && offset == size ? 0 : 1;
            const auto id = struc->props & SF_FRAME ?
                provider.get_stackframe_member_object_id(struct_id, offset, func_ea) :
                provider.get_struc_member_id(struct_id, offset, g_empty);
            const auto key = get_tid(id);
            if(key.tid == BADADDR)
            {
                const auto func = get_func(func_ea);
                const auto defname = ya::get_default_name(member_name, offset, func);
                auto ok = set_member_name(struc, offset, defname.value);
                if(!ok)
                    LOG(ERROR, "clear_struct_fields: 0x" EA_FMT ":" EA_FMT " unable to set member name %s\n", struct_id, offset, defname.value);
                ok = set_member_type(struc, offset, FF_BYTE, nullptr, field_size);
                if(!ok)
                    LOG(ERROR, "clear_struct_fields: 0x" EA_FMT ":" EA_FMT " unable to set member type to %d bytes\n", struct_id, offset, field_size);
                for(const auto repeat : {false, true})
                {
                    ok = set_member_cmt(&m, g_empty.value, repeat);
                    if(!ok)
                        LOG(ERROR, "clear_struct_fields: 0x" EA_FMT ":" EA_FMT " unable to reset %s comment\n", struct_id, offset, repeat ? "repeatable" : "non-repeatable");
                }
            }
        }
        else if(!is_new)
        {
            if(func_ea == BADADDR || !is_special_member(m.id))
            {
                const auto ok = del_struc_member(struc, offset);
                if(!ok)
                    LOG(ERROR, "clear_struct_fields: 0x" EA_FMT ":" EA_FMT " unable to delete member\n", struct_id, offset);
                else
                    --i;
            }
        }
    }

    end_type_updating(UTP_STRUCT);
}
