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

#include "Ida.h"
#include "Events.hpp"

#define  MODULE_NAME "events"
#include "YaTypes.hpp"
#include "Pool.hpp"
#include "Hash.hpp"
#include "YaHelpers.hpp"
#include "HObject.hpp"
#include "Repository.hpp"
#include "Helpers.h"
#include "HVersion.hpp"
#include "IdaModel.hpp"
#include "IdaUtils.hpp"
#include "XmlModel.hpp"
#include "MemoryModel.hpp"
#include "IModel.hpp"
#include "XmlVisitor.hpp"
#include "Utils.hpp"
#include "IdaVisitor.hpp"
#include "IModelSink.hpp"
#include "IdaModel.hpp"

#include <chrono>
#include <map>
#include <unordered_set>

#ifdef _MSC_VER
#   include <filesystem>
#else
#   include <experimental/filesystem>
#endif

namespace fs = std::experimental::filesystem;

namespace
{
    struct Ea
    {
        YaToolObjectId      id;
        YaToolObjectType_e  type;
        ea_t                ea;
    };

    bool operator<(const Ea& a, const Ea& b)
    {
        return std::make_pair(a.id, a.type) < std::make_pair(b.id, b.type);
    }

    struct Struc
    {
        tid_t id;
        ea_t  func_ea;
    };

    struct StrucMember
    {
        YaToolObjectId  parent_id;
        Struc           struc;
        ea_t            offset;
    };

    struct EnumMember
    {
        YaToolObjectId parent_id;
        enum_t         eid;
        const_t        mid;
    };

    using Eas           = std::set<Ea>;
    using Structs       = std::map<YaToolObjectId, Struc>;
    using StructMembers = std::map<YaToolObjectId, StrucMember>;
    using Enums         = std::map<YaToolObjectId, enum_t>;
    using EnumMembers   = std::map<YaToolObjectId, EnumMember>;
    using Segments      = std::set<ea_t>;

    struct Events
        : public IEvents
    {
        Events(IRepository& repo);

        // IEvents
        void touch_struc(tid_t struc_id) override;
        void touch_enum (enum_t enum_id) override;
        void touch_func (ea_t ea) override;
        void touch_code (ea_t ea) override;
        void touch_data (ea_t ea) override;
        void touch_ea   (ea_t ea) override;

        void save               () override;
        void update             () override;

        IRepository&    repo_;     
        Pool<qstring>   qpool_;

        Eas             eas_;
        Structs         strucs_;
        StructMembers   struc_members_;
        Enums           enums_;
        EnumMembers     enum_members_;
    };
}

Events::Events(IRepository& repo)
    : repo_(repo)
    , qpool_(3)
{
}

std::shared_ptr<IEvents> MakeEvents(IRepository& repo)
{
    return std::make_shared<Events>(repo);
}

namespace
{
    std::string to_hex(uint64_t ea)
    {
        char dst[2 + sizeof ea * 2];
        ea = swap(ea);
        const auto ref = binhex<sizeof ea, RemovePadding | HexaPrefix>(dst, &ea);
        return make_string(ref);
    }

    template<typename T>
    std::string to_string(const T& value)
    {
        std::stringstream stream;
        stream << value;
        return stream.str();
    }

    std::string make_frame_prefix(struc_t* frame)
    {
        const auto func_ea = get_func_by_frame(frame->id);
        return to_hex(func_ea) + ": stack ";
    }

    std::string make_struc_prefix(struc_t* struc)
    {
        if(struc->props & SF_FRAME)
            return make_frame_prefix(struc);

        qstring name;
        get_struc_name(&name, struc->id);
        if(name.empty())
            return std::string();

        return std::string("struc ") + name.c_str() + ": ";
    }

    std::string make_stackmember_prefix(struc_t* frame, member_t* member)
    {
        qstring name;
        get_member_name(&name, member->id);
        auto prefix = make_frame_prefix(frame);
        if(prefix.empty() || name.empty())
            return prefix;

        while(name[0] == ' ')
            name.remove(0, 1);
        prefix.resize(prefix.size() - 1); // remove last ' '
        return prefix + "." + name.c_str() + " ";
    }

    std::string make_member_prefix(struc_t* struc, member_t* member)
    {
        if(struc->props & SF_FRAME)
            return make_stackmember_prefix(struc, member);

        qstring name;
        get_member_name(&name, member->id);
        auto prefix = make_struc_prefix(struc);
        if(prefix.empty() || name.empty())
            return prefix;

        while(name[0] == ' ')
            name.remove(0, 1);
        prefix.resize(prefix.size() - 2); // remove last ": "
        return prefix + "." + name.c_str() + ": ";
    }

    std::string make_enum_prefix(enum_t eid)
    {
        qstring name;
        get_enum_name(&name, eid);
        if(name.empty())
            return std::string();

        return std::string("enum ") + name.c_str() + ": ";
    }

    std::string make_enum_member_prefix(enum_t eid, const_t mid)
    {
        qstring name;
        get_enum_member_name(&name, mid);
        auto prefix = make_enum_prefix(eid);
        if(prefix.empty() || name.empty())
            return std::string();

        prefix.resize(prefix.size() - 2); // remove last ": "
        return prefix + "." + name.c_str() + ": ";
    }

    std::string make_comment_prefix(ea_t ea)
    {
        if(ea == BADADDR)
            return std::string();

        auto struc = get_struc(ea);
        if(struc)
            return make_struc_prefix(struc);

        const auto member = get_member_by_id(ea, &struc);
        if(member)
            return make_member_prefix(struc, member);

        const auto idx = get_enum_idx(ea);
        if(idx != BADADDR)
            return make_enum_prefix(ea);

        const auto eid = get_enum_member_enum(ea);
        if(eid != BADADDR)
            return make_enum_member_prefix(eid, ea);

        if(!getseg(ea))
            return std::string();

        return to_hex(ea) + ": ";
    }

    void add_auto_comment(IRepository& repo, ea_t ea)
    {
        const auto prefix = make_comment_prefix(ea);
        if(!prefix.empty())
            repo.add_comment(prefix + "updated");
    }

    YaToolObjectId get_struc_stack_id(Events& ev, ea_t struc_id, ea_t func_ea)
    {
        if(func_ea != BADADDR)
            return hash::hash_stack(func_ea);

        const auto name = ev.qpool_.acquire();
        ya::wrap(&get_struc_name, *name, struc_id);
        return hash::hash_struc(ya::to_string_ref(*name));
    }

    void add_ea(Events& ev, YaToolObjectId id, YaToolObjectType_e type, ea_t ea)
    {
        const bool inserted = ev.eas_.emplace(Ea{id, type, ea}).second;
        if(inserted)
            add_auto_comment(ev.repo_, ea);
    }

    void add_ea(Events& ev, ea_t ea)
    {
        const auto flags = get_flags(ea);
        if(is_code(flags))
        {
            // we must be careful to compute func id with func start ea
            // but ea may point to the middle of any basic block
            const auto func = get_func(ea);
            if(func)
                add_ea(ev, hash::hash_function(func->start_ea), OBJECT_TYPE_FUNCTION, func->start_ea);
            ea = ya::get_range_item(ea).start_ea;
            add_ea(ev, hash::hash_ea(ea), func ? OBJECT_TYPE_BASIC_BLOCK : OBJECT_TYPE_CODE, ea);
            return;
        }
        if(is_data(flags))
        {
            ea = get_item_head(ea);
            add_ea(ev, hash::hash_ea(ea), OBJECT_TYPE_DATA, ea);
            return;
        }
    }

    void update_struc_member(Events& ev, struc_t* struc, const qstring& name, member_t* m)
    {
        const auto func_ea = get_func_by_frame(struc->id);
        const auto parent_id = func_ea != BADADDR ?
            hash::hash_stack(func_ea) :
            hash::hash_struc(ya::to_string_ref(name));
        const auto id = hash::hash_member(parent_id, m->soff);
        ev.struc_members_.emplace(id, StrucMember{parent_id, {struc->id, func_ea}, m->soff});
    }

    void update_enum_member(Events& ev, YaToolObjectId enum_id, enum_t eid, const_t cid)
    {
        const auto qbuf = ev.qpool_.acquire();
        ya::wrap(&::get_enum_member_name, *qbuf, cid);
        const auto id = hash::hash_enum_member(enum_id, ya::to_string_ref(*qbuf));
        ev.enum_members_.emplace(id, EnumMember{enum_id, eid, cid});
    }

    void update_enum(Events& ev, enum_t enum_id)
    {
        // check first whether enum_id is actually a member id
        const auto parent_id = get_enum_member_enum(enum_id);
        if(parent_id != BADADDR)
            enum_id = parent_id;

        const auto name = ev.qpool_.acquire();
        ya::wrap(&::get_enum_name, *name, enum_id);
        const auto id = hash::hash_enum(ya::to_string_ref(*name));
        ev.enums_.emplace(id, enum_id);
        ya::walk_enum_members(enum_id, [&](const_t cid, uval_t /*value*/, uchar /*serial*/, bmask_t /*bmask*/)
        {
            ::update_enum_member(ev, id, enum_id, cid);
        });
        add_auto_comment(ev.repo_, enum_id);
    }

    ea_t update_struc(Events& ev, tid_t struc_id)
    {
        add_auto_comment(ev.repo_, struc_id);
        const auto func_ea = get_func_by_frame(struc_id);
        const auto id = get_struc_stack_id(ev, struc_id, func_ea);
        ev.strucs_.emplace(id, Struc{struc_id, func_ea});

        const auto struc = get_struc(struc_id);
        if(!struc)
            return func_ea;

        const auto name = ev.qpool_.acquire();
        ya::wrap(&::get_struc_name, *name, struc->id);
        for(size_t i = 0; struc && i < struc->memqty; ++i)
            update_struc_member(ev, struc, *name, &struc->members[i]);

        return func_ea;
    }
}

void Events::touch_struc(tid_t struc_id)
{
    const auto func_ea = update_struc(*this, struc_id);
    if(func_ea != BADADDR)
        touch_func(func_ea);
}

void Events::touch_enum(enum_t enum_id)
{
    const auto parent_id = get_enum_member_enum(enum_id);
    add_auto_comment(repo_, enum_id);
    if(parent_id != BADADDR)
        enum_id = parent_id;
    update_enum(*this, enum_id);
}

void Events::touch_ea(ea_t ea)
{
    add_ea(*this, ea);
}

void Events::touch_func(ea_t ea)
{
    add_ea(*this, ea);
    const auto frame = get_frame(ea);
    if(frame)
        update_struc(*this, frame->id);
}

void Events::touch_code(ea_t ea)
{
    ea = ya::get_range_code(ea, 0, ~0U).start_ea;
    add_ea(*this, hash::hash_ea(ea), OBJECT_TYPE_CODE, ea);
}

void Events::touch_data(ea_t ea)
{
    ea = get_item_head(ea);
    add_ea(*this, hash::hash_ea(ea), OBJECT_TYPE_DATA, ea);
}

namespace
{
    bool try_accept_struc(YaToolObjectId id, const Struc& struc, qstring& qbuf)
    {
        if(struc.func_ea != BADADDR)
            return get_func_by_frame(struc.id) == struc.func_ea;

        // on struc renames, as struc_id is still valid, we need to validate its id again
        ya::wrap(&get_struc_name, qbuf, struc.id);
        const auto got_id = hash::hash_struc(ya::to_string_ref(qbuf));
        const auto idx = get_struc_idx(struc.id);
        return id == got_id && idx != BADADDR;
    }

    void save_structs(Events& ev, IModelIncremental& model, IModelVisitor& visitor)
    {
        const auto qbuf = ev.qpool_.acquire();
        for(const auto p : ev.strucs_)
        {
            // if frame, we need to update parent function
            if(p.second.func_ea != BADADDR)
                model.accept_function(visitor, p.second.func_ea);
            if(try_accept_struc(p.first, p.second, *qbuf))
                model.accept_struct(visitor, p.second.func_ea, p.second.id);
            else if(p.second.func_ea == BADADDR)
                model.delete_version(visitor, OBJECT_TYPE_STRUCT, p.first);
            else
                model.delete_version(visitor, OBJECT_TYPE_STACKFRAME, p.first);
        }

        for(const auto p : ev.struc_members_)
        {
            const auto is_valid_parent = try_accept_struc(p.second.parent_id, p.second.struc, *qbuf);
            const auto struc = p.second.struc.func_ea != BADADDR ?
                get_frame(p.second.struc.func_ea) :
                get_struc(p.second.struc.id);
            const auto member = get_member(struc, p.second.offset);
            const auto id = hash::hash_member(p.second.parent_id, member ? member->soff : -1);
            const auto is_valid_member = p.first == id;
            if(is_valid_parent && is_valid_member)
                model.accept_struct(visitor, p.second.struc.func_ea, p.second.struc.id);
            else if(p.second.struc.func_ea == BADADDR)
                model.delete_version(visitor, OBJECT_TYPE_STRUCT_MEMBER, p.first);
            else
                model.delete_version(visitor, OBJECT_TYPE_STACKFRAME_MEMBER, p.first);
        }
    }

    void save_enums(Events& ev, IModelIncremental& model, IModelVisitor& visitor)
    {
        const auto qbuf = ev.qpool_.acquire();
        for(const auto p : ev.enums_)
        {
            // on renames, as enum_id is still valid, we need to validate its id again
            ya::wrap(&get_enum_name, *qbuf, p.second);
            const auto id = hash::hash_enum(ya::to_string_ref(*qbuf));
            const auto idx = get_enum_idx(p.second);
            if(idx == BADADDR || id != p.first)
                model.delete_version(visitor, OBJECT_TYPE_ENUM, p.first);
            else
                model.accept_enum(visitor, p.second);
        }
        for(const auto p : ev.enum_members_)
        {
            // on renames, we need to check both ids
            ya::wrap(&get_enum_name, *qbuf, p.second.eid);
            const auto parent_id = hash::hash_enum(ya::to_string_ref(*qbuf));
            ya::wrap(&::get_enum_member_name, *qbuf, p.second.mid);
            const auto id = hash::hash_enum_member(parent_id, ya::to_string_ref(*qbuf));
            const auto parent = get_enum_member_enum(p.second.mid);
            if(parent == BADADDR || id != p.first || parent_id != p.second.parent_id)
                model.delete_version(visitor, OBJECT_TYPE_ENUM_MEMBER, p.first);
            else
                model.accept_enum(visitor, p.second.eid);
        }
    }

    void save_func(IModelIncremental& model, IModelVisitor& visitor, YaToolObjectId id, ea_t ea)
    {
        const auto got = hash::hash_function(ea);
        const auto func = get_func(ea);
        if(got != id || !func)
        {
            model.delete_version(visitor, OBJECT_TYPE_FUNCTION, id);
            model.accept_ea(visitor, ea);
            return;
        }

        const auto ea_id = hash::hash_ea(ea);
        model.accept_function(visitor, ea);
        model.delete_version(visitor, OBJECT_TYPE_CODE, ea_id);
        model.delete_version(visitor, OBJECT_TYPE_DATA, ea_id);
    }

    void save_code(IModelIncremental& model, IModelVisitor& visitor, YaToolObjectId id, ea_t ea)
    {
        const auto got = hash::hash_ea(ea);
        const auto flags = get_flags(ea);
        const auto is_code_not_func = is_code(flags) && !get_func(ea);
        if(got != id || !is_code_not_func)
        {
            model.delete_version(visitor, OBJECT_TYPE_CODE, id);
            model.accept_ea(visitor, ea);
            return;
        }

        model.accept_ea(visitor, ea);
        model.delete_version(visitor, OBJECT_TYPE_FUNCTION, hash::hash_function(ea));
        model.delete_version(visitor, OBJECT_TYPE_DATA, got);
    }

    void save_data(IModelIncremental& model, IModelVisitor& visitor, YaToolObjectId id, ea_t ea)
    {
        const auto got = hash::hash_ea(ea);
        const auto flags = get_flags(ea);
        if(got != id || !is_data(flags))
        {
            model.delete_version(visitor, OBJECT_TYPE_DATA, id);
            model.accept_ea(visitor, ea);
            return;
        }

        model.accept_ea(visitor, ea);
        model.delete_version(visitor, OBJECT_TYPE_FUNCTION, hash::hash_function(ea));
        model.delete_version(visitor, OBJECT_TYPE_CODE, got);
    }

    void save_block(IModelIncremental& model, IModelVisitor& visitor, YaToolObjectId id, ea_t ea)
    {
        const auto got = hash::hash_ea(ea);
        const auto func = get_func(ea);
        if(got != id || !func)
        {
            model.delete_version(visitor, OBJECT_TYPE_BASIC_BLOCK, id);
            return;
        }

        model.accept_ea(visitor, ea);
    }

    void save_eas(Events& ev, IModelIncremental& model, IModelVisitor& visitor)
    {
        for(const auto p : ev.eas_)
            switch(p.type)
            {
                case OBJECT_TYPE_FUNCTION:      save_func(model, visitor, p.id, p.ea); break;
                case OBJECT_TYPE_CODE:          save_code(model, visitor, p.id, p.ea); break;
                case OBJECT_TYPE_DATA:          save_data(model, visitor, p.id, p.ea); break;
                case OBJECT_TYPE_BASIC_BLOCK:   save_block(model, visitor, p.id, p.ea); break;
                default:                        assert(false); break;
            }
    }

    std::string get_cache_folder_path()
    {
        std::string cache_folder_path = get_path(PATH_TYPE_IDB);
        remove_substring(cache_folder_path, fs::path(cache_folder_path).filename().string());
        cache_folder_path += "cache";
        return cache_folder_path;
    }

    void save(Events& ev)
    {
        LOG(DEBUG, "Saving cache...");
        const auto time_start = std::chrono::system_clock::now();

        const auto db = MakeMemoryModel();
        db->visit_start();
        {
            const auto model = MakeIncrementalIdaModel();
            save_structs(ev, *model, *db);
            save_enums(ev, *model, *db);
            save_eas(ev, *model, *db);
        }
        db->visit_end();
        db->accept(*MakeXmlVisitor(get_cache_folder_path()));

        const auto time_end = std::chrono::system_clock::now();
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(time_end - time_start).count();
        if(elapsed)
            IDA_LOG_INFO("cache: exported in %d seconds", static_cast<int>(elapsed));
    }
}

void Events::save()
{
    ::save(*this);
    if(!repo_.commit_cache())
    {
        IDA_LOG_WARNING("An error occurred during YaCo commit");
        warning("An error occured during YaCo commit: please relaunch IDA");
    }
    eas_.clear();
    strucs_.clear();
    struc_members_.clear();
    enums_.clear();
    enum_members_.clear();
}

namespace
{
    struct DepCtx
    {
        DepCtx(const IModel& model, IModelVisitor& visitor)
            : model(model)
            , visitor(visitor)
        {
        }

        const IModel&                       model;
        IModelVisitor&                      visitor;
        std::unordered_set<YaToolObjectId>  seen;
    };

    // will add id to model on first insertion
    bool try_add_id(DepCtx& ctx, YaToolObjectId id, const HObject& hobj)
    {
        // remember which ids have been seen already
        const auto inserted = ctx.seen.emplace(id).second;
        if(inserted)
            hobj.accept(ctx.visitor);
        return inserted;
    }

    enum DepsMode
    {
        SKIP_DEPENDENCIES,
        USE_DEPENDENCIES,
    };

    bool must_add_dependencies(YaToolObjectType_e type)
    {
        // as we always recreate stacks & strucs, we always need every members
        return type == OBJECT_TYPE_STACKFRAME
            || type == OBJECT_TYPE_STRUCT
            || type == OBJECT_TYPE_ENUM;
    }

    void add_id_and_dependencies(DepCtx& ctx, YaToolObjectId id, DepsMode mode)
    {
        const auto hobj = ctx.model.get_object(id);
        if(!hobj.is_valid())
            return;

        const auto ok = try_add_id(ctx, id, hobj);
        if(!ok)
            return;

        hobj.walk_versions([&](const HVersion& hver)
        {
            // add parent id & its dependencies
            add_id_and_dependencies(ctx, hver.parent_id(), SKIP_DEPENDENCIES);
            if(mode != USE_DEPENDENCIES && !must_add_dependencies(hver.type()))
                return WALK_CONTINUE;
            hver.walk_xrefs([&](offset_t, operand_t, auto xref_id, auto)
            {
                // add xref id & its dependencies
                add_id_and_dependencies(ctx, xref_id, SKIP_DEPENDENCIES);
                return WALK_CONTINUE;
            });
            return WALK_CONTINUE;
        });
    }

    void add_missing_parents_from_deletions(DepCtx& deps, const IModel& deleted)
    {
        if(!deleted.num_objects())
            return;

        deps.model.walk_objects([&](YaToolObjectId id, const HObject& hobj)
        {
            if(!must_add_dependencies(hobj.type()))
                return WALK_CONTINUE;
            hobj.walk_versions([&](const HVersion& hver)
            {
                hver.walk_xrefs([&](offset_t, operand_t, auto xref_id, auto)
                {
                    if(deleted.has_object(xref_id))
                        add_id_and_dependencies(deps, id, USE_DEPENDENCIES);
                    return WALK_CONTINUE;
                });
                return WALK_CONTINUE;
            });
            return WALK_CONTINUE;
        });
    }

    std::shared_ptr<IModel> get_all_updates(const IModel& updated, const IModel& deleted)
    {
        // two things we need to watch for:
        // * applying a struc in a basic block, make sure the struc is reloaded
        // * deleting a struc member, make sure parent struc is reloaded

        // load all xml files into a model we can query
        const auto full = MakeMemoryModel();
        MakeXmlAllModel(".")->accept(*full);

        // prepare final updated model
        const auto all_updates = MakeMemoryModel();
        DepCtx deps(*full, *all_updates);
        all_updates->visit_start();

        // add deleted parents
        add_missing_parents_from_deletions(deps, deleted);

        // load all modified objects
        updated.walk_objects([&](auto id, const HObject& /*hobj*/)
        {
            // add this id & its dependencies
            add_id_and_dependencies(deps, id, USE_DEPENDENCIES);
            return WALK_CONTINUE;
        });

        all_updates->visit_end();
        return all_updates;
    }

    void update_from_cache(IModelSink& sink, IRepository& repo)
    {
        // load updated & deleted models
        const auto commit = repo.update_cache();
        const auto updated = MakeMemoryModel();
        const auto deleted = MakeMemoryModel();
        updated->visit_start();
        deleted->visit_start();
        repo.diff_index(commit, [&](const char* /*path*/, bool added, const void* ptr, size_t size)
        {
            MakeXmlMemoryModel(ptr, size)->accept(added ? *updated : *deleted);
            return 0;
        });
        deleted->visit_end();
        updated->visit_end();
        if(updated->num_objects() || deleted->num_objects())
            IDA_LOG_INFO("rebase: %zd updated %zd deleted", updated->num_objects(), deleted->num_objects());

        // apply changes on ida
        sink.remove(*deleted);
        sink.update(*get_all_updates(*updated, *deleted));
    }
}

void Events::update()
{
    // update cache and export modifications to IDA
    update_from_cache(*MakeIdaSink(), repo_);

    // Let IDA apply modifications
    const auto time_start = std::chrono::system_clock::now();
    const auto prev = inf.is_auto_enabled();
    inf.set_auto_enabled(true);
    auto_wait();
    inf.set_auto_enabled(prev);
    refresh_idaview_anyway();
    const auto time_end = std::chrono::system_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(time_end - time_start).count();
    if(elapsed)
        IDA_LOG_INFO("ida: analyzed in %d seconds", static_cast<int>(elapsed));
}