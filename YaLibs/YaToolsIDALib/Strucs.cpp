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
#include "Strucs.hpp"

#include "Random.hpp"
#include "BinHex.hpp"
#include "Hash.hpp"
#include "YaHelpers.hpp"
#include "IModelVisitor.hpp"
#include "HVersion.hpp"
#include "Helpers.h"
#include "Logger.hpp"
#include "Yatools.hpp"

#include <unordered_map>


namespace
{
    std::string get_struc_netnode_name(const char* struc_name)
    {
        // mandatory $ prefix for user netnodes
        return std::string("$yaco_struc_") + struc_name;
    }

    std::string get_enum_netnode_name(const char* enum_name)
    {
        // mandatory $ prefix for user netnodes
        return std::string("$yaco_enum_") + enum_name;
    }

    std::string get_local_netnode_name(const char* local_name)
    {
        // mandatory $ prefix for user netnodes
        return std::string("$yaco_local_") + local_name;
    }

    using Reply = struct
    {
        Tag             tag;
        netnode         node;
        YaToolObjectId  id;
    };

    void get_tag_from_node(Tag& tag, const netnode& node)
    {
        char buf[64];
        const auto n = node.valstr(buf, sizeof buf);
        tag.assign(buf, std::max(n, static_cast<ssize_t>(0)));
    }

    template<std::string(*get_nodename)(const char*), YaToolObjectId(*hash)(const const_string_ref&)>
    Reply hash_to_node(const char* name)
    {
        const auto nodename = get_nodename(name);
        netnode node;
        const auto created = node.create(nodename.data(), nodename.size());
        if(created)
        {
            uint8_t rng[16];
            char    buf[32];
            // generate a random value which we will assign & track
            // on our input struct
            rng::generate(&rng, sizeof rng);
            binhex(buf, hexchars_upper, &rng, sizeof rng);
            node.set(buf, sizeof buf);
        }

        Tag tag;
        get_tag_from_node(tag, node);
        const auto id = hash(make_string_ref(tag));
        return {tag, node, id};
    }

    Reply hash_struc(const char* struc_name)
    {
        return hash_to_node<&get_struc_netnode_name, &hash::hash_struc>(struc_name);
    }

    Reply hash_enum(const char* enum_name)
    {
        return hash_to_node<&get_enum_netnode_name, &hash::hash_enum>(enum_name);
    }

    Reply hash_local(const char* local_name)
    {
        return hash_to_node<&get_local_netnode_name, &hash::hash_local_type>(local_name);
    }

    Reply hash_with_struc(ea_t id)
    {
        qstring qbuf;
        ya::wrap(&get_struc_name, qbuf, id);
        return hash_struc(qbuf.c_str());
    }

    Reply hash_with_enum(enum_t id)
    {
        qstring qbuf;
        ya::wrap(&get_enum_name, qbuf, id);
        return hash_enum(qbuf.c_str());
    }

    void create_node_from(const std::string& name, const Tag& tag)
    {
        netnode node(name.data(), name.size(), true);
        node.set(tag.data(), tag.size());
    }

    Tag get_tag_from_version(const HVersion& version, bool& ok)
    {
        Tag tag;
        ok = false;
        version.walk_attributes([&](const const_string_ref& key, const const_string_ref& value)
        {
            if(key != ::make_string_ref("tag")) {
                return WALK_CONTINUE;
            }

            tag = make_string(value);
            ok = true;
            return WALK_CONTINUE;
        });
        return tag;
    }

    template<Reply (*hash)(const char*), std::string (*get_name)(const char*)>
    void rename_with(const char* oldname, const char* newname)
    {
        if(!oldname) { return; }

        auto node = hash(oldname).node;
        const auto newnodename = get_name(newname);
        netnode next(newnodename.data(), newnodename.size(), false);
        next.kill();
        node.rename(newnodename.data(), newnodename.size());
    }
}

namespace strucs
{
    YaToolObjectId hash(ea_t id)
    {
        return hash_with_struc(id).id;
    }

    Tag get_tag(ea_t id)
    {
        return hash_with_struc(id).tag;
    }

    void rename(const char* oldname, const char* newname)
    {
        rename_with<&hash_struc, &get_struc_netnode_name>(oldname, newname);
    }

    Tag remove(ea_t id)
    {
        auto r = hash_with_struc(id);
        r.node.kill();
        return r.tag;
    }

    void set_tag_with(const char* name, const Tag& tag)
    {
        create_node_from(get_struc_netnode_name(name), tag);
    }

    void set_tag(ea_t id, const Tag& tag)
    {
        qstring qbuf;
        ya::wrap(&get_struc_name, qbuf, id);
        set_tag_with(qbuf.c_str(), tag);
    }

    void visit(IModelVisitor& v, const char* name)
    {
        const auto tag = hash_struc(name).tag;
        v.visit_attribute(make_string_ref("tag"), make_string_ref(tag));
    }

    Tag accept(const HVersion& version)
    {
        bool found = false;
        const auto tag = get_tag_from_version(version, found);
        if(found) {
            set_tag_with(version.username().value, tag);
        }
        return tag;
    }
}

namespace enums
{
    YaToolObjectId hash(enum_t id)
    {
        return hash_with_enum(id).id;
    }

    Tag get_tag(enum_t id)
    {
        return hash_with_enum(id).tag;
    }

    void rename(const char* oldname, const char* newname)
    {
        rename_with<&hash_enum, &get_enum_netnode_name>(oldname, newname);
    }

    Tag remove(enum_t id)
    {
        auto r = hash_with_enum(id);
        r.node.kill();
        return r.tag;
    }

    void set_tag_with(const char* name, const Tag& tag)
    {
        create_node_from(get_enum_netnode_name(name), tag);
    }

    void set_tag(enum_t id, const Tag& tag)
    {
        qstring qbuf;
        ya::wrap(&get_enum_name, qbuf, id);
        set_tag_with(qbuf.c_str(), tag);
    }

    void visit(IModelVisitor& v, const char* name)
    {
        const auto tag = hash_enum(name).tag;
        v.visit_attribute(make_string_ref("tag"), make_string_ref(tag));
    }

    Tag accept(const HVersion& version)
    {
        bool found = false;
        const auto tag = get_tag_from_version(version, found);
        if(found) {
            set_tag_with(version.username().value, tag);
        }
        return tag;
    }
}

namespace local_types
{
    bool identify(Type* type, uint32_t ord)
    {
        type->tif.clear();
        type->name.qclear();
        auto ok = type->tif.get_numbered_type(nullptr, ord);
        if(!ok) { return false; }

        // False if cannot get name
        ok = type->tif.print(&type->name);
        if(!ok) { return false; }

        // True if can get enum ID
        const auto eid = get_enum(type->name.c_str());
        type->ghost = eid == BADADDR;
        if(eid != BADADDR) { return true; }

        // True if can get struct ID
        const auto sid = get_struc_id(type->name.c_str());
        type->ghost = sid == BADADDR;
        if(sid == BADADDR) { return true; }

        // True if not ghost
        const auto struc = get_struc(sid);
        type->ghost = !!struc;
        if(!struc) { return true; }

        type->ghost = struc->is_ghost();

        // Return True
        return true;
    }

    YaToolObjectId hash(const char* name)
    {
        return hash_local(name).id;
    }


    // Hash struct[ord]
    YaToolObjectId hash(uint32_t ord)
    {
        // Identify (i.e. Get type)
        Type type;
        const auto ok = identify(&type, ord);
        if(!ok) { return 0; }

        // Hash: type.name -> ID
        return hash(type.name.c_str());
    }

    Tag get_tag(const char* name)
    {
        return hash_local(name).tag;
    }

    void rename(const char* oldname, const char* newname)
    {
        rename_with<&hash_local, &get_local_netnode_name>(oldname, newname);
    }

    Tag remove(const char* name)
    {
        auto r = hash_local(name);
        r.node.kill();
        return r.tag;
    }

    void set_tag(const char* name, const Tag& tag)
    {
        create_node_from(get_local_netnode_name(name), tag);
    }

    void visit(IModelVisitor& v, const Type& type)
    {
        const auto tag = hash_local(type.name.c_str()).tag;
        v.visit_attribute(make_string_ref("tag"), make_string_ref(tag));
    }

    Tag accept(const HVersion& version)
    {
        bool found = false;
        const auto tag = get_tag_from_version(version, found);
        if(found) {
            set_tag(make_string(version.username()).data(), tag);
        }
        return tag;
    }
}

namespace
{
    using Tags      = std::unordered_map<std::string, std::string>;
    using Members   = std::unordered_map<YaToolObjectId, YaToolObjectId>;

    struct Filter
        : public strucs::IFilter
    {
        YaToolObjectId is_valid(const HVersion& version) override;

        Tags    strucs_;
        Tags    enums_;
        Tags    locals_;
        Members members_;
    };

    template<YaToolObjectId(*hasher)(const const_string_ref&)>
    YaToolObjectId check_version(Tags& tags, const HVersion& version)
    {
        const auto old = version.id();
        bool found = false;
        const auto tag = get_tag_from_version(version, found);
        if(!found) { return old; }

        const auto name = make_string(version.username());
        const auto it = tags.find(name);
        if(it == tags.end())
        {
            tags.insert(std::make_pair(name, tag));
            return old;
        }

        const auto cur = hasher(::make_string_ref(it->second));
        if(old == cur) { return old; }

        return cur;
    }

    YaToolObjectId check_struc_version(Tags& tags, const HVersion& version)
    {
        return check_version<hash::hash_struc>(tags, version);
    }

    YaToolObjectId check_enum_version(Tags& tags, const HVersion& version)
    {
        return check_version<hash::hash_enum>(tags, version);
    }

    // Try to add
    YaToolObjectId check_struc(Filter& f, const HVersion& version)
    {
        const auto old = version.id();
        const auto id = check_struc_version(f.strucs_, version);

        if(old != id) {
            f.members_.emplace(old, id);
        }
        return id;
    }

    // Try to add
    YaToolObjectId check_enum(Filter& f, const HVersion& version)
    {
        const auto old = version.id();
        const auto id = check_enum_version(f.enums_, version);
        if(old != id) {
            f.members_.emplace(old, id);
        }
        return id;
    }

    YaToolObjectId check_member(Filter& f, const HVersion& version)
    {
        const auto old = version.id();
        const auto parent = version.parent_id();
        const auto it = f.members_.find(parent);
        if(it == f.members_.end()) {
            return old;
        }

        return hash::hash_member(it->second, version.address());
    }

    YaToolObjectId check_enum_member(Filter& f, const HVersion& version)
    {
        const auto old = version.id();
        const auto parent = version.parent_id();
        const auto it = f.members_.find(parent);
        if(it == f.members_.end()) {
            return old;
        }

        return hash::hash_enum_member(it->second, version.username());
    }

    YaToolObjectId check_local_type(Filter& f, const HVersion& version)
    {
        return check_version<hash::hash_local_type>(f.locals_, version);
    }
}

namespace strucs
{
    std::shared_ptr<IFilter> make_filter()
    {
        return std::make_shared<Filter>();
    }
}


// Check if hVersion is valid: dispatch accroding to type
YaToolObjectId Filter::is_valid(const HVersion& version)
{
    switch(version.type())
    {
        case OBJECT_TYPE_STRUCT:
            return check_struc(*this, version);

        case OBJECT_TYPE_STRUCT_MEMBER:
            return check_member(*this, version);

        case OBJECT_TYPE_ENUM:
            return check_enum(*this, version);

        case OBJECT_TYPE_ENUM_MEMBER:
            return check_enum_member(*this, version);

        case OBJECT_TYPE_LOCAL_TYPE:
            return check_local_type(*this, version);

        default:
            return version.id();
    }
}
