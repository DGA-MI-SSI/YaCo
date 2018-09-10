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

#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("strucs", (FMT), ## __VA_ARGS__)

namespace
{
    std::string get_struc_netnode_name(const char* struc_name)
    {
        // mandatory $ prefix for user netnodes
        return std::string("$yaco_struc_") + struc_name;
    }

    using Reply = struct
    {
        strucs::Tag     tag;
        netnode         node;
        YaToolObjectId  id;
    };

    void get_tag_from_node(strucs::Tag& tag, const netnode& node)
    {
        node.valstr(tag.data, sizeof tag.data);
    }

    const_string_ref make_string_ref(const strucs::Tag& tag)
    {
        return {tag.data, sizeof tag.data - 1};
    }

    Reply hash_struc(const char* struc_name)
    {
        const auto name = get_struc_netnode_name(struc_name);
        netnode node;
        const auto created = node.create(name.data(), name.size());
        strucs::Tag tag;
        if(created)
        {
            uint8_t rng[sizeof tag.data >> 1];
            // generate a random value which we will assign & track
            // on our input struct
            rng::generate(&rng, sizeof rng);
            binhex(tag.data, hexchars_upper, &rng, sizeof rng);
            node.set(tag.data, sizeof tag.data - 1);
        }

        get_tag_from_node(tag, node);
        const auto id = hash::hash_struc(make_string_ref(tag));
        return {tag, node, id};
    }

    Reply hash_with(ea_t id)
    {
        qstring qbuf;
        ya::wrap(&get_struc_name, qbuf, id);
        return hash_struc(qbuf.c_str());
    }

    void create_node_from(const char* struc_name, const strucs::Tag& tag)
    {
        const auto name = get_struc_netnode_name(struc_name);
        netnode node(name.data(), name.size(), true);
        node.set(tag.data, sizeof tag.data - 1);
    }

    strucs::Tag get_tag_from_version(const HVersion& version, bool& ok)
    {
        strucs::Tag tag;
        ok = false;
        version.walk_attributes([&](const const_string_ref& key, const const_string_ref& value)
        {
            if(key != ::make_string_ref("tag"))
                return WALK_CONTINUE;

            memcpy(tag.data, value.value, std::min(sizeof tag.data - 1, value.size));
            ok = true;
            return WALK_CONTINUE;
        });
        return tag;
    }
}

namespace strucs
{
    YaToolObjectId hash(ea_t id)
    {
        return hash_with(id).id;
    }

    Tag get_tag(ea_t id)
    {
        return hash_with(id).tag;
    }

    void rename(const char* oldname, const char* newname)
    {
        if(!oldname)
            return;

        auto node = hash_struc(oldname).node;
        const auto newnodename = get_struc_netnode_name(newname);
        node.rename(newnodename.data(), newnodename.size());
    }

    Tag remove(ea_t id)
    {
        auto r = hash_with(id);
        r.node.kill();
        return r.tag;
    }

    void set_tag(ea_t id, const Tag& tag)
    {
        qstring qbuf;
        ya::wrap(&get_struc_name, qbuf, id);
        create_node_from(qbuf.c_str(), tag);
    }

    void visit(IModelVisitor& v, const char* name)
    {
        const auto tag = hash_struc(name).tag;
        v.visit_attribute(make_string_ref("tag"), {tag.data, sizeof tag.data - 1});
    }

    Tag accept(const HVersion& version)
    {
        bool found = false;
        const auto tag = get_tag_from_version(version, found);
        if(found)
            create_node_from(version.username().value, tag);
        return tag;
    }
}

namespace
{
    struct Filter
        : public strucs::IFilter
    {
        YaToolObjectId is_valid(const HVersion& version) override;

        std::unordered_map<std::string, std::string>        tags_;
        std::unordered_map<YaToolObjectId, YaToolObjectId>  members_;
    };

    YaToolObjectId check_struc(Filter& f, const HVersion& version)
    {
        const auto old = version.id();
        bool found = false;
        const auto tag_got = get_tag_from_version(version, found);
        if(!found)
            return old;

        const auto name = make_string(version.username());
        const auto it = f.tags_.find(name);
        const auto tag = std::string{tag_got.data, sizeof tag_got.data - 1};
        if(it == f.tags_.end())
        {
            f.tags_.insert(std::make_pair(name, tag));
            return old;
        }

        const auto cur = hash::hash_struc(::make_string_ref(it->second));
        if(old == cur)
            return old;

        f.members_.emplace(old, cur);
        return cur;
    }

    YaToolObjectId check_member(Filter& f, const HVersion& version)
    {
        const auto old = version.id();
        const auto parent = version.parent_id();
        const auto it = f.members_.find(parent);
        if(it == f.members_.end())
            return old;

        return hash::hash_member(it->second, version.address());
    }
}

namespace strucs
{
    std::shared_ptr<IFilter> make_filter()
    {
        return std::make_shared<Filter>();
    }
}

YaToolObjectId Filter::is_valid(const HVersion& version)
{
    switch(version.type())
    {
        case OBJECT_TYPE_STRUCT:
            return check_struc(*this, version);

        case OBJECT_TYPE_STRUCT_MEMBER:
            return check_member(*this, version);

        default:
            return version.id();
    }
}
