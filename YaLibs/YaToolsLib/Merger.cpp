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

#include "Merger.hpp"

#include "MemoryModel.hpp"
#include "XmlAccept.hpp"
#include "XmlVisitor.hpp"
#include "Relation.hpp"

#include <algorithm>
#include <map>

Merger::Merger(ObjectVersionMergeStrategy_e estrategy, const Merger::on_conflict_fn& on_conflict)
    : estrategy_(estrategy)
    , on_conflict_(on_conflict)
{
}

namespace
{
    bool begins_with(const const_string_ref& ref, const char* token)
    {
        return strstr(ref.value, token) == ref.value;
    }

    bool is_unset(const const_string_ref& ref)
    {
        return !ref.size
            || begins_with(ref, "var_")
            || begins_with(ref, "field_")
            || begins_with(ref, "dword_")
            || begins_with(ref, "offset_");
    }
}

MergeStatus_e Merger::merge_files(const std::string& local, const std::string& remote,
                                  const std::string& filename)
{
    const auto db1 = MakeMemoryModel();
    const auto db2 = MakeMemoryModel();

    // reload two databases with one object version in each database
    AcceptXmlMemory(*db1, local.data(), local.size());
    AcceptXmlMemory(*db2, remote.data(), remote.size());

    if(db1->size() != 1 || db2->size() != 1)
        throw std::runtime_error("invalid number of referenced object in databases");

    const auto get = [](IModel& model)
    {
        HVersion reply;
        model.walk([&](const HVersion& hver)
        {
            reply = hver;
            return WALK_STOP;
        });
        return reply;
    };

    /* Build relation */
    Relation relation;
    relation.version1_ = get(*db1);
    relation.version2_ = get(*db2);
    relation.type_ = RELATION_TYPE_EXACT_MATCH;
    relation.flags_ = 0;

    /* Merge */
    const auto output = MakeMemoryModel();
    output->visit_start();
    const auto retval = merge_ids(*output, relation, nullptr);
	output->visit_end();
    
    if(retval != OBJECT_MERGE_STATUS_NOT_UPDATED)
        output->accept(*MakeFileXmlVisitor(filename));

    return retval;
}

namespace
{
    template<typename T>
    void merge_attributes(const Merger& m, const std::string& name, const const_string_ref& local, const const_string_ref& remote, const T& on_merge)
    {
        if(local == remote)
            return on_merge(local);

        if(is_unset(local))
            return on_merge(remote);

        if(is_unset(remote))
            return on_merge(local);

        // always select tag from repository on conflicts
        if(name == "tag")
            return on_merge(remote);

        /* Conflict detected, see what is the strategy */
        switch (m.estrategy_)
        {
        case OBJECT_VERSION_MERGE_FORCE_REFERENCE:
            return on_merge(local);

        case OBJECT_VERSION_MERGE_FORCE_NEW:
        case OBJECT_VERSION_MERGE_IGNORE:
            return on_merge(remote);

        case OBJECT_VERSION_MERGE_PROMPT:
            /* A conflict is detected, need to fix conflict manually */
            const auto message = "Conflict detected on " + name + " attribute";
            const auto reply = m.on_conflict_(message, make_string(local), make_string(remote));
            return on_merge(reply.empty() ? remote : make_string_ref(reply));
        }
    }

    void merge_offsets(Merger& m, const Relation relation, IModelVisitor& v)
    {
        std::map<std::pair<offset_t, CommentType_e>, std::string> comments;
        std::map<std::pair<offset_t, operand_t>, std::string> valueviews;

        // FIXME register_views
        // FIXME hidden_areas
        switch(relation.type_)
        {
        case RELATION_TYPE_EXACT_MATCH:
            relation.version2_.walk_comments([&](offset_t offset_new, CommentType_e type_new, const const_string_ref& comment_new)
            {
               comments[std::make_pair(offset_new, type_new)] = make_string(comment_new);
               return WALK_CONTINUE;
            });
            relation.version2_.walk_value_views([&](offset_t offset, operand_t operand, const const_string_ref& value)
            {
                valueviews[std::make_pair(offset, operand)] = make_string(value);
                return WALK_CONTINUE;
            });
            relation.version1_.walk_comments([&](offset_t offset_ref, CommentType_e type_ref, const const_string_ref& comment_ref)
            {
                const auto& search = comments.find(std::make_pair(offset_ref, type_ref));
                if(search == comments.end())
                {
                    comments[std::make_pair(offset_ref, type_ref)] = make_string(comment_ref);
                }
                else
                {
                    merge_attributes(m, "comment", comment_ref, make_string_ref(search->second), [&](const const_string_ref& value)
                    {
                        comments[std::make_pair(offset_ref, type_ref)] = make_string(value);
                    });
                }
                return WALK_CONTINUE;
            });
            relation.version1_.walk_value_views([&](offset_t offset_ref, operand_t operand, const const_string_ref& value)
            {
                const auto& search = valueviews.find(std::make_pair(offset_ref, operand));
                if(search == valueviews.end())
                {
                    valueviews[std::make_pair(offset_ref, operand)] = make_string(value);
                }
                else
                {
                    merge_attributes(m, "value_view", value, make_string_ref(search->second), [&](const const_string_ref& value)
                    {
                        valueviews[std::make_pair(offset_ref, operand)] = make_string(value);
                    });
                }
                return WALK_CONTINUE;
            });
            if(!comments.empty() || !valueviews.empty())
            {
                v.visit_start_offsets();
                for(const auto& offset: comments)
                    v.visit_offset_comments(offset.first.first, offset.first.second, make_string_ref(offset.second));
                for(const auto& it: valueviews)
                    v.visit_offset_valueview(it.first.first, it.first.second, make_string_ref(it.second));
                v.visit_end_offsets();
            }
            break;

        case RELATION_TYPE_DIFF:
            // TODO propagate comments ???
        default:
            if(relation.version2_.has_comments() || relation.version2_.has_value_views())
            {
                v.visit_start_offsets();
                relation.version2_.walk_comments([&](offset_t offset, CommentType_e type, const const_string_ref& comment)
                {
                    v.visit_offset_comments(offset, type, comment);
                    return WALK_CONTINUE;
                });
                relation.version2_.walk_value_views([&](offset_t offset, operand_t operand, const const_string_ref& value)
                {
                    v.visit_offset_valueview(offset, operand, value);
                    return WALK_CONTINUE;
                });
                v.visit_end_offsets();
            }
            break;
        }
    }
}

MergeStatus_e Merger::merge_ids(IModelVisitor& visitor_db, const Relation& relation, const on_id_fn& on_id)
{
    visitor_db.visit_start_version(relation.version2_.type(), relation.version2_.id());

    visitor_db.visit_size(relation.version2_.size());
    visitor_db.visit_parent_id(relation.version2_.parent_id());
    visitor_db.visit_address(relation.version2_.address());

    /* Merge name */
    if (relation.version1_.has_username() || relation.version2_.has_username())
    {
        auto flags1 = relation.version1_.username_flags();
        auto flags2 = relation.version2_.username_flags();
        if (flags1 != flags2)
        {
            if (flags1 == -1)
            {
                flags1 = flags2;
            }
            if (flags2 == -1)
            {
                flags2 = flags1;
            }
        }
        merge_attributes(*this, "name", relation.version1_.username(), relation.version2_.username(), [&](const const_string_ref& name)
        {
            visitor_db.visit_name(name, flags1);
        });
    }

    /* Prototype */
    switch(relation.type_)
    {
    case RELATION_TYPE_EXACT_MATCH:
        if (relation.version1_.has_prototype() || relation.version2_.has_prototype())
         {
             merge_attributes(*this, "prototype", relation.version1_.prototype(), relation.version2_.prototype(), [&](const const_string_ref& prototype)
             {
                 visitor_db.visit_prototype(prototype);
             });
         }
        break;
    case RELATION_TYPE_DIFF:
        // TODO propagate prototype ???
    default:
        if(relation.version2_.has_prototype())
        {
            visitor_db.visit_prototype(relation.version2_.prototype());
        }
        break;

    }

    /*********** flags **************/
    /* Visit flags */
    visitor_db.visit_flags(relation.version1_.flags());
    /********************************/

    // string type
    auto str_type = relation.version2_.string_type();
    if (str_type != 255)
        visitor_db.visit_string_type(str_type);

    /* Visit signatures */
    if (relation.version2_.has_signatures())
    {
        visitor_db.visit_start_signatures();
        relation.version2_.walk_signatures([&](const HSignature& signature)
        {
            const auto& sign = signature.get();
            visitor_db.visit_signature(sign.method, sign.algo, make_string_ref(sign));
            return WALK_CONTINUE;
        });
        visitor_db.visit_end_signatures();
    }

    /****** header comments **********/
    switch(relation.type_)
    {
    case RELATION_TYPE_EXACT_MATCH:
        /* Header non repeatable comment */
        if (relation.version1_.has_header_comment(false) || relation.version2_.has_header_comment(false))
        {
            merge_attributes(*this, "header_nonrepeatable_comment", relation.version1_.header_comment(false), relation.version2_.header_comment(false), [&](const const_string_ref& value)
            {
                visitor_db.visit_header_comment(false, value);
            });
        }

        /* Header repeatable comment */
        if (relation.version1_.has_header_comment(true) || relation.version2_.has_header_comment(true))
        {
            merge_attributes(*this, "header_repeatable_comment", relation.version1_.header_comment(true), relation.version2_.header_comment(true), [&](const const_string_ref& value)
            {
                visitor_db.visit_header_comment(true, value);
            });
        }
        break;
    case RELATION_TYPE_DIFF:
        // TODO propagate ???
    default:
        if (relation.version2_.has_header_comment(false))
            visitor_db.visit_header_comment(false, relation.version2_.header_comment(false));

        if (relation.version2_.has_header_comment(true))
            visitor_db.visit_header_comment(true, relation.version2_.header_comment(true));
        break;

    }
    /*********************************/

    merge_offsets(*this, relation, visitor_db);

    /*********** xrefs ****************************/
    struct xref_value_s
    {
        YaToolObjectId          xref_value;
        HVersion                object;
        const XrefAttributes*   hattr;
    };
    std::map<std::pair<offset_t, operand_t>, struct xref_value_s> xrefs;

    switch(relation.type_)
    {
    case RELATION_TYPE_EXACT_MATCH:
        relation.version2_.walk_xrefs([&](offset_t xref_offset_new, operand_t xref_operand_new, YaToolObjectId xref_value_new, const XrefAttributes* hattr_new)
        {
            xrefs[std::make_pair(xref_offset_new, xref_operand_new)] = {xref_value_new, relation.version2_, hattr_new};
            return WALK_CONTINUE;
        });
        relation.version1_.walk_xrefs([&](offset_t xref_offset_ref, operand_t xref_operand_ref, YaToolObjectId xref_value_ref, const XrefAttributes* hattr_ref)
        {
            if (xrefs.find(std::make_pair(xref_offset_ref, xref_operand_ref)) == xrefs.end())
            {
                /* TODO set bConflict to true and merge xref maybe add exported ids from version1_*/

                xrefs[std::make_pair(xref_offset_ref, xref_operand_ref)] = {xref_value_ref, relation.version1_, hattr_ref};
            }
            return WALK_CONTINUE;
        });
        if (xrefs.size() > 0)
        {
            visitor_db.visit_start_xrefs();
            for (const auto& xref : xrefs)
            {
                offset_t xref_offset = xref.first.first;
                operand_t operand = xref.first.second;

                visitor_db.visit_start_xref(xref_offset, xref.second.xref_value, operand);
                if(on_id)
                    on_id(xref.second.xref_value);
                xref.second.object.walk_xref_attributes(xref.second.hattr, [&](const const_string_ref& xref_attr_key, const const_string_ref& xref_attr_value)
                {
                    visitor_db.visit_xref_attribute(xref_attr_key, xref_attr_value);
                    return WALK_CONTINUE;
                });
                visitor_db.visit_end_xref();
            }
            visitor_db.visit_end_xrefs();
        }
        break;
    case RELATION_TYPE_DIFF:
        // TODO propagate ???
    default:
        if (relation.version2_.has_xrefs())
        {
            visitor_db.visit_start_xrefs();
            relation.version2_.walk_xrefs([&](offset_t xref_offset, operand_t xref_operand, YaToolObjectId xref_value, const XrefAttributes* hattr)
            {
                visitor_db.visit_start_xref(xref_offset, xref_value, xref_operand);
                relation.version2_.walk_xref_attributes(hattr, [&](const const_string_ref& xref_attr_key, const const_string_ref& xref_attr_value)
                {
                    visitor_db.visit_xref_attribute(xref_attr_key, xref_attr_value);
                    return WALK_CONTINUE;
                });
                visitor_db.visit_end_xref();
                return WALK_CONTINUE;
            });
            visitor_db.visit_end_xrefs();
        }
        break;
    }
    /**********************************************/

    /*********** attributes ***********************/
    std::map<std::string, std::string> attributes;
    switch(relation.type_)
    {
    case RELATION_TYPE_EXACT_MATCH:
        relation.version2_.walk_attributes([&](const const_string_ref& key_new, const const_string_ref& value_new)
        {
            attributes[make_string(key_new)] = make_string(value_new);
            return WALK_CONTINUE;
        });
        relation.version1_.walk_attributes([&](const const_string_ref& key_ref, const const_string_ref& value_ref)
        {
            const auto& search = attributes.find(make_string(key_ref));
            if(search == attributes.end())
            {
                attributes[make_string(key_ref)] = make_string(value_ref);
            }
            else
            {
                const auto key = make_string(key_ref);
                merge_attributes(*this, key.data(), value_ref, make_string_ref(search->second), [&](const const_string_ref& value)
                {
                    attributes[make_string(key_ref)] = make_string(value);
                });
            }
            return WALK_CONTINUE;
        });
        for(const auto& attribute: attributes)
        {
            visitor_db.visit_attribute(make_string_ref(attribute.first), make_string_ref(attribute.second));
        }

        break;
    case RELATION_TYPE_DIFF:
        // TODO propagate ???
    default:
        relation.version2_.walk_attributes([&](const const_string_ref& key, const const_string_ref& value)
        {
            visitor_db.visit_attribute(key, value);
            return WALK_CONTINUE;
        });
        break;
    }
    /**********************************************/

    /************* blobs **************************/
    relation.version2_.walk_blobs([&](offset_t offset, const void* data, size_t len)
    {
        visitor_db.visit_blob(offset, data, len);
        return WALK_CONTINUE;
    });//TODO export blobs
    /**********************************************/


     visitor_db.visit_end_version();
     return OBJECT_MERGE_STATUS_BOTH_UPDATED;
}

