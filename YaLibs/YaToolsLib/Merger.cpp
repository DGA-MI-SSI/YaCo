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

#include "HVersion.hpp"
#include "HObject.hpp"
#include "IModelVisitor.hpp"
#include "Model.hpp"
#include "XML/XMLDatabaseModel.hpp"
#include "XML/XMLExporter.hpp"
#include "VersionRelation.hpp"

#include <functional>
#include <string>
#include <iostream>
#include <map>

Merger::Merger(PromptMergeConflict* MergePrompt, ObjectVersionMergeStrategy_e MergeStrategy) :
            mpMergePrompt(MergePrompt),
            mMergeStrategy(MergeStrategy)
{

}

static bool begins_with(const const_string_ref& ref, const char* token)
{
    return strstr(ref.value, token) == ref.value;
}

static bool is_unset(const const_string_ref& attribute)
{
    if(attribute.size == 0)
            return true;
    return attribute.value
            &&(begins_with(attribute, "var_")
        || begins_with(attribute, "field_")
        || begins_with(attribute, "dword_")
        || begins_with(attribute, "offset_"));
}

MergeStatus_e Merger::smartMerge(   const char* input_file1, const char* input_file2,
                                const char* output_file_result)
{

    /* Load XML files */
    auto file_vect1 = std::vector<std::string>();
    file_vect1.push_back(std::string(input_file1));
    auto file_vect2 = std::vector<std::string>();
    file_vect2.push_back(std::string(input_file2));

    auto database1 = MakeModel();
    auto database2 = MakeModel();

    // reload two databases with one object version in each database
    MakeXmlFilesDatabaseModel(file_vect1)->accept(*database1.visitor);
    MakeXmlFilesDatabaseModel(file_vect2)->accept(*database2.visitor);

    /* Check only one object version is present in each database */
    int count1 = 0;
    HObject db1_ref_object;
    database1.model->walk_objects([&](const YaToolObjectId& id, const HObject& obj){
        UNUSED(id);
        UNUSED(obj);
        count1++;
        db1_ref_object = obj;
        return WALK_CONTINUE;
    });
    int count2 = 0;
    HObject db2_ref_object;
    database2.model->walk_objects([&](const YaToolObjectId& id, const HObject& obj){
        UNUSED(id);
        UNUSED(obj);
        count2++;
        db2_ref_object = obj;
        return WALK_CONTINUE;
    });

    if (count1 != 1 || count2 != 1)
    {
        throw("PythonResolveFileConflictCallback: callback: invalid number of referenced object in databases");
    }

    count1 = 0;
    count2 = 0;
    HVersion db1_obj_version;
    HVersion db2_obj_version;
    db1_ref_object.walk_versions([&](const HVersion& ver)
    {
        count1++;
        db1_obj_version = ver;
        return WALK_CONTINUE;
    });
    db2_ref_object.walk_versions([&](const HVersion& ver)
    {
        count2++;
        db2_obj_version = ver;
        return WALK_CONTINUE;
    });

    if (count1 != 1 || count2 != 1)
    {
        throw("PythonResolveFileConflictCallback: callback: invalid number of object version in reference object");
    }

    auto visitor1 = MakeModel();

    /* Build relation */
    Relation relation;
    relation.version1_ = db1_obj_version;
    relation.version2_ = db2_obj_version;
    relation.type_ = RELATION_TYPE_EXACT_MATCH;
    relation.confidence_ = RELATION_CONFIDENCE_MAX;
    relation.direction_ = RELATION_DIRECTION_BOTH;
    relation.flags_ = 0;

    /* Merge */
    visitor1.visitor->visit_start();
    std::set<YaToolObjectId> newObjectIds;
    MergeStatus_e retval = mergeObjectVersions(*(visitor1.visitor), newObjectIds, relation);
	visitor1.visitor->visit_end();
    
    if(retval != OBJECT_MERGE_STATUS_NOT_UPDATED)
    {
        const std::string output_path = std::string(output_file_result);
        auto xml_exporter = MakeFileXmlExporter(output_path);
        visitor1.model->accept(*xml_exporter);
    }

    return retval;
}

void Merger::mergeAttributes(const std::string& attribute_name, const const_string_ref& ref_attr, const const_string_ref& new_attr,
                             const std::function<void(const const_string_ref&)>& fnCallback)
{
    if (ref_attr == new_attr)
    {
        /* Both same, no merge */
        fnCallback(ref_attr);
        return;
    }
    if (is_unset(ref_attr))
    {
        fnCallback(new_attr);
        return;
    }
    if (is_unset(new_attr))
    {
        fnCallback(ref_attr);
        return;
    }

    /* Conflict detected, see what is the strategy */
    switch (mMergeStrategy)
    {
    case OBJECT_VERSION_MERGE_FORCE_REFERENCE:
        fnCallback(ref_attr);
        break;
    case OBJECT_VERSION_MERGE_FORCE_NEW:
        fnCallback(new_attr);
        break;
    case OBJECT_VERSION_MERGE_IGNORE:
        fnCallback(new_attr);
        break;
    case OBJECT_VERSION_MERGE_PROMPT:
        /* A conflict is detected, need to fix conflict manualy */
        std::string message("Conflict detected between ");
        message += attribute_name;
        message += " attributes";
        std::string      result_conflict = mpMergePrompt->merge_attributes_callback(message.c_str(), new_attr.value, ref_attr.value);

        if (result_conflict.length() == 0)
        {
            fnCallback(new_attr);
        }
        fnCallback(make_string_ref(result_conflict));
        break;
    }
}


MergeStatus_e Merger::mergeObjectVersions( IModelVisitor& visitor_db, std::set<YaToolObjectId>& newObjectIds,
                                                            const Relation& relation)
{
    visitor_db.visit_start_reference_object(relation.version2_.type());

    /* Visit id */
    visitor_db.visit_id(relation.version2_.id());

    visitor_db.visit_start_object_version();

    /* Visit size */
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
        mergeAttributes("name", relation.version1_.username(), relation.version2_.username(), [&](const const_string_ref& name)
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
             mergeAttributes("prototype", relation.version1_.prototype(), relation.version2_.prototype(), [&](const const_string_ref& prototype)
             {
                 visitor_db.visit_prototype(prototype);
             });
         }
        break;
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
            mergeAttributes("header_nonrepeatable_comment", relation.version1_.header_comment(false), relation.version2_.header_comment(false), [&](const const_string_ref& value)
            {
                visitor_db.visit_header_comment(false, value);
            });
        }

        /* Header repeatable comment */
        if (relation.version1_.has_header_comment(true) || relation.version2_.has_header_comment(true))
        {
            mergeAttributes("header_repeatable_comment", relation.version1_.header_comment(true), relation.version2_.header_comment(true), [&](const const_string_ref& value)
            {
                visitor_db.visit_header_comment(true, value);
            });
        }
        break;
    default:
        if (relation.version2_.has_header_comment(false))
            visitor_db.visit_header_comment(false, relation.version2_.header_comment(false));

        if (relation.version2_.has_header_comment(true))
            visitor_db.visit_header_comment(true, relation.version2_.header_comment(true));
        break;

    }
    /*********************************/


    /********** merge offsets ****************************/
     /* Merge comments */
    //TODO export valueviews registerviews hiddenareas
    std::map<std::pair<offset_t, CommentType_e>, const_string_ref> offsets;
    switch(relation.type_)
    {
    case RELATION_TYPE_EXACT_MATCH:
        relation.version2_.walk_comments([&](offset_t offset_new, CommentType_e type_new, const const_string_ref& comment_new)
        {
           offsets[std::make_pair(offset_new, type_new)] = comment_new;
           return WALK_CONTINUE;
        });
        relation.version1_.walk_comments([&](offset_t offset_ref, CommentType_e type_ref, const const_string_ref& comment_ref)
        {
            const auto& search = offsets.find(std::make_pair(offset_ref, type_ref));
            if( search == offsets.end())
            {
                offsets[std::make_pair(offset_ref, type_ref)] = comment_ref;
            }
            else
            {
                mergeAttributes("comment", comment_ref, search->second, [&](const const_string_ref& value)
                {
                    offsets[std::make_pair(offset_ref, type_ref)] = value;
                });
            }
            return WALK_CONTINUE;
        });
        if(offsets.size() > 0)
        {
            visitor_db.visit_start_offsets();
            for(const auto& offset: offsets)
            {
                visitor_db.visit_offset_comments(offset.first.first, offset.first.second, offset.second);
            }
            visitor_db.visit_end_offsets();
        }
        break;
    default:
        if(relation.version2_.has_comments())
        {
            visitor_db.visit_start_offsets();
            relation.version2_.walk_comments([&](offset_t offset, CommentType_e type, const const_string_ref& comment)
            {
                visitor_db.visit_offset_comments(offset, type, comment);
                return WALK_CONTINUE;
            });
            visitor_db.visit_end_offsets();
        }
        break;
    }
    /******************************************************/

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
                newObjectIds.insert(xref.second.xref_value);
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

    /************* matching systems ***************/
    switch(relation.type_)
    {
    case RELATION_TYPE_EXACT_MATCH:
    default:
        if (relation.version2_.has_systems())
        {
            visitor_db.visit_start_matching_systems();
            relation.version2_.walk_systems([&](offset_t address, HSystem_id_t system)
            {
                visitor_db.visit_start_matching_system(address);
                relation.version2_.walk_system_attributes(system, [&](const const_string_ref& key, const const_string_ref& value)
                {
                    visitor_db.visit_matching_system_description(key, value);
                    return WALK_CONTINUE;
                });
                visitor_db.visit_end_matching_system();
                return WALK_CONTINUE;
            });
            visitor_db.visit_end_matching_systems();
        }
        break;

    }
    /**********************************************/


    /*********** attributes ***********************/
    std::map<const_string_ref, const_string_ref> attributes;
    switch(relation.type_)
    {
    case RELATION_TYPE_EXACT_MATCH:
        relation.version2_.walk_attributes([&](const const_string_ref& key_new, const const_string_ref& value_new)
        {
            attributes[key_new] = value_new;
            return WALK_CONTINUE;
        });
        relation.version1_.walk_attributes([&](const const_string_ref& key_ref, const const_string_ref& value_ref)
        {
            const auto& search = attributes.find(key_ref);
            if(search == attributes.end())
            {
                attributes[key_ref] = value_ref;
            }
            else
            {
                mergeAttributes("attribute", value_ref, search->second, [&](const const_string_ref& value)
                {
                    attributes[key_ref] = value;
                });
            }
            return WALK_CONTINUE;
        });
        for(const auto& attribute: attributes)
        {
            visitor_db.visit_attribute(attribute.first, attribute.second);
        }

        break;
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


     visitor_db.visit_end_object_version();

     visitor_db.visit_end_reference_object();

     return OBJECT_MERGE_STATUS_BOTH_UPDATED;
}

