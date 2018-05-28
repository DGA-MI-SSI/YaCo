#include "Propagate.hpp"

#include "IModelVisitor.hpp"
#include "Configuration.hpp"

#include "Yatools.hpp"
#include "Helpers.h"
#include <IModel.hpp>
#include <Algo/Algo.hpp>

#include <deque>
#include <assert.h>

using namespace std;

#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("propagate", (FMT), ## __VA_ARGS__)

//#define XML_CACHE_EXPORT
//#define YADIFF_MERGE_XREFS

namespace yadiff
{
static const std::string SECTION_NAME = "Propagate";


Propagate::Propagate(const Configuration& config,
                         ShowAssociations_e eShowAssociations, PromptMergeConflict* MergePrompt)
    : mpMergePrompt(MergePrompt)
    , mShowAssociations(eShowAssociations == ShowAssociations)
    , config_(config)
{
    const auto MergerStrat = config.GetOption(SECTION_NAME, "MergeStrategy");
    if(MergerStrat == "PROMPT")
    {
        assert(MergePrompt != nullptr);
        mObjectVersionMergeStrategy = OBJECT_VERSION_MERGE_PROMPT;
    }
    else if(MergerStrat == "FORCE_REFERENCE")
    {
        mObjectVersionMergeStrategy = OBJECT_VERSION_MERGE_FORCE_REFERENCE;
    }
    else if(MergerStrat == "FORCE_NEW")
    {
        mObjectVersionMergeStrategy = OBJECT_VERSION_MERGE_FORCE_NEW;
    }
    else /* (MergerStrat == "IGNORE") and default case */
    {
        mObjectVersionMergeStrategy = OBJECT_VERSION_MERGE_IGNORE;
    }

}

bool NeedExportAsChild(const HVersion& hver)
{
    switch(hver.type())
    {
        case OBJECT_TYPE_STRUCT:
        case OBJECT_TYPE_ENUM:
        case OBJECT_TYPE_ENUM_MEMBER:
        case OBJECT_TYPE_STRUCT_MEMBER:
        case OBJECT_TYPE_STACKFRAME:
        case OBJECT_TYPE_STACKFRAME_MEMBER:
        case OBJECT_TYPE_REFERENCE_INFO:
            return true;

        case OBJECT_TYPE_SEGMENT_CHUNK:
        case OBJECT_TYPE_SEGMENT:
        case OBJECT_TYPE_BASIC_BLOCK:
        case OBJECT_TYPE_FUNCTION:
        case OBJECT_TYPE_CODE:
        case OBJECT_TYPE_DATA:
        case OBJECT_TYPE_UNKNOWN:
        case OBJECT_TYPE_BINARY:
        default:
            return false;
    }
}

void Propagate::PropagateToDB(IModelVisitor& visitor_db, const IModel& ref_model, const IModel& new_model, yadiff::RelationWalkerfn walk)
{
    // set of already exported object id
    std::set<YaToolObjectId> exportedObjects;
    std::set<YaToolObjectId> newObjectIds;

    // build merger
    Merger merger(mpMergePrompt, mObjectVersionMergeStrategy);

    visitor_db.visit_start();

    /* Iterate throw relations */
        walk([&](const Relation& relation){
            if((relation.direction_ & RELATION_DIRECTION_LOCAL_TO_REMOTE) == 0)
                return true;

            // TODO check relation_confidence
            switch(relation.confidence_)
            {
            case RELATION_CONFIDENCE_MAX:
                break;
            default:
                return true;
            }

            switch(relation.type_)
            {
            case RELATION_TYPE_EXACT_MATCH:
                break;
            case RELATION_TYPE_DIFF:
                // check conf
                break;
            default:
                return true;
            }

            /* Check if object has been already exported */
            const auto obj_id = relation.version2_.id();
            if (exportedObjects.find(obj_id) != exportedObjects.end())
            {
                return true;
            }

            /* Check objects have the same type */
            if (relation.version1_.type() != relation.version2_.type())
            {
                LOG(ERROR, "PropagateToDB: Invalid object type, local: %x, remote: %x\n", relation.version1_.type(), relation.version2_.type());
                return true;
            }

            /* Check if object in db1 has difference with object in db2 */
            if (relation.version1_.is_different_from(relation.version2_) == false)
            {
                return true;
            }

            merger.mergeObjectVersions(visitor_db, newObjectIds, relation);

            exportedObjects.insert(obj_id);

            return true;
        });

    // Export children and parents
    std::set<YaToolObjectId> walkedChilds;
    const auto walkChilds = [&](std::deque<HVersion> objects, const auto& fnWalk)
    {
        while(!objects.empty())
        {
            const auto object_version = objects.front();
            objects.pop_front();
            object_version.walk_xrefs_from([&](offset_t xref_offset, operand_t xref_operand, const HVersion& xref_reference_object)
            {
                UNUSED(xref_offset);
                UNUSED(xref_operand);
                if(!walkedChilds.insert(xref_reference_object.id()).second)
                    return WALK_CONTINUE;
                if(WALK_CONTINUE == fnWalk(xref_reference_object))
                    objects.push_back(xref_reference_object);
                return WALK_CONTINUE;
            });
        }
    };

    for (const auto& newObjectId : newObjectIds)
    {
        if (!ref_model.has(newObjectId))
            continue;

        const auto& ref_reference_object = ref_model.get(newObjectId);
        walkedChilds.insert(newObjectId);
        if(!NeedExportAsChild(ref_reference_object))
            continue;

        ref_reference_object.accept(visitor_db);
        walkChilds({ref_reference_object}, [&](const HVersion& child_reference)
        {
            if(!NeedExportAsChild(child_reference))
                return WALK_STOP;

            child_reference.accept(visitor_db);
            return WALK_CONTINUE;
        });
    }

    std::set<HVersion> exportedParents;
    const auto walkParents = [&](std::deque<HVersion> versions, const auto& fnWalk)
    {
        while(!versions.empty())
        {
            const auto object_version = versions.front();
            versions.pop_front();
            object_version.walk_xrefs_to([&](const HVersion& parent_object_version)
            {
                if(!exportedParents.insert(parent_object_version).second)
                    return WALK_CONTINUE;
                fnWalk(parent_object_version);
                versions.push_back(parent_object_version);
                return WALK_CONTINUE;
            });
        }
    };

    /* These objects has been already exported */
    for (const auto& object_id : exportedObjects)
        if (new_model.has(object_id))
            exportedParents.insert(new_model.get(object_id));

    auto exportedParents_copy = exportedParents;
    for (const auto& object_version : exportedParents_copy)
    {
        walkParents({object_version}, [&](const HVersion& reference_object)
        {
            reference_object.accept(visitor_db);
            return WALK_CONTINUE;
        });
    }

    visitor_db.visit_end();
}
} // end of namespace
