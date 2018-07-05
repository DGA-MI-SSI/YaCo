#pragma once

#include <YaTypes.hpp>
#include <Merger.hpp>

#include <functional>
#include <map>


class GitRepo;
struct HVersion;

#include <Algo/Algo.hpp>

#include <map>
#include <set>

struct Relation;

class Configuration;
namespace yadiff
{


#define YADIFF_ERROR_STATUS     (~0u)
#define YADIFF_OK_STATUS        (0)


enum AutoCommit_e
{
    NoAutoCommit,
    AutoCommit,
};

enum AutoPush_e
{
    NoAutoPush,
    AutoPush,
};

enum ShowAssociations_e
{
    NoShowAssociations,
    ShowAssociations,
};

class Propagate
{
public:
    Propagate(const Configuration& config, ShowAssociations_e eShowAssociations, const Merger::on_conflict_fn& on_conflict);

    void PropagateToDB(IModelVisitor& visitor_db, const IModel& ref_model, const IModel& new_model, yadiff::RelationWalkerfn walk);

private:
    /*
     * Used when merging between attributes is needed
     */

   void mergeAttribute(const std::string& attribute_name, const const_string_ref& attribute1, const const_string_ref& attribute2,
                       const std::function<void(const const_string_ref&)>& fnCallback);


    unsigned int addCommentToComments(const std::map<std::pair<offset_t, CommentType_e>, std::string> & fromOffsetComments,
                                      const std::map<std::pair<offset_t, CommentType_e>, std::string> & toOffsetComments,
                                      ObjectVersionMergeStrategy_e MergeStrategie);

    ObjectVersionMergeStrategy_e            mObjectVersionMergeStrategy;
    ObjectVersionMergeStrategy_e            mNot_ObjectVersionMergeStrategy;
    bool                                    mShowAssociations;
    const Configuration&                    config_;
    const Merger::on_conflict_fn&           on_conflict_;
};

} // end namespace
