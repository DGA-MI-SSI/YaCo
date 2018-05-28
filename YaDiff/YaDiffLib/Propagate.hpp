#pragma once

#include <YaTypes.hpp>
#include <Merger.hpp>

#include <map>

namespace std { template<typename T> class function; }

class ResolveFileConflictCallback;
class GitRepo;
struct HVersion;

#include "YaGitLib.hpp"
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

struct MergeContext_t
{
};

class Propagate
{
public:
    Propagate(const Configuration& config, ShowAssociations_e eShowAssociations, PromptMergeConflict* MergePrompt);

    void PropagateToDB(IModelVisitor& visitor_db, const IModel& ref_model, const IModel& new_model, yadiff::RelationWalkerfn walk);

private:
    /*
     * Used when merging between attributes is needed
     */

   void mergeAttribute(const std::string& attribute_name, const const_string_ref& attribute1, const const_string_ref& attribute2,
                       const std::function<void(const const_string_ref&)>& fnCallback);


    unsigned int addCommentToComments(const std::map<std::pair<offset_t, CommentType_e>, std::string> & fromOffsetComments,
                                      const std::map<std::pair<offset_t, CommentType_e>, std::string> & toOffsetComments,
                                      ObjectVersionMergeStrategy_e MergeStrategie,
                                      PromptMergeConflict& Prompt
                                      );

    ObjectVersionMergeStrategy_e            mObjectVersionMergeStrategy;
    ObjectVersionMergeStrategy_e            mNot_ObjectVersionMergeStrategy;
    PromptMergeConflict*                    mpMergePrompt;
    bool                                    mShowAssociations;
    const Configuration&                    config_;

};

} // end namespace
