#include "ExactMatch.hpp"
#include "Algo.hpp"

#include "Helpers.h"
#include "Yatools.hpp"
#include "IModel.hpp"
#include "VersionRelation.hpp"

#include <utility>
#include <memory>
#include <chrono>


namespace yadiff {
class ExactMatchAlgo: public IDiffAlgo
{
public:
    // Ctor, getter
    const char* GetName() const override { return "ExactMatchAlgo"; }
    virtual ~ExactMatchAlgo(){}
    ExactMatchAlgo(const AlgoCfg& config);

    // Prepare input signature databases
    bool Prepare(const IModel& db1, const IModel& db2) override;

    // Use previously registered signature databases and input version relations
    //     to compute a new version relation vector
    bool Analyse(const OnAddRelationFn& output, const RelationWalkerfn& input) override;


private:
    // Store pointer to databases & config
    const IModel* pDb1_;
    const IModel* pDb2_;
    const AlgoCfg config_;
};


// Create object
std::shared_ptr<IDiffAlgo> MakeExactMatchAlgo(const AlgoCfg& config)
{
    return std::make_shared<ExactMatchAlgo>(config);
}


// Ctor
ExactMatchAlgo::ExactMatchAlgo(const AlgoCfg& config):
        pDb1_(nullptr),
        pDb2_(nullptr),
        config_(config)
{
}


// Feed
bool ExactMatchAlgo::Prepare(const IModel& db1, const IModel& db2)
{
    pDb1_ = &db1;
    pDb2_ = &db2;

    return true;
}


// Work
bool ExactMatchAlgo::Analyse(const OnAddRelationFn& output, const RelationWalkerfn& input) {
    // Stack
    UNUSED(input);
    int i = 0;
    int exactMatchInitial = 0;
    Relation relation;
    relation.type_ = RELATION_TYPE_EXACT_MATCH;

    // Check in
    if(nullptr == pDb1_ || nullptr == pDb2_) {
        return false;
    }

    LOG(DEBUG, "matching %zd objects version to %zd objects version\n", pDb1_->size(), pDb2_->size());

    // For all unique object version
    pDb1_->walk_uniques([&](const HVersion& object_version, const HSignature& signature)
    {
        // Set relation.left_part
        relation.version1_ = object_version;

        // Check if object has collisions in the other database
        if (pDb2_->size_matching(signature) != 1) {
            return WALK_CONTINUE;
        }

        // Don't trust basic block for initial association
        if (object_version.type() == OBJECT_TYPE_BASIC_BLOCK) {
            return WALK_CONTINUE;
        }

        // For all obejct verision in db2 with the same signature
        pDb2_->walk_matching(signature, [&](const HVersion& remote_object_version) -> ContinueWalking_e
        {
            // Don't associate different object types
            if (object_version.type() != remote_object_version.type()) {
                return WALK_CONTINUE;
            }

            // Set relation.right_part
            relation.version2_ = remote_object_version;
            LOG(DEBUG, "ExactMatch.cpp: associate %zx (%s) <-> %zx (%s)\n", relation.version1_.address(), relation.version1_.username().value, relation.version2_.address(), relation.version2_.username().value);
            output(relation, false);

            // Inc count
            exactMatchInitial++;

            // Not iterate : we find only one match
            // TODO : shouldn't walk_continue
            return WALK_STOP;
        });


        // Inc global count & may Log
        i++;
        if (i % 10000 == 0) {
            LOG(INFO, "ExactMatch.cpp: %d/%d objects version exactly matched\n", exactMatchInitial, i);
        }
        return WALK_CONTINUE;
    });

    //    this->sortRelations();
    return true;
}
} // End yadiff::
