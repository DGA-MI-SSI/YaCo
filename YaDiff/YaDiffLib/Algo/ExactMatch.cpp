#include "ExactMatch.hpp"
#include "Algo.hpp"

#include "Helpers.h"
#include "Yatools.hpp"
#include "IModel.hpp"
#include "VersionRelation.hpp"

#include <utility>
#include <memory>
#include <chrono>

#if 0
#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("exact", (FMT), ## __VA_ARGS__)
#else
#define LOG(...) do {} while(0)
#endif

namespace yadiff
{
class ExactMatchAlgo: public IDiffAlgo
{
public:
    virtual ~ExactMatchAlgo(){}

    ExactMatchAlgo(const AlgoCfg& config);

    /*
     * prepares input signature databases
     */
    bool Prepare(const IModel& db1, const IModel& db2) override;

    /*
     * uses previously registered signature databases and input version relations
     * to compute a new version relation vector
     */
    bool Analyse(const OnAddRelationFn& output, const RelationWalkerfn& input) override;

    const char* GetName() const override;
private:

    const IModel* pDb1_;
    const IModel* pDb2_;
    const AlgoCfg config_;
};

std::shared_ptr<IDiffAlgo> MakeExactMatchAlgo(const AlgoCfg& config)
{
    return std::make_shared<ExactMatchAlgo>(config);
}



const char* ExactMatchAlgo::GetName() const{
    return "ExactMatchAlgo";
}

ExactMatchAlgo::ExactMatchAlgo(const AlgoCfg& config):
        pDb1_(nullptr),
        pDb2_(nullptr),
        config_(config)
{
}

bool ExactMatchAlgo::Prepare(const IModel& db1, const IModel& db2)
{
    pDb1_ = &db1;
    pDb2_ = &db2;

    return true;
}

bool ExactMatchAlgo::Analyse(const OnAddRelationFn& output, const RelationWalkerfn& input)
{
    UNUSED(input);
    int i = 0;
    int exactMatchInitial = 0;

    if(nullptr == pDb1_)
        return false;

    if(nullptr == pDb2_)
        return false;

    Relation relation;
    relation.type_ = RELATION_TYPE_EXACT_MATCH;

    LOG(DEBUG, "matching %zd objects version to %zd objects version\n", pDb1_->num_objects(), pDb2_->num_objects());

    pDb1_->walk_uniques([&](const HVersion& object_version, const HSignature& signature)
    {
        //cout << object_version << endl;
        //check if object has collisions in the other database
        relation.version1_ = object_version;
        i++;
        if (pDb2_->size_matching(signature) != 1)
            return WALK_CONTINUE;

        /* Don't trust basic block for initial association */
        if (object_version.type() == OBJECT_TYPE_BASIC_BLOCK)
            return WALK_CONTINUE;

        pDb2_->walk_matching(signature, [&](const HVersion& remote_object_version) -> ContinueWalking_e
        {
            /* Don't associate different object types */
            if (object_version.type() != remote_object_version.type())
                return WALK_CONTINUE;

            relation.version2_ = remote_object_version;
            LOG(INFO, "associate %lx(%s) <-> %lx(%s)\n", relation.version1_.address(), relation.version1_.username().value, relation.version2_.address(), relation.version2_.username().value);
            output(relation, false);

            exactMatchInitial++;

            /* we do not iterate, we have found only one match */
            return WALK_STOP;
        });


        if (i % 10000 == 0)
        {
            LOG(INFO, "%d/%d objects version exactly matched (over a total of %zd)\n", exactMatchInitial, i, number_of_object);
        }
        return WALK_CONTINUE;
    });

    //    this->sortRelations();
    return true;
}
}
