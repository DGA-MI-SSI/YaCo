#include "Matching.hpp"


#include <Algo/Algo.hpp>
#include "Configuration.hpp"
#include "VersionRelation.hpp"
#include "Yatools.hpp"
#include "Helpers.h"

#include <memory>
#include <string.h>
#include <vector>
#include <unordered_map>
#include <libxml/xmlreader.h>

#if 1
#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("yadiff", (FMT), ## __VA_ARGS__)
#else
#define LOG(...) do {} while(0)
#endif

namespace yadiff
{
    static const std::string SECTION_NAME = "Matching";

#define MAKE_RELATION_KEY(r) (((uint64_t)r.version1_.id) << 32) + r.version2_.id
#define MERGE_RELATION_CONFIDENCE 0
#define MERGE_RELATION_TYPE 0

class YaDiffRelationContainer
{
public:
//    std::unordered_map<uint64_t, uint32_t> relation_map_;
    std::vector<Relation> relations_;
    std::unordered_map<uint32_t, uint32_t> all_relations_db1;
    std::unordered_map<uint32_t, uint32_t> all_relations_db2;
    int new_relation_counter_;

    YaDiffRelationContainer(){new_relation_counter_ = 0;}

    void MergeRelation(Relation& dest, const Relation& src)
    {
        dest.flags_ |= src.flags_;
#if MERGE_RELATION_CONFIDENCE
        dest.confidence_ = (dest.confidence_ + src.confidence_) % RELATION_CONFIDENCE_MAX;
#endif
#if MERGE_RELATION_TYPE
        dest.type_ = src.type_;
#endif
    }

    bool InsertRelation(const Relation& relation)
    {
        bool b_relation_untrustable = false;
        auto range = all_relations_db1.equal_range(relation.version1_.idx_);
        for(auto it = range.first; it != range.second; ++it)
        {
            Relation& existing_relation = relations_[it->second];
            if(existing_relation.version2_ != relation.version2_)
            {
                existing_relation.type_ = RELATION_TYPE_UNTRUSTABLE;
                b_relation_untrustable = true;
            }
            else
            {
                MergeRelation(relations_[it->second], relation);
                return true;
            }
        }
        range = all_relations_db2.equal_range(relation.version2_.idx_);
        for(auto it = range.first; it != range.second; ++it)
        {
            Relation& existing_relation = relations_[it->second];
            if(existing_relation.version1_ != relation.version1_)
            {
                existing_relation.type_ = RELATION_TYPE_UNTRUSTABLE;
                b_relation_untrustable = true;
            }
            else
            {
                //TODO check previous relation type
                MergeRelation(relations_[it->second], relation);
                return true;
            }
        }

        const auto index = static_cast<uint32_t>(relations_.size());
        relations_.push_back(relation);
        if(b_relation_untrustable)
        {
            relations_[index].type_ = RELATION_TYPE_UNTRUSTABLE;
        }
        ++new_relation_counter_;
        all_relations_db1[relation.version1_.idx_] = index;
        all_relations_db2[relation.version2_.idx_] = index;
        return true;
    }

    int PurgeNewRelations()
    {
        auto result = new_relation_counter_;
        new_relation_counter_ = 0;
        return result;
    }

    int WalkRelations(const yadiff::OnRelationFn& on_relation)
    {
        auto relation_size = relations_.size();
        for(unsigned int i = 0; i < relation_size; ++i)
        {
            on_relation(relations_[i]);
        }
        return PurgeNewRelations();
    }
};

class Matching: public IMatching
{
public:
    Matching(const Configuration& config);

    bool Prepare(const IModel& db1, const IModel& db2) override;
    bool Analyse(std::vector<Relation>& output) override;

private:
    std::vector<std::shared_ptr<IDiffAlgo>> Algos_;
    std::vector<AlgoCfg> AlgoCfgs_;
    const Configuration& config_;
    const IModel* pDb1_;
    const IModel* pDb2_;
};


std::shared_ptr<IMatching> MakeMatching(const Configuration& config)
{
    return std::make_shared<Matching>(config);
}

Matching::Matching(const Configuration& config)
    : config_(config)
    , pDb1_(nullptr)
    , pDb2_(nullptr)
{
}


bool Matching::Prepare(const IModel& db1, const IModel& db2)
{
    AlgoCfg AlgoConfig;
    memset(&AlgoConfig, 0, sizeof(AlgoConfig));
    pDb1_ = &db1;
    pDb2_ = &db2;


    //TODO have a real configuration
    if(config_.IsOptionTrue(SECTION_NAME, "XRefOffsetMatch"))
    {
        memset(&AlgoConfig, 0, sizeof(AlgoConfig));
        AlgoConfig.Algo = ALGO_XREF_OFFSET_MATCH;
        AlgoCfgs_.push_back(AlgoConfig);
        auto algo = MakeDiffAlgo(AlgoConfig);
        algo->Prepare(db1, db2);
        Algos_.push_back(algo);
    }
    if(config_.IsOptionTrue(SECTION_NAME, "CallerXRefMatch"))
    {
        memset(&AlgoConfig, 0, sizeof(AlgoConfig));
        AlgoConfig.Algo = ALGO_CALLER_XREF_MATCH;
        if(config_.IsOptionTrue(SECTION_NAME, "CallerXRefMatch_TrustDiffingRelations"))
        {
            AlgoConfig.CallerXRefMatch.TrustDiffingRelations = TRUST_DIFFING_RELATIONS;
        }
        AlgoCfgs_.push_back(AlgoConfig);
        auto algo = MakeDiffAlgo(AlgoConfig);
        algo->Prepare(db1, db2);
        Algos_.push_back(algo);
    }

    return true;
}

bool Matching::Analyse(std::vector<Relation>& output)
{
    if(nullptr == pDb1_)
    {
//        LOG(WARNING, "could not do analyze, call prepare before\n");
        return false;
    }
    if(nullptr == pDb2_)
    {
//        LOG(WARNING, "could not do analyze, call prepare before\n");
        return false;
    }
    auto relations = YaDiffRelationContainer();
    AlgoCfg AlgoConfig;
    bool DoAnalyzeUntilAlgoReturn0 = config_.IsOptionTrue(SECTION_NAME, "DoAnalyzeUntilAlgoReturn0");
    bool DoAnalyzeUntilAnalyzeReturn0 = config_.IsOptionTrue(SECTION_NAME, "DoAnalyzeUntilAnalyzeReturn0");

    // apply external mapping match algo
    if(config_.IsOptionTrue(SECTION_NAME, "ExternalMappingMatch"))
    {
        LOG(INFO, "start external mapping association\n");
        memset(&AlgoConfig, 0, sizeof(AlgoConfig));
        AlgoConfig.Algo = ALGO_EXTERNAL_MAPPING_MATCH;
        AlgoConfig.ExternalMappingMatch.MappingFilePath = config_.GetOption(SECTION_NAME, "ExternalMappingMatchPath").c_str();
        auto relation_confidence = config_.GetOption(SECTION_NAME, "ExternalMappingMatchRelationConfidence");
        if(relation_confidence.length() > 0)
          {
            if(relation_confidence == "GOOD")
              {
                AlgoConfig.ExternalMappingMatch.CustomRelationConfidence = true;
                AlgoConfig.ExternalMappingMatch.RelationConfidence = RELATION_CONFIDENCE_GOOD;
              }
            if(relation_confidence == "BAD")
              {
                AlgoConfig.ExternalMappingMatch.CustomRelationConfidence = true;
                AlgoConfig.ExternalMappingMatch.RelationConfidence = RELATION_CONFIDENCE_BAD;
              }
            if(relation_confidence == "MIN")
              {
                AlgoConfig.ExternalMappingMatch.CustomRelationConfidence = true;
                AlgoConfig.ExternalMappingMatch.RelationConfidence = RELATION_CONFIDENCE_MIN;
              }
            if(relation_confidence == "MAX")
              {
                AlgoConfig.ExternalMappingMatch.CustomRelationConfidence = true;
                AlgoConfig.ExternalMappingMatch.RelationConfidence = RELATION_CONFIDENCE_MAX;
              }
            else
              {
                try
                {
                    AlgoConfig.ExternalMappingMatch.RelationConfidence = std::stoul(relation_confidence);
                    AlgoConfig.ExternalMappingMatch.CustomRelationConfidence = true;
                }
                catch(const std::invalid_argument&)
                {
                  LOG(ERROR, "invalid value for ExternalMappging match relation confidence, use default value\n");
                }
                catch(const std::out_of_range&)
                {
                  LOG(ERROR, "invalid value for ExternalMappging match relation confidence, use default value\n");
                }
              }
          }
        AlgoCfgs_.push_back(AlgoConfig);
        auto algo = MakeDiffAlgo(AlgoConfig);
        if(algo->Prepare(*pDb1_, *pDb2_))
          {
            algo->Analyse(
                [&](const Relation& relation)
                {
                    return relations.InsertRelation(relation);
                },
                [&](const yadiff::OnRelationFn& on_relation)
                {
                    return relations.WalkRelations(on_relation);
                });
            LOG(INFO, "external mapping association done %zd\n", relations.relations_.size());
          }
        else
          LOG(ERROR, "could not apply external mapping\n");
    }  int new_relation_counter_g = 0;

    memset(&AlgoConfig, 0, sizeof(AlgoConfig));

    // always start with exact match algo
    AlgoConfig.Algo = ALGO_EXACT_MATCH;
    AlgoCfgs_.push_back(AlgoConfig);
    auto exact_algo = MakeDiffAlgo(AlgoConfig);
    exact_algo->Prepare(*pDb1_, *pDb2_);
    LOG(INFO, "start first association\n");
    exact_algo->Analyse(
        [&](const Relation& relation)
        {
            return relations.InsertRelation(relation);
        },
        [&](const yadiff::OnRelationFn& on_relation)
        {
            return relations.WalkRelations(on_relation);
        });
    LOG(INFO, "first association done %zd\n", relations.relations_.size());

    LOG(INFO, "start algo loop\n");
    do
    {
        LOG(INFO, "main loop relation counter: %d\n", new_relation_counter_g);
        new_relation_counter_g = 0;
        for(const auto algo: Algos_)
        {
            int new_relation_counter = 0;
            do
            {
                algo->Analyse(
                [&](const Relation& relation)
                {
                    return relations.InsertRelation(relation);
                },
                [&](const yadiff::OnRelationFn& on_relation)
                {
                    auto new_relations = relations.relations_;
                    for(const auto relation : new_relations)
                    {
                        on_relation(relation);
                    }
                    new_relation_counter = relations.PurgeNewRelations();
                    return new_relation_counter;
                });
                new_relation_counter_g += new_relation_counter;
                LOG(INFO, "algo %s found: %d new relation %zd\n", algo->GetName(), new_relation_counter, relations.relations_.size());
            }
            while(DoAnalyzeUntilAlgoReturn0 && (new_relation_counter > 0));
        }
    }
    while(DoAnalyzeUntilAnalyzeReturn0 && (new_relation_counter_g > 0));

    LOG(INFO, "algo loop done %zd\n", relations.relations_.size());

    output.insert(output.end(), relations.relations_.begin(), relations.relations_.end());
    return true;
}

} //end namespace
