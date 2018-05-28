#pragma once

#include <functional>

namespace std { template<typename T> class shared_ptr; }
struct IModel;
struct Relation;

namespace yadiff
{

    enum Algo_e
    {
        ALGO_EXACT_MATCH,
        ALGO_XREF_OFFSET_MATCH,
        ALGO_CALLER_XREF_MATCH,
        ALGO_VECTOR_SIGN,
        ALGO_EXTERNAL_MAPPING_MATCH,
    };

    enum AlgoFlag_e
    {
        AF_XREF_OFFSET_DONE = 1 << 0,
        AF_CALLER_XREF_DONE = 1 << 1,
    };

    enum TrustDiffingRelations_e
    {
        DO_NOT_TRUST_DIFFING_RELATIONS = 0,
        TRUST_DIFFING_RELATIONS = 1,
    };

    struct ExactMatchCfg
    {

    };

    struct XRefOffsetMatchCfg
    {

    };

    struct CallerXRefMatchCfg
    {
        TrustDiffingRelations_e TrustDiffingRelations;
    };

    struct VectorSignCfg
    {
        const char* mapDestination;
    };
    struct ExternalMappingMatchCfg
    {
        const char* MappingFilePath;
        bool        CustomRelationConfidence;
        int         RelationConfidence;
    };

    struct AlgoCfg
    {
        Algo_e                  Algo;
        ExactMatchCfg           ExactMatch;
        XRefOffsetMatchCfg      XRefOffsetMatch;
        CallerXRefMatchCfg      CallerXRefMatch;
        VectorSignCfg           VectorSign;
        ExternalMappingMatchCfg ExternalMappingMatch;
        int                     NbThreads;
        bool                    bMultiThread;
    };

    typedef std::function<bool (const Relation&)> OnRelationFn;
    typedef std::function<void (const OnRelationFn&)> RelationWalkerfn;

    struct IDiffAlgo
    {
        virtual ~IDiffAlgo() {}

        /*
         * prepares input signature databases
         * TODO : document return type
         */
        virtual bool Prepare(const IModel& db1, const IModel& db2) = 0;

        /*
         * uses previously registered signature databases and input version relations
         * to compute a new version relation vector
         * output: vector of new Relation
         * input: vector of previously matched Relation
         * TODO : document return type
         */
        virtual bool Analyse(const OnRelationFn& output, const RelationWalkerfn& input) = 0;
//        virtual void Analyse(YadiffRelationMap& output, const YadiffRelationMap& input) = 0;

        virtual const char* GetName() const = 0;

    };

    std::shared_ptr<IDiffAlgo> MakeDiffAlgo(const AlgoCfg& config);
}
