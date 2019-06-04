#pragma once

#include "Relation.hpp"
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
        ALGO_XREF_OFFSET_ORDER_MATCH,
        ALGO_CALLER_XREF_MATCH,
        ALGO_XREF_MATCH,
        ALGO_VECTOR_SIGN,
        ALGO_EXTERNAL_MAPPING_MATCH,
    };
    enum AlgoFlag_e
    {
        AF_XREF_OFFSET_DONE    		= 1 << 0, // 0x01
        AF_XREF_OFFSET_ORDER_DONE   = 1 << 1, // 0x02
        AF_CALLER_XREF_DONE    		= 1 << 2, // 0x04
        AF_CALLEE_XREF_DONE    		= 1 << 3, // 0x08
        AF_CALLER_NOBB_XREF_DONE    = 1 << 4, // 0x10
        AF_CALLEE_NOBB_XREF_DONE    = 1 << 5, // 0x20
		AF_ALL_ALGOS_DONE      		= 0xFF,
    };


    enum TrustDiffingRelations_e
    {
        DO_NOT_TRUST_DIFFING_RELATIONS = 0,
        TRUST_DIFFING_RELATIONS = 1,
    };

    enum XRefDirectionMode_e
    {
        XREF_DIRECTION_CALLER = 0,
		XREF_DIRECTION_CALLEE = 1,
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

    struct XRefMatchCfg
    {
    	XRefDirectionMode_e		XrefDirectionMode;
        bool 					StripBasicBlocks = false;
        TrustDiffingRelations_e TrustDiffingRelations = DO_NOT_TRUST_DIFFING_RELATIONS;
        RelationType_e			FunctionDiffType;
    };


    struct VectorSignCfg
    {
        const char* mapDestination;
        // Do I Concatenate mean parents vector to the function vector
        bool 		concatenate_children = false;
        // ... children ...
        bool 		concatenate_parents = false;
    };
    struct ExternalMappingMatchCfg
    {
    	std::string MappingFilePath;
        bool        CustomRelationConfidence = 0;
        int         RelationConfidence = 0;
    };

    // Configuration container for YaDiff (merge of all conf)
    struct AlgoCfg
    {
        Algo_e                  Algo;
        ExactMatchCfg           ExactMatch;
        XRefOffsetMatchCfg      XRefOffsetMatch;
        CallerXRefMatchCfg      CallerXRefMatch;
        XRefMatchCfg      		XRefMatch;
        VectorSignCfg           VectorSign;
        ExternalMappingMatchCfg ExternalMappingMatch;
        int                     NbThreads;
        bool                    bMultiThread;
    };

    typedef std::function<bool (const Relation&, bool update_flag_only)> OnAddRelationFn;
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
        virtual bool Analyse(const OnAddRelationFn& output, const RelationWalkerfn& input) = 0;
//        virtual void Analyse(YadiffRelationMap& output, const YadiffRelationMap& input) = 0;

        virtual const char* GetName() const = 0;

    };

    std::shared_ptr<IDiffAlgo> MakeDiffAlgo(const AlgoCfg& config);
} // End yadiff::
