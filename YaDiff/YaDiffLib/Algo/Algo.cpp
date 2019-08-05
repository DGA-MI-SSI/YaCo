#include "Algo.hpp"

#include "ExactMatch.hpp"
#include "XRefOffsetMatch.hpp"
#include "XRefOffsetOrderMatch.hpp"
#include "CallerXRefMatch.hpp"
#include "XRefMatch.hpp"
#include "ExternalMappingMatch.hpp"
#include "Helpers.h"

#include "VectorSign.hpp"

#include <memory>


namespace yadiff {

// Create diffing algorithm object
std::shared_ptr<IDiffAlgo> MakeDiffAlgo(const AlgoCfg& config) {
    switch(config.Algo) {

    // Same hash of standardised mnemonics (intrinsic) 
    case ALGO_EXACT_MATCH:
        return MakeExactMatchAlgo(config);

    // Call the same function at the same offset
    case ALGO_XREF_OFFSET_MATCH:
        return MakeXRefOffsetMatchAlgo(config);

    // Call the same function at the <third> call (or nth call)
    case ALGO_XREF_OFFSET_ORDER_MATCH:
        return MakeXRefOffsetOrderMatchAlgo(config);

    // Call someone that has only one unknown parent (i.e. caller)
    case ALGO_XREF_MATCH:
        return MakeXRefMatchAlgo(config);

    // Called by the same function
    case ALGO_CALLER_XREF_MATCH:
        return MakeCallerXRefMatchAlgo(config);

    // Signature vectors are close enough
    // TODO : some of them are propagators and others just week association
    case ALGO_VECTOR_SIGN:
        return MakeVectorSignAlgo(config);

    // Take output of an external algorithm
    case ALGO_EXTERNAL_MAPPING_MATCH:
        return MakeExternalMappingMatchAlgo(config);
    default:
        return nullptr;
    }
}
} // End yadiff::
