#include "Algo.hpp"

#include "ExactMatch.hpp"
#include "XRefOffsetMatch.hpp"
#include "CallerXRefMatch.hpp"
#include "ExternalMappingMatch.hpp"
#include "Helpers.h"

#include "VectorSign.hpp"

#include <memory>

STATIC_ASSERT_POD(yadiff::AlgoCfg);

namespace yadiff
{
std::shared_ptr<IDiffAlgo> MakeDiffAlgo(const AlgoCfg& config)
{
    switch(config.Algo)
    {
    case ALGO_EXACT_MATCH:
        return MakeExactMatchAlgo(config);
    case ALGO_XREF_OFFSET_MATCH:
        return MakeXRefOffsetMatchAlgo(config);
    case ALGO_CALLER_XREF_MATCH:
        return MakeCallerXRefMatchAlgo(config);
    case ALGO_VECTOR_SIGN:
        return MakeVectorSignAlgo(config);
      case ALGO_EXTERNAL_MAPPING_MATCH:
        return MakeExternalMappingMatchAlgo(config);
    default:
        return nullptr;
    }
}
}
