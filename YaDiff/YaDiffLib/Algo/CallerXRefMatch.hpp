#pragma once


namespace std { template<typename T> class shared_ptr; }

namespace yadiff { struct IDiffAlgo; }
namespace yadiff { struct AlgoCfg; }

namespace yadiff
{
    std::shared_ptr<IDiffAlgo> MakeCallerXRefMatchAlgo(const AlgoCfg& config);
}
