#pragma once

namespace std { template<typename T> class shared_ptr; }
class IDiffAlgo;
struct AlgoCfg;

namespace yadiff
{
    std::shared_ptr<IDiffAlgo> MakeExactMatchAlgo(const AlgoCfg& config);
}
