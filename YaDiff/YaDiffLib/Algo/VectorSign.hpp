#pragma once

namespace std { template<typename T> class shared_ptr; }

namespace yadiff { struct IDiffAlgo; }
namespace yadiff { struct AlgoCfg; }

namespace yadiff
{
    std::shared_ptr<IDiffAlgo> MakeVectorSignAlgo(const AlgoCfg& config);
}
