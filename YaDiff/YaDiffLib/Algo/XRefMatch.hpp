#pragma once


namespace std { template<typename T> class shared_ptr; }


namespace yadiff {
    struct IDiffAlgo;
    struct AlgoCfg;
    std::shared_ptr<IDiffAlgo> MakeXRefMatchAlgo(const AlgoCfg& config);
} // End yadiff::
