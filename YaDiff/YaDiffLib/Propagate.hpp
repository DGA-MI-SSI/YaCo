#pragma once

#include <YaTypes.hpp>
#include <Merger.hpp>
#include <Algo/Algo.hpp>

class Configuration;

namespace yadiff
{
    struct Propagate
    {
        Propagate(const Configuration& config, const Merger::on_conflict_fn& on_conflict);

        void PropagateToDB(IModelVisitor& visitor_, const IModel& ref_model, const IModel& new_model, yadiff::RelationWalkerfn walk);

    private:
        ObjectVersionMergeStrategy_e    estrategy_;
        const Configuration&            config_;
        const Merger::on_conflict_fn&   on_conflict_;
    };

} // end namespace
