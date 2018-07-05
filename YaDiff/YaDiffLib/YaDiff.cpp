#include "YaDiff.hpp"

#include "Helpers.h"
#include "Yatools.hpp"

#include <Matching.hpp>
#include <Configuration.hpp>
#include "Propagate.hpp"
#include "FlatBufferModel.hpp"
#include "FlatBufferVisitor.hpp"
#include "VersionRelation.hpp"


#include <vector>
#include <memory>

#if 0
#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("yadiff", (FMT), ## __VA_ARGS__)
#else
#define LOG(...) do {} while(0)
#endif

namespace yadiff
{
static const std::string SECTION_NAME = "Yadiff";

YaDiff::YaDiff(const Configuration& config)
    : config_(config)
{

}

bool WriteFBFile(const std::string& dest, const IFlatBufferVisitor& exporter)
{
    auto houtput = fopen(dest.c_str(), "wb");
    if(!houtput)
    {
        LOG(ERROR, "could not open %s\n", dest.c_str());
        return false;
    }
    const auto buffer = exporter.GetBuffer();
    const auto size = fwrite(buffer.value, buffer.size, 1, houtput);
    const auto err = fclose(houtput);
    return !err && size == 1;
}

bool YaDiff::MergeDatabases(const IModel& db1, const IModel& db2, std::vector<Relation>& output)
{
    auto matcher = MakeMatching(config_);
    matcher->Prepare(db1, db2);

    matcher->Analyse(output);
    return true;
}

namespace
{
void MergeToCache(YaDiff& differ, const Configuration& config, const std::string& db1, const std::string& db2, const std::vector<std::string>& caches)
{
    LOG(INFO, "Loading databases\n");
    const auto ref_model = MakeFlatBufferModel(db1);
    const auto new_model = MakeFlatBufferModel(db2);

    LOG(INFO, "Merging databases\n");
    std::vector<Relation> relations;
    differ.MergeDatabases(*ref_model, *new_model, relations);
    
    Propagate propagater(config, nullptr);
    for(const auto& cache : caches)
    {
        LOG(INFO, "Propagating cache %s\n", cache.data());
        auto exporter = MakeFlatBufferVisitor();
        propagater.PropagateToDB(*exporter, *ref_model, *new_model, [&](const yadiff::OnRelationFn& on_relation)
        {
            for(const auto& relation : relations)
                on_relation(relation);
        });
        
        LOG(INFO, "Writing cache %s\n", cache.data());
        WriteFBFile(cache, *exporter);
    }
    LOG(INFO, "Merge done\n");
}
}

bool YaDiff::MergeCacheFiles(const std::string& ref_db, const std::string& new_db, const std::string& new_cache, const std::string& ref_cache)
{
    MergeToCache(*this, config_, ref_db, new_db, {ref_cache, new_cache});
    return true;
}

bool YaDiff::MergeCacheFiles(const std::string& ref_db, const std::string& new_db, const std::string& cache)
{
    MergeToCache(*this, config_, ref_db, new_db, {cache});
    return true;
}

} //end namespace
