#include "YaDiff.hpp"

#include "Helpers.h"
#include "Yatools.hpp"

#include <Matching.hpp>
#include <Configuration.hpp>
#include "Propagate.hpp"
#include "FlatBufferModel.hpp"
#include "FlatBufferVisitor.hpp"
#include "VersionRelation.hpp"
#include "HVersion.hpp"

#include <vector>
#include <map>
#include <memory>
#ifdef _MSC_VER
#   include <filesystem>
#else
#   include <experimental/filesystem>
#endif

#include <sstream>
#include <cstdlib>
#include <cmath>
#include <queue>
#include <fstream>
#include <memory>
#include <iostream>

#include <numeric>


namespace yadiff {
static const std::string SECTION_NAME = "Yadiff";

// Ctor<void>
YaDiff::YaDiff(const Configuration& config)
    : config_(config) { }


// Dump yafb (Yet Another Flat Buffer)
bool WriteFBFile(const std::string& dest, const IFlatBufferVisitor& exporter) {
    // Open file && Check
    FILE* houtput = fopen(dest.c_str(), "wb");
    if(!houtput) {
        LOG(ERROR, "could not open %s\n", dest.c_str());
        return false;
    }

    // Write buffer -> file
    const auto buffer = exporter.GetBuffer();
    const auto size = fwrite(buffer.value, buffer.size, 1, houtput);

    // Close && Ret
    const auto err = fclose(houtput);
    return !err && size == 1;
}


// Merge in RAM
bool YaDiff::MergeDatabases(const IModel& db1, const IModel& db2, std::vector<Relation>& output) {
    // 1. Create algo (i.e. Get weapon)
    auto matcher = MakeMatching(config_);

    // 2. Prepare algo (i.e. Load weapon)
    matcher->Prepare(db1, db2);

    // 3. Analyse with algo (i.e. Shoot weapon)
    matcher->Analyse(output);

    // Return (i.e. Show off with weapon)
    return true;
}



// Helper to merge yadb
namespace {
void MergeToCache(YaDiff& differ, const Configuration& config, const std::string& db1, const std::string& db2, const std::vector<std::string>& caches)
{
    // Generate models
    LOG(INFO, "Loading databases\n");
    const auto ref_model = MakeFlatBufferModel(db1);
    const auto new_model = MakeFlatBufferModel(db2);

    // Merge models
    LOG(INFO, "Merging databases\n");
    std::vector<Relation> relations;
    differ.MergeDatabases(*ref_model, *new_model, relations);
    
    std::map<RelationType_e,int> counter;
    for(const auto& rel : relations)
    {
        if(rel.type_ != RELATION_TYPE_NONE
            &&  ( (rel.type_ != RELATION_TYPE_ALTERNATIVE_FROM_N
                    && rel.version1_.type() == OBJECT_TYPE_FUNCTION)
                || (rel.type_ != RELATION_TYPE_ALTERNATIVE_TO_N
                    && rel.version2_.type() == OBJECT_TYPE_FUNCTION)
                )
            )
        {
            counter[rel.type_] += 1;
        }
    }
    LOG(INFO, "Found exact/strong/diff/weak/untrust/alt/alt_slvd/alt_to_n/alt_from_n function relations : %d/%d/%d/%d/%d/%d/%d/%d/%d = %d, total = %d, correct_total = %d\n",
            counter[RELATION_TYPE_EXACT_MATCH],
            counter[RELATION_TYPE_STRONG_MATCH],
            counter[RELATION_TYPE_DIFF],
            counter[RELATION_TYPE_WEAK_MATCH],
            counter[RELATION_TYPE_UNTRUSTABLE],
            counter[RELATION_TYPE_ALTERNATIVE],
            counter[RELATION_TYPE_ALTERNATIVE_SOLVED],
            counter[RELATION_TYPE_ALTERNATIVE_TO_N],
            counter[RELATION_TYPE_ALTERNATIVE_FROM_N],
            counter[RELATION_TYPE_DIFF] + counter[RELATION_TYPE_STRONG_MATCH] + counter[RELATION_TYPE_EXACT_MATCH] + counter[RELATION_TYPE_UNTRUSTABLE],
            std::accumulate(counter.begin(), counter.end(), 0, [](int val, const auto& p) { return val+p.second;}),
            counter[RELATION_TYPE_DIFF] + counter[RELATION_TYPE_STRONG_MATCH] + counter[RELATION_TYPE_EXACT_MATCH]
            );

    Propagate propagater(config, nullptr);
    for(const auto& cache : caches)
    {
        LOG(INFO, "Propagating cache %s\n", cache.data());
        auto exporter = MakeFlatBufferVisitor();
        propagater.PropagateToDB(*exporter, *ref_model, *new_model, [&](const yadiff::OnRelationFn& on_relation)
        {
            for(const auto& relation : relations) {
                on_relation(relation);
            }
        });
        
        LOG(INFO, "Writing cache %s\n", cache.data());
        WriteFBFile(cache, *exporter);
    }
    if (!config.GetOption("Propagate", "ExportMatchesJSON").empty())
    {
        const auto matchfile = config.GetOption("Propagate", "ExportMatchesJSON");
        LOG(WARNING, "Exporting to : %s\n", matchfile.c_str());
        std::ofstream output;
        output.open(matchfile);
        output << "[" << std::endl;
        bool first = true;
        for(const auto& relation : relations)
        {
//            printf("rel: 0x%016lX to 0x%016lX\n",
//                                relation.version1_.address(),
//                                relation.version2_.address());
            bool ignore_relation = false;
            switch (relation.type_)
            {
            case RELATION_TYPE_DIFF:
            case RELATION_TYPE_EXACT_MATCH:
            case RELATION_TYPE_STRONG_MATCH:
                break;
            default:
                ignore_relation = true;
                break;
            }
            if(ignore_relation) { continue; }

            if(first) {
                first = false;
            } else {
                output << "\t," << std::endl;
            }
            output << "\t{" << std::endl;
            output << "\t\t\"src\": " << relation.version1_.address() << "," << std::endl;
            output << "\t\t\"dst\": " << relation.version2_.address() << "," << std::endl;
            output << "\t\t\"comment\": \"\"" << std::endl;
            output << "\t}" << std::endl;
        }
        output << "]" << std::endl;

    }

    if (!config.GetOption("Propagate", "ExportMatchesJSONALL").empty())
    {
        const auto matchfile = config.GetOption("Propagate", "ExportMatchesJSONALL");
        LOG(WARNING, "Exporting to : %s\n", matchfile.c_str());
        std::ofstream output;
        output.open(matchfile);
        output << "[" << std::endl;
        bool first = true;
        for(const auto& relation : relations)
        {
            bool ignore_relation = false;
            switch (relation.type_)
            {
            case RELATION_TYPE_DIFF:
            case RELATION_TYPE_EXACT_MATCH:
            case RELATION_TYPE_STRONG_MATCH:
            case RELATION_TYPE_UNTRUSTABLE:
                break;
            default:
                ignore_relation = true;
                break;
            }
            if(ignore_relation) continue;

            if(first)
                first = false;
            else
                output << "\t," << std::endl;
            output << "\t{" << std::endl;
            if(relation.type_ == RELATION_TYPE_UNTRUSTABLE)
            {
                output << "\t\t\"src\": ";
                output << "[";
                output << "]" << std::endl;
                output << "\t\t\"dst\": ";
                output << "[";
                output << "]" << std::endl;
            }
            else
            {
                output << "\t\t\"src\": " << relation.version1_.address() << "," << std::endl;
                output << "\t\t\"dst\": " << relation.version2_.address() << "," << std::endl;
            }
            output << "\t\t\"comment\": \"\"" << std::endl;
            output << "\t}" << std::endl;
        }
        output << "]" << std::endl;

    }

    if (!config.GetOption("Propagate", "ExportMatchesTxt").empty())
    //if(filesystem::exists(filesystem::path(config.IsOptionTrue(""))))
    {
        // Open matchifle
        const auto matchfile = config.GetOption("Propagate", "ExportMatchesTxt");
        LOG(WARNING, "Exporting to : %s\n", matchfile.c_str());
        std::ofstream output;
        output.open(matchfile);

        for(const auto& relation : relations)
        {
            // Check relation type
            if(relation.type_ == RELATION_TYPE_NONE
                || relation.type_ == RELATION_TYPE_ALTERNATIVE_FROM_N
                || relation.type_ == RELATION_TYPE_ALTERNATIVE_TO_N) {
                continue; }

            // Log
            char buff[1024];
            snprintf(buff, 1023, "rel: 0x%016zu to 0x%016zu, type=%d, objtype=%d, names=[%32s,%32s]",
                    relation.version1_.address(),
                    relation.version2_.address(),
                    relation.type_,
                    relation.version1_.type(),
                    relation.version1_.username().value,
                    relation.version2_.username().value
                    );
            // To match_file
            output << buff << std::endl;
        }
        output << "\t]" << std::endl;
        output << "}" << std::endl;

    }
    LOG(INFO, "Merge done\n");
}
} // End ::


// Merge yadb file : 2 exported function
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

} // End yadiff::
