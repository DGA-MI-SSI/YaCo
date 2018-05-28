#pragma once

#include <string>
#include <vector>

struct Relation;

class Configuration;
class ResolveFileConflictCallback;
struct IModel;

namespace yadiff
{

class YaDiff
{
    public:
    YaDiff(const Configuration& config);

    bool MergeCacheFiles(const std::string& ref_db, const std::string& new_db, const std::string& new_cache, const std::string& ref_cache);
    bool MergeCacheFiles(const std::string& ref_db, const std::string& new_db, const std::string& new_cache_db);
    int MergeRepos(const std::string& url1, const std::string& url2, ResolveFileConflictCallback&  ResolveFileConflict);
    bool MergeDatabases(const IModel& db1, const IModel& db2, std::vector<Relation>& output);
    private:
    const Configuration& config_;
};
} // end namespace
