#pragma once

#include <vector>

namespace std { template<typename T> class shared_ptr; }
class Configuration;
struct IModel;
struct Relation;

namespace yadiff
{

class IMatching
{
public:
    virtual ~IMatching() {}

    virtual bool Prepare(const IModel& db1, const IModel& db2) = 0;

    virtual bool Analyse(std::vector<Relation>& output) = 0;

};


std::shared_ptr<IMatching> MakeMatching(const Configuration& config);
} //end namespace
