#include "XRefOffsetMatch.hpp"

#include "Algo.hpp"
#include "Yatools.hpp"
#include "Helpers.h"

#include <Signature.hpp>
#include <VersionRelation.hpp>

#include <vector>
#include <memory>
#include <chrono>
#include <thread>

#if 0
#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("xref", (FMT), ## __VA_ARGS__)
#else
#define LOG(LEVEL, FMT, ...) do {} while(0)
#endif

namespace yadiff
{
#define ASSOCIATE_DATA 1

class XRefOffsetMatchAlgo: public IDiffAlgo
{
public:

    XRefOffsetMatchAlgo(const AlgoCfg& config);

    /*
     * prepares input signature databases
     */
    bool Prepare(const IModel& db1, const IModel& db2) override;

    /*
     * uses previously registered signature databases and input version relations
     * to compute a new version relation vector
     */
    bool Analyse(const OnAddRelationFn& output, const RelationWalkerfn& input) override;
    const char* GetName() const override;

private:
    const IModel* pDb1_;
    const IModel* pDb2_;
};

std::shared_ptr<IDiffAlgo> MakeXRefOffsetMatchAlgo(const AlgoCfg& config)
{
    return std::make_shared<XRefOffsetMatchAlgo>(config);
}

const char* XRefOffsetMatchAlgo::GetName() const{
    return "XRefOffsetMatchAlgo";
}

XRefOffsetMatchAlgo::XRefOffsetMatchAlgo(const AlgoCfg& config)
    : pDb1_(nullptr)
    , pDb2_(nullptr)
{
    UNUSED(config);
}

bool XRefOffsetMatchAlgo::Prepare(const IModel& db1, const IModel& db2)
{
    pDb1_ = &db1;
    pDb2_ = &db2;

    return true;
}

bool XRefOffsetMatchAlgo::Analyse(const OnAddRelationFn& output, const RelationWalkerfn& input)
{
    /**
     * *If offsets are available:
     * Take XRefs from the local object
     * for each XRef, use the offset and resolve the associated object
     * for the object to associate, we take the version that matches the system of the parent (Xrefing) object
     * If the signature of the resolved object does not match :
     *   If already associated, this means that the local function changed its call to another function : set the caller as RELATION_TYPE_DIFF_CALL
     *   otherwise, use RELATION_TYPE_DIFF (see later)
     * for the resolved object, if the signature matches
     *   Use RELATION_TYPE_EXACT_MATCH (overwrite any other relation already set)
     *   If it has XRefs, add it to ObjectsToVisit
     *
     * TODO : if the signature of the called function do not match, set the association as a possibility, with a score of 1
     * Anytime this potential association is found, increase the score
     * If an exact match is found, use it as the real association
     * At the end, if there is only one possibility, or if the score of one possibility is really higher than the other's, use it
     * The first part (counting) is implemented. The end (choose between the possibilities) is not.
     *
     * *If offsets are not available:
     * see what YaDiff did...
     */
    if(pDb1_ == nullptr)
        return false;
    if(pDb2_ == nullptr)
        return false;

    Relation new_relation;
    new_relation.type_ = RELATION_TYPE_EXACT_MATCH;
    new_relation.mask_algos_flags = true;

    // iterate over all previously computed relation
    input([&](const Relation& relation)
    {
        if(relation.flags_ & AF_XREF_OFFSET_DONE)
            return true;
        if(relation.type_ != RELATION_TYPE_EXACT_MATCH)
            return true;
        // set relation as treated
        Relation tmp = relation;
        tmp.flags_ |= AF_XREF_OFFSET_DONE;
        output(tmp, true);
        // use exact match only
        if(!relation.version1_.has_xrefs())
            return true;
        // for each xref from obj1
        relation.version1_.walk_xrefs_from([&](offset_t local_offset, operand_t local_operand, const HVersion& local_version)
        {
            relation.version2_.walk_xrefs_from([&](offset_t remote_offset, operand_t remote_operand, const HVersion& remote_version)
            {
                if(local_offset != remote_offset)
                    return WALK_CONTINUE;
                if(local_operand != remote_operand)
                    return WALK_CONTINUE;
                if(local_version.type() != remote_version.type())
                    return WALK_STOP;

                if (local_version.match(remote_version))
                {
                    LOG(INFO, "XROMA: from %llx(%s) <-> %llx(%s)\n", relation.version1_.address(), relation.version1_.username().value, relation.version2_.address(), relation.version2_.username().value);
                    LOG(INFO, "XROMA: --> associate %llx(%s) <-> %llx(%s)", localVer.address(), localVer.username().value, remoteVer.address(), remoteVer.username().value);
                    new_relation.version1_ = local_version;
                    new_relation.version2_ = remote_version;
                    output(new_relation, false);
                }
                else
                {
#if ASSOCIATE_DATA
                    if(!local_version.has_signatures() && !remote_version.has_signatures())
                    {
                        LOG(INFO, "XROMA DATA: from %llx(%s) <-> %llx(%s)\n", relation.version1_.address(), relation.version1_.username().value, relation.version2_.address(), relation.version2_.username().value);
                        LOG(INFO, "XROMA DATA: --> associate %llx(%s) <-> %llx(%s)", localVer.address(), localVer.username().value, remoteVer.address(), remoteVer.username().value);
                        new_relation.version1_ = local_version;
                        new_relation.version2_ = remote_version;
                        output(new_relation, false);
                    }
#endif
                }
                return WALK_CONTINUE;
            });
            return WALK_CONTINUE;
        });
        return true;
    });
    return true;
}

}
