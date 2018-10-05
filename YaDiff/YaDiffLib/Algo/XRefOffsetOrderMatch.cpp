#include "XRefOffsetMatch.hpp"

#include "Algo.hpp"
#include "Yatools.hpp"
#include "Helpers.h"
#include "HVersion.hpp"
#include "YaTypes.hpp"

#include <Signature.hpp>
#include <VersionRelation.hpp>

#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <thread>

#if 1
#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("xref", (FMT), ## __VA_ARGS__)
#else
#define LOG(LEVEL, FMT, ...) do {} while(0)
#endif

namespace yadiff
{
#define ASSOCIATE_DATA 1

class XRefOffsetOrderMatchAlgo: public IDiffAlgo
{
public:

    XRefOffsetOrderMatchAlgo(const AlgoCfg& config);

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

std::shared_ptr<IDiffAlgo> MakeXRefOffsetOrderMatchAlgo(const AlgoCfg& config)
{
    return std::make_shared<XRefOffsetOrderMatchAlgo>(config);
}

const char* XRefOffsetOrderMatchAlgo::GetName() const{
    return "XRefOffsetOrderMatchAlgo";
}

XRefOffsetOrderMatchAlgo::XRefOffsetOrderMatchAlgo(const AlgoCfg& config)
    : pDb1_(nullptr)
    , pDb2_(nullptr)
{
    UNUSED(config);
}

bool XRefOffsetOrderMatchAlgo::Prepare(const IModel& db1, const IModel& db2)
{
    pDb1_ = &db1;
    pDb2_ = &db2;

    return true;
}

bool XRefOffsetOrderMatchAlgo::Analyse(const OnAddRelationFn& output, const RelationWalkerfn& input)
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


    // iterate over all previously computed relation
    input([&](const Relation& relation)
    {
        if(relation.flags_ & AF_XREF_OFFSET_ORDER_DONE)
            return true;

    	switch(relation.type_)
    	{
//    	case RELATION_TYPE_DIFF:
    	case RELATION_TYPE_STRONG_MATCH:
    		break;
    	default:
    		return true;
    	}
        // set relation as treated
        Relation tmp = relation;
        tmp.flags_ |= AF_XREF_OFFSET_ORDER_DONE;
        output(tmp, true);
        // use exact match only
        if(!relation.version1_.has_xrefs())
            return true;
        // for each xref from obj1
        std::map<YaToolObjectType_e,std::vector<HVersion>> all_xrefs_v1;
        std::map<YaToolObjectType_e,std::vector<HVersion>> all_xrefs_v2;
        relation.version1_.walk_xrefs_from([&](offset_t /*local_offset*/, operand_t /*local_operand*/, const HVersion& local_version)
        {
        	all_xrefs_v1[local_version.type()].push_back(local_version);
        	return WALK_CONTINUE;
        });
		relation.version2_.walk_xrefs_from([&](offset_t /*remote_offset*/, operand_t /*remote_operand*/, const HVersion& remote_version)
		{
        	all_xrefs_v2[remote_version.type()].push_back(remote_version);
			return WALK_CONTINUE;
        });

		for(const auto& xref_by_types : all_xrefs_v1)
		{
			auto object_type = xref_by_types.first;
			const auto& xrefs_v1 = xref_by_types.second;
        	switch(object_type)
        	{
        	case OBJECT_TYPE_FUNCTION:
        	case OBJECT_TYPE_DATA:
        	case OBJECT_TYPE_CODE:
        		break;
        	default:
        		continue;
        	}
        	const auto& xrefs_v2 = all_xrefs_v2[object_type];

    		if(xrefs_v1.size() != xrefs_v2.size())
    			continue;

    		for(unsigned int i=0; i<xrefs_v1.size(); i++)
    		{
    			HVersion version1_ = xrefs_v1[i];
    			HVersion version2_ = xrefs_v2[i];

    		    Relation new_relation;
    		    new_relation.version1_ = version1_;
    		    new_relation.version2_ = version2_;
    		    new_relation.type_ = RELATION_TYPE_WEAK_MATCH;
    		    new_relation.flags_ = 0;
    		    new_relation.mask_algos_flags = true;
                LOG(INFO, "CXORDERMA: from 0x%016llx <-> 0x%016llx  (%s <-> %s)\n", relation.version1_.address(), relation.version2_.address(), relation.version1_.username().value, relation.version2_.username().value);
                LOG(INFO, "CXORDERMA: --> associate 0x%016llx <-> 0x%016llx  (%s <-> %s)\n", new_relation.version1_.address(), new_relation.version2_.address(), new_relation.version1_.username().value, new_relation.version2_.username().value);
    		    output(new_relation, false);
    		}
		}

        return true;
    });
    return true;
}

}
