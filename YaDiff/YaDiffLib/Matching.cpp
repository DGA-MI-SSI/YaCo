#include "Matching.hpp"


#include <Algo/Algo.hpp>
#include "Configuration.hpp"
#include "VersionRelation.hpp"
#include "Yatools.hpp"
#include "Helpers.h"

#include <memory>
#include <string.h>
#include <vector>
#include <unordered_map>
#include <libxml/xmlreader.h>

#if 1
#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("yadiff", (FMT), ## __VA_ARGS__)
#else
#define LOG(...) do {} while(0)
#endif

namespace yadiff
{
    static const std::string SECTION_NAME = "Matching";

#define MAKE_RELATION_KEY(r) (((uint64_t)r.version1_.id) << 32) + r.version2_.id
#define MERGE_RELATION_CONFIDENCE 0
#define MERGE_RELATION_TYPE 0

class YaDiffRelationContainer
{
public:
//    std::unordered_map<uint64_t, uint32_t> relation_map_;
    std::vector<Relation> relations_;
    typedef int32_t relation_idx_t;
#define RELATION_IDX_NONE ((relation_idx_t)-1)
    std::map<YaToolObjectId, std::map<YaToolObjectId, relation_idx_t>> relation_map_db1_to_db2;
    std::map<YaToolObjectId, std::map<YaToolObjectId, relation_idx_t>> relation_map_db2_to_db1;
    std::set<YaToolObjectId> relation_resolved_db1;
    std::set<YaToolObjectId> relation_resolved_db2;
    int new_relation_counter_;

    YaDiffRelationContainer(){new_relation_counter_ = 0;}

    void MergeRelation(Relation& dest, const Relation& src)
    {
    	auto old_flags = dest.flags_;
    	auto old_type = dest.type_;
        if(dest.type_ == RELATION_TYPE_DIFF && src.type_ == RELATION_TYPE_STRONG_MATCH)
        {
        	dest.type_ = RELATION_TYPE_STRONG_MATCH;
        }
        if(dest.type_ == RELATION_TYPE_WEAK_MATCH && (src.type_ == RELATION_TYPE_DIFF || src.type_ == RELATION_TYPE_STRONG_MATCH))
        {
        	dest.type_ = src.type_;
        }

    	//Apply mask on flags only in the case where there has been an improvement on relation type
        bool mask_flags = true;
        if(dest.type_ == RELATION_TYPE_STRONG_MATCH && (src.type_ == RELATION_TYPE_WEAK_MATCH || src.type_ == RELATION_TYPE_DIFF))
        {
        	mask_flags = false;
        }
        if(dest.type_ == RELATION_TYPE_DIFF && (src.type_ == RELATION_TYPE_WEAK_MATCH))
        {
        	mask_flags = false;
        }

        if(mask_flags)
        {
        	if(src.mask_algos_flags)
        	{
//        		LOG(INFO, "Masking flags");
        		dest.flags_ &= ~(AF_ALL_ALGOS_DONE);
        	}
        }
		dest.flags_ |= src.flags_;

		auto v1_addr = (dest.version1_.model_ != nullptr)?dest.version1_.address() : 0;
		auto v2_addr = (dest.version2_.model_ != nullptr)?dest.version2_.address() : 0;
		auto v1_id   = (dest.version1_.model_ != nullptr)?dest.version1_.id()      : 0;
		auto v2_id   = (dest.version2_.model_ != nullptr)?dest.version2_.id()      : 0;
    	LOG(INFO, "Merging relations 0x%016lX <-> 0x%016lX id[0x%016lX<->0x%016lX] old_type=%d, new_type=%d, src_type=%d, old_flags=0x%02X, new_flags=0x%02X, src_flags=0x%02X\n"
    			,v1_addr
    			,v2_addr
    			,v1_id
    			,v2_id
    			,old_type
    			,dest.type_
    			,src.type_
    			,old_flags
    			,dest.flags_
    			,src.flags_
				);
#if MERGE_RELATION_CONFIDENCE
        dest.confidence_ = (dest.confidence_ + src.confidence_) % RELATION_CONFIDENCE_MAX;
#endif
#if MERGE_RELATION_TYPE
        dest.type_ = src.type_;
#endif
    }

    void MaskAlgoFlags(Relation& rel)
    {
    	rel.flags_ &= ~(AF_ALL_ALGOS_DONE);
    }

    void MergeRelationFlags(Relation& dest, const Relation& src)
    {
		auto old_flags = dest.flags_;
		auto old_type = dest.type_;
		bool newer_relation_is_better = false;
		if(dest.type_ == RELATION_TYPE_NONE)
		{
			if(src.type_ != RELATION_TYPE_NONE)
			{
				newer_relation_is_better = true;
			}
		}
		if(dest.type_ == RELATION_TYPE_WEAK_MATCH)
		{
			if(
					src.type_ == RELATION_TYPE_ALTERNATIVE_SOLVED ||
					src.type_ == RELATION_TYPE_DIFF ||
					src.type_ == RELATION_TYPE_STRONG_MATCH ||
					src.type_ == RELATION_TYPE_EXACT_MATCH)
			{
				newer_relation_is_better = true;
			}
		}
		else if(dest.type_ == RELATION_TYPE_ALTERNATIVE_SOLVED)
		{
			if(
					src.type_ == RELATION_TYPE_DIFF ||
					src.type_ == RELATION_TYPE_STRONG_MATCH ||
					src.type_ == RELATION_TYPE_EXACT_MATCH)
			{
				newer_relation_is_better = true;
			}
		}
		else if(dest.type_ == RELATION_TYPE_DIFF)
		{
			if(src.type_ == RELATION_TYPE_STRONG_MATCH || src.type_ == RELATION_TYPE_EXACT_MATCH || src.type_ == RELATION_TYPE_ALTERNATIVE_SOLVED)
			{
				newer_relation_is_better = true;
			}
		}
		else if(dest.type_ == RELATION_TYPE_STRONG_MATCH && src.type_ == RELATION_TYPE_EXACT_MATCH)
		{
			newer_relation_is_better = true;
		}

		if(newer_relation_is_better)
		{
			MaskAlgoFlags(dest);
			dest.type_ = src.type_;
		}
		dest.flags_ |= src.flags_;

		auto v1_addr = (dest.version1_.model_ != nullptr)?dest.version1_.address() : 0;
		auto v2_addr = (dest.version2_.model_ != nullptr)?dest.version2_.address() : 0;
		auto v1_id   = (dest.version1_.model_ != nullptr)?dest.version1_.id()      : 0;
		auto v2_id   = (dest.version2_.model_ != nullptr)?dest.version2_.id()      : 0;
		LOG(INFO, "Merging relations flags 0x%016lX <-> 0x%016lX id[0x%016lX<->0x%016lX] old_type=%d, new_type=%d, src_type=%d, old_flags=0x%02X, new_flags=0x%02X, src_flags=0x%02X\n"
				,v1_addr
				,v2_addr
				,v1_id
				,v2_id
				,old_type
				,dest.type_
				,src.type_
				,old_flags
				,dest.flags_
				,src.flags_
				);

#if MERGE_RELATION_CONFIDENCE
		dest.confidence_ = (dest.confidence_ + src.confidence_) % RELATION_CONFIDENCE_MAX;
#endif
#if MERGE_RELATION_TYPE
		dest.type_ = src.type_;
#endif
		}

    void DestroyRelation(Relation& relation, RelationType_e with_type=RELATION_TYPE_NONE)
    {
    	if(relation.type_ != with_type)
    	{
    		LOG(INFO, "DestroyRelation with 0x%016lX <--> 0x%016lX id[0x%016lX<->0x%016lX], type=%d\n",
    				relation.version1_.address(),
					relation.version2_.address(),
    				relation.version1_.id(),
					relation.version2_.id(),
					relation.type_);
    		relation.type_ = with_type;
    	}
    }

    void DestroyOtherRelations(HVersion version1, HVersion version2, RelationType_e with_type=RELATION_TYPE_NONE)
    {
		const auto& it_v1 = relation_map_db1_to_db2.find(version1.id());
		if(it_v1 != relation_map_db1_to_db2.end())
		{
			for(auto& it2 : it_v1->second)
			{
				YaToolObjectId v2_id = it2.first;
				relation_idx_t rel_idx = it2.second;
				if(version2.id() == v2_id)
					continue;
				DestroyRelation(relations_[rel_idx], with_type);
			}
		}

		const auto& it_v2 = relation_map_db2_to_db1.find(version2.id());
		if(it_v2 != relation_map_db2_to_db1.end())
		{
			for(auto& it2 : it_v2->second)
			{
				YaToolObjectId v1_id = it2.first;
				relation_idx_t rel_idx = it2.second;
				if(version1.id() == v1_id)
					continue;
				DestroyRelation(relations_[rel_idx], with_type);
			}
		}
    }

    relation_idx_t AddRelation(Relation& relation)
    {
    	LOG(INFO, "AddRelation with 0x%016lX <--> 0x%016lX id[0x%016lX<->0x%016lX], type=%d, objtype=%d/%d\n",
    			relation.version1_.address(),
				relation.version2_.address(),
    			relation.version1_.id(),
				relation.version2_.id(),
				relation.type_,
				relation.version1_.type(),
				relation.version2_.type()
				);
        const auto index = static_cast<relation_idx_t>(relations_.size());
        relations_.push_back(relation);
        ++new_relation_counter_;
        relation_map_db1_to_db2[relation.version1_.id()][relation.version2_.id()] = index;
        relation_map_db2_to_db1[relation.version2_.id()][relation.version1_.id()] = index;
        return index;
    }

    relation_idx_t GetRelationIdx(const HVersion& version1, const HVersion& version2)
    {
		const auto& it = relation_map_db1_to_db2.find(version1.id());
		if(it != relation_map_db1_to_db2.end())
		{
			const auto& it2 = it->second.find(version2.id());
    		if(it2 != it->second.end())
    		{
    			return it2->second;
    		}
		}
		return RELATION_IDX_NONE;
    }

    std::set<relation_idx_t> GetAllRelationsDB1(HVersion version, RelationType_e type)
	{
    	std::set<relation_idx_t> return_value;
		const auto& it_v1 = relation_map_db1_to_db2.find(version.id());
		if(it_v1 != relation_map_db1_to_db2.end())
		{
			for(auto& it2 : it_v1->second)
			{
				relation_idx_t rel_idx = it2.second;
				if(relations_[rel_idx].type_ == type)
					return_value.insert(rel_idx);
			}
		}
		return return_value;
	}

    std::set<relation_idx_t> GetAllRelationsDB2(HVersion version, RelationType_e type)
	{
    	std::set<relation_idx_t> return_value;
		const auto& it_v1 = relation_map_db2_to_db1.find(version.id());
		if(it_v1 != relation_map_db2_to_db1.end())
		{
			for(auto& it2 : it_v1->second)
			{
				relation_idx_t rel_idx = it2.second;
				if(relations_[rel_idx].type_ == type)
					return_value.insert(rel_idx);
			}
		}
		return return_value;
	}

    bool InsertRelation(const Relation& pRelation, bool update_flags_only)
    {
    	if(update_flags_only)
    	{
    		relation_idx_t existing_relation_idx = GetRelationIdx(pRelation.version1_, pRelation.version2_);
			if(existing_relation_idx == RELATION_IDX_NONE)
			{
				LOG(ERROR, "Cannot update flags of non existing relation\n");
			}
			Relation& existing_relation = relations_[existing_relation_idx];
//			if(existing_relation.type_ != pRelation.type_)
//			{
//				LOG(ERROR, "trying to update flags with different type\n");
//			}
			MergeRelationFlags(existing_relation, pRelation);
			return true;
    	}

		LOG(INFO, "Updating relation with 0x%016lX <--> 0x%016lX, type=%d\n", pRelation.version1_.address(), pRelation.version2_.address(), pRelation.type_);

    	Relation relation = pRelation;

    	if(relation.type_ == RELATION_TYPE_NONE)
    	{
    		relation_idx_t existing_relation_idx = GetRelationIdx(pRelation.version1_, pRelation.version2_);
    		if(existing_relation_idx != RELATION_IDX_NONE)
    		{
    			Relation& existing_relation = relations_[existing_relation_idx];
    			DestroyRelation(existing_relation);
    		}
    	}

    	if(relation.type_ == RELATION_TYPE_REJECTED)
    	{
    		relation_idx_t existing_relation_idx = GetRelationIdx(pRelation.version1_, pRelation.version2_);
    		if(existing_relation_idx != RELATION_IDX_NONE)
    		{
    			Relation& existing_relation = relations_[existing_relation_idx];
    			DestroyRelation(existing_relation, RELATION_TYPE_REJECTED);

    			if(existing_relation.type_ == RELATION_TYPE_ALTERNATIVE_SOLVED)
    			{
    				//This was a solved alternative, but has been refused for bad scoring : destroy the other alternatives
    				DestroyOtherRelations(relation.version1_, relation.version2_, RELATION_TYPE_REJECTED);
    			}
    		}
    	}



		relation_idx_t existing_relation_idx = GetRelationIdx(pRelation.version1_, pRelation.version2_);
		bool is_new_relation = false;
//		RelationType_e existing_relation_type;
		if(existing_relation_idx == RELATION_IDX_NONE)
		{
			existing_relation_idx = AddRelation(relation);
			is_new_relation = true;
		}
		else if(relations_[existing_relation_idx].type_ == RELATION_TYPE_NONE)
		{
			is_new_relation = true;
		}
		else if(relations_[existing_relation_idx].type_ == RELATION_TYPE_REJECTED)
		{
			return false;
		}

		Relation& existing_relation = relations_[existing_relation_idx];
		//If the relation is already resolved, only merge if the update is a flag update
		if(!is_new_relation)
		{
			MergeRelationFlags(existing_relation, relation);
		}

    	if(relation.type_ == RELATION_TYPE_EXACT_MATCH)
    	{
    		//Exact matches disqualifies every other relations implying v1 or v2
    		DestroyOtherRelations(relation.version1_, relation.version2_);
    		relation_resolved_db1.insert(pRelation.version1_.id());
    		relation_resolved_db2.insert(pRelation.version2_.id());
    	}

    	if(relation.type_ == RELATION_TYPE_STRONG_MATCH)
    	{
    		//Check if we already have an exact relation : in this case, reject this one
    		std::set<relation_idx_t> other_relations_v1 = GetAllRelationsDB1(relation.version1_, RELATION_TYPE_EXACT_MATCH);
    		std::set<relation_idx_t> other_relations_v2 = GetAllRelationsDB2(relation.version2_, RELATION_TYPE_EXACT_MATCH);
    		bool discard = false;
    		if(other_relations_v1.size()>0)
    		{
    			for(relation_idx_t idx : other_relations_v1)
    			{
    				Relation& conflicting = relations_[idx];
    				if(conflicting.version2_ != relation.version2_)
    				{
    					LOG(INFO, "Discarding relation with 0x%016lX <--> 0x%016lX, type=%d\n", conflicting.version1_.address(), conflicting.version2_.address(), conflicting.type_);
    					discard = true;
    					break;
    				}
    			}
    		}
    		if(other_relations_v2.size()>0)
    		{
    			for(relation_idx_t idx : other_relations_v2)
    			{
    				Relation& conflicting = relations_[idx];
    				if(conflicting.version1_ != relation.version1_)
    				{
    					LOG(INFO, "Discarding relation with 0x%016lX <--> 0x%016lX, type=%d\n", conflicting.version1_.address(), conflicting.version2_.address(), conflicting.type_);
    					discard = true;
    					break;
    				}
    			}
    		}
    		if(discard)
    		{
    			DestroyRelation(relation);
    		}
    		else
    		{
				//Check if we have another strong relation : in this case, we should downgrade it to weak
				std::set<relation_idx_t> other_relations_v1 = GetAllRelationsDB1(relation.version1_, RELATION_TYPE_STRONG_MATCH);
				std::set<relation_idx_t> other_relations_v2 = GetAllRelationsDB2(relation.version2_, RELATION_TYPE_STRONG_MATCH);
				if(other_relations_v1.size() > 1 || other_relations_v2.size() > 1)
				{
					std::set<relation_idx_t> all_others;
					all_others.insert(other_relations_v1.begin(), other_relations_v1.end());
					all_others.insert(other_relations_v2.begin(), other_relations_v2.end());
					for(relation_idx_t conflicting_idx : all_others)
					{
						Relation& conclicting = relations_[conflicting_idx];
						LOG(INFO, "Downgrading relation with 0x%016lX <--> 0x%016lX, type=%d\n", conclicting.version1_.address(), conclicting.version2_.address(), conclicting.type_);
						MaskAlgoFlags(conclicting);
						conclicting.type_ = RELATION_TYPE_WEAK_MATCH;
					}
				}
				else
				{
					LOG(INFO, "marking as resolved 0x%016lX <--> 0x%016lX\n", pRelation.version1_.address(), pRelation.version2_.address());
					//Strong match disqualifies every other relations implying v1 or v2
					DestroyOtherRelations(relation.version1_, relation.version2_);
					relation_resolved_db1.insert(pRelation.version1_.id());
					relation_resolved_db2.insert(pRelation.version2_.id());
				}
    		}
    	}


    	return is_new_relation;
    	/*
    	if(relation.type_ == RELATION_TYPE_ALTERNATIVE_TO_N)
    	{
//    		LOG(INFO, "Adding relation ALT_TO_N with 0x%016lX\n", relation.version1_.address());
            auto it = all_relations_db1.find(relation.version1_.idx_);
            if(it != all_relations_db1.end())
            {
            	Relation& existing_relation = relations_[it->second];
            	if(existing_relation.type_ == RELATION_TYPE_ALTERNATIVE_TO_N)
            	{
            		//Merge the alternatives : maybe we should intersect ?
            		existing_relation.alternate_version_2.insert(relation.alternate_version_2.begin(), relation.alternate_version_2.end());
            		MergeRelation(existing_relation, relation);
            		return true;
            	}
            	else
            	{
            		return true;
            	}
            }
    	}
    	else if (relation.type_ == RELATION_TYPE_ALTERNATIVE_FROM_N)
    	{
//    		LOG(INFO, "Adding relation ALT_FR_N with 0x%016lX\n", relation.version2_.address());
            auto it = all_relations_db2.find(relation.version2_.idx_);
            if(it != all_relations_db2.end())
            {
            	Relation& existing_relation = relations_[it->second];
            	if(existing_relation.type_ == RELATION_TYPE_ALTERNATIVE_FROM_N)
            	{
            		//Merge the alternatives : maybe we should intersect ?
            		existing_relation.alternate_version_1.insert(relation.alternate_version_1.begin(), relation.alternate_version_1.end());
            		MergeRelation(existing_relation, relation);
            		return true;
            	}
            	else
            	{
            		return true;
            	}
            }
    	}
    	else
    	{
//    		LOG(INFO, "Adding relation with 0x%016lX <--> 0x%016lX\n", relation.version1_.address(), relation.version2_.address());
    		std::vector<unsigned int> relations_updated;

			auto it = all_relations_db1.find(relation.version1_.idx_);
			if(it != all_relations_db1.end())
			{
				auto relation_index = it->second;
				Relation& existing_relation = relations_[relation_index];
				if(existing_relation.type_ == RELATION_TYPE_ALTERNATIVE_TO_N)
				{
//					LOG(INFO, "ALT_TO_N Relation Solved at %d\n", relation_index);
						LOG(INFO, "ALT_TO_N Relation Solved at %d\n", relation_index);
						//replace with the new relation
						existing_relation.version2_ = relation.version2_;
						existing_relation.alternate_version_2.clear();
						existing_relation.alternate_version_2.insert(existing_relation.version2_);
						MergeRelation(existing_relation, relation);
						relations_updated.push_back(relation_index);
				}
				else
				{
					if(existing_relation.version2_ != relation.version2_)
					{
						if(existing_relation.alternate_version_1.size() > 1)
							existing_relation.type_ = RELATION_TYPE_UNTRUSTABLE;
						else
							existing_relation.type_ = RELATION_TYPE_ALTERNATIVE_TO_N;
						existing_relation.alternate_version_2.insert(relation.version2_);
						relation.alternate_version_2.insert(existing_relation.version2_);

						return true;
					}
					else
					{
						MergeRelation(existing_relation, relation);
						relations_updated.push_back(relation_index);
					}
				}
            }

			it = all_relations_db2.find(relation.version2_.idx_);
			if(it != all_relations_db2.end())
			{
				auto relation_index = it->second;
				Relation& existing_relation = relations_[relation_index];
				if(existing_relation.type_ == RELATION_TYPE_ALTERNATIVE_FROM_N)
				{
//					LOG(INFO, "ALT_FROM_N Relation Solved at %d\n", relation_index);
						LOG(INFO, "ALT_FROM_N Relation Solved at %d\n", relation_index);
						//replace with the new relation
						existing_relation.version1_ = relation.version1_;
						existing_relation.alternate_version_1.clear();
						existing_relation.alternate_version_1.insert(existing_relation.version1_);
						existing_relation.type_ = relation.type_;
						MergeRelation(existing_relation, relation);
						relations_updated.push_back(relation_index);
				}
				else
				{
					if(existing_relation.version1_ != relation.version1_)
					{
						if(existing_relation.alternate_version_2.size() > 1)
							existing_relation.type_ = RELATION_TYPE_UNTRUSTABLE;
						else
							existing_relation.type_ = RELATION_TYPE_ALTERNATIVE_FROM_N;
						existing_relation.alternate_version_1.insert(relation.version1_);
						relation.alternate_version_1.insert(existing_relation.version1_);

						MergeRelation(existing_relation, relation);
						relations_updated.push_back(relation_index);
					}
					else
					{
						//TODO check previous relation type
						MergeRelation(existing_relation, relation);
						relations_updated.push_back(relation_index);
					}
				}
			}

			if(relations_updated.size() > 0)
			{
//				LOG(INFO, "existing_relation_updated : %ld\n", relations_updated.size());
				for(unsigned int i=1; i<relations_updated.size(); i++)
				{
					if(relations_updated[i] != relations_updated[0])
					{
						DestroyRelation(relations_[relations_updated[i]]);
					}
				}
				Relation correct_relation = relations_[relations_updated[0]];
				all_relations_db1[correct_relation.version1_.idx_] = relations_updated[0];
				all_relations_db2[correct_relation.version2_.idx_] = relations_updated[0];
				return true;
			}
    	}

        if(b_relation_untrustable)
        {
            relation.type_ = RELATION_TYPE_UNTRUSTABLE;
        }

        if(relation.type_ != RELATION_TYPE_ALTERNATIVE_FROM_N)
        	relation.alternate_version_1.insert(relation.version1_);
        if(relation.type_ != RELATION_TYPE_ALTERNATIVE_TO_N)
        	relation.alternate_version_2.insert(relation.version2_);

        //Check for alternative relation type
        if(relation.alternate_version_1.size() == 1 && relation.alternate_version_2.size() > 1)
        {
        	relation.type_ = RELATION_TYPE_ALTERNATIVE_TO_N;
        }
        if(relation.alternate_version_2.size() == 1 && relation.alternate_version_1.size() > 1)
        {
        	relation.type_ = RELATION_TYPE_ALTERNATIVE_FROM_N;
        }

        const auto index = static_cast<uint32_t>(relations_.size());
        relations_.push_back(relation);
        ++new_relation_counter_;
        if(relation.type_ != RELATION_TYPE_ALTERNATIVE_FROM_N)
        	all_relations_db1[relation.version1_.idx_] = index;
        if(relation.type_ != RELATION_TYPE_ALTERNATIVE_TO_N)
        	all_relations_db2[relation.version2_.idx_] = index;
        return true;
        */
    }

    int PurgeNewRelations()
    {
        auto result = new_relation_counter_;
        new_relation_counter_ = 0;
        return result;
    }

    int WalkRelations(const yadiff::OnRelationFn& on_relation)
    {
        auto relation_size = relations_.size();
        for(unsigned int i = 0; i < relation_size; ++i)
        {
        	if(relations_[i].type_ != RELATION_TYPE_NONE)
        	{
        		on_relation(relations_[i]);
        	}
        }
        return PurgeNewRelations();
    }
};

class Matching: public IMatching
{
public:
    Matching(const Configuration& config);

    bool Prepare(const IModel& db1, const IModel& db2) override;
    bool Analyse(std::vector<Relation>& output) override;

private:
    std::vector<std::shared_ptr<IDiffAlgo>> Algos_;
    std::vector<AlgoCfg> AlgoCfgs_;
    const Configuration& config_;
    const IModel* pDb1_;
    const IModel* pDb2_;
};


std::shared_ptr<IMatching> MakeMatching(const Configuration& config)
{
    return std::make_shared<Matching>(config);
}

Matching::Matching(const Configuration& config)
    : config_(config)
    , pDb1_(nullptr)
    , pDb2_(nullptr)
{
}


bool Matching::Prepare(const IModel& db1, const IModel& db2)
{

    pDb1_ = &db1;
    pDb2_ = &db2;

    //TODO have a real configuration
    if(config_.IsOptionTrue(SECTION_NAME, "XRefOffsetMatch"))
    {
    	AlgoCfg AlgoConfig;

        AlgoConfig.Algo = ALGO_XREF_OFFSET_MATCH;
        AlgoCfgs_.push_back(AlgoConfig);
        auto algo = MakeDiffAlgo(AlgoConfig);
        algo->Prepare(db1, db2);
        Algos_.push_back(algo);
    }
    if(config_.IsOptionTrue(SECTION_NAME, "XRefOffsetOrderMatch"))
    {
    	AlgoCfg AlgoConfig;

        AlgoConfig.Algo = ALGO_XREF_OFFSET_ORDER_MATCH;
        AlgoCfgs_.push_back(AlgoConfig);
        auto algo = MakeDiffAlgo(AlgoConfig);
        algo->Prepare(db1, db2);
        Algos_.push_back(algo);
    }
    if(config_.IsOptionTrue(SECTION_NAME, "CallerXRefMatch"))
    {
    	AlgoCfg AlgoConfig;
        AlgoConfig.Algo = ALGO_CALLER_XREF_MATCH;
        if(config_.IsOptionTrue(SECTION_NAME, "CallerXRefMatch_TrustDiffingRelations"))
        {
            AlgoConfig.CallerXRefMatch.TrustDiffingRelations = TRUST_DIFFING_RELATIONS;
        }
        AlgoCfgs_.push_back(AlgoConfig);
        auto algo = MakeDiffAlgo(AlgoConfig);
        algo->Prepare(db1, db2);
        Algos_.push_back(algo);
    }


    if(config_.IsOptionTrue(SECTION_NAME, "XRefMatch"))
    {
    	std::vector<bool> strip_bb_vect;
    	auto& bbmode = config_.GetOption(SECTION_NAME, "XRefMatch_StripBasicBlocksMode");
    	if(bbmode.empty() || bbmode == "default" || bbmode == "both")
    	{
    		strip_bb_vect.push_back(false);
    	}
    	if(bbmode == "both" || bbmode == "strip")
    	{
    		strip_bb_vect.push_back(true);
    	}

    	std::vector<yadiff::XRefDirectionMode_e> xref_directions;
    	auto& directionmode = config_.GetOption(SECTION_NAME, "XRefMatch_XrefDirectionMode");
    	if(directionmode.empty() || directionmode == "callee" || directionmode == "both")
    	{
    		xref_directions.push_back(yadiff::XREF_DIRECTION_CALLEE);
    	}
    	if(directionmode == "both" || directionmode == "caller")
    	{
    		xref_directions.push_back(yadiff::XREF_DIRECTION_CALLER);
    	}

		AlgoCfg AlgoConfig;
		AlgoConfig.Algo = ALGO_XREF_MATCH;
		if(config_.IsOptionTrue(SECTION_NAME, "XRefMatch_TrustDiffingRelations"))
		{
			AlgoConfig.XRefMatch.TrustDiffingRelations = TRUST_DIFFING_RELATIONS;
		}

    	auto& difftype = config_.GetOption(SECTION_NAME, "XRefMatch_FunctionDiffType");
    	if(difftype.empty() || difftype == "diff")
    	{
    		AlgoConfig.XRefMatch.FunctionDiffType = RELATION_TYPE_DIFF;
    	}
    	else if (difftype == "weak")
    	{
    		AlgoConfig.XRefMatch.FunctionDiffType = RELATION_TYPE_WEAK_MATCH;
    	}

    	for(bool strib_bb : strip_bb_vect)
    	{
    		for(yadiff::XRefDirectionMode_e xref_direction : xref_directions)
    		{
				AlgoConfig.XRefMatch.StripBasicBlocks = strib_bb;
				AlgoConfig.XRefMatch.XrefDirectionMode = xref_direction;

				AlgoCfgs_.push_back(AlgoConfig);
				auto algo = MakeDiffAlgo(AlgoConfig);
				algo->Prepare(db1, db2);
				Algos_.push_back(algo);
    		}
    	}
    }

    return true;
}

bool Matching::Analyse(std::vector<Relation>& output)
{
    if(nullptr == pDb1_)
    {
//        LOG(WARNING, "could not do analyze, call prepare before\n");
        return false;
    }
    if(nullptr == pDb2_)
    {
//        LOG(WARNING, "could not do analyze, call prepare before\n");
        return false;
    }
    auto relations = YaDiffRelationContainer();

    bool DoAnalyzeUntilAlgoReturn0 = config_.IsOptionTrue(SECTION_NAME, "DoAnalyzeUntilAlgoReturn0");
    bool DoAnalyzeUntilAnalyzeReturn0 = config_.IsOptionTrue(SECTION_NAME, "DoAnalyzeUntilAnalyzeReturn0");

    // apply external mapping match algo
    if(config_.IsOptionTrue(SECTION_NAME, "ExternalMappingMatch"))
    {
    	AlgoCfg AlgoConfig;
        LOG(INFO, "start external mapping association\n");
        AlgoConfig.Algo = ALGO_EXTERNAL_MAPPING_MATCH;
        AlgoConfig.ExternalMappingMatch.MappingFilePath = config_.GetOption(SECTION_NAME, "ExternalMappingMatchPath").c_str();
        auto relation_confidence = config_.GetOption(SECTION_NAME, "ExternalMappingMatchRelationConfidence");
        if(relation_confidence.length() > 0)
          {
            if(relation_confidence == "GOOD")
              {
                AlgoConfig.ExternalMappingMatch.CustomRelationConfidence = true;
                AlgoConfig.ExternalMappingMatch.RelationConfidence = RELATION_CONFIDENCE_GOOD;
              }
            if(relation_confidence == "BAD")
              {
                AlgoConfig.ExternalMappingMatch.CustomRelationConfidence = true;
                AlgoConfig.ExternalMappingMatch.RelationConfidence = RELATION_CONFIDENCE_BAD;
              }
            if(relation_confidence == "MIN")
              {
                AlgoConfig.ExternalMappingMatch.CustomRelationConfidence = true;
                AlgoConfig.ExternalMappingMatch.RelationConfidence = RELATION_CONFIDENCE_MIN;
              }
            if(relation_confidence == "MAX")
              {
                AlgoConfig.ExternalMappingMatch.CustomRelationConfidence = true;
                AlgoConfig.ExternalMappingMatch.RelationConfidence = RELATION_CONFIDENCE_MAX;
              }
            else
              {
                try
                {
                    AlgoConfig.ExternalMappingMatch.RelationConfidence = std::stoul(relation_confidence);
                    AlgoConfig.ExternalMappingMatch.CustomRelationConfidence = true;
                }
                catch(const std::invalid_argument&)
                {
                  LOG(ERROR, "invalid value for ExternalMappging match relation confidence, use default value\n");
                }
                catch(const std::out_of_range&)
                {
                  LOG(ERROR, "invalid value for ExternalMappging match relation confidence, use default value\n");
                }
              }
          }
        AlgoCfgs_.push_back(AlgoConfig);
        auto algo = MakeDiffAlgo(AlgoConfig);
        if(algo->Prepare(*pDb1_, *pDb2_))
          {
            algo->Analyse(
                [&](const Relation& relation, bool update_flag_only)
                {
                    return relations.InsertRelation(relation, update_flag_only);
                },
                [&](const yadiff::OnRelationFn& on_relation)
                {
                    return relations.WalkRelations(on_relation);
                });
            LOG(INFO, "external mapping association done %zd\n", relations.relations_.size());
          }
        else
          LOG(ERROR, "could not apply external mapping\n");
    }  int new_relation_counter_g = 0;

	AlgoCfg AlgoConfig;
    // always start with exact match algo
    AlgoConfig.Algo = ALGO_EXACT_MATCH;
    AlgoCfgs_.push_back(AlgoConfig);
    auto exact_algo = MakeDiffAlgo(AlgoConfig);
    exact_algo->Prepare(*pDb1_, *pDb2_);
    LOG(INFO, "start first association\n");
    exact_algo->Analyse(
        [&](const Relation& relation, bool update_flag_only)
        {
            return relations.InsertRelation(relation, update_flag_only);
        },
        [&](const yadiff::OnRelationFn& on_relation)
        {
            return relations.WalkRelations(on_relation);
        });
    LOG(INFO, "first association done %zd\n", relations.relations_.size());

    LOG(INFO, "start algo loop\n");
    do
    {
        LOG(INFO, "main loop relation counter: %d\n", new_relation_counter_g);
        new_relation_counter_g = 0;
        for(const auto algo: Algos_)
        {
            int new_relation_counter = 0;
            do
            {
                algo->Analyse(
                [&](const Relation& relation, bool update_flag_only)
                {
                    return relations.InsertRelation(relation, update_flag_only);
                },
                [&](const yadiff::OnRelationFn& on_relation)
                {
                    auto new_relations = relations.relations_;
                    for(const auto relation : new_relations)
                    {
                        on_relation(relation);
                    }
                    new_relation_counter = relations.PurgeNewRelations();
                    return new_relation_counter;
                });
                new_relation_counter_g += new_relation_counter;
                LOG(INFO, "algo %s found: %d new relation %zd\n", algo->GetName(), new_relation_counter, relations.relations_.size());
            }
            while(DoAnalyzeUntilAlgoReturn0 && (new_relation_counter > 0));
        }
    }
    while(DoAnalyzeUntilAnalyzeReturn0 && (new_relation_counter_g > 0));

    LOG(INFO, "algo loop done %zd\n", relations.relations_.size());

    output.insert(output.end(), relations.relations_.begin(), relations.relations_.end());
    return true;
}

} //end namespace
