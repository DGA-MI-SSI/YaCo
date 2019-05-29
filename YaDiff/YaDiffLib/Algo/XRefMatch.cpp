#include "XRefOffsetMatch.hpp"

#include "Algo.hpp"
#include "Helpers.h"
#include "Yatools.hpp"
#include "YaTypes.hpp"
#include "HVersion.hpp"
#include <Signature.hpp>
#include <VersionRelation.hpp>
#include "MemoryModel.hpp"

#include "json.hpp"

#include <utility>
#include <memory>
#include <map>
#include <set>
#include <chrono>
#include <fstream>
#include <iostream>
#include <unordered_map>

#ifdef _MSC_VER
#   include <filesystem>
#else
#   include <experimental/filesystem>
#endif

using namespace std;
using namespace std::experimental;

using json = nlohmann::json;


namespace {

class XRefMatchAlgo: public yadiff::IDiffAlgo {
public:
    virtual ~XRefMatchAlgo(){}

    XRefMatchAlgo(const yadiff::AlgoCfg& config);

    /*
     * prepares input signature databases
     */
    bool Prepare(const IModel& db1, const IModel& db2) override;

    /*
     * uses previously registered signature databases and input version relations
     * to compute a new version relation vector
     */
    bool Analyse(const yadiff::OnAddRelationFn& output, const yadiff::RelationWalkerfn& input) override;

    const char* GetName() const override;

private:
    const IModel* pDb1_;
    const IModel* pDb2_;
    const IModel* pDb1Src;
    const IModel* pDb2Src;
    const yadiff::AlgoCfg config_;
    std::shared_ptr<IModel> pDb1_Stripped;
    std::shared_ptr<IModel> pDb2_Stripped;
    HVersion local1_db_to_outer_db(HVersion version);
    HVersion local2_db_to_outer_db(HVersion version);
    HVersion outer1_db_to_local_db(HVersion version);
    HVersion outer2_db_to_local_db(HVersion version);
};

} // End ::

const char* XRefMatchAlgo::GetName() const{
    if(config_.XRefMatch.StripBasicBlocks) {
        if (config_.XRefMatch.XrefDirectionMode == yadiff::XREF_DIRECTION_CALLER) {
            return "XRefMatchAlgo_NOBB_Caller";
        }
        if (config_.XRefMatch.XrefDirectionMode == yadiff::XREF_DIRECTION_CALLEE) {
            return "XRefMatchAlgo_NOBB_Callee";
        }
    }
    else {
        if (config_.XRefMatch.XrefDirectionMode == yadiff::XREF_DIRECTION_CALLER) {
            return "XRefMatchAlgo_BB_Caller";
        }
        if (config_.XRefMatch.XrefDirectionMode == yadiff::XREF_DIRECTION_CALLEE) {
            return "XRefMatchAlgo_BB_Callee";
        }
    }
    return "XRefMatchAlgo_error";
}


namespace yadiff {

std::shared_ptr<IDiffAlgo> MakeXRefMatchAlgo(const AlgoCfg& config) {
    return std::make_shared<XRefMatchAlgo>(config);
}
} // End yadiff::

XRefMatchAlgo::XRefMatchAlgo(const yadiff::AlgoCfg& config):
                pDb1_(nullptr),
                pDb2_(nullptr),
                pDb1Src(nullptr),
                pDb2Src(nullptr),
                config_(config) {
    // Welcome in the void
}

namespace {
void StripBasicBlocks(IModelVisitor& visitor, const IModel& model)
{
    visitor.visit_start();
    model.walk([&](const HVersion& version)
    {
        if (version.type() == OBJECT_TYPE_BASIC_BLOCK) {
            return WALK_CONTINUE;
        }
        if (version.type() != OBJECT_TYPE_FUNCTION) {
            version.accept(visitor);
            return WALK_CONTINUE;
        }

        YaToolObjectId firstbb_id = 0;
           version.walk_xrefs([&](offset_t offset, operand_t /*base_operand*/, YaToolObjectId base_id, const XrefAttributes* /*base_hattr*/)
        {
               const auto& refed_obj = model.get(base_id);
               if(refed_obj.type() == OBJECT_TYPE_BASIC_BLOCK && (version.address() == refed_obj.address() || offset == 0))
            {
                   firstbb_id = base_id;
                   return WALK_STOP;
            }
               return WALK_CONTINUE;
        });

           const auto& firstbb = model.get(firstbb_id);

        visitor.visit_start_version(version.type(), version.id());
        visitor.visit_size(version.size());
        visitor.visit_parent_id(version.parent_id());
        visitor.visit_address(version.address());

        if (firstbb.username().size > 0) {
            visitor.visit_name(firstbb.username(), firstbb.username_flags());
        }

        if (version.prototype().size > 0) {
            visitor.visit_prototype(version.prototype());
        }

        visitor.visit_flags(version.flags());

        const auto string_type = version.string_type();
        if (string_type != UINT8_MAX) {
            visitor.visit_string_type(string_type);
        }

        // signatures
        visitor.visit_start_signatures();

        version.walk_signatures([&](const HSignature& sig) {
            const auto& s = sig.get();
            visitor.visit_signature(s.method, s.algo, make_string_ref(s.buffer));
            return WALK_CONTINUE;
        });
        visitor.visit_end_signatures();

        if (version.header_comment(true).size > 0) {
            visitor.visit_header_comment(true, version.header_comment(true));
        }

        if (version.header_comment(false).size > 0) {
            visitor.visit_header_comment(false, version.header_comment(false));
        }

        // offsets
        if(version.has_comments() || version.has_value_views() || version.has_register_views() || version.has_hidden_areas()) {
            visitor.visit_start_offsets();
            version.walk_comments([&](offset_t offset, CommentType_e this_type, const const_string_ref& this_comment)
            {
                visitor.visit_offset_comments(offset, this_type, this_comment);
                return WALK_CONTINUE;
            });
            version.walk_value_views([&](offset_t offset, operand_t operand, const const_string_ref& value)
            {
                visitor.visit_offset_valueview(offset, operand, value);
                return WALK_CONTINUE;
            });
            version.walk_register_views([&](offset_t offset, offset_t end, const const_string_ref& name, const const_string_ref& newname)
            {
                visitor.visit_offset_registerview(offset, end, name, newname);
                return WALK_CONTINUE;
            });
            version.walk_hidden_areas([&](offset_t offset, offset_t offset_end, const const_string_ref& value)
            {
                visitor.visit_offset_hiddenarea(offset, offset_end, value);
                return WALK_CONTINUE;
            });
            visitor.visit_end_offsets();
        }

        // For all Xrefs:
        visitor.visit_start_xrefs();
           version.walk_xrefs([&](offset_t base_offset, operand_t base_operand, YaToolObjectId base_id, const XrefAttributes* base_hattr) {

               // Get object
               const auto& refed_obj = model.get(base_id);

               // If BB: 
               if(refed_obj.type() != OBJECT_TYPE_BASIC_BLOCK) {
                   visitor.visit_start_xref(base_offset, base_id, base_operand);
                   version.walk_xref_attributes(base_hattr, [&](const const_string_ref& key, const const_string_ref& value) {
                       visitor.visit_xref_attribute(key, value);
                       return WALK_CONTINUE;
                   });

                   visitor.visit_end_xref();
                   return WALK_CONTINUE;
               }

               // For basic blocks : walk their xrefs and propagate them to this function object
               refed_obj.walk_xrefs([&](offset_t offset, operand_t operand, YaToolObjectId id, const XrefAttributes* hattr) {
                   const auto& refed_obj_by_bb = model.get(id);
                   if(refed_obj_by_bb.model_ == nullptr) {
                       return WALK_CONTINUE;
                   }

                   if(refed_obj_by_bb.type() == OBJECT_TYPE_BASIC_BLOCK) {
                       id = refed_obj_by_bb.parent_id();
                       if (id == version.id()) {
                           return WALK_CONTINUE;
                       }
                   }

               visitor.visit_start_xref(base_offset + offset, id, operand);
               version.walk_xref_attributes(hattr, [&](const const_string_ref& key, const const_string_ref& value) {
                    visitor.visit_xref_attribute(key, value);
                    return WALK_CONTINUE;
               });
               visitor.visit_end_xref();
               return WALK_CONTINUE;
            });

            return WALK_CONTINUE;
        });
        visitor.visit_end_xrefs();

        // attributes
        version.walk_attributes([&](const const_string_ref& key, const const_string_ref& val)
        {
            visitor.visit_attribute(key, val);
            return WALK_CONTINUE;
        });

        // blobs
        version.walk_blobs([&](offset_t offset, const void* data, size_t len)
        {
            visitor.visit_blob(offset, data, len);
            return WALK_CONTINUE;
        });

        visitor.visit_end_version();

        return WALK_CONTINUE;
    });
    visitor.visit_end();
}
}
HVersion XRefMatchAlgo::local1_db_to_outer_db(HVersion version)
{
    if(pDb1_ == pDb1Src) {
        return version;
    }
    return pDb1Src->get(version.id());
}
HVersion XRefMatchAlgo::local2_db_to_outer_db(HVersion version)
{
    if(pDb2_ == pDb2Src) {
        return version;
    }
    return pDb2Src->get(version.id());
}
HVersion XRefMatchAlgo::outer1_db_to_local_db(HVersion version)
{
    if(pDb1_ == pDb1Src) {
        return version;
    }
    return pDb1_->get(version.id());
}
HVersion XRefMatchAlgo::outer2_db_to_local_db(HVersion version)
{
    if(pDb2_ == pDb2Src) {
        return version;
    }
    return pDb2_->get(version.id());
}

bool XRefMatchAlgo::Prepare(const IModel& db1, const IModel& db2)
{
    pDb1Src = &db1;
    pDb2Src = &db2;
    pDb1_ = &db1;
    pDb2_ = &db2;


    if (config_.XRefMatch.StripBasicBlocks)
    {
        std::shared_ptr<IModelAndVisitor> m1 = MakeMemoryModel();
        std::shared_ptr<IModelAndVisitor> m2 = MakeMemoryModel();
        pDb1_Stripped = m1;
        pDb2_Stripped = m2;
        pDb1_= pDb1_Stripped.get();
        pDb2_= pDb2_Stripped.get();
        LOG(INFO, "StripBasicBlocks DB 1\n");
        StripBasicBlocks(*m1, db1);
        LOG(INFO, "StripBasicBlocks DB 2\n");
        StripBasicBlocks(*m2, db2);
        LOG(INFO, "StripBasicBlocks Finished\n");
    }

    return true;
}

bool XRefMatchAlgo::Analyse(const yadiff::OnAddRelationFn& output, const yadiff::RelationWalkerfn& input) {

    // Check In
    if(nullptr == pDb1_ || nullptr == pDb2_) {
        return false;
    }

    uint32_t this_algo_flag;
    if(config_.XRefMatch.StripBasicBlocks)
    {
        if(config_.XRefMatch.XrefDirectionMode == yadiff::XREF_DIRECTION_CALLER) {
            this_algo_flag = yadiff::AF_CALLER_NOBB_XREF_DONE;
        }
        if(config_.XRefMatch.XrefDirectionMode == yadiff::XREF_DIRECTION_CALLEE) {
            this_algo_flag = yadiff::AF_CALLEE_NOBB_XREF_DONE;
        }
    }
    else
    {
        if(config_.XRefMatch.XrefDirectionMode == yadiff::XREF_DIRECTION_CALLER) {
            this_algo_flag = yadiff::AF_CALLER_XREF_DONE;
        }
        if(config_.XRefMatch.XrefDirectionMode == yadiff::XREF_DIRECTION_CALLEE) {
            this_algo_flag = yadiff::AF_CALLEE_XREF_DONE;
        }
    }
    struct sig_association_s
    {
        std::set<HVersion>        local_obj;
        std::set<HVersion>        remote_obj;
    };
    struct sig_map_t
    {
        std::map<HSignature, sig_association_s> data;
    };
    typedef std::map<YaToolObjectType_e, sig_map_t> sigs_container_t;

    // Iterate over all previously computed relation
    input([&](const Relation& relation){
        if(relation.flags_ & this_algo_flag) {
            return true;
        }

        switch (relation.type_)
        {
        case RELATION_TYPE_DIFF:
            if (config_.XRefMatch.TrustDiffingRelations == yadiff::DO_NOT_TRUST_DIFFING_RELATIONS) {
                return true;
            }
            break;
        case RELATION_TYPE_STRONG_MATCH:
            // LOG(INFO, "Got Strong match relation\n");
            break;
        case RELATION_TYPE_EXACT_MATCH:
            break;
        default:
            return true;
            break;
        }
        const auto& version1_ = outer1_db_to_local_db(relation.version1_);
        const auto& version2_ = outer2_db_to_local_db(relation.version2_);

        Relation tmp = relation;
        tmp.flags_ |= this_algo_flag;
        LOG(INFO, "CXMAF: FLAG 0x%016zu <-> 0x%016zu  (%s <-> %s)\n", relation.version1_.address(), relation.version2_.address(), relation.version1_.username().value, relation.version2_.username().value);
        output(tmp, true);

        // Diregard BB sons (center on Fct sons)
        if(config_.XRefMatch.StripBasicBlocks) {
            if(relation.version1_.type() == OBJECT_TYPE_BASIC_BLOCK
                || relation.version2_.type() == OBJECT_TYPE_BASIC_BLOCK) {
                return true;
            }
            // if(relation.version1_.type() != OBJECT_TYPE_FUNCTION || relation.version2_.type() != OBJECT_TYPE_FUNCTION)
            //     return true;
        }

        sigs_container_t                sigs_container;

        /************ construct signature maps ****************************************/
        if (config_.XRefMatch.XrefDirectionMode == yadiff::XREF_DIRECTION_CALLER)
        {
            // for each xref from obj1
            version1_.walk_xrefs_to([&](const HVersion& local_version)
            {
                const auto type = local_version.type();
                local_version.walk_signatures([&](const HSignature& signature)
                {
                    sigs_container[type].data[signature].local_obj.insert(local_version);
                    return WALK_CONTINUE;
                });
                return WALK_CONTINUE;
            });

            // for each xref from obj2
            version2_.walk_xrefs_to([&](const HVersion& remote_version)
            {
                const auto type = remote_version.type();
                remote_version.walk_signatures([&](const HSignature& signature)
                {
                    sigs_container[type].data[signature].remote_obj.insert(remote_version);
                    return WALK_CONTINUE;
                });
                return WALK_CONTINUE;
            });

            // set relation as treated
            output(tmp, true);
        }

        if (config_.XRefMatch.XrefDirectionMode == yadiff::XREF_DIRECTION_CALLEE)
        {
            // for each xref from obj1
            version1_.walk_xrefs_from([&](offset_t /*off*/, operand_t /*op*/, const HVersion& local_version)
            {
                const auto type = local_version.type();
                local_version.walk_signatures([&](const HSignature& signature)
                {
                    sigs_container[type].data[signature].local_obj.insert(local_version);
                    return WALK_CONTINUE;
                });
                return WALK_CONTINUE;
            });

            // for each xref from obj2
            version2_.walk_xrefs_from([&](offset_t /*off*/, operand_t /*op*/, const HVersion& remote_version)
            {
                const auto type = remote_version.type();
                remote_version.walk_signatures([&](const HSignature& signature)
                {
                    sigs_container[type].data[signature].remote_obj.insert(remote_version);
                    return WALK_CONTINUE;
                });
                return WALK_CONTINUE;
            });
        }
        /*******************************************************************************/

        for (const auto& sig_container : sigs_container)
        {
            const auto                        object_type = sig_container.first;
            const sig_map_t&                  sig_map = sig_container.second;

            std::set<HVersion>    LocalDiffsObjectVersion;
            std::set<HVersion>    RemoteDiffsObjectVersion;

            for (const auto& sig : sig_map.data)
            {
                const std::set<HVersion>& LocalXrefObjectVersionSet = sig.second.local_obj;
                const std::set<HVersion>& RemoteXrefObjectVersionSet = sig.second.remote_obj;

                LOG(DEBUG, "LocalXrefObjectVersionSet.size(): %zd RemoteXrefObjectVersionSet.size(): %zd\n", LocalXrefObjectVersionSet.size(), RemoteXrefObjectVersionSet.size());

                //ASSOCIATION : if entry has two set of one element each
                if ( (LocalXrefObjectVersionSet.size() == 1) && (RemoteXrefObjectVersionSet.size() == 1) )
                {
//                    HVersion localXrefObjectVersion = *LocalXrefObjectVersionSet.begin();
//                    HVersion remoteXrefObjectVersion = *RemoteXrefObjectVersionSet.begin();

                    // add relation ???
                    Relation new_relation;
                    new_relation.type_ = RELATION_TYPE_EXACT_MATCH;
                    new_relation.mask_algos_flags = true;
                    new_relation.version1_ = local1_db_to_outer_db(*LocalXrefObjectVersionSet.begin());
                    new_relation.version2_ = local2_db_to_outer_db(*RemoteXrefObjectVersionSet.begin());
                    LOG(INFO, "CXMA1: from 0x%016llx <-> 0x%016llx  (%s <-> %s)\n", version1_.address(), version2_.address(), version1_.username().value, version2_.username().value);
                    LOG(INFO, "CXMA1: --> associate 0x%016llx <-> 0x%016llx  (%s <-> %s)\n", new_relation.version1_.address(), new_relation.version2_.address(), new_relation.version1_.username().value, new_relation.version2_.username().value);
                    output(new_relation, false);
                }
                else
                {
                    if((LocalXrefObjectVersionSet.size() == 1) && (RemoteXrefObjectVersionSet.size() == 0))
                    {
                        LocalDiffsObjectVersion.insert(*LocalXrefObjectVersionSet.begin());
                    }
                    if((LocalXrefObjectVersionSet.size() == 0) && (RemoteXrefObjectVersionSet.size() == 1))
                    {
                        RemoteDiffsObjectVersion.insert(*RemoteXrefObjectVersionSet.begin());
                    }
                }
            }

            // if there is only one signature for each local ad remote db, and a diffing relation
            if((LocalDiffsObjectVersion.size() == 1) && (RemoteDiffsObjectVersion.size() == 1))
            {
                const HVersion&             diff_version1 = *LocalDiffsObjectVersion.begin();
                const HVersion&             diff_version2 = *RemoteDiffsObjectVersion.begin();
                const HVersion*             diff_parent1 = nullptr;
                const HVersion*             diff_parent2 = nullptr;

                Relation new_relation;
                new_relation.mask_algos_flags = true;
                if (diff_version1.type() == OBJECT_TYPE_FUNCTION && diff_version2.type() == OBJECT_TYPE_FUNCTION) {
                    new_relation.type_ = config_.XRefMatch.FunctionDiffType;
                }
                else {
                    new_relation.type_ = RELATION_TYPE_DIFF;
                }

//                if(diff_version1.type() == OBJECT_TYPE_FUNCTION && diff_version1.address()==0x000000000001D826)
//                {
//                    printf("relation diff : 0x%016lX --> 0x%016lX\n", diff_version1.address(), diff_version2.address());
//                }
                new_relation.version1_ = local1_db_to_outer_db(diff_version1);
                new_relation.version2_ = local2_db_to_outer_db(diff_version2);
                LOG(INFO, "CXMA2: from 0x%016llx <-> 0x%016llx  (%s <-> %s)\n", version1_.address(), version2_.address(), version1_.username().value, version2_.username().value);
                LOG(INFO, "CXMA2: --> associate 0x%016llx <-> 0x%016llx  (%s <-> %s)\n", new_relation.version1_.address(), new_relation.version2_.address(), new_relation.version1_.username().value, new_relation.version2_.username().value);
                output(new_relation, false);

                /* try to propagate diff relations to parent only for basic blocks */
                if (OBJECT_TYPE_BASIC_BLOCK != object_type) {
                    continue;
                }

                uint32_t version1_parent_count = 0;
                uint32_t version2_parent_count = 0;
                diff_version1.walk_xrefs_to([&](const HVersion& local_version)
                {
                    if(local_version.type() != OBJECT_TYPE_FUNCTION) {
                        return WALK_CONTINUE;
                    }
                    version1_parent_count++;
                    diff_parent1 = &local_version;
                    new_relation.version1_ = local1_db_to_outer_db(local_version);
                    return WALK_CONTINUE;
                });

                diff_version2.walk_xrefs_to([&](const HVersion& local_version)
                {
                    if (local_version.type() != OBJECT_TYPE_FUNCTION) {
                        return WALK_CONTINUE;
                    }
                    version2_parent_count++;
                    diff_parent2 = &local_version;
                    new_relation.version2_ = local2_db_to_outer_db(local_version);
                    return WALK_CONTINUE;
                });

                if (nullptr != diff_parent1 && nullptr != diff_parent2)
                {
                    if(version1_parent_count==1 && version2_parent_count==1)
                    {
                        LOG(INFO, "CXMA3: from 0x%016llx <-> 0x%016llx  (%s <-> %s)\n", version1_.address(), version2_.address(), version1_.username().value, version2_.username().value);
                        LOG(INFO, "CXMA3: --> associate 0x%016llx <-> 0x%016llx  (%s <-> %s)\n", new_relation.version1_.address(), new_relation.version2_.address(), new_relation.version1_.username().value, new_relation.version2_.username().value);
                        output(new_relation, false);
                    }
                    else
                    {
                        LOG(INFO, "CXMA3: from 0x%016llx <-> 0x%016llx  (%s <-> %s)\n", version1_.address(), version2_.address(), version1_.username().value, version2_.username().value);
                        LOG(INFO, "CXMA3: --> Multiple parents\n");
                    }
                }
            }

            if((LocalDiffsObjectVersion.size() == 1) && (RemoteDiffsObjectVersion.size() > 1))
            {
                const HVersion&             diff_version1 = *LocalDiffsObjectVersion.begin();

                Relation new_relation;
                new_relation.type_ = RELATION_TYPE_ALTERNATIVE_TO_N;
                new_relation.version1_ = local1_db_to_outer_db(diff_version1);
                for(const auto& v2: RemoteDiffsObjectVersion)
                {
                    new_relation.version2_ = local2_db_to_outer_db(v2);
                    output(new_relation, false);
                }

//                for(const auto& diff_version2 : RemoteDiffsObjectVersion)
//                {
//                    new_relation.version2_ = local2_db_to_outer_db(diff_version2);
//                    output(new_relation);
//                }
            }

            if((LocalDiffsObjectVersion.size() > 1) && (RemoteDiffsObjectVersion.size() == 1))
            {
                const HVersion&             diff_version2 = *RemoteDiffsObjectVersion.begin();

                Relation new_relation;
                new_relation.type_ = RELATION_TYPE_ALTERNATIVE_FROM_N;
                new_relation.version2_ = local2_db_to_outer_db(diff_version2);
                for(const auto& v1: LocalDiffsObjectVersion)
                {
                    new_relation.version1_ = local1_db_to_outer_db(v1);
                    output(new_relation, false);
                }
            }

        }

    return true;
    });

    return true;
}
