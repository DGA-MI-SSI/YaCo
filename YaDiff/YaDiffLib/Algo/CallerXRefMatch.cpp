#include "XRefOffsetMatch.hpp"

#include "Algo.hpp"
#include "Helpers.h"
#include "Yatools.hpp"
#include <Signature.hpp>
#include <VersionRelation.hpp>

#include <memory>
#include <map>
#include <set>

#include "CallerXRefMatch.hpp"

namespace {

class CallerXRefMatchAlgo: public yadiff::IDiffAlgo {

public:
    virtual ~CallerXRefMatchAlgo(){}

    CallerXRefMatchAlgo(const yadiff::AlgoCfg& config);

    // Prepare input signature databases
    bool Prepare(const IModel& db1, const IModel& db2) override;

    /*
     * Use previously registered signature databases and input version relations
     * to compute a new version relation vector
     */
    bool Analyse(const yadiff::OnAddRelationFn& output, const yadiff::RelationWalkerfn& input) override;

    const char* GetName() const override;

private:
    const IModel* pDb1_;
    const IModel* pDb2_;
    const yadiff::AlgoCfg config_;
};

} // End ::


// Declare my name
const char* CallerXRefMatchAlgo::GetName() const{
    return "CallerXRefMatchAlgo";
}


// Create algo
std::shared_ptr<yadiff::IDiffAlgo> MakeCallerXRefMatchAlgo(const yadiff::AlgoCfg& config) {
    return std::make_shared<CallerXRefMatchAlgo>(config);
}


// Construct(or) default
CallerXRefMatchAlgo::CallerXRefMatchAlgo(const yadiff::AlgoCfg& config):
        pDb1_(nullptr),
        pDb2_(nullptr),
        config_(config) {
}


// Prepare algo: feed database -> class varaibles
bool CallerXRefMatchAlgo::Prepare(const IModel& db1, const IModel& db2) {
    // Class asignement
    pDb1_ = &db1;
    pDb2_ = &db2;

    // Ok
    return true;
}


// Worker
bool CallerXRefMatchAlgo::Analyse(const yadiff::OnAddRelationFn& output, const yadiff::RelationWalkerfn& input) {

    // Check In (databases)
    if (nullptr == pDb1_ || nullptr == pDb2_) {
        return false;
    }

    // Create relation
    Relation new_relation;
    new_relation.type_ = RELATION_TYPE_EXACT_MATCH;


    // Iterate over all previously computed relation
    input([&](const Relation& relation) {
        // Break if already done
        if (relation.flags_ & yadiff::AF_CALLER_XREF_DONE) {
            return true;
        }

        // Break if smell bad
        switch (relation.type_) {
        case RELATION_TYPE_DIFF:
            if (config_.CallerXRefMatch.TrustDiffingRelations == yadiff::DO_NOT_TRUST_DIFFING_RELATIONS) {
                return true;
            }
            break;
        case RELATION_TYPE_EXACT_MATCH:
        case RELATION_TYPE_STRONG_MATCH:
            break;
        default:
            return true;
            break;
        }

        // Set relation as treated
        Relation tmp = relation;
        tmp.flags_ |= yadiff::AF_CALLER_XREF_DONE;
        output(tmp, true);
        sigs_container_t sigs_container;


        // Forge signature container dictionary
        // --- For each xref from obj1 : append to sigs_container
        relation.version1_.walk_xrefs_to([&](const HVersion& local_version)
        {
            const auto type = local_version.type();
            local_version.walk_signatures([&](const HSignature& signature)
            {
                sigs_container[type].data[signature].local_obj.insert(local_version);
                return WALK_CONTINUE;
            });
            return WALK_CONTINUE;
        });
        // --- Foreach xref from obj2 : append to sigs_container
        relation.version2_.walk_xrefs_to([&](const HVersion& remote_version)
        {
            const auto type = remote_version.type();
            remote_version.walk_signatures([&](const HSignature& signature)
            {
                sigs_container[type].data[signature].remote_obj.insert(remote_version);
                return WALK_CONTINUE;
            });
            return WALK_CONTINUE;
        });


        // Foreach container
        for (const auto& sig_container : sigs_container)
        {
            const auto            object_type = sig_container.first;
            const sig_map_t&      sig_map = sig_container.second;
            std::set<HVersion>    LocalDiffsObjectVersion;
            std::set<HVersion>    RemoteDiffsObjectVersion;

            // Foreach signature in container
            for (const auto& sig : sig_map.data)
            {
                const std::set<HVersion>& LocalXrefObjectVersionSet = sig.second.local_obj;
                const std::set<HVersion>& RemoteXrefObjectVersionSet = sig.second.remote_obj;

                LOG(DEBUG, "LocalXrefObjectVersionSet.size(): %zd RemoteXrefObjectVersionSet.size(): %zd\n", LocalXrefObjectVersionSet.size(), RemoteXrefObjectVersionSet.size());

                // Associate exact if entry has two set of one element each
                if ( (LocalXrefObjectVersionSet.size() == 1) && (RemoteXrefObjectVersionSet.size() == 1) ) { 
                    // Add One-to-One relation
                    new_relation.type_ = RELATION_TYPE_EXACT_MATCH;
                    new_relation.version1_ = *LocalXrefObjectVersionSet.begin();
                    new_relation.version2_ = *RemoteXrefObjectVersionSet.begin();
                    LOG(DEBUG, "CXMA.cpp: from %zx (%s) <-> %zx (%s)\n", relation.version1_.address(), relation.version1_.username().value, relation.version2_.address(), relation.version2_.username().value);
                    LOG(DEBUG, "CXMA.cpp: --> associate %zx (%s) <-> %zx (%s)\n", new_relation.version1_.address(), new_relation.version1_.username().value, new_relation.version2_.address(), new_relation.version2_.username().value);
                    output(new_relation, false);
                }
                else {
                    // Add anarchist relation
                    if((LocalXrefObjectVersionSet.size() == 1) && (RemoteXrefObjectVersionSet.size() == 0)) {
                        LocalDiffsObjectVersion.insert(*LocalXrefObjectVersionSet.begin());
                    }
                    if((LocalXrefObjectVersionSet.size() == 0) && (RemoteXrefObjectVersionSet.size() == 1)) {
                        RemoteDiffsObjectVersion.insert(*RemoteXrefObjectVersionSet.begin());
                    }
                }
            }

            // Associate diff if there is only one signature for each local ad remote db
            if((LocalDiffsObjectVersion.size() == 1) && (RemoteDiffsObjectVersion.size() == 1)) {
                const HVersion&             diff_version1 = *LocalDiffsObjectVersion.begin();
                const HVersion&             diff_version2 = *RemoteDiffsObjectVersion.begin();
                const HVersion*             diff_parent1 = nullptr;
                const HVersion*             diff_parent2 = nullptr;

                // Add diff relation
                new_relation.type_ = RELATION_TYPE_DIFF;
                new_relation.version1_ = diff_version1;
                new_relation.version2_ = diff_version2;
                LOG(DEBUG, "CXMA.cpp: from %zx (%s) <-> %zx(%s)\n", relation.version1_.address(), relation.version1_.username().value, relation.version2_.address(), relation.version2_.username().value);
                LOG(DEBUG, "CXMA.cpp: --> associate %zx (%s) <-> %zx (%s)\n", new_relation.version1_.address(), new_relation.version1_.username().value, new_relation.version2_.address(), new_relation.version2_.username().value);
                output(new_relation, false);

                // Continue if not BB : try to propagate diff relations to parent only for basic blocks
                if (OBJECT_TYPE_BASIC_BLOCK != object_type) {
                    continue;
                }

                // Get parent1 (TODO make helper ??)
                diff_version1.walk_xrefs_to([&](const HVersion& local_version) {
                    diff_parent1 = &local_version;
                    new_relation.version1_ = local_version;
                    return WALK_STOP;
                });

                // Get parent2
                diff_version2.walk_xrefs_to([&](const HVersion& local_version) {
                    diff_parent2 = &local_version;
                    new_relation.version2_ = local_version;
                    return WALK_STOP;
                });

                // Propagate if can
                if (nullptr != diff_parent1 && nullptr != diff_parent2) {
                    LOG(DEBUG, "CXMA.cpp: from %zx(%s) <-> %zx(%s)\n", relation.version1_.address(), relation.version1_.username().value, relation.version2_.address(), relation.version2_.username().value);
                    LOG(DEBUG, "CXMA.cpp: --> associate %zx(%s) <-> %zx(%s)\n", new_relation.version1_.address(), new_relation.version1_.username().value, new_relation.version2_.address(), new_relation.version2_.username().value);
                    output(new_relation, false);
                }
            }
        }

        // Return from relation iteration
        return true;
    });

    // Return from Analyse function
    return true;
}
