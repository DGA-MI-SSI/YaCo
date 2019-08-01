#include "XRefOffsetMatch.hpp"

#include "Algo.hpp"
#include "Helpers.h"
#include "Yatools.hpp"
#include <Signature.hpp>
#include <VersionRelation.hpp>

#include <memory>
#include <map>
#include <set>

#if 0
#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("caller", (FMT), ## __VA_ARGS__)
#else
#define LOG(...) do {} while(0)
#endif

namespace
{
class CallerXRefMatchAlgo: public yadiff::IDiffAlgo
{
public:
    virtual ~CallerXRefMatchAlgo(){}

    CallerXRefMatchAlgo(const yadiff::AlgoCfg& config);

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
    const yadiff::AlgoCfg config_;
};

}

const char* CallerXRefMatchAlgo::GetName() const{
    return "CallerXRefMatchAlgo";
}

namespace yadiff
{
std::shared_ptr<IDiffAlgo> MakeCallerXRefMatchAlgo(const AlgoCfg& config)
{
    return std::make_shared<CallerXRefMatchAlgo>(config);
}
}

CallerXRefMatchAlgo::CallerXRefMatchAlgo(const yadiff::AlgoCfg& config):
        pDb1_(nullptr),
        pDb2_(nullptr),
        config_(config)
{
}

bool CallerXRefMatchAlgo::Prepare(const IModel& db1, const IModel& db2)
{
    pDb1_ = &db1;
    pDb2_ = &db2;

    return true;
}

bool CallerXRefMatchAlgo::Analyse(const yadiff::OnAddRelationFn& output, const yadiff::RelationWalkerfn& input)
{
    if(pDb1_ == nullptr)
        return false;
    if(pDb2_ == nullptr)
        return false;

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

    Relation new_relation;
    new_relation.type_ = RELATION_TYPE_EXACT_MATCH;


    // iterate over all previously computed relation
    input([&](const Relation& relation){
        if(relation.flags_ & yadiff::AF_CALLER_XREF_DONE)
            return true;

        switch (relation.type_)
        {
        case RELATION_TYPE_DIFF:
            if (config_.CallerXRefMatch.TrustDiffingRelations == yadiff::DO_NOT_TRUST_DIFFING_RELATIONS)
            {
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

        // set relation as treated
        Relation tmp = relation;
        tmp.flags_ |= yadiff::AF_CALLER_XREF_DONE;
        output(tmp, true);
        sigs_container_t                sigs_container;

        /************ construct signature maps ****************************************/
        // for each xref from obj1
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

        // for each xref from obj2
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
                    new_relation.type_ = RELATION_TYPE_EXACT_MATCH;
                    new_relation.version1_ = *LocalXrefObjectVersionSet.begin();
                    new_relation.version2_ = *RemoteXrefObjectVersionSet.begin();
                    LOG(INFO, "CXMA: from %lx(%s) <-> %lx(%s)\n", relation.version1_.address(), relation.version1_.username().value, relation.version2_.address(), relation.version2_.username().value);
                    LOG(INFO, "CXMA: --> associate %lx(%s) <-> %lx(%s)\n", new_relation.version1_.address(), new_relation.version1_.username().value, new_relation.version2_.address(), new_relation.version2_.username().value);
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

                new_relation.type_ = RELATION_TYPE_DIFF;
                new_relation.version1_ = diff_version1;
                new_relation.version2_ = diff_version2;
                LOG(INFO, "CXMA: from %lx(%s) <-> %lx(%s)\n", relation.version1_.address(), relation.version1_.username().value, relation.version2_.address(), relation.version2_.username().value);
                LOG(INFO, "CXMA: --> associate %lx(%s) <-> %lx(%s)\n", new_relation.version1_.address(), new_relation.version1_.username().value, new_relation.version2_.address(), new_relation.version2_.username().value);
                output(new_relation, false);

                /* try to propagate diff relations to parent only for basic blocks */
                if (OBJECT_TYPE_BASIC_BLOCK != object_type)
                {
                    continue;
                }

                diff_version1.walk_xrefs_to([&](const HVersion& local_version)
                {
                    diff_parent1 = &local_version;
                    new_relation.version1_ = local_version;
                    return WALK_STOP;
                });

                diff_version2.walk_xrefs_to([&](const HVersion& local_version)
                {
                    diff_parent2 = &local_version;
                    new_relation.version2_ = local_version;
                    return WALK_STOP;
                });

                if (nullptr != diff_parent1 && nullptr != diff_parent2)
                {
                    LOG(INFO, "CXMA: from %lx(%s) <-> %lx(%s)\n", relation.version1_.address(), relation.version1_.username().value, relation.version2_.address(), relation.version2_.username().value);
                    LOG(INFO, "CXMA: --> associate %lx(%s) <-> %lx(%s)\n", new_relation.version1_.address(), new_relation.version1_.username().value, new_relation.version2_.address(), new_relation.version2_.username().value);
                    output(new_relation, false);
                }
            }

        }

    return true;
    });

    return true;
}

