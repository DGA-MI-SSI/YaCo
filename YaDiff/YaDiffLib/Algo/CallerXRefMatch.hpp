#pragma once

#include <map>

typedef struct _sig_association_s {
    std::set<HVersion>        local_obj;
    std::set<HVersion>        remote_obj;
} sig_association_s, *p_sig_assiciation_s;

typedef struct _sig_map_t {
    std::map<HSignature, sig_association_s> data;
} sig_map_t, *p_sig_map_t;

typedef std::map<YaToolObjectType_e, sig_map_t> sigs_container_t;

namespace std { template<typename T> class shared_ptr; }

namespace yadiff { struct IDiffAlgo; }
struct yadiff::AlgoCfg;

std::shared_ptr<yadiff::IDiffAlgo> MakeCallerXRefMatchAlgo(const yadiff::AlgoCfg& config);
