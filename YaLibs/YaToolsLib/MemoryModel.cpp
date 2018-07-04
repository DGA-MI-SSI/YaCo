//  Copyright (C) 2017 The YaCo Authors
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include "MemoryModel.hpp"

#include "Helpers.h"
#include "IModel.hpp"
#include "HVersion.hpp"
#include "HSignature.hpp"
#include "IModelSink.hpp"
#include "ModelIndex.hpp"

#include <assert.h>
#include <functional>

#if 0
#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("std", (FMT), ## __VA_ARGS__)
#else
#define LOG(...) do {} while(0)
#endif

namespace
{
struct StdUsername
{
    StdUsername(const std::string& value, uint32_t flags)
        : value(value)
        , flags(flags)
    {
    }

    StdUsername()
        : flags(0)
    {
    }

    std::string value;
    uint32_t    flags;
};

struct StdAttribute
{
    StdAttribute(const std::string& key, const std::string& value)
        : key(key)
        , value(value)
    {
    }

    StdAttribute()
    {
    }

    std::string key;
    std::string value;
};

struct StdBlob
{
    StdBlob(const uint8_t* ptr, size_t len, uint64_t offset)
        : data(ptr, ptr+len)
        , offset(offset)
    {
    }

    StdBlob()
        : offset(0)
    {
    }

    std::vector<uint8_t>    data;
    uint64_t                offset;
};

struct StdXref
{
    StdXref(const std::vector<StdAttribute>& attributes, uint64_t offset, YaToolObjectId id, operand_t operand)
        : attributes(attributes)
        , offset(offset)
        , id(id)
        , operand(operand)
    {
    }

    StdXref()
        : offset(0)
        , id(0)
        , operand(0)
    {
    }

    std::vector<StdAttribute>   attributes;
    uint64_t                    offset;
    YaToolObjectId              id;
    operand_t                   operand;
};

struct StdComment
{
    StdComment(const std::string& value, uint64_t offset, CommentType_e type)
        : value(value)
        , offset(offset)
        , type(type)
    {
    }

    StdComment()
        : offset(0)
        , type(COMMENT_COUNT)
    {
    }

    std::string     value;
    uint64_t        offset;
    CommentType_e   type;
};

struct StdValueView
{
    StdValueView(const std::string& value, uint64_t offset, operand_t operand)
        : value(value)
        , offset(offset)
        , operand(operand)
    {
    }

    StdValueView()
        : offset(0)
        , operand(0)
    {
    }

    std::string value;
    uint64_t    offset;
    operand_t   operand;
};

struct StdRegisterView
{
    StdRegisterView(const std::string& name, const std::string& new_name, offset_t offset, offset_t end_offset)
        : name(name)
        , new_name(new_name)
        , offset(offset)
        , end_offset(end_offset)
    {
    }

    StdRegisterView()
        : offset(0)
        , end_offset(0)
    {
    }

    std::string name;
    std::string new_name;
    offset_t    offset;
    offset_t    end_offset;
};

struct StdHiddenArea
{
    StdHiddenArea(const std::string& value, uint64_t offset, uint64_t area_size)
        : value(value)
        , offset(offset)
        , area_size(area_size)
    {
    }

    StdHiddenArea()
        : offset(0)
        , area_size(0)
    {
    }

    std::string value;
    uint64_t    offset;
    uint64_t    area_size;
};

struct StdSignature
{
    StdSignature(const Signature& value, VersionIndex idx)
        : value(value)
        , idx(idx)
    {
    }

    StdSignature()
        : idx(UINT32_MAX)
    {
        memset(&value, 0, sizeof value);
    }

    Signature       value;
    VersionIndex    idx;
};

struct StdVersion
{
    StdVersion()
        : id(0)
        , idx(UINT32_MAX)
        , parent(0)
        , address(0)
        , type(OBJECT_TYPE_COUNT)
        , sig_idx(UINT32_MAX)
        , size(0)
        , offset(0)
        , flags(0)
        , strtype(UINT8_MAX)
        , xref_to_idx(UINT32_MAX)
    {
    }

    void clear()
    {
        // clear vectors but keep their capacities
        attributes.clear();
        blobs.clear();
        comments.clear();
        valueviews.clear();
        registerviews.clear();
        hiddenareas.clear();
        xrefs.clear();

        // clear strings but keep their capacities
        username.value.clear();
        prototype.clear();
        header_comment_repeatable.clear();
        header_comment_nonrepeatable.clear();

        // reset every scalars
        id = 0;
        idx = UINT32_MAX;
        parent = 0;
        address = 0;
        type = OBJECT_TYPE_COUNT;
        sig_idx = UINT32_MAX;
        size = 0;
        offset = 0;
        flags = 0;
        strtype = UINT8_MAX;
        xref_to_idx = UINT32_MAX;
    }

    std::vector<StdAttribute>       attributes;
    std::vector<StdBlob>            blobs;
    std::vector<StdComment>         comments;
    std::vector<StdValueView>       valueviews;
    std::vector<StdRegisterView>    registerviews;
    std::vector<StdHiddenArea>      hiddenareas;
    std::vector<StdXref>            xrefs;

    StdUsername                 username;
    std::string                 prototype;
    std::string                 header_comment_repeatable;
    std::string                 header_comment_nonrepeatable;

    YaToolObjectId              id;
    VersionIndex                idx;
    YaToolObjectId              parent;
    offset_t                    address;
    YaToolObjectType_e          type;
    HSignature_id_t             sig_idx;
    offset_t                    size;
    offset_t                    offset;
    uint32_t                    flags;
    uint8_t                     strtype;
    uint32_t                    xref_to_idx;
};

typedef std::unordered_map<YaToolObjectId, bool> ObjFound;

struct Model;

struct ViewVersions
    : public IVersions
{
    ViewVersions(const Model& db)
        : db_(db)
    {
    }

    void                accept(VersionIndex idx, IModelVisitor& visitor) const override;

    YaToolObjectId      id              (VersionIndex idx) const override;
    YaToolObjectId      parent_id       (VersionIndex idx) const override;
    offset_t            size            (VersionIndex idx) const override;
    YaToolObjectType_e  type            (VersionIndex idx) const override;
    offset_t            address         (VersionIndex idx) const override;
    const_string_ref    username        (VersionIndex idx) const override;
    int                 username_flags  (VersionIndex idx) const override;
    const_string_ref    prototype       (VersionIndex idx) const override;
    flags_t             flags           (VersionIndex idx) const override;
    int                 string_type     (VersionIndex idx) const override;
    const_string_ref    header_comment  (VersionIndex idx, bool repeatable) const override;
    bool                has_signature   (VersionIndex idx) const override;

    void                walk_signatures         (VersionIndex idx, const OnSignatureFn& fnWalk) const override;
    void                walk_xrefs_from         (VersionIndex idx, const OnXrefFromFn& fnWalk) const override;
    void                walk_xrefs_to           (VersionIndex idx, const OnVersionFn& fnWalk) const override;
    void                walk_blobs              (VersionIndex idx, const OnBlobFn& fnWalk) const override;
    void                walk_comments           (VersionIndex idx, const OnCommentFn& fnWalk) const override;
    void                walk_value_views        (VersionIndex idx, const OnValueViewFn& fnWalk) const override;
    void                walk_register_views     (VersionIndex idx, const OnRegisterViewFn& fnWalk) const override;
    void                walk_hidden_areas       (VersionIndex idx, const OnHiddenAreaFn& fnWalk) const override;
    void                walk_xrefs              (VersionIndex idx, const OnXrefFn& fnWalk) const override;
    void                walk_xref_attributes    (VersionIndex idx, const XrefAttributes* hattr, const OnAttributeFn& fnWalk) const override;
    void                walk_attributes         (VersionIndex idx, const OnAttributeFn& fnWalk) const override;

    const Model& db_;
};

struct ViewSignatures
    : public ISignatures
{
    ViewSignatures(const Model& db)
        : db_(db)
    {
    }

    Signature get(HSignature_id_t id) const override;

    const Model& db_;
};

struct Model
    : public IModelAndVisitor
{
    Model();

    // IModelVisitor
    void visit_start() override;
    void visit_end() override;
    void visit_start_version(YaToolObjectType_e type, YaToolObjectId id) override;
    void visit_deleted(YaToolObjectType_e type, YaToolObjectId id) override;
    void visit_end_version() override;
    void visit_parent_id(YaToolObjectId id) override;
    void visit_address(offset_t address) override;
    void visit_name(const const_string_ref& name, int flags) override;
    void visit_size(offset_t size) override;
    void visit_start_signatures() override;
    void visit_signature(SignatureMethod_e method, SignatureAlgo_e algo, const const_string_ref& hex) override;
    void visit_end_signatures() override;
    void visit_prototype(const const_string_ref& prototype) override;
    void visit_string_type(int str_type) override;
    void visit_header_comment(bool repeatable, const const_string_ref& comment) override;
    void visit_start_offsets() override;
    void visit_end_offsets() override;
    void visit_offset_comments(offset_t offset, CommentType_e comment_type, const const_string_ref& comment) override;
    void visit_offset_valueview(offset_t offset, operand_t operand, const const_string_ref& view_value) override;
    void visit_offset_registerview(offset_t offset, offset_t end_offset, const const_string_ref& register_name, const const_string_ref& register_new_name) override;
    void visit_offset_hiddenarea(offset_t offset, offset_t area_size, const const_string_ref& hidden_area_value) override;
    void visit_start_xrefs() override;
    void visit_end_xrefs() override;
    void visit_start_xref(offset_t offset, YaToolObjectId offset_value, operand_t operand) override;
    void visit_end_xref() override;
    void visit_xref_attribute(const const_string_ref& attribute_key, const const_string_ref& attribute_value) override;
    void visit_segments_start() override;
    void visit_segments_end() override;
    void visit_attribute(const const_string_ref& attr_name, const const_string_ref& attr_value) override;
    void visit_blob(offset_t offset, const void* blob, size_t len) override;
    void visit_flags(flags_t flags) override;


    // IModel
    void        accept          (IModelVisitor& visitor) override;
    void        walk            (const OnVersionFn& fnWalk) const override;
    size_t      size            () const override;
    size_t      size_matching   (const HSignature& hash) const override;
    void        walk_matching   (const HSignature& hash, const OnVersionFn& fnWalk) const override;
    HVersion    get             (YaToolObjectId id) const override;
    bool        has             (YaToolObjectId id) const override;
    void        walk_uniques    (const OnSignatureFn& fnWalk) const override;
    void        walk_matching   (const HVersion& object, size_t min_size, const OnVersionFn& fnWalk) const override;

    ViewVersions                    view_versions_;
    ViewSignatures                  view_signatures_;
    StdVersion                      current_;
    std::vector<StdVersion>         versions_;
    std::vector<StdSignature>       signatures_;
    std::vector<StdVersion>         deleted_;
    std::vector<const StdVersion*>  ordered_;
    ModelIndex                      index_;
};
}

Model::Model()
    : view_versions_    (*this)
    , view_signatures_  (*this)
{
}

std::shared_ptr<IModelAndVisitor> MakeMemoryModel()
{
    return std::make_shared<Model>();
}

void Model::visit_start()
{
}

namespace
{
template<typename T>
void walk_xrefs_to(const Model& db, const StdVersion& object, const T& operand)
{
    walk_xrefs(db.index_, object.idx, object.xref_to_idx, [&](VersionIndex idx)
    {
        return operand(idx);
    });
}

template<typename T>
void walk_signatures(const Model& db, const StdVersion& ver, const T& operand)
{
    optional<VersionIndex> idx;
    const auto end = db.signatures_.size();
    for(auto i = ver.sig_idx; i < end; ++i)
    {
        const auto& sig = db.signatures_[i];
        if(idx && *idx != sig.idx)
            return;
        idx = sig.idx;
        if(operand(i, sig) == WALK_STOP)
            return;
    }
}

template<typename T>
void walk_xrefs(const Model&, const StdVersion& version, const T& operand)
{
    for(const auto& xref : version.xrefs)
        if(operand(xref) != WALK_CONTINUE)
            return;
}

void accept_version(const Model& db, const StdVersion& version, IModelVisitor& visitor)
{
    visitor.visit_start_version(version.type, version.id);
    visitor.visit_size(version.size);
    visitor.visit_parent_id(version.parent);
    visitor.visit_address(version.address);

    if(!version.username.value.empty())
        visitor.visit_name(make_string_ref(version.username.value), version.username.flags);

    if(!version.prototype.empty())
        visitor.visit_prototype(make_string_ref(version.prototype));

    visitor.visit_flags(version.flags);

    const auto string_type = version.strtype;
    if(string_type != UINT8_MAX)
        visitor.visit_string_type(string_type);

    // signatures
    visitor.visit_start_signatures();
    walk_signatures(db, version, [&](HSignature_id_t, const StdSignature& sig)
    {
        const auto& s = sig.value;
        visitor.visit_signature(s.method, s.algo, make_string_ref(s.buffer));
        return WALK_CONTINUE;
    });
    visitor.visit_end_signatures();

    if(!version.header_comment_repeatable.empty())
        visitor.visit_header_comment(true, make_string_ref(version.header_comment_repeatable));

    if(!version.header_comment_nonrepeatable.empty())
        visitor.visit_header_comment(false, make_string_ref(version.header_comment_nonrepeatable));

    // offsets
    if(!version.comments.empty() || !version.valueviews.empty() || !version.registerviews.empty() || !version.hiddenareas.empty())
    {
        visitor.visit_start_offsets();
        for(const auto& comment : version.comments)
            visitor.visit_offset_comments(comment.offset, comment.type, make_string_ref(comment.value));
        for(const auto& view : version.valueviews)
            visitor.visit_offset_valueview(view.offset, view.operand, make_string_ref(view.value));
        for(const auto& view : version.registerviews)
            visitor.visit_offset_registerview(view.offset, view.end_offset, make_string_ref(view.name), make_string_ref(view.new_name));
        for(const auto& hidden : version.hiddenareas)
            visitor.visit_offset_hiddenarea(hidden.offset, hidden.area_size, make_string_ref(hidden.value));
        visitor.visit_end_offsets();
    }

    // xrefs
    visitor.visit_start_xrefs();
    walk_xrefs(db, version, [&](const StdXref& xref)
    {
        visitor.visit_start_xref(xref.offset, xref.id, xref.operand);
        for(const auto& attr : xref.attributes)
            visitor.visit_xref_attribute(make_string_ref(attr.key), make_string_ref(attr.value));
        visitor.visit_end_xref();
        return WALK_CONTINUE;
    });
    visitor.visit_end_xrefs();

    // attributes
    for(const auto& attr : version.attributes)
        visitor.visit_attribute(make_string_ref(attr.key), make_string_ref(attr.value));

    // blobs
    for(const auto& blob : version.blobs)
        visitor.visit_blob(blob.offset, &blob.data[0], blob.data.size());

    visitor.visit_end_version();
}

void finish_index(Model& db)
{
    finish_indexs(db.index_);

    for(const auto& version : db.versions_)
        for(const auto& xref : version.xrefs)
            add_xref_to(db.index_, version.idx, xref.id);

    finish_xrefs(db.index_, [&](VersionIndex to, uint32_t xref_to_idx)
    {
        auto& obj = db.versions_[to];
        assert(obj.idx == to);
        auto& idx = obj.xref_to_idx;
        idx = std::min(idx, xref_to_idx);
    });

    SigMap sigmap;
    HSignature_id_t sig_id = 0;
    for(const auto& sig : db.signatures_)
        add_sig(db.index_, sigmap, make_string_ref(sig.value), sig_id++);
    finish_sigs(db.index_, sigmap);
}
}

void Model::visit_end()
{
    finish_index(*this);

    // sort objects by type
    ordered_.reserve(versions_.size());
    for(const auto& it : versions_)
        ordered_.emplace_back(&it);
    std::sort(ordered_.begin(), ordered_.end(), [](const auto& a, const auto& b)
    {
        return std::make_pair(indexed_types[a->type], a->id) < std::make_pair(indexed_types[b->type], b->id);
    });
}

void Model::visit_start_version(YaToolObjectType_e type, YaToolObjectId id)
{
    current_.clear();
    current_.type = type;
    current_.idx = static_cast<VersionIndex>(versions_.size());
    current_.id = id;
}

void Model::visit_deleted(YaToolObjectType_e type, YaToolObjectId id)
{
    visit_start_version(type, id);
    deleted_.emplace_back(current_);
}

void Model::visit_end_version()
{
    versions_.emplace_back(current_);
    add_index(index_, current_.id, current_.idx);
}

void Model::visit_parent_id(YaToolObjectId id)
{
    current_.parent = id;
}

void Model::visit_address(offset_t address)
{
    current_.address = address;
}

void Model::visit_name(const const_string_ref& name, int flags)
{
    current_.username.value = make_string(name);
    current_.username.flags = flags;
}

void Model::visit_size(offset_t size)
{
    current_.size = size;
}

void Model::visit_start_signatures()
{
}

void Model::visit_signature(SignatureMethod_e method, SignatureAlgo_e algo, const const_string_ref& hex)
{
    const auto sig_idx = static_cast<HSignature_id_t>(signatures_.size());
    current_.sig_idx = std::min(current_.sig_idx, sig_idx);
    const auto idx = static_cast<VersionIndex>(versions_.size());
    signatures_.push_back({MakeSignature(algo, method, hex), idx});
}

void Model::visit_end_signatures()
{
}

void Model::visit_prototype(const const_string_ref& prototype)
{
    current_.prototype = make_string(prototype);
}

void Model::visit_string_type(int strtype)
{
    current_.strtype = static_cast<uint8_t>(strtype);
}

void Model::visit_header_comment(bool repeatable, const const_string_ref& comment)
{
    auto& dst = repeatable ? current_.header_comment_repeatable : current_.header_comment_nonrepeatable;
    dst = make_string(comment);
}

void Model::visit_start_offsets()
{
}

void Model::visit_end_offsets()
{
}

void Model::visit_offset_comments(offset_t offset, CommentType_e comment_type, const const_string_ref& comment)
{
    current_.comments.emplace_back(make_string(comment), offset, comment_type);
}

void Model::visit_offset_valueview(offset_t offset, operand_t operand, const const_string_ref& view_value)
{
    current_.valueviews.emplace_back(make_string(view_value), offset, operand);
}

void Model::visit_offset_registerview(offset_t offset, offset_t end_offset, const const_string_ref& register_name, const const_string_ref& register_new_name)
{
    current_.registerviews.emplace_back(make_string(register_name), make_string(register_new_name), offset, end_offset);
}

void Model::visit_offset_hiddenarea(offset_t offset, offset_t area_size, const const_string_ref& hidden_area_value)
{
    current_.hiddenareas.emplace_back(make_string(hidden_area_value), offset, area_size);
}

void Model::visit_start_xrefs()
{
    current_.xrefs.clear();
}

void Model::visit_end_xrefs()
{
}

void Model::visit_start_xref(offset_t offset, YaToolObjectId id, operand_t operand)
{
    current_.xrefs.emplace_back(std::vector<StdAttribute>(), offset, id, operand);
}

void Model::visit_xref_attribute(const const_string_ref& key, const const_string_ref& value)
{
    current_.xrefs.back().attributes.emplace_back(make_string(key), make_string(value));
}

void Model::visit_end_xref()
{
}

void Model::visit_segments_start()
{
}

void Model::visit_segments_end()
{
}

void Model::visit_attribute(const const_string_ref& key, const const_string_ref& value)
{
    current_.attributes.push_back({make_string(key), make_string(value)});
}

void Model::visit_blob(offset_t offset, const void* blob, size_t len)
{
    const uint8_t* ptr = static_cast<const uint8_t*>(blob);
    current_.blobs.emplace_back(ptr, len, offset);
}

void Model::visit_flags(flags_t flags)
{
    current_.flags = flags;
}

void Model::accept(IModelVisitor& visitor)
{
    visitor.visit_start();
    for(const auto it : deleted_)
        visitor.visit_deleted(it.type, it.id);
    for(const auto& version : versions_)
        accept_version(*this, version, visitor);
    visitor.visit_end();
}

void Model::walk(const OnVersionFn& fnWalk) const
{
    for(const auto& it : ordered_)
        if(fnWalk({&view_versions_, it->idx}) != WALK_CONTINUE)
            return;
}

size_t Model::size() const
{
    return versions_.size();
}

void Model::walk_matching(const HSignature& hash, const OnVersionFn& fnWalk) const
{
    walk_sigs(index_, make_string_ref(hash.get()), [&](const Sig& sig)
    {
        return fnWalk({&view_versions_, signatures_[sig.idx].idx});
    });
}

size_t Model::size_matching(const HSignature& hash) const
{
    return num_sigs(index_, make_string_ref(hash.get()));
}

void Model::walk_matching(const HVersion& remoteVersion, size_t min_size, const OnVersionFn& fnWalk) const
{
    // iterate over remote signatures
    ContinueWalking_e stop_current_iteration = WALK_CONTINUE;
    remoteVersion.walk_signatures([&](const HSignature& remote)
    {
        walk_sigs(index_, make_string_ref(remote.get()), [&](const Sig& sig)
        {
            const auto version_id = signatures_[sig.idx].idx;
            const auto& version = versions_[version_id];
            if(version.size != remoteVersion.size())
                return WALK_CONTINUE;
            if(!is_unique_sig(index_, sig.key) && version.size < min_size)
                return WALK_CONTINUE;
            if(fnWalk({&view_versions_, version_id}) != WALK_STOP)
                return WALK_CONTINUE;
            stop_current_iteration = WALK_STOP;
            return stop_current_iteration;
        });
        return stop_current_iteration;
    });
}

void Model::walk_uniques(const OnSignatureFn& fnWalk) const
{
    walk_all_unique_sigs(index_, [&](const Sig& sig)
    {
        return fnWalk({&view_versions_, signatures_[sig.idx].idx}, {&view_signatures_, sig.idx});
    });
}

HVersion Model::get(YaToolObjectId id) const
{
    if(const auto idx = find_index(index_, id))
        return{&view_versions_, *idx};
    return{nullptr, 0};
}

bool Model::has(YaToolObjectId id) const
{
    return !!find_index(index_, id);
}

bool ViewVersions::has_signature(VersionIndex idx) const
{
    bool found = false;
    ::walk_signatures(db_, db_.versions_[idx], [&](HSignature_id_t, const StdSignature&)
    {
        found = true;
        return WALK_STOP;
    });
    return found;
}

void ViewVersions::accept(VersionIndex idx, IModelVisitor& visitor) const
{
    accept_version(db_, db_.versions_[idx], visitor);
}

YaToolObjectId ViewVersions::id(VersionIndex idx) const
{
    return db_.versions_[idx].id;
}

YaToolObjectId ViewVersions::parent_id(VersionIndex idx) const
{
    return db_.versions_[idx].parent;
}

offset_t ViewVersions::size(VersionIndex idx) const
{
    return db_.versions_[idx].size;
}

YaToolObjectType_e ViewVersions::type(VersionIndex idx) const
{
    return db_.versions_[idx].type;
}

offset_t ViewVersions::address(VersionIndex idx) const
{
    return db_.versions_[idx].address;
}

const_string_ref ViewVersions::username(VersionIndex idx) const
{
    return make_string_ref(db_.versions_[idx].username.value);
}

int ViewVersions::username_flags(VersionIndex idx) const
{
    return db_.versions_[idx].username.flags;
}

const_string_ref ViewVersions::prototype(VersionIndex idx) const
{
    return make_string_ref(db_.versions_[idx].prototype);
}

flags_t ViewVersions::flags(VersionIndex idx) const
{
    return db_.versions_[idx].flags;
}

int ViewVersions::string_type(VersionIndex idx) const
{
    return db_.versions_[idx].strtype;
}

const_string_ref ViewVersions::header_comment(VersionIndex idx, bool repeatable) const
{
    const auto& version = db_.versions_[idx];
    const auto& value = repeatable ? version.header_comment_repeatable : version.header_comment_nonrepeatable;
    return make_string_ref(value);
}

void ViewVersions::walk_signatures(VersionIndex idx, const OnSignatureFn& fnWalk) const
{
    ::walk_signatures(db_, db_.versions_[idx], [&](HSignature_id_t id, const StdSignature&)
    {
        return fnWalk({&db_.view_signatures_, id});
    });
}

void ViewVersions::walk_xrefs_from(VersionIndex idx, const OnXrefFromFn& fnWalk) const
{
    ::walk_xrefs(db_, db_.versions_[idx], [&](const StdXref& xref)
    {
        const auto ref = db_.get(xref.id);
        if(!ref.is_valid())
            return WALK_CONTINUE;
        return fnWalk(xref.offset, xref.operand, ref);
    });
}

void ViewVersions::walk_xrefs_to(VersionIndex idx, const OnVersionFn& fnWalk) const
{
    ::walk_xrefs_to(db_, db_.versions_[idx], [&](VersionIndex to)
    {
        return fnWalk({this, to});
    });
}

void ViewVersions::walk_blobs(VersionIndex idx, const OnBlobFn& fnWalk) const
{
    for(const auto& blob : db_.versions_[idx].blobs)
        if(fnWalk(blob.offset, &blob.data[0], blob.data.size()) != WALK_CONTINUE)
            return;
}

void ViewVersions::walk_comments(VersionIndex idx, const OnCommentFn& fnWalk) const
{
    for(const auto& comment : db_.versions_[idx].comments)
        if(fnWalk(comment.offset, comment.type, make_string_ref(comment.value)) != WALK_CONTINUE)
            return;
}

void ViewVersions::walk_value_views(VersionIndex idx, const OnValueViewFn& fnWalk) const
{
    for(const auto& view : db_.versions_[idx].valueviews)
        if(fnWalk(view.offset, view.operand, make_string_ref(view.value)) != WALK_CONTINUE)
            return;
}

void ViewVersions::walk_register_views(VersionIndex idx, const OnRegisterViewFn& fnWalk) const
{
    for(const auto& view : db_.versions_[idx].registerviews)
        if(fnWalk(view.offset, view.end_offset, make_string_ref(view.name), make_string_ref(view.new_name)) != WALK_CONTINUE)
            return;
}

void ViewVersions::walk_hidden_areas(VersionIndex idx, const OnHiddenAreaFn& fnWalk) const
{
    for(const auto& hidden : db_.versions_[idx].hiddenareas)
        if(fnWalk(hidden.offset, hidden.area_size, make_string_ref(hidden.value)) != WALK_CONTINUE)
            return;
}

void ViewVersions::walk_xrefs(VersionIndex idx, const OnXrefFn& fnWalk) const
{
    ::walk_xrefs(db_, db_.versions_[idx], [&](const StdXref& xref)
    {
        return fnWalk(xref.offset, xref.operand, xref.id, reinterpret_cast<const XrefAttributes*>(&xref));
    });
}

void ViewVersions::walk_xref_attributes(VersionIndex, const XrefAttributes* hattr, const OnAttributeFn& fnWalk) const
{
    const StdXref* xref = reinterpret_cast<const StdXref*>(hattr);
    for(const auto& attr : xref->attributes)
        if(fnWalk(make_string_ref(attr.key), make_string_ref(attr.value)) != WALK_CONTINUE)
            return;
}

void ViewVersions::walk_attributes(VersionIndex idx, const OnAttributeFn& fnWalk) const
{
    for(const auto& attr : db_.versions_[idx].attributes)
        if(fnWalk(make_string_ref(attr.key), make_string_ref(attr.value)) != WALK_CONTINUE)
            return;
}

Signature ViewSignatures::get(HSignature_id_t id) const
{
    return db_.signatures_[id].value;
}