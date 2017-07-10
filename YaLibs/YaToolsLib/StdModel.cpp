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

#include "StdModel.hpp"

#include "../Helpers.h"
#include "IModel.hpp"
#include "HObject.hpp"
#include "HVersion.hpp"
#include "HSignature.hpp"
#include "IObjectListener.hpp"
#include "ModelIndex.hpp"

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

struct StdOffset
{
    StdOffset(uint64_t offset, HSystem_id_t system_idx)
        : offset(offset)
        , system_idx(system_idx)
    {
    }

    StdOffset()
        : offset(0)
        , system_idx(UINT32_MAX)
    {
    }

    uint64_t        offset;
    HSystem_id_t    system_idx;
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
    StdSignature(const Signature& value, HVersion_id_t version_idx)
        : value(value)
        , version_idx(version_idx)
    {
    }

    StdSignature()
        : version_idx(UINT32_MAX)
    {
        memset(&value, 0, sizeof value);
    }

    Signature       value;
    HVersion_id_t   version_idx;
};

struct StdVersion
{
    StdVersion()
        : id(0)
        , parent(0)
        , address(0)
        , type(OBJECT_TYPE_COUNT)
        , object_idx(UINT32_MAX)
        , sig_idx(UINT32_MAX)
        , size(0)
        , offset(0)
        , flags(0)
        , strtype(UINT8_MAX)
    {
    }

    void reset()
    {
        // clear vectors but keep their capacities
        attributes.clear();
        blobs.clear();
        comments.clear();
        valueviews.clear();
        registerviews.clear();
        hiddenareas.clear();
        offsets.clear();
        xrefs.clear();

        // clear strings but keep their capacities
        username.value.clear();
        prototype.clear();
        header_comment_repeatable.clear();
        header_comment_nonrepeatable.clear();

        // reset every scalars
        id = 0;
        parent = 0;
        address = 0;
        type = OBJECT_TYPE_COUNT;
        object_idx = UINT32_MAX;
        sig_idx = UINT32_MAX;
        size = 0;
        offset = 0;
        flags = 0;
        strtype = UINT8_MAX;
    }

    std::vector<StdAttribute>       attributes;
    std::vector<StdBlob>            blobs;
    std::vector<StdComment>         comments;
    std::vector<StdValueView>       valueviews;
    std::vector<StdRegisterView>    registerviews;
    std::vector<StdHiddenArea>      hiddenareas;
    std::vector<StdOffset>          offsets;
    std::vector<StdXref>            xrefs;

    StdUsername                 username;
    std::string                 prototype;
    std::string                 header_comment_repeatable;
    std::string                 header_comment_nonrepeatable;

    YaToolObjectId              id;
    YaToolObjectId              parent;
    offset_t                    address;
    YaToolObjectType_e          type;
    HObject_id_t                object_idx;
    HSignature_id_t             sig_idx;
    offset_t                    size;
    offset_t                    offset;
    uint32_t                    flags;
    uint8_t                     strtype;
};

struct StdObject
{
    StdObject()
        : id(0)
        , type(OBJECT_TYPE_COUNT)
        , idx(UINT32_MAX)
        , version_idx(UINT32_MAX)
        , xref_to_idx(UINT32_MAX)
    {
    }

    void reset()
    {
        *this = {};
    }

    YaToolObjectId      id;
    YaToolObjectType_e  type;
    HObject_id_t        idx;
    HVersion_id_t       version_idx;
    uint32_t            xref_to_idx;
};

struct StdSystem
{
    StdSystem(const std::string& eq, const std::string& os)
        : equipment(eq)
        , os(os)
    {
    }

    StdSystem()
    {
    }

    std::string equipment;
    std::string os;
};

typedef std::unordered_map<YaToolObjectId, bool> ObjFound;

struct Current
{
    StdObject   object;
    StdVersion  version;
    StdSystem   system;
    uint64_t    offset;
    bool        is_default;
    bool        is_deleted;
};

struct StdModel;

struct ViewObjects
    : public IObjects
{
    ViewObjects(const StdModel& db)
        : db_(db)
    {
    }

    // IObjects methods
    void                accept          (HObject_id_t object_id, IModelVisitor& visitor) const override;
    YaToolObjectType_e  type            (HObject_id_t object_id) const override;
    YaToolObjectId      id              (HObject_id_t object_id) const override;
    bool                has_signature   (HObject_id_t object_id) const override;
    void                walk_versions   (HObject_id_t object_id, const OnVersionFn& fnWalk) const override;
    void                walk_xrefs_from (HObject_id_t object_id, const OnXrefFromFn& fnWalk) const override;
    void                walk_xrefs_to   (HObject_id_t object_id, const OnObjectFn& fnWalk) const override;
    bool                match           (HObject_id_t object_id, const HObject& remote) const override;

    const StdModel& db_;
};

struct ViewVersions
    : public IVersions
{
    ViewVersions(const StdModel& db)
        : db_(db)
    {
    }

    void                accept(HVersion_id_t version_id, IModelVisitor& visitor) const override;

    YaToolObjectId      id              (HVersion_id_t version_id) const override;
    YaToolObjectId      parent_id       (HVersion_id_t version_id) const override;
    offset_t            size            (HVersion_id_t version_id) const override;
    YaToolObjectType_e  type            (HVersion_id_t version_id) const override;
    offset_t            address         (HVersion_id_t version_id) const override;
    const_string_ref    username        (HVersion_id_t version_id) const override;
    int                 username_flags  (HVersion_id_t version_id) const override;
    const_string_ref    prototype       (HVersion_id_t version_id) const override;
    YaToolFlag_T        flags           (HVersion_id_t version_id) const override;
    int                 string_type     (HVersion_id_t version_id) const override;
    const_string_ref    header_comment  (HVersion_id_t version_id, bool repeatable) const override;

    void                walk_signatures         (HVersion_id_t version_id, const OnSignatureFn& fnWalk) const override;
    void                walk_xrefs_from         (HVersion_id_t version_id, const OnXrefFromFn& fnWalk) const override;
    void                walk_xrefs_to           (HVersion_id_t version_id, const OnObjectFn& fnWalk) const override;
    void                walk_blobs              (HVersion_id_t version_id, const OnBlobFn& fnWalk) const override;
    void                walk_comments           (HVersion_id_t version_id, const OnCommentFn& fnWalk) const override;
    void                walk_value_views        (HVersion_id_t version_id, const OnValueViewFn& fnWalk) const override;
    void                walk_register_views     (HVersion_id_t version_id, const OnRegisterViewFn& fnWalk) const override;
    void                walk_hidden_areas       (HVersion_id_t version_id, const OnHiddenAreaFn& fnWalk) const override;
    void                walk_xrefs              (HVersion_id_t version_id, const OnXrefFn& fnWalk) const override;
    void                walk_xref_attributes    (HVersion_id_t version_id, const XrefAttributes* hattr, const OnAttributeFn& fnWalk) const override;
    void                walk_systems            (HVersion_id_t version_id, const OnSystemFn& fnWalk) const override;
    void                walk_system_attributes  (HVersion_id_t version_id, HSystem_id_t system, const OnAttributeFn& fnWalk) const override;
    void                walk_attributes         (HVersion_id_t version_id, const OnAttributeFn& fnWalk) const override;

    const StdModel& db_;
};

struct ViewSignatures
    : public ISignatures
{
    ViewSignatures(const StdModel& db)
        : db_(db)
    {
    }

    Signature get(HSignature_id_t id) const override;

    const StdModel& db_;
};

struct StdModel
    : public IModelVisitor
    , public IModel
{
    StdModel(IObjectListener* listener);

    // IModelVisitor
    void visit_start() override;
    void visit_end() override;
    void visit_start_object(YaToolObjectType_e type) override;
    void visit_start_reference_object(YaToolObjectType_e type) override;
    void visit_start_deleted_object(YaToolObjectType_e type) override;
    void visit_start_default_object(YaToolObjectType_e type) override;
    void visit_end_deleted_object() override;
    void visit_end_default_object() override;
    void visit_end_reference_object() override;
    void visit_id(YaToolObjectId id) override;
    void visit_start_object_version() override;
    void visit_parent_id(YaToolObjectId id) override;
    void visit_address(offset_t address) override;
    void visit_end_object_version() override;
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
    void visit_start_matching_systems() override;
    void visit_end_matching_systems() override;
    void visit_start_matching_system(offset_t address) override;
    void visit_matching_system_description(const const_string_ref& description_key, const const_string_ref& description_value) override;
    void visit_end_matching_system() override;
    void visit_segments_start() override;
    void visit_segments_end() override;
    void visit_attribute(const const_string_ref& attr_name, const const_string_ref& attr_value) override;
    void visit_blob(offset_t offset, const void* blob, size_t len) override;
    void visit_flags(flags_t flags) override;

    // IModelAccept
    void accept(IModelVisitor& visitor) override;

    // IModel
    void    walk_objects                    (const OnObjectAndIdFn& fnWalk) const override;
    size_t  num_objects                     () const override;
    void    walk_objects_with_signature     (const HSignature& hash, const OnObjectFn& fnWalk) const override;
    size_t  num_objects_with_signature      (const HSignature& hash) const override;
    void    walk_versions_with_signature    (const HSignature& hash, const OnVersionFn& fnWalk) const override;
    HObject get_object                      (YaToolObjectId id) const override;
    bool    has_object                      (YaToolObjectId id) const override;
    void    walk_versions_without_collision (const OnSigAndVersionFn& fnWalk) const override;
    void    walk_systems                    (const OnSystemFn& fnWalk) const override;
    void    walk_matching_versions          (const HObject& object, size_t min_size, const OnVersionPairFn& fnWalk) const override;

    IObjectListener*            listener_;
    ViewObjects                 view_objects_;
    ViewVersions                view_versions_;
    ViewSignatures              view_signatures_;
    std::unique_ptr<Current>    current_;
    std::vector<StdObject>      objects_;
    std::vector<StdVersion>     versions_;
    std::vector<StdSignature>   signatures_;
    std::vector<StdSystem>      systems_;
    std::vector<YaToolObjectId> deleted_;
    std::vector<YaToolObjectId> default_;
    ModelIndex                  index_;
};
}

StdModel::StdModel(IObjectListener* listener)
    : listener_         (listener)
    , view_objects_     (*this)
    , view_versions_    (*this)
    , view_signatures_  (*this)
{
}

StdModelAndVisitor MakeStdModel()
{
    const auto ptr = std::make_shared<StdModel>(nullptr);
    return {ptr, ptr};
}

std::shared_ptr<IModelVisitor> MakeVisitorFromListener(IObjectListener& listener)
{
    return std::make_shared<StdModel>(&listener);
}

void StdModel::visit_start()
{
    current_ = std::make_unique<Current>();
}

namespace
{
template<typename T>
void walk_versions(const StdModel& db, const StdObject& object, const T& operand)
{
    const auto end = db.versions_.size();
    for(auto i = object.version_idx; i < end; ++i)
    {
        const auto& version = db.versions_[i];
        if(object.idx != version.object_idx)
            break;
        if(operand(i, version) == WALK_STOP)
            break;
    }
}

template<typename T>
void walk_xrefs_to(const StdModel& db, const StdObject& object, const T& operand)
{
    walk_xrefs(db.index_, object.idx, object.xref_to_idx, [&](HObject_id_t from)
    {
        return operand(from);
    });
}

template<typename T>
void walk_signatures(const StdModel& db, const StdVersion& ver, const T& operand)
{
    optional<HVersion_id_t> version_idx;
    const auto end = db.signatures_.size();
    for(auto i = ver.sig_idx; i < end; ++i)
    {
        const auto& sig = db.signatures_[i];
        if(version_idx && *version_idx != sig.version_idx)
            return;
        version_idx = sig.version_idx;
        if(operand(i, sig) == WALK_STOP)
            return;
    }
}

template<typename T>
void walk_systems(const StdModel&, const StdVersion& ver, const T& operand)
{
    for(const auto& offset : ver.offsets)
        if(operand(offset) != WALK_CONTINUE)
            return;
}

template<typename T>
void walk_xrefs(const StdModel&, const StdVersion& version, const T& operand)
{
    for(const auto& xref : version.xrefs)
        if(operand(xref) != WALK_CONTINUE)
            return;
}

const char               gEquipment[] = "equipment";
const char               gOs[] = "os";
const const_string_ref   gEquipmentRef = {gEquipment, sizeof gEquipment - 1};
const const_string_ref   gOsRef = {gOs, sizeof gOs - 1};

void accept_version(const StdModel& db, const StdVersion& version, IModelVisitor& visitor)
{
    visitor.visit_start_object_version();
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

    // matching system
    visitor.visit_start_matching_systems();
    walk_systems(db, version, [&](const StdOffset& offset)
    {
        visitor.visit_start_matching_system(offset.offset);
        const auto& sys = db.systems_[offset.system_idx];
        visitor.visit_matching_system_description(gEquipmentRef, make_string_ref(sys.equipment));
        visitor.visit_matching_system_description(gOsRef, make_string_ref(sys.os));
        visitor.visit_end_matching_system();
        return WALK_CONTINUE;
    });
    visitor.visit_end_matching_systems();

    // attributes
    for(const auto& attr : version.attributes)
        visitor.visit_attribute(make_string_ref(attr.key), make_string_ref(attr.value));

    // blobs
    for(const auto& blob : version.blobs)
        visitor.visit_blob(blob.offset, &blob.data[0], blob.data.size());

    visitor.visit_end_object_version();
}

void accept_object(const StdModel& db, const StdObject& object, IModelVisitor& visitor)
{
    visitor.visit_start_reference_object(object.type);
    visitor.visit_id(object.id);
    walk_versions(db, object, [&](HVersion_id_t, const StdVersion& version)
    {
        accept_version(db, version, visitor);
        return WALK_CONTINUE;
    });
    visitor.visit_end_reference_object();
}

void finish_index(StdModel& db)
{
    finish_objects(db.index_);

    for(const auto& version : db.versions_)
        for(const auto& xref : version.xrefs)
            add_xref_to(db.index_, version.object_idx, xref.id);

    finish_xrefs(db.index_, [&](HObject_id_t to, uint32_t xref_to_idx)
    {
        auto& obj = db.objects_[to];
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

void StdModel::visit_end()
{
    finish_index(*this);
    current_.reset();
    if(!listener_)
        return;

    for(HObject_id_t id = 0, end = static_cast<HObject_id_t>(objects_.size()); id < end; ++id)
        listener_->on_object({&view_objects_, id});
    for(const auto id : default_)
        listener_->on_default(id);
    for(const auto id : deleted_)
        listener_->on_deleted(id);

}

void StdModel::visit_start_object(YaToolObjectType_e type)
{
    current_->is_deleted = false;
    current_->is_default = false;
    current_->object.reset();
    current_->object.type = type;
    current_->object.idx = static_cast<HObject_id_t>(objects_.size());
    current_->object.version_idx = static_cast<HVersion_id_t>(versions_.size());
}

void StdModel::visit_start_reference_object(YaToolObjectType_e type)
{
    visit_start_object(type);
}

void StdModel::visit_start_deleted_object(YaToolObjectType_e)
{
    current_->is_deleted = true;
}

void StdModel::visit_start_default_object(YaToolObjectType_e)
{
    current_->is_default = true;
}

void StdModel::visit_end_deleted_object()
{
    visit_end_reference_object();
}

void StdModel::visit_end_default_object()
{
    visit_end_reference_object();
}

void StdModel::visit_end_reference_object()
{
    if(current_->is_deleted)
    {
        deleted_.emplace_back(current_->object.id);
        return;
    }
    if(current_->is_default)
    {
        default_.emplace_back(current_->object.id);
        return;
    }

    objects_.emplace_back(current_->object);
    add_object(index_, current_->object.id, current_->object.idx);
}

void StdModel::visit_id(YaToolObjectId id)
{
    current_->object.id = id;
}

void StdModel::visit_start_object_version()
{
    current_->version.reset();
    current_->version.object_idx = static_cast<HObject_id_t>(objects_.size());
    current_->version.id = current_->object.id;
    current_->version.type = current_->object.type;
}

void StdModel::visit_parent_id(YaToolObjectId id)
{
    current_->version.parent = id;
}

void StdModel::visit_address(offset_t address)
{
    current_->version.address = address;
}

void StdModel::visit_end_object_version()
{
    std::sort(current_->version.offsets.begin(), current_->version.offsets.end(), [](const auto& a, const auto& b)
    {
        return a.offset < b.offset;
    });
    versions_.emplace_back(current_->version);
}

void StdModel::visit_name(const const_string_ref& name, int flags)
{
    current_->version.username.value = make_string(name);
    current_->version.username.flags = flags;
}

void StdModel::visit_size(offset_t size)
{
    current_->version.size = size;
}

void StdModel::visit_start_signatures()
{
}

void StdModel::visit_signature(SignatureMethod_e method, SignatureAlgo_e algo, const const_string_ref& hex)
{
    const auto sig_idx = static_cast<HSignature_id_t>(signatures_.size());
    current_->version.sig_idx = std::min(current_->version.sig_idx, sig_idx);
    const auto ver_idx = static_cast<HVersion_id_t>(versions_.size());
    signatures_.push_back({MakeSignature(algo, method, hex), ver_idx});
}

void StdModel::visit_end_signatures()
{
}

void StdModel::visit_prototype(const const_string_ref& prototype)
{
    current_->version.prototype = make_string(prototype);
}

void StdModel::visit_string_type(int strtype)
{
    current_->version.strtype = static_cast<uint8_t>(strtype);
}

void StdModel::visit_header_comment(bool repeatable, const const_string_ref& comment)
{
    auto& dst = repeatable ? current_->version.header_comment_repeatable : current_->version.header_comment_nonrepeatable;
    dst = make_string(comment);
}

void StdModel::visit_start_offsets()
{
    current_->version.offsets.clear();
}

void StdModel::visit_end_offsets()
{
}

void StdModel::visit_offset_comments(offset_t offset, CommentType_e comment_type, const const_string_ref& comment)
{
    current_->version.comments.emplace_back(make_string(comment), offset, comment_type);
}

void StdModel::visit_offset_valueview(offset_t offset, operand_t operand, const const_string_ref& view_value)
{
    current_->version.valueviews.emplace_back(make_string(view_value), offset, operand);
}

void StdModel::visit_offset_registerview(offset_t offset, offset_t end_offset, const const_string_ref& register_name, const const_string_ref& register_new_name)
{
    current_->version.registerviews.emplace_back(make_string(register_name), make_string(register_new_name), offset, end_offset);
}

void StdModel::visit_offset_hiddenarea(offset_t offset, offset_t area_size, const const_string_ref& hidden_area_value)
{
    current_->version.hiddenareas.emplace_back(make_string(hidden_area_value), offset, area_size);
}

void StdModel::visit_start_xrefs()
{
    current_->version.xrefs.clear();
}

void StdModel::visit_end_xrefs()
{
}

void StdModel::visit_start_xref(offset_t offset, YaToolObjectId id, operand_t operand)
{
    current_->version.xrefs.emplace_back(std::vector<StdAttribute>(), offset, id, operand);
}

void StdModel::visit_xref_attribute(const const_string_ref& key, const const_string_ref& value)
{
    current_->version.xrefs.back().attributes.emplace_back(make_string(key), make_string(value));
}

void StdModel::visit_end_xref()
{
}

void StdModel::visit_start_matching_systems()
{
}

void StdModel::visit_end_matching_systems()
{
}

void StdModel::visit_start_matching_system(offset_t offset)
{
    current_->offset = offset;
}

void StdModel::visit_matching_system_description(const const_string_ref& key, const const_string_ref& value)
{
    if(!strcmp(key.value, "None")
    || !strcmp(key.value, "")
    || !strcmp(key.value, "none"))
        return;
    if(!strcmp(key.value, "os"))
        current_->system.os = make_string(value);
    else if(!strcmp(key.value, "equipment"))
        current_->system.equipment = make_string(value);
}

void StdModel::visit_end_matching_system()
{
    const auto find_system_idx = [&]()
    {
        uint32_t idx = 0;
        for(const auto& system : systems_)
        {
            if(system.equipment == current_->system.equipment
            && system.os        == current_->system.os)
                return idx;
            ++idx;
        }
        systems_.emplace_back(current_->system.equipment, current_->system.os);
        return idx;
    };
    current_->version.offsets.emplace_back(current_->offset, find_system_idx());
}

void StdModel::visit_segments_start()
{
}

void StdModel::visit_segments_end()
{
}

void StdModel::visit_attribute(const const_string_ref& key, const const_string_ref& value)
{
    current_->version.attributes.push_back({make_string(key), make_string(value)});
}

void StdModel::visit_blob(offset_t offset, const void* blob, size_t len)
{
    const uint8_t* ptr = static_cast<const uint8_t*>(blob);
    current_->version.blobs.emplace_back(ptr, len, offset);
}

void StdModel::visit_flags(flags_t flags)
{
    current_->version.flags = flags;
}

void StdModel::accept(IModelVisitor& visitor)
{
    visitor.visit_start();
    for(const auto& object : objects_)
        accept_object(*this, object, visitor);
    visitor.visit_end();
}

void StdModel::walk_objects(const OnObjectAndIdFn& fnWalk) const
{
    for(const auto& it : objects_)
        if(fnWalk(it.id, {&view_objects_, it.idx}) != WALK_CONTINUE)
            return;
}

size_t StdModel::num_objects() const
{
    return objects_.size();
}

void StdModel::walk_objects_with_signature(const HSignature& hash, const OnObjectFn& fnWalk) const
{
    walk_sigs(index_, make_string_ref(hash.get()), [&](const Sig& sig)
    {
        return fnWalk({&view_objects_, versions_[signatures_[sig.idx].version_idx].object_idx});
    });
}

void StdModel::walk_versions_with_signature(const HSignature& hash, const OnVersionFn& fnWalk) const
{
    walk_sigs(index_, make_string_ref(hash.get()), [&](const Sig& sig)
    {
        return fnWalk({&view_versions_, signatures_[sig.idx].version_idx});
    });
}

size_t StdModel::num_objects_with_signature(const HSignature& hash) const
{
    return num_sigs(index_, make_string_ref(hash.get()));
}

void StdModel::walk_matching_versions(const HObject& object, size_t min_size, const OnVersionPairFn& fnWalk) const
{
    object.walk_versions([&](const HVersion& remoteVersion)
    {
        //iterate over remote signatures
        ContinueWalking_e stop_current_iteration = WALK_CONTINUE;
        remoteVersion.walk_signatures([&](const HSignature& remote)
        {
            walk_sigs(index_, make_string_ref(remote.get()), [&](const Sig& sig)
            {
                const auto version_id = signatures_[sig.idx].version_idx;
                const auto& version = versions_[version_id];
                if(version.size != remoteVersion.size())
                    return WALK_CONTINUE;
                if(!is_unique_sig(index_, sig.key) && version.size < min_size)
                    return WALK_CONTINUE;
                if(fnWalk({&view_versions_, version_id}, remoteVersion) != WALK_STOP)
                    return WALK_CONTINUE;
                stop_current_iteration = WALK_STOP;
                return stop_current_iteration;
            });
            return stop_current_iteration;
        });
        return stop_current_iteration;
    });
}

void StdModel::walk_versions_without_collision(const OnSigAndVersionFn& fnWalk) const
{
    walk_all_unique_sigs(index_, [&](const Sig& sig)
    {
        return fnWalk({&view_signatures_, sig.idx}, {&view_versions_, signatures_[sig.idx].version_idx});
    });
}

void StdModel::walk_systems(const OnSystemFn& fnWalk) const
{
    const auto end = static_cast<HSystem_id_t>(systems_.size());
    for(HSystem_id_t id = 0; id < end; ++id)
        if(fnWalk(id) == WALK_STOP)
            return;
}

HObject StdModel::get_object(YaToolObjectId id) const
{
    if(const auto object_id = find_object_id(index_, id))
        return{&view_objects_, *object_id};
    return{nullptr, 0};
}

bool StdModel::has_object(YaToolObjectId id) const
{
    return !!find_object_id(index_, id);
}

void ViewObjects::accept(HObject_id_t object_id, IModelVisitor& visitor) const
{
    accept_object(db_, db_.objects_[object_id], visitor);
}

YaToolObjectType_e ViewObjects::type(HObject_id_t object_id) const
{
    return db_.objects_[object_id].type;
}

YaToolObjectId ViewObjects::id(HObject_id_t object_id) const
{
    return db_.objects_[object_id].id;
}

bool ViewObjects::has_signature(HObject_id_t object_id) const
{
    bool found = false;
    ::walk_versions(db_, db_.objects_[object_id], [&](HVersion_id_t, const StdVersion& version)
    {
        walk_signatures(db_, version, [&](HSignature_id_t, const StdSignature&)
        {
            found = true;
            return WALK_STOP;
        });
        return found ? WALK_STOP : WALK_CONTINUE;
    });
    return found;
}

void ViewObjects::walk_versions(HObject_id_t object_id, const OnVersionFn& fnWalk) const
{
    ::walk_versions(db_, db_.objects_[object_id], [&](HVersion_id_t version_id, const StdVersion&)
    {
        return fnWalk({&db_.view_versions_, version_id});
    });
}

void ViewObjects::walk_xrefs_from(HObject_id_t object_id, const OnXrefFromFn& fnWalk) const
{
    ::walk_versions(db_, db_.objects_[object_id], [&](HVersion_id_t, const StdVersion& ver)
    {
        ContinueWalking_e stop = WALK_CONTINUE;
        walk_xrefs(db_, ver, [&](const StdXref& xref)
        {
            const auto object = db_.get_object(xref.id);
            if(object.is_valid())
                stop = fnWalk(xref.offset, xref.operand, object);
            return stop;
        });
        return stop;
    });
}

void ViewObjects::walk_xrefs_to(HObject_id_t object_id, const OnObjectFn& fnWalk) const
{
    ::walk_xrefs_to(db_, db_.objects_[object_id], [&](HObject_id_t from)
    {
        return fnWalk({this, from});
    });
}

bool ViewObjects::match(HObject_id_t object_id, const HObject& remote) const
{
    bool match_found = false;
    remote.walk_versions([&](const HVersion& remoteVersion)
    {
        const auto& local = db_.objects_[object_id];
        ::walk_versions(db_, local, [&](const HVersion_id_t, const StdVersion& local)
        {
            if(local.size != remoteVersion.size())
                return WALK_CONTINUE;

            bool this_match_found = true;
            int local_count = 0;
            int remote_count = 0;
            remoteVersion.walk_signatures([&](const HSignature& signature)
            {
                const auto signref = make_string_ref(signature.get());
                local_count++;
                int found = 0;
                remote_count = 0;
                //Look for all our signatures
                walk_signatures(db_, local, [&](HSignature_id_t, const StdSignature& sign)
                {
                    remote_count++;
                    found += !strcmp(signref.value, sign.value.buffer);
                    return WALK_CONTINUE;
                });
                if(found != 1)
                    this_match_found = false;
                return WALK_CONTINUE;
            });

            match_found |= this_match_found && local_count == remote_count;
            return WALK_CONTINUE;
        });
        if(match_found)
            return WALK_STOP;
        return WALK_CONTINUE;
    });
    return match_found;
}

void ViewVersions::accept(HVersion_id_t version_id, IModelVisitor& visitor) const
{
    accept_version(db_, db_.versions_[version_id], visitor);
}

YaToolObjectId ViewVersions::id(HVersion_id_t version_id) const
{
    return db_.versions_[version_id].id;
}

YaToolObjectId ViewVersions::parent_id(HVersion_id_t version_id) const
{
    return db_.versions_[version_id].parent;
}

offset_t ViewVersions::size(HVersion_id_t version_id) const
{
    return db_.versions_[version_id].size;
}

YaToolObjectType_e ViewVersions::type(HVersion_id_t version_id) const
{
    return db_.versions_[version_id].type;
}

offset_t ViewVersions::address(HVersion_id_t version_id) const
{
    return db_.versions_[version_id].address;
}

const_string_ref ViewVersions::username(HVersion_id_t version_id) const
{
    return make_string_ref(db_.versions_[version_id].username.value);
}

int ViewVersions::username_flags(HVersion_id_t version_id) const
{
    return db_.versions_[version_id].username.flags;
}

const_string_ref ViewVersions::prototype(HVersion_id_t version_id) const
{
    return make_string_ref(db_.versions_[version_id].prototype);
}

YaToolFlag_T ViewVersions::flags(HVersion_id_t version_id) const
{
    return db_.versions_[version_id].flags;
}

int ViewVersions::string_type(HVersion_id_t version_id) const
{
    return db_.versions_[version_id].strtype;
}

const_string_ref ViewVersions::header_comment(HVersion_id_t version_id, bool repeatable) const
{
    const auto& version = db_.versions_[version_id];
    const auto& value = repeatable ? version.header_comment_repeatable : version.header_comment_nonrepeatable;
    return make_string_ref(value);
}

void ViewVersions::walk_signatures(HVersion_id_t version_id, const OnSignatureFn& fnWalk) const
{
    ::walk_signatures(db_, db_.versions_[version_id], [&](HSignature_id_t id, const StdSignature&)
    {
        return fnWalk({&db_.view_signatures_, id});
    });
}

void ViewVersions::walk_xrefs_from(HVersion_id_t version_id, const OnXrefFromFn& fnWalk) const
{
    ::walk_xrefs(db_, db_.versions_[version_id], [&](const StdXref& xref)
    {
        const auto ref = db_.get_object(xref.id);
        if(!ref.is_valid())
            return WALK_CONTINUE;
        return fnWalk(xref.offset, xref.operand, ref);
    });
}

void ViewVersions::walk_xrefs_to(HVersion_id_t version_id, const OnObjectFn& fnWalk) const
{
    db_.view_objects_.walk_xrefs_to(db_.versions_[version_id].object_idx, fnWalk);
}

void ViewVersions::walk_blobs(HVersion_id_t version_id, const OnBlobFn& fnWalk) const
{
    for(const auto& blob : db_.versions_[version_id].blobs)
        if(fnWalk(blob.offset, &blob.data[0], blob.data.size()) != WALK_CONTINUE)
            return;
}

void ViewVersions::walk_comments(HVersion_id_t version_id, const OnCommentFn& fnWalk) const
{
    for(const auto& comment : db_.versions_[version_id].comments)
        if(fnWalk(comment.offset, comment.type, make_string_ref(comment.value)) != WALK_CONTINUE)
            return;
}

void ViewVersions::walk_value_views(HVersion_id_t version_id, const OnValueViewFn& fnWalk) const
{
    for(const auto& view : db_.versions_[version_id].valueviews)
        if(fnWalk(view.offset, view.operand, make_string_ref(view.value)) != WALK_CONTINUE)
            return;
}

void ViewVersions::walk_register_views(HVersion_id_t version_id, const OnRegisterViewFn& fnWalk) const
{
    for(const auto& view : db_.versions_[version_id].registerviews)
        if(fnWalk(view.offset, view.end_offset, make_string_ref(view.name), make_string_ref(view.new_name)) != WALK_CONTINUE)
            return;
}

void ViewVersions::walk_hidden_areas(HVersion_id_t version_id, const OnHiddenAreaFn& fnWalk) const
{
    for(const auto& hidden : db_.versions_[version_id].hiddenareas)
        if(fnWalk(hidden.offset, hidden.area_size, make_string_ref(hidden.value)) != WALK_CONTINUE)
            return;
}

void ViewVersions::walk_xrefs(HVersion_id_t version_id, const OnXrefFn& fnWalk) const
{
    ::walk_xrefs(db_, db_.versions_[version_id], [&](const StdXref& xref)
    {
        return fnWalk(xref.offset, xref.operand, xref.id, reinterpret_cast<const XrefAttributes*>(&xref));
    });
}

void ViewVersions::walk_xref_attributes(HVersion_id_t, const XrefAttributes* hattr, const OnAttributeFn& fnWalk) const
{
    const StdXref* xref = reinterpret_cast<const StdXref*>(hattr);
    for(const auto& attr : xref->attributes)
        if(fnWalk(make_string_ref(attr.key), make_string_ref(attr.value)) != WALK_CONTINUE)
            return;
}

void ViewVersions::walk_systems(HVersion_id_t version_id, const OnSystemFn& fnWalk) const
{
    ::walk_systems(db_, db_.versions_[version_id], [&](const StdOffset& offset)
    {
        return fnWalk(offset.offset, offset.system_idx);
    });
}

void ViewVersions::walk_system_attributes(HVersion_id_t, HSystem_id_t system_id, const OnAttributeFn& fnWalk) const
{
    const auto& system = db_.systems_[system_id];
    fnWalk(gEquipmentRef, make_string_ref(system.equipment));
    fnWalk(gOsRef, make_string_ref(system.os));
}

void ViewVersions::walk_attributes(HVersion_id_t version_id, const OnAttributeFn& fnWalk) const
{
    for(const auto& attr : db_.versions_[version_id].attributes)
        if(fnWalk(make_string_ref(attr.key), make_string_ref(attr.value)) != WALK_CONTINUE)
            return;
}

Signature ViewSignatures::get(HSignature_id_t id) const
{
    return db_.signatures_[id].value;
}
