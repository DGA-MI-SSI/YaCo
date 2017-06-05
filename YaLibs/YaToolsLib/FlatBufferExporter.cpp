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

#include "FlatBufferExporter.hpp"

#include "IModelAccept.hpp"
#include "IModelVisitor.hpp"
#include "YaToolObjectId.hpp"
#include "Hexa.h"
#include "Signature.hpp"
#include "Logger.h"
#include "Yatools.h"
#include "../Helpers.h"

#include <flatbuffers/flatbuffers.h>
#include <yadb_generated.h>

#include <vector>
#include <memory>
#include <set>
#include <type_traits>

#ifdef _MSC_VER
#   include <optional.hpp>
    using namespace nonstd;
#else
#   include <experimental/optional>
    using namespace std::experimental;
#endif


namespace fb = flatbuffers;

#if 0
#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("fb_export", (FMT), ## __VA_ARGS__)
#else
#define LOG(...) do {} while(0)
#endif

namespace
{
static yadb::ObjectType get_object_type(YaToolObjectType_e value)
{
    switch(value)
    {
        case OBJECT_TYPE_COUNT:
        case OBJECT_TYPE_UNKNOWN:           return yadb::ObjectType_Unknown;
        case OBJECT_TYPE_BINARY:            return yadb::ObjectType_Binary;
        case OBJECT_TYPE_DATA:              return yadb::ObjectType_Data;
        case OBJECT_TYPE_CODE:              return yadb::ObjectType_Code;
        case OBJECT_TYPE_FUNCTION:          return yadb::ObjectType_Function;
        case OBJECT_TYPE_STRUCT:            return yadb::ObjectType_Struct;
        case OBJECT_TYPE_ENUM:              return yadb::ObjectType_Enum;
        case OBJECT_TYPE_ENUM_MEMBER:       return yadb::ObjectType_EnumMember;
        case OBJECT_TYPE_BASIC_BLOCK:       return yadb::ObjectType_BasicBlock;
        case OBJECT_TYPE_SEGMENT:           return yadb::ObjectType_Segment;
        case OBJECT_TYPE_SEGMENT_CHUNK:     return yadb::ObjectType_SegmentChunk;
        case OBJECT_TYPE_STRUCT_MEMBER:     return yadb::ObjectType_StructMember;
        case OBJECT_TYPE_STACKFRAME:        return yadb::ObjectType_StackFrame;
        case OBJECT_TYPE_STACKFRAME_MEMBER: return yadb::ObjectType_StackFrameMember;
        case OBJECT_TYPE_REFERENCE_INFO:    return yadb::ObjectType_ReferenceInfo;
    }
    return yadb::ObjectType_Unknown;
}

static yadb::CommentType get_comment_type(CommentType_e value)
{
    switch(value)
    {
        case COMMENT_COUNT:
        case COMMENT_UNKNOWN:           return yadb::CommentType_Unknown;
        case COMMENT_REPEATABLE:        return yadb::CommentType_Repeatable;
        case COMMENT_NON_REPEATABLE:    return yadb::CommentType_NonRepeatable;
        case COMMENT_ANTERIOR:          return yadb::CommentType_Anterior;
        case COMMENT_POSTERIOR:         return yadb::CommentType_Posterior;
        case COMMENT_BOOKMARK:          return yadb::CommentType_Bookmark;
    }
    return yadb::CommentType_Unknown;
}

static yadb::HashType get_hash_type(SignatureAlgo_e value)
{
    switch(value)
    {
        case SIGNATURE_ALGORITHM_COUNT:
        case SIGNATURE_ALGORITHM_UNKNOWN:   return yadb::HashType_Unknown;
        case SIGNATURE_ALGORITHM_NONE:      return yadb::HashType_None;
        case SIGNATURE_ALGORITHM_CRC32:     return yadb::HashType_Crc32;
        case SIGNATURE_ALGORITHM_MD5:       return yadb::HashType_Md5;
    }
    return yadb::HashType_Unknown;
}

static yadb::SignatureMethod get_signature_method(SignatureMethod_e value)
{
    switch(value)
    {
        case SIGNATURE_METHOD_COUNT:
        case SIGNATURE_UNKNOWN:             return yadb::SignatureMethod_Unknown;
        case SIGNATURE_FIRSTBYTE:           return yadb::SignatureMethod_FirstByte;
        case SIGNATURE_FULL:                return yadb::SignatureMethod_Full;
        case SIGNATURE_INVARIANTS:          return yadb::SignatureMethod_Invariants;
        case SIGNATURE_OPCODE_HASH:         return yadb::SignatureMethod_OpCode;
        case SIGNATURE_INTRA_GRAPH_HASH:    return yadb::SignatureMethod_IntraGraph;
        case SIGNATURE_STRING_HASH:         return yadb::SignatureMethod_String;
    }
    return yadb::SignatureMethod_Unknown;
}

struct System
{
    std::string equipment;
    std::string os;
};

struct Xref
{
    YaToolObjectId  id;
    offset_t        offset;
    operand_t       operand;
};

struct FBExporter : public IFlatExporter
{
    FBExporter();

    // IModelVisitor
    void visit_start() override;
    void visit_end() override;
    void visit_start_object(YaToolObjectType_e object_type) override;
    void visit_start_reference_object(YaToolObjectType_e object_type) override;
    void visit_start_deleted_object(YaToolObjectType_e object_type) override;
    void visit_start_default_object(YaToolObjectType_e object_type) override;
    void visit_end_deleted_object() override;
    void visit_end_default_object() override;
    void visit_end_reference_object() override;
    void visit_id(YaToolObjectId object_id) override;
    void visit_start_object_version() override;
    void visit_parent_id(YaToolObjectId object_id) override;
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

    ExportedBuffer GetBuffer() const override;

    fb::FlatBufferBuilder fbbuilder_;

    std::vector<yadb::Object>                   objects_;
    std::vector<System>                         systems_;
    std::vector<fb::Offset<yadb::Version>>      versions_;
    std::vector<fb::Offset<yadb::Version>>      binaries_;
    std::vector<fb::Offset<yadb::Version>>      structs_;
    std::vector<fb::Offset<yadb::Version>>      struct_members_;
    std::vector<fb::Offset<yadb::Version>>      enums_;
    std::vector<fb::Offset<yadb::Version>>      enum_members_;
    std::vector<fb::Offset<yadb::Version>>      segments_;
    std::vector<fb::Offset<yadb::Version>>      segment_chunks_;
    std::vector<fb::Offset<yadb::Version>>      functions_;
    std::vector<fb::Offset<yadb::Version>>      stackframes_;
    std::vector<fb::Offset<yadb::Version>>      stackframe_members_;
    std::vector<fb::Offset<yadb::Version>>      reference_infos_;
    std::vector<fb::Offset<yadb::Version>>      codes_;
    std::vector<fb::Offset<yadb::Version>>      datas_;
    std::vector<fb::Offset<yadb::Version>>      basic_blocks_;
    std::vector<fb::Offset<fb::String>>         strings_;

    // version
    YaToolObjectType_e                  object_type_;
    YaToolObjectId                      object_id_;
    optional<YaToolObjectId>            parent_id_;
    optional<offset_t>                  address_;
    optional<uint32_t>                  flags_;
    optional<std::string>               prototype_;
    optional<uint32_t>                  size_;
    std::vector<yadb::UserName>         username_;
    optional<std::string>               comment_repeatable_;
    optional<std::string>               comment_nonrepeatable_;
    optional<uint8_t>                   string_type_;
    optional<Xref>                      xref_;
    std::vector<yadb::Attribute>        attributes_;
    std::vector<fb::Offset<yadb::Blob>> blobs_;
    std::vector<yadb::Comment>          comments_;
    std::vector<yadb::ValueView>        value_views_;
    std::vector<yadb::RegisterView>     register_views_;
    std::vector<yadb::HiddenArea>       hidden_areas_;
    std::vector<yadb::Offset>           offsets_;
    std::vector<fb::Offset<yadb::Xref>> xrefs_;
    std::vector<yadb::Signature>        signatures_;

    // system
    optional<uint64_t>      system_address_;
    optional<std::string>   system_equipment_;
    optional<std::string>   system_os_;

    bool is_default_object_;
    bool is_ready_;
};
}

std::shared_ptr<IFlatExporter> MakeFlatBufferExporter()
{
    return std::make_shared<FBExporter>();
}

FBExporter::FBExporter()
    : is_default_object_(false)
    , is_ready_(false)
{
}

static uint32_t index_string(FBExporter& db, const const_string_ref& ref)
{
    if(!ref.size || !ref.value)
        return 0;
    const auto value = db.fbbuilder_.CreateSharedString(ref.value, ref.size);
    db.strings_.emplace_back(value);
    return static_cast<uint32_t>(db.strings_.size() - 1);
}

static uint32_t make_string(FBExporter& db, optional<std::string>& ref)
{
    if(!ref)
        return 0;
    const auto value = *ref;
    ref = nullopt;
    return index_string(db, make_string_ref(value));
}

template<typename T>
static T make_optional(optional<T>& value)
{
    const auto reply = value ? *value : T();
    value = nullopt;
    return reply;
}

template<typename T>
static fb::Offset<fb::Vector<const T*>> make_structs(fb::FlatBufferBuilder& fbb, std::vector<T>& value)
{
    if(value.empty())
        return 0;
    const auto reply = fbb.CreateVectorOfStructs(value);
    value.clear();
    return reply;
}

template<typename T>
static fb::Offset<fb::Vector<T>> make_tables(fb::FlatBufferBuilder& fbb, std::vector<T>& value)
{
    if(value.empty())
        return 0;
    const auto reply = fbb.CreateVector(value);
    value.clear();
    return reply;
}

void FBExporter::visit_start()
{
    // add an empty string first so index = 0 == an empty string
    strings_.emplace_back(fbbuilder_.CreateSharedString("", 0));
}

void FBExporter::visit_end()
{
    auto systems = [&]
    {
        std::vector<yadb::System> fbsys;
        for(const auto& sys : systems_)
            fbsys.emplace_back(
                index_string(*this, make_string_ref(sys.equipment)), 
                index_string(*this, make_string_ref(sys.os))
            );
        systems_.clear();
        return fbsys;
    }();

    yadb::FinishRootBuffer(fbbuilder_, yadb::CreateRoot(fbbuilder_,
        make_structs(fbbuilder_, objects_),
        make_structs(fbbuilder_, systems),
        make_tables(fbbuilder_, binaries_),
        make_tables(fbbuilder_, structs_),
        make_tables(fbbuilder_, struct_members_),
        make_tables(fbbuilder_, enums_),
        make_tables(fbbuilder_, enum_members_),
        make_tables(fbbuilder_, segments_),
        make_tables(fbbuilder_, segment_chunks_),
        make_tables(fbbuilder_, functions_),
        make_tables(fbbuilder_, stackframes_),
        make_tables(fbbuilder_, stackframe_members_),
        make_tables(fbbuilder_, reference_infos_),
        make_tables(fbbuilder_, codes_),
        make_tables(fbbuilder_, datas_),
        make_tables(fbbuilder_, basic_blocks_),
        make_tables(fbbuilder_, strings_)
    ));
    is_ready_ = true;
}

ExportedBuffer FBExporter::GetBuffer() const
{
    STATIC_ASSERT_POD(ExportedBuffer);
    if(!is_ready_)
        return ExportedBuffer{nullptr, 0};
    return ExportedBuffer{fbbuilder_.GetBufferPointer(), fbbuilder_.GetSize()};
}

void FBExporter::visit_start_object(YaToolObjectType_e type)
{
    object_type_ = type;
    is_default_object_ = false;
}

void FBExporter::visit_start_reference_object(YaToolObjectType_e type)
{
    object_type_ = type;
    is_default_object_ = false;
}

void FBExporter::visit_start_deleted_object(YaToolObjectType_e type)
{
    object_type_ = type;
    is_default_object_ = false;
}

void FBExporter::visit_start_default_object(YaToolObjectType_e type)
{
    object_type_ = type;
    is_default_object_ = true;
}

void FBExporter::visit_end_reference_object()
{
    const auto dstvec = [&]() -> std::vector<fb::Offset<yadb::Version>>*
    {
        switch(object_type_)
        {
            case OBJECT_TYPE_COUNT:
            case OBJECT_TYPE_UNKNOWN:           return nullptr;
            case OBJECT_TYPE_BINARY:            return &binaries_;
            case OBJECT_TYPE_DATA:              return &datas_;
            case OBJECT_TYPE_CODE:              return &codes_;
            case OBJECT_TYPE_FUNCTION:          return &functions_;
            case OBJECT_TYPE_STRUCT:            return &structs_;
            case OBJECT_TYPE_ENUM:              return &enums_;
            case OBJECT_TYPE_ENUM_MEMBER:       return &enum_members_;
            case OBJECT_TYPE_BASIC_BLOCK:       return &basic_blocks_;
            case OBJECT_TYPE_SEGMENT:           return &segments_;
            case OBJECT_TYPE_SEGMENT_CHUNK:     return &segment_chunks_;
            case OBJECT_TYPE_STRUCT_MEMBER:     return &struct_members_;
            case OBJECT_TYPE_STACKFRAME:        return &stackframes_;
            case OBJECT_TYPE_STACKFRAME_MEMBER: return &stackframe_members_;
            case OBJECT_TYPE_REFERENCE_INFO:    return &reference_infos_;
        }
        return nullptr;
    }();
    if(!dstvec)
    {
        YALOG_ERROR(nullptr, "unhandled object %s type %x dropped\n", YaToolObjectId_To_StdString(object_id_).data(), object_type_);
        return;
    }

    dstvec->insert(dstvec->end(), versions_.begin(), versions_.end());
    versions_.clear();
    objects_.emplace_back(object_id_, get_object_type(object_type_));
}

void FBExporter::visit_end_deleted_object()
{
    assert(false);
    visit_end_reference_object();
}

void FBExporter::visit_end_default_object()
{
    visit_end_reference_object();
}

void FBExporter::visit_id(YaToolObjectId id)
{
    object_id_ = id;
}

void FBExporter::visit_parent_id(YaToolObjectId id)
{
    parent_id_ = id;
}

void FBExporter::visit_address(offset_t address)
{
    address_ = address;
}

void FBExporter::visit_start_object_version()
{
}

void FBExporter::visit_end_object_version()
{
    versions_.push_back(yadb::CreateVersion(fbbuilder_,
        object_id_,
        make_optional(parent_id_),
        make_optional(address_),
        make_optional(flags_),
        make_string(*this, prototype_),
        make_optional(size_),
        !username_.empty() ? &username_[0] : nullptr,
        make_string(*this, comment_repeatable_),
        make_string(*this, comment_nonrepeatable_),
        make_optional(string_type_),
        make_structs(fbbuilder_, attributes_),
        make_tables(fbbuilder_, blobs_),
        make_structs(fbbuilder_, comments_),
        make_structs(fbbuilder_, value_views_),
        make_structs(fbbuilder_, register_views_),
        make_structs(fbbuilder_, hidden_areas_),
        make_structs(fbbuilder_, offsets_),
        make_tables(fbbuilder_, xrefs_),
        make_structs(fbbuilder_, signatures_)
    ));
    username_.clear();
}

void FBExporter::visit_name(const const_string_ref& name, int flags)
{
    username_.emplace_back(flags, index_string(*this, name));
}

void FBExporter::visit_size(offset_t size)
{
    size_ = static_cast<uint32_t>(size);
}

void FBExporter::visit_start_signatures()
{
}

void FBExporter::visit_signature(SignatureMethod_e method, SignatureAlgo_e algo, const const_string_ref& hex)
{
    signatures_.emplace_back(
        index_string(*this, hex),
        get_hash_type(algo),
        get_signature_method(method)
    );
}

void FBExporter::visit_end_signatures()
{
}

void FBExporter::visit_prototype(const const_string_ref& prototype)
{
    prototype_ = make_string(prototype);
}

void FBExporter::visit_string_type(int str_type)
{
    string_type_ = static_cast<uint8_t>(str_type);
}

void FBExporter::visit_header_comment(bool repeatable, const const_string_ref& comment)
{
    auto& dst = repeatable ? comment_repeatable_ : comment_nonrepeatable_;
    dst = make_string(comment);
}

void FBExporter::visit_start_offsets()
{
}

void FBExporter::visit_offset_comments(offset_t offset, CommentType_e comment_type, const const_string_ref& comment)
{
    comments_.emplace_back(offset,
        index_string(*this, comment),
        get_comment_type(comment_type)
    );
}

void FBExporter::visit_offset_valueview(offset_t offset, operand_t operand,
        const const_string_ref& view_value)
{
    value_views_.emplace_back(
        offset,
        index_string(*this, view_value),
        static_cast<uint8_t>(operand)
    );
}

void FBExporter::visit_offset_registerview(offset_t offset, offset_t end_offset,
        const const_string_ref& register_name, const const_string_ref& register_new_name)
{
    register_views_.emplace_back(
        offset,
        end_offset,
        index_string(*this, register_name),
        index_string(*this, register_new_name)
    );
}

void FBExporter::visit_offset_hiddenarea(offset_t offset, offset_t area_size,
        const const_string_ref& hidden_area_value)
{
    hidden_areas_.emplace_back(
        offset,
        area_size,
        index_string(*this, hidden_area_value)
    );
}

void FBExporter::visit_end_offsets()
{
}

void FBExporter::visit_start_xrefs()
{
}

void FBExporter::visit_start_xref(offset_t offset, YaToolObjectId id, operand_t operand)
{
    xref_ = Xref{id, offset, operand};
}

void FBExporter::visit_xref_attribute(const const_string_ref& attribute_key,
        const const_string_ref& attribute_value)
{
    attributes_.emplace_back(
        index_string(*this, attribute_key),
        index_string(*this, attribute_value)
    );
}

void FBExporter::visit_end_xref()
{
    xrefs_.push_back(yadb::CreateXref(fbbuilder_,
        xref_->offset,
        xref_->id,
        static_cast<uint8_t>(xref_->operand),
        make_structs(fbbuilder_, attributes_)
    ));
    xref_ = nullopt;
}

void FBExporter::visit_end_xrefs()
{
}

void FBExporter::visit_start_matching_systems()
{
}

void FBExporter::visit_start_matching_system(offset_t address)
{
    system_address_ = address;
}

void FBExporter::visit_matching_system_description(const const_string_ref& description_key, const const_string_ref& description_value)
{
    if(!strcmp(description_value.value, "None")
    || !strcmp(description_value.value, "")
    || !strcmp(description_value.value, "none"))
        return;
    if(!strcmp(description_key.value, "os"))
        system_os_ = make_string(description_value);
    else if(!strcmp(description_key.value, "equipment"))
        system_equipment_ = make_string(description_value);
}

void FBExporter::visit_end_matching_system()
{
    assert(system_address_);
    const auto is_equal = [](const auto& value, auto& optional)
    {
        if(!optional)
            return value.empty();
        return !strcmp(optional->data(), value.data());
    };
    const auto get_string = [&](const auto& optional)
    {
        return optional ? *optional : std::string();
    };
    const auto find_system_idx = [&]()
    {
        uint32_t idx = 0;
        for(auto& system : systems_)
        {
            if(is_equal(system.equipment, system_equipment_)
            && is_equal(system.os,        system_os_))
                return idx;
            ++idx;
        }
        systems_.push_back({get_string(system_equipment_), get_string(system_os_)});;
        return idx;
    };
    offsets_.emplace_back(*system_address_, find_system_idx());
}

void FBExporter::visit_end_matching_systems()
{
}

void FBExporter::visit_segments_start()
{
}

void FBExporter::visit_segments_end()
{
}

void FBExporter::visit_attribute(const const_string_ref& attr_name, const const_string_ref& attr_value)
{
    attributes_.emplace_back(
        index_string(*this, attr_name),
        index_string(*this, attr_value)
    );
}

void FBExporter::visit_flags(flags_t flags)
{
    flags_ = flags;
}

static fb::Offset<fb::Vector<uint8_t>> create_blob(fb::FlatBufferBuilder& fbb, const void* ptr, size_t size)
{
    if(!ptr)
        return 0;
    return fbb.CreateVector(reinterpret_cast<const uint8_t*>(ptr), size);
}

void FBExporter::visit_blob(offset_t offset, const void* blob, size_t len)
{
    blobs_.push_back(yadb::CreateBlob(fbbuilder_,
        offset,
        create_blob(fbbuilder_, blob, len)
    ));
}

