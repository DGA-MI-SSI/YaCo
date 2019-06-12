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

#include "IModelVisitor.hpp"
#include "Signature.hpp"
#include "FlatBufferModel.hpp"
#include "IModel.hpp"
#include "Yatools.hpp"
#include "FileUtils.hpp"
#include "XmlAccept.hpp"
#include "Helpers.h"

#include <flatbuffers/flatbuffers.h>
#include <yadb_generated.h>

#include <vector>
#include <memory>
#include <set>
#include <type_traits>

#include "FlatBufferVisitor.hpp"

#ifdef _MSC_VER
#   include <optional.hpp>
    using namespace nonstd;
#else
#   include <experimental/optional>
    using namespace std::experimental;
#endif

namespace fb = flatbuffers;


// Lookup comment type : repeateable|bookmark : seems pretty useless ... (TOSEE)
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

// Lookup hash type : count|crc32
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

// Lookup signature firstbyte|invariant
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

// TODO I think this should go to mutualize with IdaModel
struct Xref
{
    YaToolObjectId  id;
    offset_t        offset;
    operand_t       operand;
};

enum VisitorMode
{
    STANDARD,
    SKIP_START_END,
};

struct FlatBufferVisitor : public IFlatBufferVisitor
{
    FlatBufferVisitor(VisitorMode mode);

    // IModelVisitor interface so I have to override
    DECLARE_VISITOR_INTERFACE_METHODS

    ExportedBuffer GetBuffer() const override;

    const bool            skip_start_end_;
    fb::FlatBufferBuilder fbbuilder_;

    // Version containers
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
    std::vector<fb::Offset<yadb::Version>>      local_types_;
    std::vector<fb::Offset<fb::String>>         strings_;

    // Version
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
    std::vector<fb::Offset<yadb::Xref>> xrefs_;
    std::vector<yadb::Signature>        signatures_;

    bool is_ready_;
};

// Ctor : make shared
std::shared_ptr<IFlatBufferVisitor> MakeFlatBufferVisitor()
{
    return std::make_shared<FlatBufferVisitor>(STANDARD);
}


// Init : nothing
FlatBufferVisitor::FlatBufferVisitor(VisitorMode mode)
    : skip_start_end_(mode == SKIP_START_END)
    , object_type_(OBJECT_TYPE_UNKNOWN)
    , object_id_(0)
    , is_ready_(false)
{
}


// Indexify string and put in database
static uint32_t index_string(FlatBufferVisitor& db, const const_string_ref& ref)
{
    // Check in
    if (!ref.size || !ref.value) { return 0; }

    // Convert string -> value
    const auto value = db.fbbuilder_.CreateSharedString(ref.value, ref.size);

    // Push in database
    db.strings_.emplace_back(value);

    // Return ref to me
    return static_cast<uint32_t>(db.strings_.size() - 1);
}


// Retrieve string <- ref
static uint32_t make_string(FlatBufferVisitor& db, optional<std::string>& ref)
{
    // Check in
    if (!ref) { return 0; }
    const auto value = *ref;
    ref = nullopt;
    // Append string to db and retrieve its ref
    return index_string(db, make_string_ref(value));
}

// Make optional : retur nvalu eor nullopt
template<typename T>
static T make_optional(optional<T>& value)
{
    const auto reply = value ? *value : T();
    value = nullopt;
    return reply;
}


// Create Vectors of structures <- include/flatbuffers.h
template<typename T>
static fb::Offset<fb::Vector<const T*>> make_strucs(fb::FlatBufferBuilder& fbb, std::vector<T>& value)
{
    // Check in
    if (value.empty()) { return 0; }

    // Create resfrom faltbuffer.h
    const auto reply = fbb.CreateVectorOfStructs(value);
    value.clear();

    // Return
    return reply;
}

// Make table <- include/flatbuffers.h
template<typename T>
static fb::Offset<fb::Vector<T>> make_tables(fb::FlatBufferBuilder& fbb, std::vector<T>& value)
{
    if (value.empty()) { return 0; }
    const auto reply = fbb.CreateVector(value);
    value.clear();
    return reply;
}


namespace {
    // Init void
    void visit_start(FlatBufferVisitor& v)
    {
        // Add an empty string first so index = 0 == an empty string
        v.strings_.emplace_back(v.fbbuilder_.CreateSharedString("", 0));
    }

    // Finilize FlatBuffer : make_tables
    void visit_end(FlatBufferVisitor& v)
    {
        yadb::FinishRootBuffer(v.fbbuilder_, yadb::CreateRoot(v.fbbuilder_,
            make_tables(v.fbbuilder_, v.binaries_),
            make_tables(v.fbbuilder_, v.structs_),
            make_tables(v.fbbuilder_, v.struct_members_),
            make_tables(v.fbbuilder_, v.enums_),
            make_tables(v.fbbuilder_, v.enum_members_),
            make_tables(v.fbbuilder_, v.segments_),
            make_tables(v.fbbuilder_, v.segment_chunks_),
            make_tables(v.fbbuilder_, v.functions_),
            make_tables(v.fbbuilder_, v.stackframes_),
            make_tables(v.fbbuilder_, v.stackframe_members_),
            make_tables(v.fbbuilder_, v.reference_infos_),
            make_tables(v.fbbuilder_, v.codes_),
            make_tables(v.fbbuilder_, v.datas_),
            make_tables(v.fbbuilder_, v.basic_blocks_),
            make_tables(v.fbbuilder_, v.local_types_),
            make_tables(v.fbbuilder_, v.strings_)
        ));
        v.is_ready_ = true;
    }
} // End ::

// Redefine visit_start as Class function
void FlatBufferVisitor::visit_start()
{
    if (!skip_start_end_) { ::visit_start(*this); }
}

// Redefine visit_end as Class function
void FlatBufferVisitor::visit_end()
{
    if (!skip_start_end_) { ::visit_end(*this); }
}

// Return (flat)buffer if ready
ExportedBuffer FlatBufferVisitor::GetBuffer() const
{
    // Check if plain C
    STATIC_ASSERT_POD(ExportedBuffer);

    // Check if ready
    if (!is_ready_) {
        return ExportedBuffer{ nullptr, 0 };
    }

    // Return fbbuilder buffer
    return ExportedBuffer{fbbuilder_.GetBufferPointer(), fbbuilder_.GetSize()};
}

// Visit : Init version
void FlatBufferVisitor::visit_start_version(YaToolObjectType_e type, YaToolObjectId id)
{
    object_type_ = type;
    object_id_ = id;
}

// Visit : Nop
void FlatBufferVisitor::visit_deleted(YaToolObjectType_e /*type*/, YaToolObjectId /*id*/)
{
}

// Visit : End version obejct vistior => store into db
void FlatBufferVisitor::visit_end_version()
{
    // Dispatch table (switch)
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
            case OBJECT_TYPE_LOCAL_TYPE:        return &local_types_;
        }
        return nullptr;
    }();
    // Check
    if(!dstvec)
    {
        YALOG_ERROR(nullptr, "unhandled object %" PRIx64 " type %x dropped\n", object_id_, object_type_);
        return;
    }

    // Push all my attributes, my new finialised version object to dstvec
    dstvec->push_back(yadb::CreateVersion(fbbuilder_,
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
        make_strucs(fbbuilder_, attributes_),
        make_tables(fbbuilder_, blobs_),
        make_strucs(fbbuilder_, comments_),
        make_strucs(fbbuilder_, value_views_),
        make_strucs(fbbuilder_, register_views_),
        make_strucs(fbbuilder_, hidden_areas_),
        make_tables(fbbuilder_, xrefs_),
        make_strucs(fbbuilder_, signatures_)
    ));

    // Clear username (TOSEE IDK why)
    username_.clear();
}

// Visit : Parent Id -> stack
void FlatBufferVisitor::visit_parent_id(YaToolObjectId id)
{
    parent_id_ = id;
}

// Visit : Address -> stack
void FlatBufferVisitor::visit_address(offset_t address)
{
    address_ = address;
}

// Visit : username
void FlatBufferVisitor::visit_name(const const_string_ref& name, int flags)
{
    username_.emplace_back(flags, index_string(*this, name));
}

// Visit : Size
void FlatBufferVisitor::visit_size(offset_t size)
{
    size_ = static_cast<uint32_t>(size);
}

// Visit : Init signatures : Nop
void FlatBufferVisitor::visit_start_signatures()
{
}

void FlatBufferVisitor::visit_signature(SignatureMethod_e method, SignatureAlgo_e algo, const const_string_ref& hex)
{
    signatures_.emplace_back(
        index_string(*this, hex),
        get_hash_type(algo),
        get_signature_method(method)
    );
}

// Visit : End signatures : Nop
void FlatBufferVisitor::visit_end_signatures()
{
}

// Visit : Prototype -> Make string
void FlatBufferVisitor::visit_prototype(const const_string_ref& prototype)
{
    prototype_ = make_string(prototype);
}

// Visit : Type -> Enum
void FlatBufferVisitor::visit_string_type(int str_type)
{
    string_type_ = static_cast<uint8_t>(str_type);
}

// Visit : Header comment -> String
void FlatBufferVisitor::visit_header_comment(bool repeatable, const const_string_ref& comment)
{
    auto& dst = repeatable ? comment_repeatable_ : comment_nonrepeatable_;
    dst = make_string(comment);
}

// Visit : Offset -> Nop
void FlatBufferVisitor::visit_start_offsets()
{
}

// Visit : Comment -> Stack
void FlatBufferVisitor::visit_offset_comments(offset_t offset, CommentType_e comment_type, const const_string_ref& comment)
{
    comments_.emplace_back(offset,
        index_string(*this, comment),
        get_comment_type(comment_type)
    );
}

// Visit : Offset (TOSEE : what is a valuview)
void FlatBufferVisitor::visit_offset_valueview(offset_t offset, operand_t operand,
        const const_string_ref& view_value)
{
    value_views_.emplace_back(
        offset,
        index_string(*this, view_value),
        static_cast<uint8_t>(operand)
    );
}

// Visit :
void FlatBufferVisitor::visit_offset_registerview(offset_t offset, offset_t end_offset,
        const const_string_ref& register_name, const const_string_ref& register_new_name)
{
    register_views_.emplace_back(
        offset,
        end_offset,
        index_string(*this, register_name),
        index_string(*this, register_new_name)
    );
}

// Visit :
void FlatBufferVisitor::visit_offset_hiddenarea(offset_t offset, offset_t area_size,
        const const_string_ref& hidden_area_value)
{
    hidden_areas_.emplace_back(
        offset,
        area_size,
        index_string(*this, hidden_area_value)
    );
}

// Visit : Offset end : Nop
void FlatBufferVisitor::visit_end_offsets()
{
}

// Visit : Xrefs start : Nop
void FlatBufferVisitor::visit_start_xrefs()
{
}

// Visit : Xref start : Init xref_
void FlatBufferVisitor::visit_start_xref(offset_t offset, YaToolObjectId id, operand_t operand)
{
    xref_ = Xref{id, offset, operand};
}

// Visit : Attribute : Append
void FlatBufferVisitor::visit_xref_attribute(const const_string_ref& attribute_key,
        const const_string_ref& attribute_value)
{
    attributes_.emplace_back(
        index_string(*this, attribute_key),
        index_string(*this, attribute_value)
    );
}

// Vistit : Xref end
void FlatBufferVisitor::visit_end_xref()
{
    // Push new xref object to stack
    xrefs_.push_back(yadb::CreateXref(fbbuilder_,
        xref_->offset,
        xref_->id,
        static_cast<uint8_t>(xref_->operand),
        make_strucs(fbbuilder_, attributes_)
    ));

    // Null xref_ memeber
    xref_ = nullopt;
}

// Nop
void FlatBufferVisitor::visit_end_xrefs()
{
}

// Nop
void FlatBufferVisitor::visit_segments_start()
{
}

// Nop
void FlatBufferVisitor::visit_segments_end()
{
}

// Visit : Attribute : Push
void FlatBufferVisitor::visit_attribute(const const_string_ref& attr_name, const const_string_ref& attr_value)
{
    attributes_.emplace_back(
        index_string(*this, attr_name),
        index_string(*this, attr_value)
    );
}

// Visit : flag : Set memebr
void FlatBufferVisitor::visit_flags(flags_t flags)
{
    flags_ = flags;
}


// Create blob <- (ptr, size)
static fb::Offset<fb::Vector<uint8_t>> create_blob(fb::FlatBufferBuilder& fbb, const void* ptr, size_t size)
{
    if (!ptr) { return 0; }
    return fbb.CreateVector(reinterpret_cast<const uint8_t*>(ptr), size);
}

// Visit : Blob -> Stack
void FlatBufferVisitor::visit_blob(offset_t offset, const void* blob, size_t len)
{
    blobs_.push_back(yadb::CreateBlob(fbbuilder_,
        offset,
        create_blob(fbbuilder_, blob, len)
    ));
}

namespace {
    // Class: memory map with buffer value/size Getter
    struct ExportedMmap : public Mmap_ABC
    {
        ExportedMmap(const std::shared_ptr<IFlatBufferVisitor>& exporter)
            : exporter_(exporter)
            , buffer_  (exporter->GetBuffer())
        {
        }

        const void* Get() const override
        {
            return buffer_.value;
        }

        size_t GetSize() const override
        {
            return buffer_.size;
        }

        std::shared_ptr<IFlatBufferVisitor>  exporter_;
        ExportedBuffer                       buffer_;
    };

    // Export all input filenames into our in-memory flatbuffer export
    std::shared_ptr<IFlatBufferVisitor> ExportToFlatBuffer(const std::vector<std::string>& filenames)
    {
        const auto exporter = std::make_shared<FlatBufferVisitor>(SKIP_START_END);
        visit_start(*exporter);
        for(const auto& filename : filenames)
        {
            LOG(INFO, "* importing %s\n", filename.data());
            MakeFlatBufferModel(filename)->accept(*exporter);
        }
        visit_end(*exporter);
        return exporter;
    }
} // End ::

std::shared_ptr<IModel> MakeMultiFlatBufferModel(const std::vector<std::string>& filenames)
{
    // Check in
    if (filenames.size() == 1) { return MakeFlatBufferModel(filenames.front()); }

    // Parse multiple files
    const auto exporter = ExportToFlatBuffer(filenames);

    // Make one flatbuffer
    return MakeFlatBufferModel(std::make_shared<ExportedMmap>(exporter));
}

// Merge : N Xmls -> 1 YaDb
bool merge_xmls_to_yadb(const std::string& output, const std::vector<std::string>& inputs)
{
    // Init
    const auto exporter = MakeFlatBufferVisitor();

    // Parse in
    AcceptXmlFiles(*exporter, inputs);

    // Get export buffer <- xmls
    const auto buf = exporter->GetBuffer();

    // Write to file
    FILE* fh = fopen(output.data(), "wb");
    if (!fh) { return false; }
    const auto size = fwrite(buf.value, buf.size, 1, fh);
    const auto err = fclose(fh);

    // Return
    return size == 1 && !err;
}