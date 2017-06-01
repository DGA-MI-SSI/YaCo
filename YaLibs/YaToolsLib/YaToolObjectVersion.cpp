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

#include "YaToolObjectVersion.hpp"

#include "HVersion.hpp"
#include "YaToolReferencedObject.hpp"
#include "YaToolObjectId.hpp"
#include "IModelVisitor.hpp"
#include "Signature.hpp"
#include "MatchingSystem.hpp"
#include "Logger.h"
#include "Yatools.h"
#include "../Helpers.h"

#include <algorithm>
#include <functional>
#include <sstream>
#include <type_traits>

#ifdef DEBUG
#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("object_version", (FMT), ## __VA_ARGS__)
#else
#define LOG(...) do {} while(0)
#endif

#ifdef _MSC_VER
#   include <optional.hpp>
using namespace nonstd;
#else
#   include <experimental/optional>
using namespace std::experimental;
#endif

static void UpdateComparable(std::string& comparable, const YaToolObjectId Id, offset_t size, const std::vector<Signature>& signatures)
{
    char buffer[YATOOL_OBJECT_ID_STR_LEN + 1];
    YaToolObjectId_To_String(buffer, YATOOL_OBJECT_ID_STR_LEN+1, Id);

    comparable = buffer;


    std::ostringstream oss;
    oss << "-" << std::hex << size << "-";
    comparable.append(oss.str());

    for(const auto& sig : signatures)
        comparable.append(sig.buffer, sig.size);
}

struct YaToolObjectVersion::Data
{
    Data();

    std::string                                                                     objectComment_;
    std::string                                                                     objectRepeatableComment_;
    std::string                                                                     header_nonrepeatable_comment_;
    std::string                                                                     header_repeatable_comment_;
    std::string                                                                     prototype_;
    std::string                                                                     object_name_;
    int                                                                             name_flags_;
    std::map<offset_t, std::vector<unsigned char>>                                  blobs_;

    //If the object is a std::string, this field stores its type
    int                                                                             string_type_;
    YaToolObjectType_e                                                              object_type_;
    offset_t                                                                        object_size_;
    int                                                                             flags_;
    ObjectVersionFlag_T                                                             object_flags_;
    optional<YaToolObjectId>                                                        object_id_;
    optional<YaToolObjectId>                                                        parent_object_id_;
    optional<offset_t>                                                              absolute_address_;
    std::weak_ptr<YaToolReferencedObject>                                           ParentObject_;
    std::map<std::pair<offset_t, operand_t>, std::vector<XrefedId_T>>               xrefFromIds_;
    std::vector<Signature>                                                          signatures_;
    std::unordered_map<YaToolObjectId, std::weak_ptr<YaToolReferencedObject>>       xrefsFrom_;
    std::unordered_map<YaToolObjectId, std::weak_ptr<YaToolReferencedObject>>       xrefsTo_;
    /**
        * This std::map contains :
        * Keys : pair (ea, operand) : where the xref is located (eventually, operand=0 by default)
        * Values : std::pair<object, std::map> : the std::map represents the attributes of the xref (essentially the delta)
        */
    std::map<std::pair<offset_t,operand_t>, std::vector<XrefedObject_T>>            xrefsFromByOffset_;
    std::unordered_set<std::weak_ptr<MatchingSystem>>                               matchingSystemsSet_;
    std::unordered_map<std::weak_ptr<MatchingSystem>, offset_t>                     matchingSystems_;

    std::map<std::pair<offset_t, CommentType_e>, std::string>                       offset_comments_;
    std::map<std::pair<offset_t, operand_t>, std::string>                           offset_valueview_;

    std::string                                                                     comparableValue_;
    /*
        * key.first   : ea_start
        * key.second  : reg_name
        * val.first   : ea_end
        * val.second  : new_reg_name
        */
    std::map<std::pair<offset_t, std::string>, std::pair<offset_t, std::string>>    offset_registerview_;
    std::map<std::pair<offset_t, offset_t>, std::string>                            offset_hidden_area_;

    YaToolObjectVersion*                                                            parent_object_version_;

    std::map<std::string, std::string>                                              attributes_;

    friend std::ostream & operator<<(std::ostream& oss, const YaToolObjectVersion& pYaToolObjectVersion);
};

YaToolObjectVersion::Data::Data()
    : name_flags_           (0)
    , string_type_          (0)
    , object_type_          (OBJECT_TYPE_UNKNOWN)
    , object_size_          (0)
    , flags_                (0)
    , object_flags_         (0)
    , parent_object_version_(nullptr)
{
}

YaToolObjectVersion::YaToolObjectVersion()
    : d(std::make_shared<Data>())
{
}

void YaToolObjectVersion::accept(IModelVisitor& visitor)
{
    visitor.visit_start_object_version();

    if (get_size() != 0)
    {
        visitor.visit_size(get_size());
    }

    if (has_parent_object_id())
    {
        visitor.visit_parent_id(get_parent_object_id());
    }

    if (d->absolute_address_)
    {
        visitor.visit_address(*d->absolute_address_);
    }

    if (get_name().length() > 0)
    {
        visitor.visit_name(make_string_ref(get_name()), get_name_flags());
    }

    if (get_prototype().length() > 0)
    {
        visitor.visit_prototype(make_string_ref(get_prototype()));
    }

    if (get_object_flags() != 0)
    {
        visitor.visit_flags(get_object_flags());
    }

    if (get_string_type() != 0)
    {
        visitor.visit_string_type(get_string_type());
    }

    for(const auto& v : get_blobs())
    {
        if (v.second.size() != 0)
        {
            visitor.visit_blob(v.first, v.second.data(), v.second.size());
        }
    }

    visitor.visit_start_signatures();
    for (const auto& sig : getHashes())
    {
        visitor.visit_signature(sig.method, sig.algo, make_string_ref(sig));
    }
    visitor.visit_end_signatures();

    for (bool repeatable : { true, false })
    {
        if (get_header_comment(repeatable).length() > 0)
        {
            visitor.visit_header_comment(repeatable, make_string_ref(get_header_comment(repeatable)));
        }
    }

    /**************** offsets ********************/
    visitor.visit_start_offsets();
    /**
     * We need to iterate over the offsets in the right order.
     * However, they are split into 4 maps. Thus, we take iterators from all of the maps, and increment them as necessary
     */
    const std::map<std::pair<offset_t, CommentType_e>, std::string>& comments = get_offset_comments();
    const std::map<std::pair<offset_t, operand_t>, std::string>& valueviews = get_offset_valueviews();
    const std::map<std::pair<offset_t, std::string>, std::pair<offset_t, std::string>>& registerviews = get_offset_registerviews();
    const std::map<std::pair<offset_t, offset_t>, std::string>& hiddenarea = get_offset_hiddenareas();

    auto comments_it = comments.begin();
    auto valueviews_it = valueviews.begin();
    auto registerviews_it = registerviews.begin();
    auto hiddenarea_it = hiddenarea.begin();

    while (comments_it != comments.end() || valueviews_it != valueviews.end() || registerviews_it != registerviews.end()
            || hiddenarea_it != hiddenarea.end())
    {
        //First, get the minimal ea from the current positions of the iterators
        offset_t current_ea = UNKNOWN_ADDR;
        if (comments_it != comments.end())
        {
            current_ea = std::min(current_ea, comments_it->first.first);
        }
        if (valueviews_it != valueviews.end())
        {
            current_ea = std::min(current_ea, valueviews_it->first.first);
        }
        if (registerviews_it != registerviews.end())
        {
            current_ea = std::min(current_ea, registerviews_it->first.first);
        }
        if (hiddenarea_it != hiddenarea.end())
        {
            current_ea = std::min(current_ea, hiddenarea_it->first.first);
        }

        //Now that we have the minimal ea, export all the elements of the maps
        //corresponding to that ea

        while (comments_it != comments.end() && comments_it->first.first == current_ea)
        {
            //export
            visitor.visit_offset_comments(current_ea, comments_it->first.second, make_string_ref(comments_it->second));
            comments_it++;
        }

        while (valueviews_it != valueviews.end() && valueviews_it->first.first == current_ea)
        {
            //export
            visitor.visit_offset_valueview(current_ea, valueviews_it->first.second, make_string_ref(valueviews_it->second));
            valueviews_it++;
        }

        while (registerviews_it != registerviews.end() && registerviews_it->first.first == current_ea)
        {
            //export
            visitor.visit_offset_registerview(current_ea, registerviews_it->second.first,
                    make_string_ref(registerviews_it->first.second), make_string_ref(registerviews_it->second.second));
            registerviews_it++;
        }

        while (hiddenarea_it != hiddenarea.end() && hiddenarea_it->first.first == current_ea)
        {
            //export
            visitor.visit_offset_hiddenarea(current_ea, hiddenarea_it->first.second, make_string_ref(hiddenarea_it->second));
            hiddenarea_it++;
        }
    }

    visitor.visit_end_offsets();
    /*********************************************/

    /************* xrefs *************************/
    visitor.visit_start_xrefs();

    for (const auto& it : get_xrefed_id_map())
    {
        offset_t ea = it.first.first;
        operand_t operand = it.first.second;
        for (const auto& it2 : it.second)
        {
            visitor.visit_start_xref(ea, it2.object_id, operand);

            for (const auto& attr_it : it2.attributes)
            {
                visitor.visit_xref_attribute(make_string_ref(attr_it.first), make_string_ref(attr_it.second));
            }
            visitor.visit_end_xref();
        }
    }


    visitor.visit_end_xrefs();
    /*********************************************/

    /********************  matching system *******/
    visitor.visit_start_matching_systems();
    for(const auto& wsys : getMatchingSystems())
    {
        const auto sys = wsys.lock();
        offset_t addr = getMatchingSystemAddress(sys);
        if(addr != UNKNOWN_ADDR)
        {
            visitor.visit_start_matching_system(addr);
            sys->accept(visitor);
            visitor.visit_end_matching_system();
        }
    }
    visitor.visit_end_matching_systems();
    /*********************************************/

    /******************** attributes *************/
    for(const auto& attr : get_attributes())
    {
        visitor.visit_attribute(make_string_ref(attr.first), make_string_ref(attr.second));
    }
    /*********************************************/

    visitor.visit_end_object_version();
}

void YaToolObjectVersion::set_id(YaToolObjectId id)
{
    d->object_id_ = id;
    UpdateComparable(d->comparableValue_, id, get_size(), d->signatures_);
}

void YaToolObjectVersion::set_type(YaToolObjectType_e object_type)
{
    d->object_type_ = object_type;
}

YaToolObjectType_e YaToolObjectVersion::get_type() const
{
    return d->object_type_;
}

YaToolObjectId YaToolObjectVersion::get_id() const
{
    const auto& v = d->object_id_;
    return v ? *v : 0;
}

bool YaToolObjectVersion::has_id() const
{
    return !!d->object_id_;
}

void YaToolObjectVersion::set_parent_object_id(YaToolObjectId id)
{
    d->parent_object_id_ = id;
}

YaToolObjectId YaToolObjectVersion::get_parent_object_id() const
{
    const auto& v = d->parent_object_id_;
    return v ? *v : 0;
}

bool YaToolObjectVersion::has_parent_object_id() const
{
    return !!d->parent_object_id_;
}

void YaToolObjectVersion::set_name(const std::string& name)
{
    d->object_name_ = name;
}

const std::string& YaToolObjectVersion::get_name() const
{
    return d->object_name_;
}

void YaToolObjectVersion::set_name_flags(int flags)
{
    d->name_flags_ = flags;
}

int YaToolObjectVersion::get_name_flags() const
{
    return d->name_flags_;
}

bool YaToolObjectVersion::is_yatool_flag_set(YaToolFlag_T flag) const
{
    return (d->flags_ & flag) == flag;
}

void YaToolObjectVersion::set_yaTool_flag(YaToolFlag_T flag, bool enabled)
{
    if (enabled)
    {
        d->flags_ = d->flags_ | flag;
    }
    else
    {
        d->flags_ = d->flags_ & (~flag);
    }
}

void YaToolObjectVersion::set_object_flags(uint32_t value)
{
    d->object_flags_ = value;
}

ObjectVersionFlag_T YaToolObjectVersion::get_object_flags() const
{
    return d->object_flags_;
}

void YaToolObjectVersion::set_prototype(const std::string& prototype)
{
    d->prototype_ = prototype;
}

const std::string& YaToolObjectVersion::get_prototype() const
{
    return d->prototype_;
}

void YaToolObjectVersion::set_string_type(int string_type)
{
    d->string_type_ = string_type;
}

int YaToolObjectVersion::get_string_type() const
{
    return d->string_type_;
}

void YaToolObjectVersion::set_size(offset_t size)
{
    d->object_size_ = size;
}

offset_t YaToolObjectVersion::get_size() const
{
    return d->object_size_;
}

std::shared_ptr<YaToolReferencedObject> YaToolObjectVersion::get_referenced_object() const
{
    return d->ParentObject_.lock();
}

void YaToolObjectVersion::set_referenced_object(const std::shared_ptr<YaToolReferencedObject>& object)
{
    d->ParentObject_ = object;
}

void YaToolObjectVersion::setComment(const std::string& comment)
{
    d->objectComment_ = comment;
}

void YaToolObjectVersion::setRepeatableComment(const std::string& comment)
{
    d->objectComment_ = comment;
}

void YaToolObjectVersion::set_header_comment(bool repeatable, const std::string& comment)
{
    if (repeatable)
    {
        d->header_repeatable_comment_ = comment;
    }
    else
    {
        d->header_nonrepeatable_comment_ = comment;
    }
}

const std::string& YaToolObjectVersion::get_header_comment(bool repeatable) const
{
    if (repeatable)
    {
        return d->header_repeatable_comment_;
    }
    else
    {
        return d->header_nonrepeatable_comment_;
    }
}

const std::string& YaToolObjectVersion::getComment() const
{
    return d->objectComment_;
}
const std::string& YaToolObjectVersion::getRepeatableComment() const
{
    return d->objectRepeatableComment_;
}

void YaToolObjectVersion::add_offset_comment(offset_t offset, CommentType_e type, const std::string& comment)
{
    d->offset_comments_[std::make_pair(offset, type)] = comment;
}

void YaToolObjectVersion::add_offset_valueview(offset_t offset, operand_t operand, const std::string& valueview)
{
    d->offset_valueview_[std::make_pair(offset, operand)] = valueview;
}

void YaToolObjectVersion::add_offset_registerview(offset_t offset_range_start, offset_t offset_range_end, const std::string& original_name, const std::string& new_name)
{
    d->offset_registerview_[std::make_pair(offset_range_start, original_name)] = std::make_pair(offset_range_end, new_name);
}

void YaToolObjectVersion::add_offset_hidden_area(std::pair<offset_t,offset_t> area_range, const std::string& area_value)
{
    d->offset_hidden_area_.insert(std::make_pair(area_range, area_value));
}

const std::map<std::pair<offset_t, CommentType_e>, std::string>& YaToolObjectVersion::get_offset_comments()
{
    return d->offset_comments_;
}

const std::map<std::pair<offset_t, operand_t>, std::string>& YaToolObjectVersion::get_offset_valueviews()
{
    return d->offset_valueview_;
}

const std::map<std::pair<offset_t, std::string>, std::pair<offset_t, std::string>>& YaToolObjectVersion::get_offset_registerviews()
{
    return d->offset_registerview_;
}

const std::map<std::pair<offset_t, offset_t>, std::string>& YaToolObjectVersion::get_offset_hiddenareas()
{
    return d->offset_hidden_area_;
}

void YaToolObjectVersion::addXRefFrom(const std::shared_ptr<YaToolReferencedObject>& object)
{
    d->xrefsFrom_.insert(std::make_pair(object->getId(), object));
    for(const auto& remote_version : object->getVersions())
    {
        const auto obj = get_referenced_object();
        LOG(INFO, "+ xref to   %s -> %s (count %zu)\n",
            YaToolObjectId_To_StdString(remote_version->get_id()).data(),
            YaToolObjectId_To_StdString(obj->getId()).data(),
            remote_version->xrefsTo_.size() + 1);
        remote_version.lock()->addXrefTo(obj);
    }
}

void YaToolObjectVersion::addXRef(const std::shared_ptr<YaToolReferencedObject>& object, offset_t offset, operand_t operand)
{
//  if(getId_() == 3689)
//  {
//      printf("adding xref 0x%08X (->%d) in object version %d\n", offset, object->getId(), getId_());
//  }
    if (offset != UNKNOWN_ADDR)
    {
        set_yaTool_flag(OBJECT_VERSION_XREF_OFFSET_AVAILABLES, true);
    }
    d->xrefsFromByOffset_[std::make_pair(offset, operand)].push_back(XrefedObject_T{object, std::map<std::string, std::string>()});

    addXRefFrom(object);
}

void YaToolObjectVersion::addXrefTo(const std::shared_ptr<YaToolReferencedObject>& object)
{
    d->xrefsTo_.insert(std::make_pair(object->getId(), object));
}

void YaToolObjectVersion::addXRefId(offset_t offset, operand_t operand, YaToolObjectId target_id, const std::map<std::string, std::string>& attributes)
{
//  printf("adding xref to function version\n");
    if (offset != UNKNOWN_ADDR)
    {
        set_yaTool_flag(OBJECT_VERSION_XREF_OFFSET_AVAILABLES, true);
    }
    d->xrefFromIds_[std::make_pair(offset, operand)].push_back(XrefedId_T{target_id, attributes});
}

std::set<YaToolObjectId> YaToolObjectVersion::get_xrefed_ids() const
{
    std::set<YaToolObjectId> toReturn;
    if(d->xrefFromIds_.size() != 0)
    {
        for(const auto& elem : d->xrefFromIds_)
        {
            for(const auto& vect_entry : elem.second)
            {
                toReturn.insert(vect_entry.object_id);
            }
        }
    }
    if(d->xrefsFrom_.size()>0)
    {
        YALOG_ERROR(nullptr, "Not implemented : get ids from resolved Xrefs (easy to do)\n");
        assert(false);
    }
    return toReturn;
}

const std::map<std::pair<offset_t, operand_t>, std::vector<XrefedId_T>>& YaToolObjectVersion::get_xrefed_id_map() const
{
    LOG(INFO, "%s returning crefed id map of size %zx (%zx)\n", TO_STRING(YaToolObjectId_To_StdString(object_id_)), xrefFromIds_.size(), xrefsFrom_.size());
    return d->xrefFromIds_;
}

void YaToolObjectVersion::setParentObject(YaToolObjectVersion* object_version)
{

    if (d->parent_object_version_ == object_version)
    {
        return;
    }
    if (IS_PARENT_OF(object_version->get_type(), get_type()))
    {
        if (d->parent_object_version_ != nullptr)
        {
            LOG(ERROR, ": trying to associate parent %s to object %s which has already a parent %s\n",
                TO_STRING(*object_version), TO_STRING(*this), TO_STRING(*parent_object_version_));
        }
        assert(d->parent_object_version_ == nullptr);
        d->parent_object_version_ = object_version;
    }

}

YaToolObjectVersion& YaToolObjectVersion::getParentObject()
{
    assert(d->parent_object_version_ != nullptr);
    return *d->parent_object_version_;

}


bool YaToolObjectVersion::hasParent()
{
    return (d->parent_object_version_ != nullptr);
}


void YaToolObjectVersion::linkXrefs(const std::unordered_map<YaToolObjectId,std::shared_ptr<YaToolReferencedObject>>& objects)
{
    for (const auto& it : d->xrefFromIds_)
    {
        offset_t ea = it.first.first;
        operand_t operand = it.first.second;

        for (const XrefedId_T& it2 : it.second)
        {
            auto o = objects.find(it2.object_id);
            if (o == objects.end())
                continue;

            std::shared_ptr<YaToolReferencedObject> xref_reference_object = o->second;

            LOG(INFO, "+ xref from %s -> %s %llx %d (ids = %zu, count = %zu)\n",
                YaToolObjectId_To_StdString(get_id()).data(),
                YaToolObjectId_To_StdString(xref_reference_object->getId()).data(),
                ea, operand,
                xrefsFrom_.size() + 1,
                xrefsFromByOffset_.size() + 1);

            d->xrefsFromByOffset_[std::make_pair(ea, operand)].push_back(XrefedObject_T{xref_reference_object, it2.attributes});
            addXRefFrom(xref_reference_object);

            /* try to add xref as parentality relation */
            xref_reference_object->setParentObject(this);

            //get_referenced_object_()->setParentObject(reference_object);
        }
    }
}

void YaToolObjectVersion::add_matching_system(const std::shared_ptr<MatchingSystem>& sys, offset_t address)
{
    d->matchingSystems_[sys] = address;
    d->matchingSystemsSet_.insert(sys);
}

void YaToolObjectVersion::add_attribute(const std::string& attr_name, const std::string& attr_value)
{
    d->attributes_[attr_name] = attr_value;
}

const std::map<std::string, std::string>& YaToolObjectVersion::get_attributes() const
{
    return d->attributes_;
}

void YaToolObjectVersion::add_blob(offset_t offset, const std::vector<unsigned char>& blob)
{
    assert(has_id());
    LOG(INFO, "%s received a blob at %" PRIXOFFSET " of len %zx for object %s\n", TO_STRING(YaToolObjectId_To_StdString(object_id_)), offset, blob.size(), object_name_.data());
    d->blobs_[offset] = blob;
}

const std::map<offset_t, std::vector<unsigned char>>& YaToolObjectVersion::get_blobs() const
{
    return d->blobs_;
}

const std::vector<offset_t> YaToolObjectVersion::get_blob_offsets() const
{
    std::vector<offset_t> toReturn;
    for(const auto& it : d->blobs_)
    {
        toReturn.push_back(it.first);
    }
    return toReturn;
}

void YaToolObjectVersion::get_blob_array(offset_t offset, char** buffer, size_t* len) const
{
    auto it = d->blobs_.find(offset);
    if(it == d->blobs_.end() || (*it).second.empty())
    {
        LOG(INFO, "blob empty or no blob\n");
        * buffer = (char*)malloc(0);
        *len = 0;
    }
    else
    {
        auto blob = (*it).second;
        LOG(INFO, "blob of len %zx at %" PRIXOFFSET " for object %s\n", blob.size(), offset, object_name_.data());
        * buffer = (char*)malloc(blob.size());
        assert(*buffer != nullptr);

        memcpy(*buffer, blob.data(), blob.size());
        *len = blob.size();
    }
}

void YaToolObjectVersion::set_blob_array(offset_t offset, char* buffer, size_t len)
{
    d->blobs_[offset] = std::vector<unsigned char>((unsigned char*)buffer, (unsigned char*)(buffer+len));
}

offset_t YaToolObjectVersion::get_object_address() const
{
    if(d->absolute_address_)
    {
        return get_absolute_object_address();
    }
    else
    {
        return get_relative_object_address();
    }
}

bool YaToolObjectVersion::is_absolute_address_set() const
{
    return !!d->absolute_address_;
}

offset_t YaToolObjectVersion::get_absolute_object_address() const
{
    return *d->absolute_address_;
}

offset_t YaToolObjectVersion::get_relative_object_address() const
{
    auto it = d->matchingSystems_.begin();
    if (it == d->matchingSystems_.end())
    {
        return UNKNOWN_ADDR;
    }
    return (*(it)).second;
}

void YaToolObjectVersion::set_absolute_object_address(offset_t address)
{
    d->absolute_address_ = address;
}

offset_t YaToolObjectVersion::getMatchingSystemAddress(const std::shared_ptr<MatchingSystem>& sys) const
{
    auto it = d->matchingSystems_.find(sys);
    if (it == d->matchingSystems_.end())
    {
        return UNKNOWN_ADDR;
    }
    return it->second;
}

size_t YaToolObjectVersion::getMatchingSystemsCount() const
{
    return d->matchingSystemsSet_.size();
}

const std::unordered_set<std::weak_ptr<MatchingSystem>>& YaToolObjectVersion::getMatchingSystems() const
{
    return d->matchingSystemsSet_;
}

void YaToolObjectVersion::add_signature(const Signature& signature)
{
//  printf("adding hash to function version\n");
    d->signatures_.push_back(signature);
    UpdateComparable(d->comparableValue_, get_id(), get_size(), d->signatures_);
}

bool YaToolObjectVersion::matches_signature(HSignature signature) const
{
    const auto& sign = signature.get();
    for(const auto& h : getHashes())
        if(std::equal_to<>()(sign, h))
            return true;
    return false;
}

bool YaToolObjectVersion::has_signature() const
{
    return getHashes().empty() == false;
}

bool YaToolObjectVersion::matches_signature(const HVersion& version) const
{
//  if (DatabaseId_ == version->getDatabaseId())
//  {
//      /**
//       * the objects belong to the same database : we should compare their Ids.
//       * it will be faster and avoid collisions.
//       */
//
//      return get_id_() == version->get_id();
//  }
    size_t hashesCount = 0;
    bool match = true;
    version.walk_signatures([&](const HSignature& h)
    {
    //the match is OK only if all hashes are equals !
//    for (const auto& h : version->getHashes())
//    {
        hashesCount++;
        if (matches_signature(h) == false)
        {
            match = false;
            return WALK_STOP;
        }
        return WALK_CONTINUE;
    });

    if(hashesCount == getHashes().size())
    {
        return match;
    }

    if(hashesCount == 0 && getHashes().size() == 0)
    {
        return is_yatool_flag_set(OBJECT_VERSION_SIGNATURE_EMPTY_ALLOWED);
    }

    return false;
}

bool YaToolObjectVersion::matchesVersion(const HVersion& version) const
{
    return version.size() == get_size() && matches_signature(version);
}

const std::unordered_map<YaToolObjectId, std::weak_ptr<YaToolReferencedObject>>& YaToolObjectVersion::getXRefs() const
{
    return d->xrefsFrom_;
}

const std::map<std::pair<offset_t, operand_t>,
    std::vector<XrefedObject_T> >& YaToolObjectVersion::getXRefsMap() const
{
    return d->xrefsFromByOffset_;
}

std::shared_ptr<YaToolReferencedObject> YaToolObjectVersion::getOneXRefAt(offset_t address, operand_t operand) const
{
    if (is_yatool_flag_set(OBJECT_VERSION_XREF_OFFSET_AVAILABLES) == false)
    {
        YALOG_ERROR(nullptr, "offsets not available : no corresponding Xref\n");
        return nullptr;
    }

    auto it = d->xrefsFromByOffset_.find(std::make_pair(address, operand));
    if (it == d->xrefsFromByOffset_.end())
    {
        return nullptr;
    }
    else
    {
        if(it->second.size()==1)
        {
            return it->second[0].object;
        }
        else
            return nullptr;
    }
}

std::set<YaToolObjectId> YaToolObjectVersion::getXRefIdsAt(offset_t address, operand_t operand) const
{
    std::set<YaToolObjectId> toReturn;
    auto it = d->xrefsFromByOffset_.find(std::make_pair(address, operand));
    if (it != d->xrefsFromByOffset_.end())
    {
        for(const auto& elem : it->second)
        {
            toReturn.insert(elem.object->getId());
        }
    }

    auto it_id = d->xrefFromIds_.find(std::make_pair(address, operand));
    if (it_id != d->xrefFromIds_.end())
    {
        for (const auto& it_vect : it_id->second)
        {
            toReturn.insert(it_vect.object_id);
        }
    }
    return toReturn;
}

const std::unordered_map<YaToolObjectId, std::weak_ptr<YaToolReferencedObject>>& YaToolObjectVersion::getXRefsTo() const
{
    return d->xrefsTo_;
}

const std::vector<Signature>& YaToolObjectVersion::getHashes() const
{
    return d->signatures_;
}

void YaToolObjectVersion::buildHashCode() const
{
    hashUpdate(*d->object_id_);
    for(auto& sig : d->signatures_)
        hashUpdate(sig.buffer);
}

const std::string& YaToolObjectVersion::getComparableValue() const
{
    return d->comparableValue_;
}

std::ostream & operator<<(std::ostream& oss, const YaToolObjectVersion& YaToolObjectVersion)
{
    oss << "=== ObjectVersion ===" << std::endl;
    oss << "ObjectID: ";
    oss << std::hex << *YaToolObjectVersion.d->object_id_ << std::endl;
    oss << "Type: " << std::hex << YaToolObjectVersion.d->object_type_ << std::endl;
    oss << "Name: " << std::hex << YaToolObjectVersion.d->object_name_ << std::endl;
    oss << "Signatures: " << std::endl;
    for (const auto& signature : YaToolObjectVersion.d->signatures_)
    {
        oss << ToString(signature) << std::endl;
    }
    oss << "ComparableValue: " << std::endl;
    oss << YaToolObjectVersion.getComparableValue() << std::endl;
    oss << "Hash: " << std::endl;
    oss << YaToolObjectVersion.getHashcode() << std::endl;
    oss << "--- ObjectVersion ---" << std::endl;

    return oss;
}

/* Parentality */
static const std::multimap<YaToolObjectType_e, YaToolObjectType_e> PARENT_MAPPING = {
    { OBJECT_TYPE_BINARY, OBJECT_TYPE_SEGMENT },
    { OBJECT_TYPE_SEGMENT, OBJECT_TYPE_SEGMENT_CHUNK },
    { OBJECT_TYPE_SEGMENT_CHUNK, OBJECT_TYPE_FUNCTION },
    { OBJECT_TYPE_SEGMENT_CHUNK, OBJECT_TYPE_DATA },
    { OBJECT_TYPE_SEGMENT_CHUNK, OBJECT_TYPE_CODE },
    { OBJECT_TYPE_FUNCTION, OBJECT_TYPE_STACKFRAME },
    { OBJECT_TYPE_FUNCTION, OBJECT_TYPE_BASIC_BLOCK },
    { OBJECT_TYPE_STACKFRAME, OBJECT_TYPE_STACKFRAME_MEMBER },
    { OBJECT_TYPE_STRUCT, OBJECT_TYPE_STRUCT_MEMBER },
    { OBJECT_TYPE_ENUM, OBJECT_TYPE_ENUM_MEMBER },

};

bool IS_PARENT_OF(YaToolObjectType_e parent, YaToolObjectType_e child)
{
    auto it = PARENT_MAPPING.equal_range(parent);
    auto curr_pos = it.first;
    while (curr_pos != it.second)
    {
        if (child == (*(curr_pos)).second)
        {
            return true;
        }
        curr_pos++;
    }
    return false;
}
