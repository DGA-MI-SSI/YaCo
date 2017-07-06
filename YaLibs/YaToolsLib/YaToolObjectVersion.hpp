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

#pragma once

#include "YaTypes.hpp"
#include "Hashable.hpp"
#include "Comparable.hpp"
#include "IModelAccept.hpp"

#include <map>
#include <set>
#include <unordered_set>
#include <vector>

class YaToolObjectVersion;
class YaToolReferencedObject;
class MatchingSystem;

namespace std { template<typename T> class function; }

/**
 * Internal flags of YaTool
 */
#define OBJECT_VERSION_VISITED                  ((ObjectVersionFlag_T)0x01)
#define OBJECT_VERSION_XREF_OFFSET_AVAILABLES   ((ObjectVersionFlag_T)0x02)

bool IS_PARENT_OF(YaToolObjectType_e parent, YaToolObjectType_e child);

/*
 * If this flag is set, the absence of signature is normal for this object.
 * Thus, matchesHash will return true if the object ant the compared object both have no signature.
 */
#define OBJECT_VERSION_SIGNATURE_EMPTY_ALLOWED  ((ObjectVersionFlag_T)0x04)

/**
 * Flags from IDA (isStruct, isXXX)
 * */
typedef uint32_t ObjectVersionFlag_T;

struct XrefedId_T
{
    YaToolObjectId                      object_id;
    std::map<std::string, std::string>  attributes;
};

struct XrefedObject_T
{
    std::shared_ptr<YaToolReferencedObject> object;
    std::map<std::string, std::string>      attributes;
};

class YaToolObjectVersion
    : public Hashable
    , public Comparable<YaToolObjectVersion>
    , public IModelAccept
{
    public:
        YaToolObjectVersion();

        // IModelAccept
        void accept(IModelVisitor& visitor) override;

        void            set_id(YaToolObjectId id);
        YaToolObjectId  get_id() const;
        bool            has_id() const;

        void                set_type(YaToolObjectType_e object_type);
        YaToolObjectType_e  get_type() const;

        void            set_parent_object_id(YaToolObjectId id);
        YaToolObjectId  get_parent_object_id() const;
        bool            has_parent_object_id() const;

        /**
         * Sets the name of this object
         */
        void                set_name(const std::string& name);
        const std::string&  get_name() const;

        void    set_name_flags(int flags);
        int     get_name_flags() const;

        void                set_prototype(const std::string& prototype);
        const std::string&  get_prototype() const;

        void    set_string_type(int string_type);
        int     get_string_type() const;

        void        set_size(offset_t size);
        offset_t    get_size() const;

        bool    is_yatool_flag_set(YaToolFlag_T flag) const;
        void    set_yaTool_flag(YaToolFlag_T flag, bool enabled);

        ObjectVersionFlag_T get_object_flags() const;
        void                set_object_flags(ObjectVersionFlag_T flag);


        std::shared_ptr<YaToolReferencedObject> get_referenced_object() const;
        void                                    set_referenced_object(const std::shared_ptr<YaToolReferencedObject>&);

        void                setComment(const std::string& comment);
        void                setRepeatableComment(const std::string& comment);
        void                set_header_comment(bool repeatable, const std::string& comment);
        const std::string&  get_header_comment(bool repeatable) const;
        const std::string&  getComment() const;
        const std::string&  getRepeatableComment() const;

        void add_offset_comment(offset_t offset ,CommentType_e type, const std::string& comment);
        void add_offset_valueview(offset_t offset ,operand_t operand, const std::string& valueview);

        /*
         * offset_register.first  : ea_start
         * offset_register.second : reg_name
         * rename_mapping.first   : ea_end
         * rename_mapping.second  : new_reg_name
         */
        void add_offset_registerview(offset_t offset_range_start, offset_t offset_range_end, const std::string& original_name, const std::string& new_name);
        void add_offset_hidden_area(std::pair<offset_t, offset_t> area_range, const std::string& area_value);

        const std::map<std::pair<offset_t, CommentType_e>, std::string>&                        get_offset_comments() const;
        const std::map<std::pair<offset_t,operand_t>,std::string >&                             get_offset_valueviews() const;
        const std::map<std::pair<offset_t, std::string>, std::pair<offset_t, std::string> >&    get_offset_registerviews() const;
        const std::map<std::pair<offset_t, offset_t>, std::string>&                             get_offset_hiddenareas() const;

        void addXRefFrom(const std::shared_ptr<YaToolReferencedObject>& object);
        void addXRef(const std::shared_ptr<YaToolReferencedObject>& object, offset_t offset, operand_t operand=0);

        /**
         * Return the address of the object when found in the corresponding system.
         */
        offset_t    get_object_address() const;
        offset_t    get_relative_object_address() const;
        offset_t    get_absolute_object_address() const;
        bool        is_absolute_address_set() const;
        void        set_absolute_object_address(offset_t address);
        offset_t    getMatchingSystemAddress(const std::shared_ptr<MatchingSystem>& sys) const;
        size_t      getMatchingSystemsCount() const;

        const std::map<std::pair<offset_t,operand_t>, std::vector<XrefedObject_T> >&    getXRefsMap() const;
        void                                                                            addXRefId(offset_t offset, operand_t operand, YaToolObjectId target_id, const std::map<std::string, std::string>& attributes);
        const std::map<std::pair<offset_t, operand_t>, std::vector<XrefedId_T> >&       get_xrefed_id_map() const;

        std::set<YaToolObjectId> getXRefIdsAt(offset_t address, operand_t operand) const;

        const std::map<std::string, std::string>&               get_attributes() const;
        const std::map<offset_t,std::vector<unsigned char> >&   get_blobs() const;
        const std::vector<offset_t>                             get_blob_offsets() const;
        void                                                    get_blob_array(offset_t offset, char** buffer, size_t* len) const;
        void                                                    set_blob_array(offset_t offset, char* buffer, size_t len);
        std::set<YaToolObjectId>                                get_xrefed_ids() const;

#ifndef SWIG
        void                    addXrefTo(const std::shared_ptr<YaToolReferencedObject>& object);
        void                    linkXrefs(const std::unordered_map<YaToolObjectId, std::shared_ptr<YaToolReferencedObject>>& objects);
        void                    setParentObject(YaToolObjectVersion* object_version);
        YaToolObjectVersion&    getParentObject();
        bool                    hasParent();
        void                    add_matching_system(const std::shared_ptr<MatchingSystem>& sys, offset_t address);
        void                    add_attribute(const std::string& attr_name, const std::string& attr_value);
        void                    add_blob(offset_t offset, const std::vector<unsigned char>& blob);

        void    add_signature(const Signature& signature);
        bool    matches_signature(HSignature signature) const;
        bool    has_signature() const;

        /**
         * return true if this object matches one of the hash passed as parameter
         */
        bool    matches_signature(const HVersion& version) const;
        bool    matchesVersion(const HVersion& version) const;

        const std::unordered_set<std::weak_ptr<MatchingSystem>>&                          getMatchingSystems() const;
        const std::unordered_map<YaToolObjectId, std::weak_ptr<YaToolReferencedObject>>&  getXRefs() const;
        std::shared_ptr<YaToolReferencedObject>                                           getOneXRefAt(offset_t address, operand_t operand=0) const;
        const std::unordered_map<YaToolObjectId, std::weak_ptr<YaToolReferencedObject>>&  getXRefsTo() const;

#endif //SWIG
        const std::vector<Signature>& getHashes() const;

        // Hashable
        void                buildHashCode() const override;

        // Comparable
        const std::string&  getComparableValue() const override;

        struct Data;
        std::shared_ptr<Data> d;
};

#ifndef SWIG
namespace std
{
    template<>
    struct hash<YaToolObjectVersion*>
    {
        size_t operator()(const YaToolObjectVersion* pHashable) const
        {
            return pHashable->getHashcode();
        }
    };

    inline bool operator==(const std::weak_ptr<YaToolObjectVersion>& a, const std::weak_ptr<YaToolObjectVersion>& b)
    {
        const auto pa = a.lock();
        const auto pb = b.lock();
        return pa && pb ? pa == pb : pa.get() == pb.get();
    }

    template<>
    struct hash<std::weak_ptr<YaToolObjectVersion>>
    {
        size_t operator()(const std::weak_ptr<YaToolObjectVersion>& pHashable) const
        {
            return pHashable.lock()->getHashcode();
        }
    };
}
#endif//SWIG