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

#include "IModelAccept.hpp"
#include "Hashable.hpp"
#include "YaToolObjectVersion.hpp"


class YaToolReferencedObject
    : public Hashable
    , public Comparable<YaToolReferencedObject>
    , public IModelAccept
{

    public:
        YaToolReferencedObject(YaToolObjectType_e p_object_type);
        virtual ~YaToolReferencedObject(){}

        // IModelAccept
        void accept(IModelVisitor& visitor) override;

        // Hashable
        void buildHashCode() const override;

        // Comparable
        const std::string& getComparableValue() const override;


        void setId(YaToolObjectId id);
        void putVersion(const std::shared_ptr<YaToolObjectVersion>& v);

        YaToolObjectId getId() const;
        bool hasId() const;
        YaToolObjectType_e get_object_type();

        /**
         * Function to call when resolving ids
         */
        void linkXRefs(const std::unordered_map<YaToolObjectId, std::shared_ptr<YaToolReferencedObject>>& objectsById);
        void setParentObject(YaToolObjectVersion* object_version);
        bool hasParentObject();
        const std::unordered_set<std::weak_ptr<YaToolObjectVersion>> &getVersions() const;

        /**
         * Does this object match this one?
         * the check is made on the signatures (hash)
         * This is not a real equality, since it is used to compare two different sets of functions
         */
        bool matchObject(const HObject& object) const;

        /**
         * Return a version from this object that matches a version/signature eventually comming from another object
         * If no version matches, return null
         */
        std::shared_ptr<YaToolObjectVersion> getMatchingVersion(HVersion version, HSignature signature) const;

        /**
         * Get all the versions of this object that match a list of systems.
         * This function returns a newly allocated object, that needs to be freed by the caller
         */
        std::unordered_set<std::weak_ptr<YaToolObjectVersion>> getVersionsForSystems(const std::unordered_set<std::shared_ptr<MatchingSystem>>& systems);

        void setVersionForSystem(std::shared_ptr<MatchingSystem> sys, const std::shared_ptr<YaToolObjectVersion>& version);

        /**
         * Add a set of objects as matching to this one.
         * In many cases, this set should have a size of 1, since one function can only match
         * one single function in another database. However, since a function can be matched in several
         * different databases, this function can still be useful.
         * Furthermore, in a more sophisticated version, we could be able to detect when a function
         * is being split or merged between two databases.
         */
#ifndef SWIG
        friend std::ostream & operator<<(std::ostream& oss, std::shared_ptr<YaToolReferencedObject> pYaToolReferencedObject);
#endif // SWIG

    private:
        struct Data;
        std::shared_ptr<Data> d;
};

#ifndef SWIG
namespace std
{
    template<>
    struct hash<YaToolReferencedObject*>
    {
        size_t operator()(const YaToolReferencedObject* pHashable) const
        {
            return pHashable->getHashcode();
        }
    };
}
#endif //SWIG
