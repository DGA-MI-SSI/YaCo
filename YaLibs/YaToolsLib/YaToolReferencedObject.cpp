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

#include "YaToolReferencedObject.hpp"

#include "HObject.hpp"
#include "HVersion.hpp"
#include "YaToolObjectId.hpp"
#include "IModelVisitor.hpp"
#include "Signature.hpp"
#include "MatchingSystem.hpp"
#include "../Helpers.h"

#include <functional>
#include <string>
#include <type_traits>

#ifdef _MSC_VER
#   include <optional.hpp>
using namespace nonstd;
#else
#   include <experimental/optional>
using namespace std::experimental;
#endif

static void UpdateComparable(std::string& comparable, YaToolObjectType_e object_type, const YaToolObjectId Id)
{
    char buffer[4 + 1 + YATOOL_OBJECT_ID_STR_LEN + 1];
    snprintf(buffer, 5, "04%X-", object_type);

    size_t len = strlen(buffer);
    YaToolObjectId_To_String(&(buffer[len]), sizeof(buffer)-len, Id);

    comparable = buffer;
}

struct YaToolReferencedObject::Data
{
    Data(YaToolObjectType_e p_object_type)
        : object_type(p_object_type)
    {
    }

    const YaToolObjectType_e    object_type;
    std::string                 comparable;
    optional<YaToolObjectId>    id;

    std::unordered_set<std::weak_ptr<YaToolObjectVersion>>                                  Versions;
    std::unordered_map<std::weak_ptr<MatchingSystem>, std::weak_ptr<YaToolObjectVersion>>   systemVersions;
};

YaToolReferencedObject::YaToolReferencedObject(YaToolObjectType_e p_object_type)
    : d(std::make_shared<Data>(p_object_type))
{
    UpdateComparable(d->comparable, d->object_type, 0);
}

void YaToolReferencedObject::accept(IModelVisitor& visitor)
{
    visitor.visit_start_reference_object(get_object_type());
    visitor.visit_id(getId());
    for (const auto& version : getVersions())
        version.lock()->accept(visitor);
    visitor.visit_end_reference_object();
}

void YaToolReferencedObject::setId(YaToolObjectId id)
{
    d->id = id;
    UpdateComparable(d->comparable, d->object_type, *d->id);
}

YaToolObjectId YaToolReferencedObject::getId() const
{
    return *d->id;
}

bool YaToolReferencedObject::hasId() const
{
    return !!d->id;
}

YaToolObjectType_e YaToolReferencedObject::get_object_type()
{
    return d->object_type;
}

bool YaToolReferencedObject::matchObject(const HObject& object) const
{
    bool match_found = false;
    //Iterate over all versions of the object in both databases
    for (const auto& wthisVer : getVersions())
    {
        const auto thisVer = wthisVer.lock();
        object.walk_versions([&](const HVersion& compVer)
        {
            //signature cannot match if the size differ
            if (thisVer->get_size() == compVer.size())
            {
                if (thisVer->matchesVersion(compVer))
                {
                    match_found = true;
                    return WALK_STOP;
                }
            }
            return WALK_CONTINUE;
        });
    }

    return match_found;
}



void YaToolReferencedObject::setVersionForSystem(std::shared_ptr<MatchingSystem> sys, const std::shared_ptr<YaToolObjectVersion>& version)
{
    d->systemVersions.insert(std::make_pair(sys, version));
}

void YaToolReferencedObject::putVersion(const std::shared_ptr<YaToolObjectVersion>& v)
{
    d->Versions.insert(v);
    for(const auto& sys : v->getMatchingSystems())
    {
        setVersionForSystem(sys.lock(), v);
    }
}

void YaToolReferencedObject::buildHashCode() const
{
    hashUpdate(d->id ? *d->id : 0);
}


void YaToolReferencedObject::linkXRefs(const std::unordered_map<YaToolObjectId, std::shared_ptr<YaToolReferencedObject>>& objectsById)
{
    for (const auto& it : d->Versions)
    {
        it.lock()->linkXrefs(objectsById);
    }
}

void YaToolReferencedObject::setParentObject(YaToolObjectVersion* object_version)
{
    for (const auto& it : d->Versions)
    {
        it.lock()->setParentObject(object_version);
    }
}

bool YaToolReferencedObject::hasParentObject()
{
    for (const auto& it : d->Versions)
    {
        if (it.lock()->hasParent())
        {
            return true;
        }
    }

    return false;
}

const std::unordered_set<std::weak_ptr<YaToolObjectVersion>>& YaToolReferencedObject::getVersions() const
{
    return d->Versions;
}

/**
 * Return a version from this object that matches a version/signature eventually coming from another object
 * If no version matches, return null
 */
std::shared_ptr<YaToolObjectVersion> YaToolReferencedObject::getMatchingVersion(HVersion version, HSignature signature) const
{
    const auto size = version.size();
    const auto& sign = signature.get();
    //Iterate over all versions of the object in both databases
    for (const auto& wthisVer : d->Versions)
    {
        const auto thisVer = wthisVer.lock();
        //signature cannot match if the size differ
        if (thisVer->get_size() == size)
        {
            //Iterate over all signatures in both databases
            for (const auto& thisSig : thisVer->getHashes())
            {
                if(std::equal_to<>()(sign, thisSig))
                {
                    return thisVer;
                }
            }
        }
    }

    return nullptr;
}

/**
 * Get all the versions of this object that match a list of systems.
 * This function returns a newly allocated object, that needs to be freed by the caller
 */
//TODO: avoid allocation object.
std::unordered_set<std::weak_ptr<YaToolObjectVersion>> YaToolReferencedObject::getVersionsForSystems(const std::unordered_set<std::shared_ptr<MatchingSystem>>& systems)
{
    std::unordered_set<std::weak_ptr<YaToolObjectVersion>> toReturn;

    for(const auto& sys : systems)
    {
        auto it = d->systemVersions.find(sys);
        if(it != d->systemVersions.end())
        {
            const auto matchingVersion = it->second;
            toReturn.insert(matchingVersion);
        }
    }

    return toReturn;
}

std::ostream & operator<<(std::ostream& oss, std::shared_ptr<YaToolReferencedObject> pYaToolReferencedObject)
{

    oss << ">>> ReferenceObject\n";
    for (auto it = pYaToolReferencedObject->getVersions().begin(); it != pYaToolReferencedObject->getVersions().end(); it++)
    {
        oss << it->lock() << "\n";
    }
    oss << "ReferenceObject <<<\n";

    return oss;
}

const std::string& YaToolReferencedObject::getComparableValue() const
{
    return d->comparable;
}
