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

#ifndef MATCHINGSYSTEM_H_
#define MATCHINGSYSTEM_H_

#include "IModelAccept.hpp"
#include "Hashable.hpp"

#include <map>
#include "YaTypes.hpp"

class MatchingSystem
    : public Hashable
    , public IModelAccept
{
    public:
        MatchingSystem(int id, const std::map<const std::string,const std::string>& attributes);
        MatchingSystem(const std::map<const std::string,const std::string>& attributes);
        ~MatchingSystem() override;

        // Hashable
        void buildHashCode() const override;

        // IModelAccept
        void accept(IModelVisitor& visitor) override;

        const std::map<const std::string,const std::string> getAttributes() const;

    private:
        const std::map<const std::string,const std::string> system_attributes;
};

#ifndef SWIG
namespace std
{
inline bool operator==(const std::weak_ptr<MatchingSystem>& a, const std::weak_ptr<MatchingSystem>& b)
{
    return a.lock() == b.lock();
}

template<>
struct hash<std::weak_ptr<MatchingSystem>>
{
    size_t operator()(const std::weak_ptr<MatchingSystem>& pHashable) const
    {
        return pHashable.lock()->getHashcode();
    }
};
}
#endif

#endif /* MATCHINGSYSTEM_H_ */
