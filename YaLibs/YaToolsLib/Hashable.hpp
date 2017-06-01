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

#ifndef HASHABLE_H_
#define HASHABLE_H_

#include <stdint.h>
#include <string>

typedef uint32_t hashcode_t;

class Hashable
{
    public:

        Hashable();
        virtual ~Hashable() {}

        void hashString(const std::string& str) const;
        void hashString(const char* str) const;
        void hashUpdate(const char* str) const;
        void hashUpdate(const std::string& str) const;
        void hashUpdate(uint32_t i) const;
        void hashUpdate(uint64_t i) const;

        hashcode_t getHashcode() const;

        virtual void buildHashCode() const = 0;

    private:
        mutable hashcode_t  hashcode;
        mutable bool        hash_built;
};

#ifndef SWIG
namespace std
{
    template<>
    struct hash<Hashable>
    {
        size_t operator()(const Hashable& pHashable) const
        {
            return pHashable.getHashcode();
        }
    };
}
#endif//SWIG

#endif /* HASHABLE_H_ */
