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

namespace std { template<typename T> class shared_ptr; }

template <typename T>
class Comparable {
public:
             Comparable() {}
    virtual ~Comparable() {}

#ifndef SWIG
    friend bool operator<(const std::shared_ptr<T>& t1, const std::shared_ptr<T>& t2)
    {
        return t1->compare(t2) < 0;
    }

    friend bool operator<=(const std::shared_ptr<T>& t1, const std::shared_ptr<T>& t2)
    {
        return t1->compare(t2) <= 0;
    }

    friend bool operator==(const std::shared_ptr<T>& t1, const std::shared_ptr<T>& t2)
    {
        return t1->compare(t2) == 0;
    }

    friend bool operator!=(const std::shared_ptr<T>& t1, const std::shared_ptr<T>& t2)
    {
        return t1->compare(t2) != 0;
    }

    friend bool operator>=(const std::shared_ptr<T>& t1, const std::shared_ptr<T>& t2)
    {
        return t1->compare(t2) >= 0;
    }

    friend bool operator>(const std::shared_ptr<T>& t1, const std::shared_ptr<T>& t2)
    {
        return t1->compare(t2) > 0;
    }

    int compare(std::shared_ptr<T> t)
    {
        return getComparableValue().compare(t->getComparableValue());
    }
#endif//SWIG

    virtual const std::string& getComparableValue() const = 0;

};

