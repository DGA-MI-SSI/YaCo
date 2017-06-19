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

template<typename T>
struct Pool
{
    struct Item
    {
        Item(Pool& pool, std::unique_ptr<T> str)
            : pool_(pool)
            , str_(std::move(str))
        {
        }

        Item(Item&& ref)
            : pool_(ref.pool_)
            , str_(std::move(ref.str_))
        {
        }

        ~Item()
        {
            pool_.release(std::move(str_));
        }

        T& operator*() const
        {
            return *str_;
        }

        T* operator->() const
        {
            return str_.get();
        }

        Pool&               pool_;
        std::unique_ptr<T>  str_;
    };

    Pool(size_t size)
    {
        for(size_t i = 0; i < size; ++i)
            pool_.push_back(std::make_unique<T>());
    }

    ~Pool()
    {
        pool_.clear();
    }

    Item acquire()
    {
        if(pool_.empty())
            pool_.push_back(std::make_unique<T>());
        auto str = std::move(pool_.back());
        pool_item_clear(*str);
        pool_.pop_back();
        return{*this, std::move(str)};
    }

    void release(std::unique_ptr<T> str)
    {
        pool_.push_back(std::move(str));
    }

    std::vector<std::unique_ptr<T>> pool_;
};