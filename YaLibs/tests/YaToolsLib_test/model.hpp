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

namespace
{
struct Buffer : public Mmap_ABC
{
    Buffer(const void* pdata, size_t szdata)
        : data(reinterpret_cast<const uint8_t*>(pdata), reinterpret_cast<const uint8_t*>(pdata) + szdata)
    {
    }

    const void* Get() const
    {
        return &data[0];
    }

    size_t GetSize() const
    {
        return data.size();
    }

    std::vector<uint8_t> data;
};

template<typename T>
std::shared_ptr<IModel> create_fbmodel_with(const T& operand)
{
    const auto get_mmap = [&]
    {
        auto exporter = MakeFlatBufferExporter();
        operand(exporter);
        const auto buf = exporter->GetBuffer();
        return std::make_shared<Buffer>(buf.value, buf.size);
    };
    // enforce exporter deletion before model creation
    return MakeFlatBufferDatabaseModel(get_mmap());
}

template<typename T>
void expect_eq(T& values, const T& expected)
{
    EXPECT_EQ(expected, values);
    if(expected != values)
    {
        T empty, invalid_entries, missing_entries;
        for(const auto& value : expected)
        {
            const auto it = values.find(value);
            if(it != values.end())
                values.erase(it);
            else
                missing_entries.insert(value);
        }
        for(const auto& value : values)
            invalid_entries.insert(value);
        for(const auto& value : invalid_entries)
            fprintf(stderr, "invalid %s\n", ::testing::PrintToString(value).data());
        for(const auto& value : missing_entries)
            fprintf(stderr, "missing %s\n", ::testing::PrintToString(value).data());
        EXPECT_EQ(0u, invalid_entries.size());
        EXPECT_EQ(0u, missing_entries.size());
    }
    values.clear();
}

std::string str(const HSignature& sig)
{
    const auto& v = sig.get();
    return std::string(v.buffer, v.size);
}

std::string str(YaToolObjectId id)
{
    return YaToolObjectId_To_StdString(id);
}

std::string str(const HVersion& hver)
{
    return get_object_type_string(hver.type()) + std::string("_") + str(hver.id());
}

std::string str(const HObject& href)
{
    return get_object_type_string(href.type()) + std::string("_") + str(href.id());
}
}