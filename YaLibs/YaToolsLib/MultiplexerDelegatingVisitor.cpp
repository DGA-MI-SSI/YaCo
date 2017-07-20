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

#include "MultiplexerDelegatingVisitor.hpp"

#include "PathDebuggerVisitor.hpp"
#include "ExporterValidatorVisitor.hpp"
#include "DelegatingVisitor.hpp"
#include "../Helpers.h"

#include <memory>

std::shared_ptr<IModelVisitor> MakeMultiplexerDebugger(const std::shared_ptr<IModelVisitor>& inner)
{
    auto exporter = MakeExporterValidatorVisitor();
    auto debugger = MakePathDebuggerVisitor("SaveValidator", exporter, PrintValues);
    auto delegater = std::make_shared<DelegatingVisitor>();
    delegater->add_delegate(debugger);
    delegater->add_delegate(inner);
    return delegater;
}

namespace
{
#define DECLARE_REF(name, value)\
    const char name ## _txt[] = value;\
    const const_string_ref name = {name ## _txt, sizeof name ## _txt - 1};
    DECLARE_REF(g_loc_, "loc_")
    DECLARE_REF(g_locret_, "locret_")
    DECLARE_REF(g_sub_, "sub_")
    DECLARE_REF(g_asc_, "asc_")
    DECLARE_REF(g_byte_, "byte_")
    DECLARE_REF(g_word_, "word_")
    DECLARE_REF(g_dword_, "dword_")
    DECLARE_REF(g_qword_, "qword_")
    DECLARE_REF(g_str_, "str_")
    DECLARE_REF(g_stru_, "stru_")
    DECLARE_REF(g_unk_, "unk_")
    DECLARE_REF(g_def_, "def_")
#undef DECLARE_REF

    const const_string_ref default_prefixes[] =
    {
        g_loc_,
        g_locret_,
        g_sub_,
        g_asc_,
        g_byte_,
        g_word_,
        g_dword_,
        g_qword_,
        g_str_,
        g_stru_,
        g_unk_,
        g_def_,
    };

    const_string_ref has_default_prefix(const const_string_ref& value)
    {
        for(const auto& prefix : default_prefixes)
        {
            if(value.size > prefix.size)
                if(!memcmp(prefix.value, value.value, prefix.size))
                    return const_string_ref{&value.value[prefix.size], value.size - prefix.size};
        }
        return {nullptr, 0};
    }
}

bool IsDefaultName(const const_string_ref& value)
{
    const auto str = has_default_prefix(value);
    if(!str.size)
        return false;
    const auto is_in_range = [](char a, char min, char max)
    {
        return min <= a && a <= max;
    };
    for(size_t i = 0; i < str.size; ++i)
        if(!is_in_range(str.value[i], '0', '9')
        && !is_in_range(str.value[i], 'a', 'f')
        && !is_in_range(str.value[i], 'A', 'F'))
            return false;
    return true;
}

namespace
{
struct DecoratorVisitor
    : public DelegatingVisitor
{
    DecoratorVisitor(const std::shared_ptr<IModelVisitor>& visitor, const std::string& prefix)
        : prefix_(prefix)
    {
        add_delegate(visitor);
    }

    void visit_name(const const_string_ref& name, int flags) override
    {
        if(!name.size)
            return DelegatingVisitor::visit_name(name, flags);

        if(IsDefaultName(name))
            return DelegatingVisitor::visit_name(name, flags);

        // prefix non-default names
        return DelegatingVisitor::visit_name(make_string_ref(prefix_ + name.value), flags);
    }

private:
    const std::string prefix_;
};
}

std::shared_ptr<IModelVisitor> MakeDecoratorVisitor(const std::shared_ptr<IModelVisitor>& visitor, const std::string& prefix)
{
    return std::make_shared<DecoratorVisitor>(visitor, prefix);
}
