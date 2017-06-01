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
#include <regex>

std::shared_ptr<IModelVisitor> MakeMultiplexerDebugger(const std::shared_ptr<IModelVisitor>& inner)
{
    auto exporter = MakeExporterValidatorVisitor();
    auto debugger = MakePathDebuggerVisitor("SaveValidator", exporter, PrintValues);
    auto delegater = std::make_shared<DelegatingVisitor>();
    delegater->add_delegate(debugger);
    delegater->add_delegate(inner);
    return delegater;
}

static const std::regex r_is_default_name("(?:"
                                          "loc|"
                                          "locret|"
                                          "sub|"
                                          "asc|"
                                          "byte|"
                                          "word|"
                                          "dword|"
                                          "qword|"
                                          "str|"
                                          "stru|"
                                          "unk"
                                          ")_[A-Fa-f0-9]+");

bool IsDefaultName(const const_string_ref& value)
{
    return std::regex_match(value.value, value.value + value.size, r_is_default_name);
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
