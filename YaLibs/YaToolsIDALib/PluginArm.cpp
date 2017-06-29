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

#include "YaTypes.hpp"
#include "Ida.h"
#include "PluginModel.hpp"

#include "IModelVisitor.hpp"

#ifdef __EA64__
#define SEL_FMT "%lld"
#else
#define SEL_FMT "%d"
#endif

namespace
{
    struct Arm
        : public PluginModel
    {
        Arm();
        void accept_block(IModelVisitor& v, ea_t ea) override;
        void accept_function(IModelVisitor& v, ea_t ea) override;

        const int thumb_segment_register;
    };

#define DECLARE_REF(name, value)\
    const char name ## _txt[] = value;\
    const const_string_ref name = {name ## _txt, sizeof name ## _txt - 1};
    DECLARE_REF(g_thumb_mode_flag, "thumb_mode_flag");
#undef DECLARE_REF

    void accept_ea(IModelVisitor& v, ea_t ea, int thumb_segment_register)
    {
        char buf[100];
        const auto thumb_flag = get_segreg(ea, thumb_segment_register);
        const auto n = snprintf(buf, sizeof buf, SEL_FMT, thumb_flag);
        if(n > 0)
            v.visit_attribute(g_thumb_mode_flag, {buf, static_cast<size_t>(n)});
    }
}

std::shared_ptr<PluginModel> MakeArmPluginModel()
{
    return std::make_shared<Arm>();
}

Arm::Arm()
    : thumb_segment_register(str2reg("T"))
{
}

void Arm::accept_block(IModelVisitor& v, ea_t ea)
{
    accept_ea(v, ea, thumb_segment_register);

}

void Arm::accept_function(IModelVisitor& v, ea_t ea)
{
    accept_ea(v, ea, thumb_segment_register);
}