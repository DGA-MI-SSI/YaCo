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
#include "Plugins.hpp"

#include "IModelVisitor.hpp"
#include "HVersion.hpp"
#include "Logger.h"

#include <functional>
#include <memory>

#ifdef __EA64__
#define EA_PREFIX "ll"
#else
#define EA_PREFIX ""
#endif
#define EA_FMT  "%" EA_PREFIX "x"
#define SEL_FMT "%" EA_PREFIX "d"

#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("arm", (FMT), ## __VA_ARGS__)

namespace
{
    struct ArmModel
        : public IPluginModel
    {
        ArmModel();

        // IPluginModel methods
        void accept_block   (IModelVisitor& v, ea_t ea) override;
        void accept_function(IModelVisitor& v, ea_t ea) override;

        const int thumb_segment_register;
    };

#define DECLARE_REF(name, value)\
    const char name ## _txt[] = value;\
    const const_string_ref name = {name ## _txt, sizeof name ## _txt - 1};
    DECLARE_REF(g_thumb_mode_flag, "thumb_mode_flag");
    DECLARE_REF(g_thumb_flag, "thumb_flag");
#undef DECLARE_REF

    void accept_ea(IModelVisitor& v, ea_t ea, int thumb_segment_register)
    {
        char buf[100];
        const auto thumb_flag = get_sreg(ea, thumb_segment_register);
        const auto n = snprintf(buf, sizeof buf, SEL_FMT, thumb_flag);
        if(n > 0)
            v.visit_attribute(g_thumb_mode_flag, {buf, static_cast<size_t>(n)});
    }
}

std::shared_ptr<IPluginModel> MakeArmPluginModel()
{
    return std::make_shared<ArmModel>();
}

ArmModel::ArmModel()
    : thumb_segment_register(str2reg("T"))
{
}

void ArmModel::accept_block(IModelVisitor& v, ea_t ea)
{
    accept_ea(v, ea, thumb_segment_register);

}

void ArmModel::accept_function(IModelVisitor& v, ea_t ea)
{
    accept_ea(v, ea, thumb_segment_register);
}

namespace
{
    struct ArmVisitor
        : public IPluginVisitor
    {
        ArmVisitor();

        // IPluginVisitor methods
        void make_basic_block_enter (const HVersion& version, ea_t ea) override;
        void make_basic_block_exit  (const HVersion& version, ea_t ea) override;
        void make_function_enter    (const HVersion& version, ea_t ea) override;
        void make_function_exit     (const HVersion& version, ea_t ea) override;

        const int thumb_segment_register;
    };
}

std::shared_ptr<IPluginVisitor> MakeArmPluginVisitor()
{
    return std::make_shared<ArmVisitor>();
}

ArmVisitor::ArmVisitor()
    : thumb_segment_register(str2reg("T"))
{
}

namespace
{
    void make_ea(const HVersion& version, ea_t ea, int thumb_segment_register)
    {
        std::string strthumb_flag;
        version.walk_attributes([&](const const_string_ref& key, const const_string_ref& val)
        {
            if(!(key == g_thumb_flag))
                return WALK_CONTINUE;
            strthumb_flag = make_string(val);
            return WALK_STOP;
        });
        if(strthumb_flag.empty())
            return;

        sel_t thumb_flag = 0;
        const auto n = sscanf(strthumb_flag.data(), SEL_FMT, &thumb_flag);
        if(n != 1)
            return;

        const auto current_thumb_flag = get_sreg(ea, thumb_segment_register);
        if(current_thumb_flag == thumb_flag)
            return;

        const auto end = static_cast<ea_t>(ea + version.size());
        set_sreg_at_next_code(ea, end, thumb_segment_register, thumb_flag);
    }
}

void ArmVisitor::make_basic_block_enter(const HVersion& /*version*/, ea_t /*ea*/)
{
}

void ArmVisitor::make_basic_block_exit(const HVersion& version, ea_t ea)
{
    make_ea(version, ea, thumb_segment_register);
}

void ArmVisitor::make_function_enter(const HVersion& version, ea_t ea)
{
    make_ea(version, ea, thumb_segment_register);
}

void ArmVisitor::make_function_exit(const HVersion& /*version*/, ea_t /*ea*/)
{
}
