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

#include "Helpers.h"

#include "YaTypes.hpp"
#include "Ida.h"
#include "Plugins.hpp"

#include "IModelVisitor.hpp"
#include "HVersion.hpp"
#include "YaHelpers.hpp"

#include <functional>
#include <memory>

namespace
{
    struct ArmModel
        : public IPluginModel
    {
        // Ctor
        ArmModel();

        // IPluginModel methods
        void accept_block   (IModelVisitor& v, ea_t ea) override;
        void accept_function(IModelVisitor& v, ea_t ea) override;

        const int thumb_segment_register;
    };

    // Declare g_tumb_mode global strings
    DECLARE_REF(g_thumb_mode_flag, "thumb_mode_flag");
    DECLARE_REF(g_thumb_flag, "thumb_flag");

    void accept_ea(IModelVisitor& v, ea_t ea, int thumb_segment_register)
    {
        // Return if thumb 
        char buf[100];
        const auto thumb_flag = get_sreg(ea, thumb_segment_register);
        const auto n = snprintf(buf, sizeof buf, "%" PRIdEA, thumb_flag);
        if(n <=  0) { return; }
        // Else visit flag
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
    // Manage thumb flag 
    void make_ea(const HVersion& version, ea_t ea, int thumb_segment_register)
    {
        std::string strthumb_flag;
        version.walk_attributes([&](const const_string_ref& key, const const_string_ref& val)
        {
            // Continue if current node is flag
            if(!(key == g_thumb_flag)) {
                return WALK_CONTINUE;
            }
            // Else get string
            strthumb_flag = make_string(val);
            return WALK_STOP;
        });
        // Return if flag == 0
        if(strthumb_flag.empty()) { return; }

        // Scan flag string & Check
        sel_t thumb_flag = 0;
        const auto n = sscanf(strthumb_flag.data(), "%" PRIdEA, &thumb_flag);
        if(n != 1) { return; }

        // Get ea flag & Check
        const auto current_thumb_flag = get_sreg(ea, thumb_segment_register);
        if(current_thumb_flag == thumb_flag) { return; }

        // Set thumb as far as you can
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
