#pragma once

#include "IArch.hpp"

namespace yadiff
{
    std::shared_ptr<IArch> MakeX86Arch();
}