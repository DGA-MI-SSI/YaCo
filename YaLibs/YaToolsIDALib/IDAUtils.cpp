#include "IDAUtils.hpp"

#include "Utils.hpp"
#include "Ida.h"

std::string ea_to_hex(ea_t ea)
{
    char buffer[32];
    const int len = snprintf(buffer, COUNT_OF(buffer), "0x" EA_FMT, ea);
    return std::string(buffer, len);
}
