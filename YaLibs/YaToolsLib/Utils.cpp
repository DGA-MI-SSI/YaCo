#include "Utils.hpp"

bool remove_substring(std::string& str, const std::string& substr)
{
    if (substr.empty())
        return false;

    const size_t pos = str.rfind(substr);
    if (pos == std::string::npos)
        return false;

    str.erase(pos, substr.size());
    return true;
}
