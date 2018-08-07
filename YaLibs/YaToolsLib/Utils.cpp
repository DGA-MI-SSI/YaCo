#include "Utils.hpp"

#include "YaTypes.hpp"

#include <regex>

#ifdef _MSC_VER
#   include <optional.hpp>
using namespace nonstd;
#else
#   include <experimental/optional>
using namespace std::experimental;
#endif

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

bool is_default_name(const const_string_ref& value)
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
    const std::regex r_yaco_version{"v(\\d+).(\\d+)-(\\d+)-g[a-fA-F0-9]+(:?-dirty)?\\s*(:?\\n)?"};

    optional<int> get_version_api(const std::string& version)
    {
        std::smatch match;
        const auto ok = std::regex_match(version, match, r_yaco_version);
        if(!ok)
            return nullopt;

        const auto major = std::stol(match.str(1));
        if(major < 0 || major > 0xFF)
            return nullopt;

        const auto minor = std::stol(match.str(2));
        if(minor < 0 || minor > 0xFF)
            return nullopt;

        const auto rev = std::stol(match.str(3));
        if(rev < 0 || rev > 0xFFFF)
            return nullopt;

        return major * 0x1000000
             + minor * 0x10000
             + rev;
    }
}

namespace ver
{
    ECheck check_yaco(const std::string& repo, const std::string& current)
    {
        const auto repo_ver = get_version_api(repo);
        const auto curr_ver = get_version_api(current);
        if(!repo_ver || !curr_ver)
            return INVALID;

        if(repo_ver < curr_ver)
            return OLDER;

        if(repo_ver > curr_ver)
            return NEWER;

        return OK;
    }
}
