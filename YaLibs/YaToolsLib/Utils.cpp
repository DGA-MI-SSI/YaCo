#include "Utils.hpp"

#include "YaTypes.hpp"

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