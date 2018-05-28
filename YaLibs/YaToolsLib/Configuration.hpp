#pragma once

#include <string>
#include <functional>
namespace std { template<typename T> class shared_ptr;}



typedef std::function<bool (const std::string& option, const std::string& value)> OptionWalkerfn;

class Configuration
{
public:
    ~Configuration();
    Configuration(const std::string& filename);
    const std::string GetOption(const std::string& section, const std::string& option) const;
    bool IsOptionTrue(const std::string& section, const std::string& option) const;

private:
    const std::string filename_;
};
