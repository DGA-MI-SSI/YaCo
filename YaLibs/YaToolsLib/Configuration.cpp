#include "Configuration.hpp"

#include "Helpers.h"
#include "Yatools.hpp"

#include <memory>
#include <string.h>
#include <libxml/xmlreader.h>

#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("cfg", (FMT), ## __VA_ARGS__)

Configuration::~Configuration()
{

}
Configuration::Configuration(const std::string& filename):
        filename_(filename)
{
}

static std::string xml_get_prop(xmlNode* node, const char* name)
{
    const auto value = xmlGetProp(node, BAD_CAST name);
    if(!value)
        return std::string();
    std::string reply{(char*) value};
    xmlFree(value);
    return reply;

}
xmlNodePtr GetSection(std::shared_ptr<xmlTextReader> reader, const std::string& section)
{
    do
    {
        auto current_obj = xmlTextReaderExpand(reader.get());
        if(xmlNodeIsText(current_obj)) {
            continue;
        }
        if (nullptr == current_obj)
        {
            return nullptr;
        }
        if(xmlStrcasecmp(current_obj->name, BAD_CAST section.c_str()) == 0)
        {
            return current_obj;
        }
    }while (xmlTextReaderNext(reader.get()) == 1);
    return nullptr;
}

const std::string Configuration::GetOption(const std::string& section, const std::string& option) const
{
    auto reader = std::shared_ptr<xmlTextReader>(xmlReaderForFile(filename_.c_str(), nullptr, 0),xmlFreeTextReader);
        if(reader.get() == nullptr) {
            LOG(ERROR, "could not parse file%s\n", filename_.c_str());
            return std::string();
        }
    // move to yadiff
    if(xmlTextReaderRead(reader.get()) != 1){
        LOG(ERROR, "could not parse file (1rst xmlTextReaderRead\n");
        return std::string();
    }
    // move to first section
    if(xmlTextReaderRead(reader.get()) != 1){
        LOG(ERROR, "could not parse file (2nd xmlTextReaderRead\n");
        return std::string();
    }
    auto section_node = GetSection(reader, section);
    if(nullptr == section_node)
    {
        LOG(WARNING, "could not find section %s\n", section.c_str());
        return std::string();
    }
    for (xmlNodePtr child = section_node->children; child != nullptr; child = child->next)
    {
        if(xmlStrcasecmp(child->name, BAD_CAST "option") != 0)
        {
            continue;
        }
        const auto attr = xml_get_prop(child, option.data());
        if(!attr.empty())
            return attr;
    }
    return std::string();
}

static const std::string TRUE_OPTION_VALUE = "true";

bool Configuration::IsOptionTrue(const std::string& section, const std::string& option) const
{
    return GetOption(section, option).compare(TRUE_OPTION_VALUE) == 0;
}
