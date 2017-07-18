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

#include "XMLDatabaseModel.hpp"

#include "YaToolObjectId.hpp"
#include "Hexa.h"
#include "DelegatingVisitor.hpp"
#include "Signature.hpp"
#include "IModelAccept.hpp"
#include "../IModelVisitor.hpp"
#include "../YaTypes.hpp"
#include "../Logger.h"
#include "../Yatools.h"

#include <string>
#include <libxml/xmlreader.h>
#include <experimental/filesystem>
#include <list>
#include <map>
#include <unordered_map>

using namespace std::experimental;

#define THROW(FMT, ...) do {\
    YALOG_ERROR(nullptr, (FMT), ## __VA_ARGS__);\
    throw std::runtime_error("unexpected error");\
} while(0)

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

namespace
{
    struct XmlCleanup
    {
        ~XmlCleanup()
        {
            xmlCleanupParser();
        }
    };
    XmlCleanup cleanup;

    static const std::vector<std::string> gFolders =
    {
        "binary",
        "struc",
        "strucmember",
        "enum",
        "enum_member",
        "segment",
        "segment_chunk",
        "function",
        "stackframe",
        "stackframe_member",
        "reference_info",
        "code",
        "data",
        "basic_block",
    };

    class XMLDatabaseModelImpl : public IModelAccept
    {

    protected:
        void accept_file(const std::string& filename, IModelVisitor& visitor);
        void accept_file_node(xmlNodePtr node, IModelVisitor& visitor);
        void accept_reference_object(const std::string& object_type, xmlNodePtr node, IModelVisitor& visitor);
        void accept_version(xmlNodePtr node, IModelVisitor& visitor);

        const std::vector<std::string>& getFolderNames()
        {
            return gFolders;
        }
    };

    class XMLDatabaseModelFiles : public XMLDatabaseModelImpl {
        public:

        XMLDatabaseModelFiles(const std::vector<std::string>& files)
            : files(files)
        {
        }

        void accept(IModelVisitor& visitor) override;

        private:
        std::vector<std::string> files;
    };

    class XMLDatabaseModelPath : public XMLDatabaseModelImpl {
        public:

        XMLDatabaseModelPath(const std::string& path)
            : path(path)
        {
        }

        void accept(IModelVisitor& visitor) override;

        private:
        std::string path;
    };

    void SkipDelete(IModelVisitor* ptr)
    {
        UNUSED(ptr);
    }

    struct SkipVisitStartEndVisitor : public DelegatingVisitor
    {
        SkipVisitStartEndVisitor(IModelVisitor& next_visitor)
        {
            add_delegate(std::shared_ptr<IModelVisitor>(&next_visitor, &SkipDelete));
        }
        void visit_start() override {}
        void visit_end()   override {}
    };

    class XMLAllDatabaseModel : public IModelAccept
    {
    public:
        XMLAllDatabaseModel(const std::string& folder);
        void accept(IModelVisitor& visitor) override;
    private:
        std::string folder;
    };
}

std::shared_ptr<IModelAccept> MakeXmlAllDatabaseModel(const std::string& folder)
{
    return std::make_shared<XMLAllDatabaseModel>(folder);
}

std::shared_ptr<IModelAccept> MakeXmlDatabaseModel(const std::string& folder)
{
    return std::make_shared<XMLDatabaseModelPath>(folder);
}

std::shared_ptr<IModelAccept> MakeXmlFilesDatabaseModel(const std::vector<std::string>& files)
{
    return std::make_shared<XMLDatabaseModelFiles>(files);
}

XMLAllDatabaseModel::XMLAllDatabaseModel(const std::string& folder)
    : folder(folder)
{
}

void XMLAllDatabaseModel::accept(IModelVisitor& visitor) {
    visitor.visit_start();
    SkipVisitStartEndVisitor visitor_(visitor);

    filesystem::path cache_folder_path(folder);
    cache_folder_path /= "cache";
    filesystem::path db_folder_path(folder);
    db_folder_path /= "";

    /************ first import cache file *********************/
    if(filesystem::exists(db_folder_path)) {
        XMLDatabaseModelPath path_model(db_folder_path.string());
        path_model.accept(visitor_);
    }
    else
    {
        YALOG_ERROR(nullptr, "input database.xml not found as %s\n", db_folder_path.string().data());
    }
    /**********************************************************/

    /************ import cache / patches **********************/
    if(filesystem::is_directory(cache_folder_path)){
        XMLDatabaseModelPath path_model(cache_folder_path.string());
        path_model.accept(visitor_);
    }
    else
    {
        YALOG_ERROR(nullptr, "input cache not found as %s\n", cache_folder_path.string().data());
    }
    /**********************************************************/

    visitor.visit_end();
}

void XMLDatabaseModelFiles::accept(IModelVisitor& visitor){
    visitor.visit_start();
    for(const auto& filename : files) {
        accept_file(filename, visitor);
    }
    visitor.visit_end();
}

void XMLDatabaseModelImpl::accept_file(const std::string& filename, IModelVisitor& visitor) {
    auto reader = std::shared_ptr<xmlTextReader>(xmlReaderForFile(filename.c_str(), nullptr, 0),xmlFreeTextReader);
    if(reader.get() == nullptr) {
        THROW("could not parse file\n");
    }
    // move to sigfile
    if(xmlTextReaderRead(reader.get()) != 1){
        THROW("could not parse file (1rst xmlTextReaderRead\n");
    }
    //move to first referenced object
    if(xmlTextReaderRead(reader.get()) != 1){
        THROW("could not parse file (2nd xmlTextReaderRead\n");
    }
    do
    {
        auto current_obj = xmlTextReaderExpand(reader.get());
        if(xmlNodeIsText(current_obj)) {
            continue;
        }
        if (current_obj == nullptr)
        {
            return;
        }
        accept_file_node(current_obj, visitor);
    }while (xmlTextReaderNext(reader.get()) == 1);
}

void XMLDatabaseModelPath::accept(IModelVisitor& visitor){
    visitor.visit_start();
    const auto& folder_names = getFolderNames();
    try
    {
        filesystem::path root_folder(path);
        if (filesystem::exists(root_folder) && filesystem::is_directory(root_folder))
        {
            for (const auto& sub_folder : folder_names)
            {
                filesystem::path sub_folder_path(root_folder);
                sub_folder_path /= sub_folder;
                if (filesystem::exists(sub_folder_path) && filesystem::is_directory(sub_folder_path))
                {
                    std::list<std::string> files;
                    for (filesystem::directory_iterator file(sub_folder_path), end; file != end; file++)
                    {
                        filesystem::path file_path(*file);
                        files.push_back(file_path.string());
                    }
                    files.sort();
                    for(const auto& file : files)
                    {
                        accept_file(file, visitor);
                    }
                }
            }
        }
        else
        {
            THROW("input folder %s does not exist or is not a directory\n", root_folder.string().data());
        }
    }
    catch (const filesystem::filesystem_error& ex)
    {
        YALOG_ERROR(nullptr, "%s\n", ex.what());
    }

    visitor.visit_end();
}


void XMLDatabaseModelImpl::accept_file_node(xmlNodePtr node, IModelVisitor& visitor)
{
    for (const auto& object_type : getFolderNames())
    {
        accept_reference_object(object_type, node, visitor);
    }
}

static std::string xml_get_content(xmlNode* node)
{
    const auto value = xmlNodeGetContent(node);
    if(!value)
        return std::string();
    std::string reply{(char*) value};
    xmlFree(value);
    return reply;
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

void XMLDatabaseModelImpl::accept_reference_object(const std::string& object_type, xmlNodePtr node, IModelVisitor& visitor)
{
    if (xmlStrcmp(node->name, BAD_CAST object_type.c_str()) == 0)
    {
        const auto otype = get_object_type(object_type.data());
        if (otype == OBJECT_TYPE_UNKNOWN)
        {
            YALOG_ERROR(nullptr, "bug spotted, object_type %s\n", object_type.data());
        }
        visitor.visit_start_reference_object(otype);

        // id
        for (xmlNodePtr id_child = node->children; id_child != nullptr; id_child = id_child->next)
        {
            if (xmlStrcasecmp(id_child->name, BAD_CAST "id") == 0)
            {
                const auto node_content = xml_get_content(id_child->children);
                if(!node_content.empty())
                {
                    visitor.visit_id(YaToolObjectId_From_String(node_content.data(), node_content.size()));
                }
            }
        }

        for (xmlNodePtr version_child = node->children; version_child != nullptr; version_child = version_child->next)
        {
            if (xmlStrcasecmp(version_child->name, BAD_CAST "version") == 0)
            {
                accept_version(version_child, visitor);
            }

        }

        visitor.visit_end_reference_object();
    }
}

void XMLDatabaseModelImpl::accept_version(xmlNodePtr node, IModelVisitor& visitor)
{

    std::string name;
    std::string size;
    std::string parent_id;
    std::string address;
    std::string flags;
    std::string prototype;
    std::string str_type;
    std::string headercomment;
    std::string headercomment_repeatable;
    std::string userdefinedname;
    xmlNodePtr  signature_node = nullptr;
    uint32_t    name_flags = 0;
    uint32_t    userdefinedname_flags = 0;
    std::map<offset_t, std::string> blobs;


    visitor.visit_start_object_version();



    for (xmlNodePtr child = node->children; child != nullptr; child = child->next)
    {
        if (xmlStrcasecmp(child->name, BAD_CAST "parent_id") == 0)
        {
            parent_id = xml_get_content(child->children);
        }
        else if (xmlStrcasecmp(child->name, BAD_CAST "size") == 0)
        {
            size = xml_get_content(child->children);
        }
        else if(xmlStrcasecmp(child->name, BAD_CAST "address") == 0)
        {
            address = xml_get_content(child->children);
        }
        else if (xmlStrcasecmp(child->name, BAD_CAST "name") == 0)
        {
            name = xml_get_content(child->children);
            for (xmlAttr* attr = child->properties; attr != NULL; attr = attr->next)
            {
                name_flags = strtoul(xml_get_prop(child, "flags").data(), nullptr, 16);
            }
        }
        else if (xmlStrcasecmp(child->name, BAD_CAST "flags") == 0)
        {
            flags = xml_get_content(child->children);
        }
        else if (xmlStrcasecmp(child->name, BAD_CAST "proto") == 0)
        {
            prototype = xml_get_content(child->children);
        }
        else if (xmlStrcasecmp(child->name, BAD_CAST "str_type") == 0)
        {
            str_type = xml_get_content(child->children);
        }
        else if (xmlStrcasecmp(child->name, BAD_CAST "blob") == 0)
        {
            const auto blob_content = xml_get_content(child->children);
            //TODO ref (added by void) : should we free it??
            const auto blob_offset_str = xml_get_prop(child, "offset");
            if(blob_offset_str.empty())
            {
                YALOG_ERROR(nullptr, "no offset for blob\n");
            }
            else
            {
                offset_t blob_offset = strtoull(blob_offset_str.data(), nullptr, 16);
                blobs[blob_offset] = blob_content;
            }
        }
        else if (xmlStrcasecmp(child->name, BAD_CAST "repeatable_headercomment") == 0)
        {
            headercomment_repeatable = xml_get_content(child->children);
        }
        else if (xmlStrcasecmp(child->name, BAD_CAST "nonrepeatable_headercomment") == 0)
        {
            headercomment = xml_get_content(child->children);
        }
        else if (xmlStrcasecmp(child->name, BAD_CAST "userdefinedname") == 0)
        {
            userdefinedname = xml_get_content(child->children);
            const auto uflags = xml_get_prop(child, "flags");
            if (!uflags.empty())
            {
                userdefinedname_flags = strtoul(uflags.data(), nullptr, 16);
            }
        }
        else if (xmlStrcasecmp(child->name, BAD_CAST "signatures") == 0)
        {
            signature_node = child;
        }
    }

    if(!size.empty())
        visitor.visit_size(strtoull(size.data(), nullptr, 16));
    if(!userdefinedname.empty())
        visitor.visit_name(make_string_ref(userdefinedname), userdefinedname_flags);
    if(!parent_id.empty())
        visitor.visit_parent_id(YaToolObjectId_From_String(parent_id.data(), parent_id.size()));
    if(!address.empty())
        visitor.visit_address(strtoull(address.data(), nullptr, 16));
    if(!name.empty())
        visitor.visit_name(make_string_ref(name), name_flags);
    if(!prototype.empty())
        visitor.visit_prototype(make_string_ref(prototype));
    if(!flags.empty())
        visitor.visit_flags((flags_t)strtoull(flags.data(), nullptr, 16));
    if(!str_type.empty())
        visitor.visit_string_type(strtol(str_type.data(), nullptr, 10));

    /************ signatures ************/
    if (signature_node != nullptr)
    {
        visitor.visit_start_signatures();
        for (xmlNodePtr child = signature_node->children; child != nullptr; child = child->next)
        {
            if (xmlStrcasecmp(child->name, BAD_CAST"signature") == 0)
            {
                SignatureAlgo_e algo;
                SignatureMethod_e method;

                method = get_signature_method(xml_get_prop(child, "method").data());
                algo = get_signature_algo(xml_get_prop(child, "algo").data());

                visitor.visit_signature(method, algo, make_string_ref(xml_get_content(child)));
            }
        }
        visitor.visit_end_signatures();
    }
    /*****************************************/

    if(!headercomment.empty())
        visitor.visit_header_comment(false, make_string_ref(headercomment));

    if(!headercomment_repeatable.empty())
        visitor.visit_header_comment(true, make_string_ref(headercomment_repeatable));


    /**************** offsets ********************/
    bool offsets_started = false;
    for (xmlNodePtr child = node->children; child != nullptr; child = child->next)
    {
        if (xmlStrcasecmp(child->name, BAD_CAST"offsets") == 0)
        {
            if(!offsets_started) {
                visitor.visit_start_offsets();
                offsets_started = true;
            }
            for (xmlNodePtr offset = child->children; offset != nullptr; offset = offset->next)
            {
                if (xmlStrcasecmp(offset->name, BAD_CAST"comments") == 0)
                {
                    visitor.visit_offset_comments(
                        strtoull(xml_get_prop(offset, "offset").data(), nullptr, 16),
                        get_comment_type(xml_get_prop(offset, "type").data()),
                        make_string_ref(xml_get_content(offset->children))
                        );
                }
                else if (xmlStrcasecmp(offset->name, BAD_CAST"valueview") == 0)
                {
                    visitor.visit_offset_valueview(
                        strtoull(xml_get_prop(offset, "offset").data(), nullptr, 16),
                        strtoul(xml_get_prop(offset, "operand").data(), nullptr, 16),
                        make_string_ref(xml_get_content(offset->children))
                        );
                }
                else if (xmlStrcasecmp(offset->name, BAD_CAST"registerview") == 0)
                {
                    visitor.visit_offset_registerview(
                        strtoull(xml_get_prop(offset, "offset").data(), nullptr, 16),
                        strtoull(xml_get_prop(offset, "end_offset").data(), nullptr, 16),
                        make_string_ref(xml_get_prop(offset, "register")),
                        make_string_ref(xml_get_content(offset->children))
                        );
                }
                else if (xmlStrcasecmp(offset->name, BAD_CAST"hiddenarea") == 0)
                {
                    visitor.visit_offset_hiddenarea(
                        strtoull(xml_get_prop(offset, "offset").data(), nullptr, 16),
                        strtoull(xml_get_prop(offset, "size").data(), nullptr, 16),
                        make_string_ref(xml_get_content(offset->children))
                        );
                }
            }
        }
    }
    if(offsets_started) {
        visitor.visit_end_offsets();
    }
    /*********************************************/

    /************* xrefs *************************/
    bool xrefs_started = false;

    for (xmlNodePtr child = node->children; child != nullptr; child = child->next)
    {
        if (xmlStrcasecmp(child->name, BAD_CAST"xrefs") == 0)
        {
            if(!xrefs_started)
            {
                xrefs_started = true;
                visitor.visit_start_xrefs();
            }
            for (xmlNodePtr xref = child->children; xref != nullptr; xref = xref->next)
            {
                if (xmlStrcasecmp(xref->name, BAD_CAST"xref") == 0)
                {
                    uint64_t offset = 0;
                    uint32_t operand = 0;
                    std::unordered_map<std::string, std::string> attributes;

                    const auto id_char = xml_get_content(xref->children);
                    YaToolObjectId object_id = YaToolObjectId_From_String(id_char.data(), id_char.size());

                    for (xmlAttr* attr = xref->properties; attr != nullptr; attr = attr->next)
                    {
                        if (xmlStrcasecmp(attr->name, BAD_CAST"operand") == 0)
                        {
                            operand = strtoul(xml_get_content(attr->children).data(), nullptr, 16);
                        }
                        else if (xmlStrcasecmp(attr->name, BAD_CAST"offset") == 0)
                        {
                            offset = strtoull(xml_get_content(attr->children).data(), nullptr, 16);
                        }
                        else
                        {
                            attributes[(char*)attr->name] = xml_get_content(attr->children);
                        }

                    }
                    visitor.visit_start_xref(offset, object_id, operand);

                    for (const auto& it : attributes)
                    {
                        visitor.visit_xref_attribute(make_string_ref(it.first), make_string_ref(it.second));
                    }

                    visitor.visit_end_xref();
                }
            }
        }
    }
    if(xrefs_started)
    {
        visitor.visit_end_xrefs();
    }
    /*********************************************/


    /********************  matching system *******/
    visitor.visit_start_matching_systems();

    for (xmlNodePtr child = node->children; child != nullptr; child = child->next)
    {
        if (xmlStrcasecmp(child->name, BAD_CAST"matchingsystem") == 0)
        {
            offset_t offset = UNKNOWN_ADDR;
            std::map<const std::string, const std::string> description;
            for (xmlNodePtr system = child->children; system != nullptr; system = system->next)
            {
                if (xmlStrcasecmp(system->name, BAD_CAST"equipment") == 0)
                {
                    description.insert(std::make_pair("equipment", xml_get_content(system->children)));
                }
                else if (xmlStrcasecmp(system->name, BAD_CAST"os") == 0)
                {
                    description.insert(std::make_pair("os", xml_get_content(system->children)));
                }
                else if (xmlStrcasecmp(system->name, BAD_CAST"address") == 0)
                {
                    offset = strtoull(xml_get_content(system->children).data(), nullptr, 16);
                }
            }
            visitor.visit_start_matching_system(offset);

            for (auto it = description.begin(); it != description.end(); it++)
            {
                visitor.visit_matching_system_description(make_string_ref(it->first), make_string_ref(it->second));
            }

            visitor.visit_end_matching_system();
        }
    }

    visitor.visit_end_matching_systems();
    /*********************************************/

    /******************** attributes *************/
    for (xmlNodePtr child = node->children; child != nullptr; child = child->next)
    {
        if (xmlStrcasecmp(child->name, BAD_CAST"attribute") == 0)
        {
            visitor.visit_attribute(make_string_ref(xml_get_prop(child, "key")), make_string_ref(xml_get_content(child->children)));
        }
    }
    /*********************************************/

    for(const auto& it : blobs)
    {
        const offset_t offset = it.first;
        size_t byte_count = (it.second.length()+1)/2;
        std::vector<uint8_t> buffer(byte_count);
        hex_to_buffer(it.second.c_str(), byte_count, &buffer[0]);
        visitor.visit_blob(offset, &buffer[0], byte_count);
    }
    visitor.visit_end_object_version();
}
