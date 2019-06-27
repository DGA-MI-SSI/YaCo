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

#include "XmlAccept.hpp"

#include "Signature.hpp"
#include "IModelVisitor.hpp"
#include "YaTypes.hpp"
#include "BinHex.hpp"
#include "Helpers.h"
#include "Yatools.hpp"

#include <libxml/xmlreader.h>

#include <algorithm>
#include <map>

#ifdef _MSC_VER
#   include <filesystem>
#else
#   include <experimental/filesystem>
#endif

namespace fs = std::experimental::filesystem;


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

    YaToolObjectId id_from_string(const const_string_ref& txt)
    {
        YaToolObjectId id = 0;
        const auto n = hexbin(&id, sizeof id, txt.value, txt.size);
        return swap(id << (8 - n) * 8);
    }

    YaToolObjectType_e get_object_type_from_path(const fs::path& path)
    {
        auto it = path.begin();
        if(it == path.end())
            return OBJECT_TYPE_UNKNOWN;
        ++it;
        return it != path.end() ? get_object_type(it->string().data()) : OBJECT_TYPE_UNKNOWN;
    }

    std::vector<std::string> sort_files(std::vector<std::string> files)
    {
        std::sort(files.begin(), files.end(), [](const fs::path& a, const fs::path& b)
        {
            const auto atype = get_object_type_from_path(a);
            const auto btype = get_object_type_from_path(b);
            // make sure file order is stable
            return std::make_pair(indexed_types[atype], a) < std::make_pair(indexed_types[btype], b);
        });
        return files;
    }

    struct XmlModelFiles
    {
        XmlModelFiles(const std::vector<std::string>& files)
            : files_(sort_files(files))
        {
        }

        void accept(IModelVisitor& visitor);

        const std::vector<std::string> files_;
    };

    struct XmlModelMemory
    {
        XmlModelMemory(const void* data, size_t szdata)
            : data_(data)
            , szdata_(szdata)
        {
        }

        void accept(IModelVisitor& visitor);

        const void* data_;
        size_t      szdata_;
    };

    struct XmlModelPath
    {
        XmlModelPath(const std::string& path)
            : path_(path)
        {
        }

        void accept(IModelVisitor& visitor);

        const std::string path_;
    };

    struct XMLAllDatabaseModel
    {
        XMLAllDatabaseModel(const std::string& folder)
            : folder_(folder)
        {
        }

        void accept(IModelVisitor& visitor);

        const fs::path folder_;
    };
} // End ::

void AcceptXmlCache(IModelVisitor& visitor, const std::string& folder)
{
    XMLAllDatabaseModel(folder).accept(visitor);
}

void AcceptXmlFiles(IModelVisitor& visitor, const std::vector<std::string>& files)
{
    XmlModelFiles(files).accept(visitor);
}

void AcceptXmlMemory(IModelVisitor& visitor, const void* data, size_t szdata)
{
    visitor.visit_start();
    XmlModelMemory(data, szdata).accept(visitor);
    visitor.visit_end();
}

void AcceptXmlMemoryChunk(IModelVisitor& visitor, const void* data, size_t szdata)
{
    XmlModelMemory(data, szdata).accept(visitor);
}

namespace
{
    std::string xml_get_content(xmlNode* node)
    {
        const auto value = xmlNodeGetContent(node);
        if(!value)
            return std::string();

        std::string reply{(char*) value};
        xmlFree(value);
        return reply;
    }

    std::string xml_get_prop(xmlNode* node, const char* name)
    {
        const auto value = xmlGetProp(node, BAD_CAST name);
        if(!value)
            return std::string();

        std::string reply{(char*) value};
        xmlFree(value);
        return reply;
    }

    void accept_version(xmlNodePtr node, IModelVisitor& visitor)
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
                    LOG(ERROR, "missing blob offset\n");
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
            visitor.visit_parent_id(id_from_string(make_string_ref(parent_id)));
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
                        std::map<std::string, std::string> attributes;

                        const auto id_char = xml_get_content(xref->children);
                        const auto object_id = id_from_string(make_string_ref(id_char));

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

        /******************** attributes *************/
        for (xmlNodePtr child = node->children; child != nullptr; child = child->next)
        {
            if (xmlStrcasecmp(child->name, BAD_CAST"attribute") == 0)
            {
                visitor.visit_attribute(make_string_ref(xml_get_prop(child, "key")), make_string_ref(xml_get_content(child->children)));
            }
        }
        /*********************************************/

        std::vector<uint8_t> buffer;
        for(const auto& it : blobs)
        {
            const auto offset = it.first;
            const auto sizein = (it.second.size() + 1) >> 1;
            buffer.resize(sizein);
            const auto sizeout = hexbin(&buffer[0], sizein, it.second.data(), it.second.size());
            visitor.visit_blob(offset, &buffer[0], sizeout);
        }
    }

    void accept_object(YaToolObjectType_e type, xmlNodePtr node, IModelVisitor& visitor)
    {
        // Check if known type
        if (type == OBJECT_TYPE_UNKNOWN) {
            return;
        }

        if(xmlStrcmp(node->name, BAD_CAST get_object_type_string(type)))
            return;

        bool has_id = false;
        YaToolObjectId id = 0;
        for(auto id_child = node->children; id_child != nullptr; id_child = id_child->next)
        {
            if(xmlStrcasecmp(id_child->name, BAD_CAST "id"))
                continue;
            const auto node_content = xml_get_content(id_child->children);
            if(node_content.empty())
                continue;
            has_id = true;
            id = id_from_string(make_string_ref(node_content));
            break;
        }
        if(!has_id)
            return;

        visitor.visit_start_version(type, id);
        for(auto version_child = node->children; version_child != nullptr; version_child = version_child->next)
            if(xmlStrcasecmp(version_child->name, BAD_CAST "version") == 0)
                accept_version(version_child, visitor);
        visitor.visit_end_version();
    }

    void accept_node(xmlNodePtr node, IModelVisitor& visitor)
    {
        for (const auto type : ordered_types) {
            accept_object(type, node, visitor);
        }
    }

    void accept_reader(xmlTextReaderPtr reader, IModelVisitor& visitor)
    {
        // Check in != NULL
        if(!reader)
        {
            LOG(ERROR, "invalid xml reader\n");
            return;
        }

        // Check all file readable
        for (int i = 0; i < 2; ++i) {
            if (xmlTextReaderRead(reader) != 1)
            {
                LOG(ERROR, "unable to read xml node\n");
                return;
            }
        }
        do
        {
            auto current_obj = xmlTextReaderExpand(reader);
            if (xmlNodeIsText(current_obj)) {
                continue;
            }
            if (current_obj == nullptr) {
                return;
            }
            accept_node(current_obj, visitor);
        } while(xmlTextReaderNext(reader) == 1);
    }

    void accept_file(const std::string& filename, IModelVisitor& visitor)
    {
        auto reader = std::shared_ptr<xmlTextReader>(xmlReaderForFile(filename.c_str(), nullptr, 0), &xmlFreeTextReader);
        accept_reader(reader.get(), visitor);
    }
}

void XmlModelFiles::accept(IModelVisitor& visitor)
{
    visitor.visit_start();
    for (const auto& filename : files_) {
        accept_file(filename, visitor);
    }
    visitor.visit_end();
}

void XmlModelMemory::accept(IModelVisitor& visitor)
{
    auto reader = std::shared_ptr<xmlTextReader>(xmlReaderForMemory(static_cast<const char*>(data_), static_cast<int>(szdata_), "", nullptr, 0), &xmlFreeTextReader);
    accept_reader(reader.get(), visitor);
}

void XmlModelPath::accept(IModelVisitor& visitor)
{
    std::error_code ec;
    const auto root = fs::path(path_);
    if(!fs::is_directory(root, ec))
    {
        LOG(ERROR, "invalid directory %s\n", root.generic_string().data());
        return;
    }

    std::vector<std::string> files;
    for(const auto type : ordered_types)
    {
        files.clear();
        for(fs::directory_iterator it(root / get_object_type_string(type), ec), end; !ec && it != end; ++it)
            files.push_back(it->path().generic_string());
        std::sort(files.begin(), files.end());
        for(const auto& file : files)
            accept_file(file, visitor);
    }
}

void XMLAllDatabaseModel::accept(IModelVisitor& visitor)
{
    visitor.visit_start();
    if(fs::is_directory(folder_))
        XmlModelPath(folder_.string()).accept(visitor);
    else
        LOG(ERROR, "invalid directory %s\n", folder_.generic_string().data());
    visitor.visit_end();
}
