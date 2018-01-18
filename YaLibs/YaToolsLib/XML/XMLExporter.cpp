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

#include "XMLExporter.hpp"

#include "common.hpp"
#include "IModelAccept.hpp"
#include "Hexa.h"
#include "../../Helpers.h"
#include "Logger.h"
#include "Yatools.h"
#include "Signature.hpp"
#include "IModelVisitor.hpp"
#include "BinHex.hpp"

#include <iostream>
#include <stdexcept>
#include <vector>

#define LIBXML_WRITER_ENABLED
#define LIBXML_OUTPUT_ENABLED
#include <libxml/encoding.h>
#include <libxml/xmlwriter.h>

#ifdef _MSC_VER
#   include <filesystem>
#else
#   include <experimental/filesystem>
#endif

#include <fstream>

using namespace std;
using namespace std::experimental;

namespace
{
#define XML_ENCODING "iso-8859-15"
#define INDENT_STRING "  "

class XMLExporter_common : public IModelVisitor
{
public:
    XMLExporter_common();

    void visit_start_object(YaToolObjectType_e object_type) override;
    void visit_start_default_object(YaToolObjectType_e object_type) override;
    void visit_start_object_version() override;
    void visit_parent_id(YaToolObjectId object_id) override;
    void visit_address(offset_t address) override;
    void visit_end_object_version() override;
    void visit_name(const const_string_ref& name, int flags) override;
    void visit_size(offset_t size) override;
    void visit_start_signatures() override;
    void visit_signature(SignatureMethod_e method, SignatureAlgo_e algo, const const_string_ref& hex) override;
    void visit_end_signatures() override;
    void visit_prototype(const const_string_ref& prototype) override;
    void visit_string_type(int str_type) override;
    void visit_header_comment(bool repeatable, const const_string_ref& comment) override;
    void visit_start_offsets() override;
    void visit_end_offsets() override;
    void visit_offset_comments(offset_t offset, CommentType_e comment_type, const const_string_ref& comment) override;
    void visit_offset_valueview(offset_t offset, operand_t operand, const const_string_ref& view_value) override;
    void visit_offset_registerview(offset_t offset, offset_t end_offset, const const_string_ref& register_name, const const_string_ref& register_new_name) override;
    void visit_offset_hiddenarea(offset_t offset, offset_t area_size, const const_string_ref& hidden_area_value) override;
    void visit_start_xrefs() override;
    void visit_end_xrefs() override;
    void visit_start_xref(offset_t offset, YaToolObjectId offset_value, operand_t operand) override;
    void visit_end_xref() override;
    void visit_xref_attribute(const const_string_ref& attribute_key, const const_string_ref& attribute_value) override;
    void visit_start_matching_systems() override;
    void visit_end_matching_systems() override;
    void visit_start_matching_system(offset_t address) override;
    void visit_matching_system_description(const const_string_ref& description_key, const const_string_ref& description_value) override;
    void visit_end_matching_system() override;
    void visit_segments_start() override;
    void visit_segments_end() override;
    void visit_attribute(const const_string_ref& attr_name, const const_string_ref& attr_value) override;
    void visit_blob(offset_t offset, const void* blob, size_t len) override;
    void visit_flags(flags_t flags) override;

protected:
    std::shared_ptr<xmlTextWriter>  writer_;
    std::shared_ptr<xmlDoc>         doc_;
    std::string                     tmp_value_;
    std::string                     bufkey_;
    std::string                     bufval_;
    YaToolObjectType_e              object_type_;
    bool                            delete_file_;
};

class XMLExporter : public XMLExporter_common
{
public:
    XMLExporter(const std::string& path);
    void visit_start() override;
    void visit_end() override;
    void visit_start_reference_object(YaToolObjectType_e object_type) override;
    void visit_end_reference_object() override;
    void visit_start_deleted_object(YaToolObjectType_e object_type) override;
    void visit_end_deleted_object() override;
    void visit_end_default_object() override;
    void visit_id(YaToolObjectId object_id) override;

protected:
    const std::vector<std::string>& getFolderNames();

private:
    std::string path_;
    std::string current_xml_file_path_;
};

class FileXMLExporter : public XMLExporter_common
{
public:
    FileXMLExporter(const std::string& path);
    void visit_start() override;
    void visit_end() override;
    void visit_start_reference_object(YaToolObjectType_e object_type) override;
    void visit_end_reference_object() override;
    void visit_start_deleted_object(YaToolObjectType_e object_type) override;
    void visit_end_deleted_object() override;
    void visit_end_default_object() override;
    void visit_id(YaToolObjectId object_id) override;

private:
    std::string                 path_;
    std::ofstream               output_;
    std::shared_ptr<xmlBuffer>  buffer_;
};
}

std::shared_ptr<IModelVisitor> MakeXmlExporter(const std::string& path)
{
    return std::make_shared<XMLExporter>(path);
}

std::shared_ptr<IModelVisitor> MakeFileXmlExporter(const std::string& path)
{
    return std::make_shared<FileXMLExporter>(path);
}

FileXMLExporter::FileXMLExporter(const std::string& path)
    : path_     (path)
{
}

XMLExporter::XMLExporter(const std::string& path)
    : path_     (path)
{
}

XMLExporter_common::XMLExporter_common()
    : object_type_  (OBJECT_TYPE_DATA)
    , delete_file_  (false)
{
}

void XMLExporter::visit_start()
{
    //ensure destination folders
    filesystem::path root_folder(path_);
    if (filesystem::exists(root_folder) == false)
    {
        filesystem::create_directory(root_folder);
    }
    if (filesystem::is_directory(root_folder) == false)
    {
        throw invalid_argument("output folder is a not a directory");
    }

    for (const auto& sub_folder : getFolderNames())
    {
        filesystem::path sub_folder_path(root_folder);
        sub_folder_path /= sub_folder;

        if (filesystem::exists(sub_folder_path) == false)
        {
            filesystem::create_directory(sub_folder_path);
        }
    }
}

void XMLExporter::visit_end()
{
}

void FileXMLExporter::visit_start()
{
    if(writer_ != nullptr)
    {
        throw "could not start visiting reference object, last visit is not ended";
    }
    output_.open(path_);
    output_ << "<?xml version=\"1.0\" encoding=\"" << XML_ENCODING << "\"?>\n<sigfile>\n";

}

void FileXMLExporter::visit_end()
{
    output_ << "</sigfile>";
    output_.close();
}

void XMLExporter_common::visit_start_object(YaToolObjectType_e object_type)
{
    UNUSED(object_type);
}

namespace
{
const char g_empty[] = "";

const char* make_text(std::string& dst, const const_string_ref& src)
{
    dst.assign(src.value, src.size);
    return dst.empty() ? g_empty : &dst[0];
}

void start_element(xmlTextWriter& xml, const char* name)
{
    const auto err = xmlTextWriterStartElement(&xml, BAD_CAST name);
    if(err < 0)
        throw std::runtime_error(std::string("unable to start element ") + name);
}

void add_element(xmlTextWriter& xml, const char* name, const char* content)
{
    const auto err = xmlTextWriterWriteElement(&xml, BAD_CAST name, BAD_CAST content);
    if(err < 0)
        throw std::runtime_error(std::string("unable to add element ") + name + ": " + content);
}

void end_element(xmlTextWriter& xml, const char* name)
{
    const auto err = xmlTextWriterEndElement(&xml);
    if(err < 0)
        throw std::runtime_error(std::string("unable to end element ") + name);
}

void add_attribute(xmlTextWriter& xml, const char* key, const char* value)
{
    const auto err = xmlTextWriterWriteAttribute(&xml, BAD_CAST key, BAD_CAST value);
    if(err < 0)
        throw std::runtime_error(std::string("unable to write attribute ") + key + ": " + value);
}

void write_string(xmlTextWriter& xml, const char* content)
{
    const auto err = xmlTextWriterWriteString(&xml, BAD_CAST content);
    if(err < 0)
        throw std::runtime_error(std::string("unable to write string ") + content);
}
}

void XMLExporter::visit_start_reference_object(YaToolObjectType_e object_type)
{
    delete_file_ = false;
    int rc = 0;
    object_type_ = object_type;
    if(writer_)
        throw "could not start visiting reference object, last visit is not ended";

    xmlDocPtr pdoc = nullptr;
    writer_.reset(xmlNewTextWriterDoc(&pdoc, 0), xmlFreeTextWriter);
    doc_.reset(pdoc, xmlFreeDoc);
    xmlTextWriterSetIndentString(writer_.get(), BAD_CAST INDENT_STRING);
    if (writer_ == nullptr)
    {
        throw "could not create xml doc writer_";
    }
    rc = xmlTextWriterStartDocument(writer_.get(), NULL, XML_ENCODING, NULL);
    if (rc < 0)
    {
        throw "could not start xml document";
    }

    start_element(*writer_, "sigfile");
    start_element(*writer_, get_object_type_string(object_type));

    filesystem::path tmp_path(path_);
    tmp_path /= get_object_type_string(object_type);

    current_xml_file_path_ = tmp_path.string();
}

void FileXMLExporter::visit_start_reference_object(YaToolObjectType_e object_type)
{
    delete_file_ = false;
    buffer_.reset(xmlBufferCreate(), xmlBufferFree);
    writer_.reset(xmlNewTextWriterMemory(buffer_.get(), 0), xmlFreeTextWriter);
    xmlTextWriterSetIndentString(writer_.get(), BAD_CAST INDENT_STRING);
    xmlTextWriterSetIndent(writer_.get(), 1);
    start_element(*writer_, get_object_type_string(object_type));
}

void XMLExporter::visit_start_deleted_object(YaToolObjectType_e object_type)
{
    delete_file_ = true;
    object_type_ = object_type;
    if(writer_)
    {
        throw "could not start visiting reference object, last visit is not ended";
    }

    filesystem::path tmp_path(path_);
    tmp_path /= get_object_type_string(object_type);

    current_xml_file_path_ = tmp_path.string();
}

void FileXMLExporter::visit_start_deleted_object(YaToolObjectType_e object_type)
{
    delete_file_ = true;
    object_type_ = object_type;
}

void XMLExporter_common::visit_start_default_object(YaToolObjectType_e object_type)
{
    visit_start_deleted_object(object_type);
}

void XMLExporter::visit_end_deleted_object()
{
    try
    {
        filesystem::remove(current_xml_file_path_);
    }
    catch(const std::exception& exc)
    {
        YALOG_ERROR(nullptr, "Warning : could not delete object : %s\n", exc.what());
    }
}

void XMLExporter::visit_end_default_object()
{
    try
    {
        filesystem::remove(current_xml_file_path_);
    }
    catch(const std::exception&)
    {
        //Ignore this error : default objects might already not exist
    }
}

void FileXMLExporter::visit_end_deleted_object()
{

}

void FileXMLExporter::visit_end_default_object()
{

}

void XMLExporter::visit_end_reference_object()
{
    int rc = 0;

    end_element(*writer_, "object_type");
    end_element(*writer_, "sigfile");

    rc = xmlTextWriterEndDocument(writer_.get());
    if (rc < 0)
    {
        throw "could not end xml document";
    }
    writer_.reset();

    rc = xmlSaveFormatFileEnc((char*)current_xml_file_path_.c_str(), &*doc_, XML_ENCODING, 1);
    doc_.reset();
}

void FileXMLExporter::visit_end_reference_object()
{
    end_element(*writer_, "object_type");

    writer_.reset();
    doc_.reset();

    output_ << xmlBufferContent(buffer_.get());
    output_.flush();
    buffer_.reset();
}

void XMLExporter::visit_id(YaToolObjectId object_id)
{
    char buf[sizeof object_id * 2 + 1];
    to_hex<NullTerminate>(buf, object_id);

    filesystem::path tmp_path(current_xml_file_path_);
    tmp_path /= string(buf) + ".xml";
    current_xml_file_path_ = tmp_path.string();

    if(delete_file_)
        return;

    add_element(*writer_, "id", buf);
}

void FileXMLExporter::visit_id(YaToolObjectId object_id)
{
    if(delete_file_)
        return;

    char buf[sizeof object_id * 2 + 1];
    to_hex<NullTerminate>(buf, object_id);
    add_element(*writer_, "id", buf);
}

void XMLExporter_common::visit_start_object_version()
{
    start_element(*writer_, "version");
}

void XMLExporter_common::visit_parent_id(YaToolObjectId object_id)
{
    if(!object_id)
        return;

    char buf[sizeof object_id * 2 + 1];
    to_hex<NullTerminate>(buf, object_id);
    add_element(*writer_, "parent_id", buf);
}

void XMLExporter_common::visit_address(offset_t address)
{
    if(!address)
        return;

    char buf[sizeof address * 2 + 1];
    const auto str = to_hex<RemovePadding | NullTerminate>(buf, address);
    add_element(*writer_, "address", str.value);
}

void XMLExporter_common::visit_end_object_version()
{
    end_element(*writer_, "version");
}

void XMLExporter_common::visit_name(const const_string_ref& name, int flags)
{
    start_element(*writer_, "userdefinedname");
    if(flags)
    {
        char buf[2 + sizeof flags * 2 + 1];
        to_hex<HexaPrefix | NullTerminate>(buf, static_cast<uint32_t>(flags));
        add_attribute(*writer_, "flags", buf);
    }
    if(name.size)
        write_string(*writer_, make_text(bufkey_, name));
    
    end_element(*writer_, "userdefinedname");
}

void XMLExporter_common::visit_size(offset_t size)
{
    char buf[2 + sizeof size * 2 + 1];
    to_hex<HexaPrefix | NullTerminate>(buf, size);
    add_element(*writer_, "size", buf);
}

void  XMLExporter_common::visit_start_signatures()
{
    start_element(*writer_, "signatures");
}

void XMLExporter_common::visit_signature(SignatureMethod_e method, SignatureAlgo_e algo, const const_string_ref& hex)
{
    start_element(*writer_, "signature");
    add_attribute(*writer_, "algo", get_signature_algo_string(algo));
    add_attribute(*writer_, "method", get_signature_method_string(method));
    write_string(*writer_, make_text(bufkey_, hex));
    end_element(*writer_, "signature");
}

void XMLExporter_common::visit_end_signatures()
{
    end_element(*writer_, "signatures");
}

void XMLExporter_common::visit_prototype(const const_string_ref& prototype)
{
    add_element(*writer_, "proto", make_text(bufkey_, prototype));
}

void XMLExporter_common::visit_string_type(int str_type)
{
    char str_type_buffer[sizeof(str_type) * 2 + 2] = { 0 };
    sprintf(str_type_buffer, "%d", str_type);
    add_element(*writer_, "str_type", str_type_buffer);
}

static std::string xml_escape(const const_string_ref& ref)
{
    return xml_escape(make_string(ref));
}

void XMLExporter_common::visit_header_comment(bool repeatable, const const_string_ref& comment)
{
    const char* key = repeatable ? "repeatable_headercomment" : "nonrepeatable_headercomment";
    add_element(*writer_, key, xml_escape(comment).data());
}

void XMLExporter_common::visit_start_offsets()
{
    start_element(*writer_, "offsets");
}

void XMLExporter_common::visit_end_offsets()
{
    end_element(*writer_, "offsets");
}

void XMLExporter_common::visit_offset_comments(offset_t offset, CommentType_e comment_type, const const_string_ref& comment)
{
    char buf[sizeof offset * 2 + 1];
    start_element(*writer_, "comments");
    add_attribute(*writer_, "offset", to_hex<NullTerminate>(buf, offset).value);
    add_attribute(*writer_, "type", get_comment_type_string(comment_type));
    write_string(*writer_, xml_escape(comment).data());
    end_element(*writer_, "comments");
}

void XMLExporter_common::visit_offset_valueview(offset_t offset, operand_t operand, const const_string_ref& view_value)
{
    char offbuf[sizeof offset * 2 + 1];
    char opbuf[sizeof operand * 2 + 1];
    start_element(*writer_, "valueview");
    add_attribute(*writer_, "offset", to_hex<NullTerminate>(offbuf, offset).value);
    add_attribute(*writer_, "operand", to_hex<NullTerminate>(opbuf, static_cast<uint32_t>(operand)).value);
    write_string(*writer_, make_text(bufkey_, view_value));
    end_element(*writer_, "valueview");
}

void XMLExporter_common::visit_offset_registerview(offset_t offset, offset_t end_offset, const const_string_ref& register_name, const const_string_ref& register_new_name)
{
    char buf[sizeof offset * 2 + 1];
    start_element(*writer_, "registerview");
    add_attribute(*writer_, "offset", to_hex<NullTerminate>(buf, offset).value);
    add_attribute(*writer_, "end_offset", to_hex<NullTerminate>(buf, end_offset).value);
    add_attribute(*writer_, "register", make_text(bufkey_, register_name));
    write_string(*writer_, make_text(bufkey_, register_new_name));
    end_element(*writer_, "registerview");
}

void XMLExporter_common::visit_offset_hiddenarea(offset_t offset, offset_t area_size, const const_string_ref& hidden_area_value)
{
    char buf[sizeof offset * 2 + 1];
    start_element(*writer_, "hiddenarea");
    add_attribute(*writer_, "offset", to_hex<NullTerminate>(buf, offset).value);
    add_attribute(*writer_, "size", to_hex<NullTerminate>(buf, area_size).value);
    write_string(*writer_, make_text(bufkey_, hidden_area_value));
    end_element(*writer_, "hiddenarea");
}

void XMLExporter_common::visit_start_xrefs()
{
    start_element(*writer_, "xrefs");
}

void XMLExporter_common::visit_end_xrefs()
{
    end_element(*writer_, "xrefs");
}

void XMLExporter_common::visit_start_matching_systems()
{
    if(false)
        start_element(*writer_, "matchingsystem");
}


void XMLExporter_common::visit_end_matching_systems()
{
    if(false)
        end_element(*writer_, "matchingsystem");
}

void XMLExporter_common::visit_segments_start()
{

}

void XMLExporter_common::visit_segments_end()
{

}

void XMLExporter_common::visit_attribute(const const_string_ref& attr_name, const const_string_ref& attr_value)
{
    start_element(*writer_, "attribute");
    add_attribute(*writer_, "key", make_text(bufkey_, attr_name));
    write_string(*writer_, make_text(bufkey_, attr_value));
    end_element(*writer_, "attribute");
}

void XMLExporter_common::visit_start_xref(offset_t offset, YaToolObjectId offset_value, operand_t operand)
{
    char offbuf[2 + sizeof offset * 2 + 1];
    start_element(*writer_, "xref");
    add_attribute(*writer_, "offset", to_hex<NullTerminate | HexaPrefix>(offbuf, offset).value);
    if(operand)
        add_attribute(*writer_, "operand", to_hex<NullTerminate | HexaPrefix>(offbuf, static_cast<offset_t>(operand)).value);

    // keep this value until we can write it (all attributes must be set before)
    char buf[sizeof offset_value * 2];
    tmp_value_ = make_string(to_hex(buf, offset_value));
}

void XMLExporter_common::visit_end_xref()
{
    write_string(*writer_, tmp_value_.data());
    end_element(*writer_, "xref");
}

void XMLExporter_common::visit_xref_attribute(const const_string_ref& attribute_key, const const_string_ref& attribute_value)
{
    add_attribute(*writer_, make_text(bufkey_, attribute_key), make_text(bufval_, attribute_value));
}

void XMLExporter_common::visit_start_matching_system(offset_t address)
{
    char buf[sizeof address * 2 + 1];
    start_element(*writer_, "matchingsystem");
    if(address != UNKNOWN_ADDR)
        add_element(*writer_, "address", to_hex<NullTerminate>(buf, address).value);
}

void XMLExporter_common::visit_matching_system_description(const const_string_ref& description_key, const const_string_ref& description_value)
{
    add_element(*writer_, make_text(bufkey_, description_key), make_text(bufval_, description_value));
}

void XMLExporter_common::visit_end_matching_system()
{
    end_element(*writer_, "matchingsystem");
}

void XMLExporter_common::visit_blob(offset_t offset, const void* blob, size_t len)
{
    std::vector<char> buffer(len*2 + 1);

    buffer_to_hex(blob, len, &buffer[0]);
    buffer[len*2] = 0;

    static_assert(sizeof offset == sizeof(uint64_t), "bad offset_t sizeof");

    char buf[sizeof offset * 2 + 1];
    start_element(*writer_, "blob");
    add_attribute(*writer_, "offset", to_hex<NullTerminate>(buf, offset).value);
    write_string(*writer_, &buffer[0]);
    end_element(*writer_, "blob");
}

void XMLExporter_common::visit_flags(flags_t flags)
{
    if(!flags)
        return;

    char buffer[(sizeof(flags) + 3) * 2] = { 0 };
    sprintf(buffer, "0x%X", flags);
    add_element(*writer_, "flags", buffer);
}

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

//TODO "Add a static assert here"


const std::vector<std::string>& XMLExporter::getFolderNames()
{
    return gFolders;
}
