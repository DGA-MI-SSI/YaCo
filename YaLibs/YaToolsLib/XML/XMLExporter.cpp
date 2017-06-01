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
#include "YaToolObjectId.hpp"
#include "IModelVisitor.hpp"

#include <iostream>
#include <stdexcept>

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
typedef struct _xmlTextWriter xmlTextWriter;
typedef xmlTextWriter* xmlTextWriterPtr;
typedef struct _xmlDoc xmlDoc;
typedef xmlDoc* xmlDocPtr;
typedef struct _xmlBuffer xmlBuffer;
typedef xmlBuffer *xmlBufferPtr;

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
    YaToolObjectType_e              object_type_;
    bool                            delete_file_;
    std::shared_ptr<xmlTextWriter>  writer_;
    std::shared_ptr<xmlDoc>         doc_;
    std::string                     tmp_value_;
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
    , doc_          (nullptr)
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

    rc = xmlTextWriterStartElement(writer_.get(), BAD_CAST "sigfile");
    if (rc < 0)
    {
        throw "could not start xml element sigfile";
    }

    rc = xmlTextWriterStartElement(writer_.get(), BAD_CAST get_object_type_string(object_type));
    if (rc < 0)
    {
        throw "could not start xml element sigfile";
    }
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
    int rc = xmlTextWriterStartElement(writer_.get(), BAD_CAST get_object_type_string(object_type));
    if (rc < 0)
    {
        throw "could not start xml element sigfile";
    }
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
    // close object_type
    rc = xmlTextWriterEndElement(writer_.get());
    if (rc < 0)
    {
        throw "could not end object_type element";
    }

    //close sigfile
    rc = xmlTextWriterEndElement(writer_.get());
    if (rc < 0)
    {
        throw "could not end sigfile element";
    }

    rc = xmlTextWriterEndDocument(writer_.get());
    if (rc < 0)
    {
        throw "could not end xml document";
    }
    writer_.reset();

    rc = xmlSaveFormatFileEnc((char*)current_xml_file_path_.c_str(), &*doc_, XML_ENCODING, 1);
    doc_.reset();
}
void FileXMLExporter::visit_end_reference_object() {

    int rc = 0;
    // close object_type
    rc = xmlTextWriterEndElement(writer_.get());
    if (rc < 0)
        throw "could not end object_type element";

    writer_.reset();
    doc_.reset();

    output_ << xmlBufferContent(buffer_.get());
    output_.flush();
    buffer_.reset();
}

void XMLExporter::visit_id(YaToolObjectId object_id)
{
    filesystem::path tmp_path(current_xml_file_path_);
    char id_str[YATOOL_OBJECT_ID_STR_LEN+1];
    YaToolObjectId_To_String(id_str, YATOOL_OBJECT_ID_STR_LEN+1, object_id);
    tmp_path /= string(id_str) + ".xml";

    current_xml_file_path_ = tmp_path.string();

    if(delete_file_ == false)
    {
        int rc = xmlTextWriterWriteElement(writer_.get(), BAD_CAST"id", BAD_CAST id_str);
        if (rc < 0)
        {
            throw "could not write id";
        }
    }
}

void FileXMLExporter::visit_id(YaToolObjectId object_id)
{
    if(delete_file_ == false)
    {
        char id_str[YATOOL_OBJECT_ID_STR_LEN+1];
        YaToolObjectId_To_String(id_str, YATOOL_OBJECT_ID_STR_LEN+1, object_id);

        int rc = xmlTextWriterWriteElement(writer_.get(), BAD_CAST"id", BAD_CAST id_str);
        if (rc < 0)
        {
            throw "could not write id";
        }
    }

}

void XMLExporter_common::visit_start_object_version()
{
    int rc = 0;
    rc = xmlTextWriterStartElement(writer_.get(), BAD_CAST"version");
    if (rc < 0)
    {
        throw "could not write version";
    }
}

void XMLExporter_common::visit_parent_id(YaToolObjectId object_id)
{
    char buffer[64];
    if(!object_id)
        return;

    memset(buffer, 0, sizeof buffer);
    sprintf(buffer, "%016" PRIXOFFSET, object_id);
    if(xmlTextWriterWriteElement(writer_.get(), BAD_CAST "parent_id", BAD_CAST buffer) < 0)
    {
        throw "could not add parent_id element";
    }
}

void XMLExporter_common::visit_address(offset_t address)
{
    char buffer[64];
    if(!address)
        return;

    memset(buffer, 0, sizeof buffer);
    sprintf(buffer, "%" PRIXOFFSET, address);
    if(xmlTextWriterWriteElement(writer_.get(), BAD_CAST "address", BAD_CAST buffer) < 0)
    {
        throw "could not add address element";
    }
}

void XMLExporter_common::visit_end_object_version()
{
    int rc = 0;
    rc = xmlTextWriterEndElement(writer_.get());
    if (rc < 0)
    {
        throw "could not write version end";
    }
}

void XMLExporter_common::visit_name(const const_string_ref& name, int flags)
{
    int rc = 0;
    rc = xmlTextWriterStartElement(writer_.get(), BAD_CAST"userdefinedname");
    if (rc < 0)
    {
        throw "could not start name element";
    }
    if (flags != 0)
    {
        char flags_buffer[(sizeof(flags) + 3) * 2] = {0};
        sprintf(flags_buffer, "0x%08X", flags);
        rc = xmlTextWriterWriteAttribute(writer_.get(), BAD_CAST "flags", BAD_CAST flags_buffer);
        if (rc < 0)
        {
            throw "could not add flag attribute to name element";
        }

    }
    if (name.size && xmlTextWriterWriteString(writer_.get(), BAD_CAST name.value) < 0)
    {
        throw "could not write user defined name value";
    }
    rc = xmlTextWriterEndElement(writer_.get());
    if (rc < 0)
    {
        throw "could not end name element";
    }
}

void XMLExporter_common::visit_size(offset_t size)
{
    char size_buffer[(sizeof(size) + 3) * 2] = { 0 };
    sprintf(size_buffer, "0x%016" PRIXOFFSET, size);
    if (xmlTextWriterWriteElement(writer_.get(), BAD_CAST "size", BAD_CAST size_buffer) < 0)
    {
        throw "could not add size element";
    }
}

void  XMLExporter_common::visit_start_signatures()
{
    if (xmlTextWriterStartElement(writer_.get(), BAD_CAST "signatures") < 0)
    {
        throw "could not start signatures element";
    }
}

void XMLExporter_common::visit_signature(SignatureMethod_e method, SignatureAlgo_e algo, const const_string_ref& hex)
{
    if (xmlTextWriterStartElement(writer_.get(), BAD_CAST "signature") < 0)
    {
        throw "could not start signature element";
    }
    if (xmlTextWriterWriteAttribute(writer_.get(), BAD_CAST "algo", BAD_CAST get_signature_algo_string(algo)) < 0)
    {
        throw "could not add algo attribute to signature element";
    }
    if (xmlTextWriterWriteAttribute(writer_.get(), BAD_CAST "method", BAD_CAST get_signature_method_string(method)) < 0)
    {
        throw "could not add algo attribute to signature element";
    }

    if (xmlTextWriterWriteString(writer_.get(), BAD_CAST hex.value)  < 0)
    {
        throw "could not add hash value to signature";
    }
    if (xmlTextWriterEndElement(writer_.get()) < 0)
    {
        throw "could not end signature element";
    }
}

void XMLExporter_common::visit_end_signatures()
{
    if (xmlTextWriterEndElement(writer_.get()) < 0)
    {
        throw "could not end signatures element";
    }
}

void XMLExporter_common::visit_prototype(const const_string_ref& prototype)
{
    if (xmlTextWriterWriteElement(writer_.get(), BAD_CAST"proto", BAD_CAST prototype.value) < 0)
    {
        throw "could not end signatures element";
    }
}

void XMLExporter_common::visit_string_type(int str_type)
{
    char str_type_buffer[sizeof(str_type) * 2 + 2] = { 0 };
    sprintf(str_type_buffer, "%d", str_type);
    if (xmlTextWriterWriteElement(writer_.get(), BAD_CAST "str_type", BAD_CAST str_type_buffer) < 0)
    {
        throw "could not add str_type element";
    }
}

static std::string xml_escape(const const_string_ref& ref)
{
    return xml_escape(make_string(ref));
}

void XMLExporter_common::visit_header_comment(bool repeatable, const const_string_ref& comment)
{
    if (repeatable == true)
    {
        if (xmlTextWriterWriteElement(writer_.get(), BAD_CAST "repeatable_headercomment", BAD_CAST xml_escape(comment).c_str()) < 0)
        {
            throw "could not add repeatable_headercomment element";
        }
    }
    else
    {
        if (xmlTextWriterWriteElement(writer_.get(), BAD_CAST "nonrepeatable_headercomment", BAD_CAST xml_escape(comment).c_str()) < 0)
        {
            throw "could not add nonrepeatable_headercomment element";
        }
    }
}

void XMLExporter_common::visit_start_offsets()
{
    if (xmlTextWriterStartElement(writer_.get(), BAD_CAST"offsets") < 0)
    {
        throw "could not start offsets element";
    }
}

void XMLExporter_common::visit_end_offsets()
{
    if (xmlTextWriterEndElement(writer_.get()) < 0)
    {
        throw "could not end offsets element";
    }
}

void XMLExporter_common::visit_offset_comments(offset_t offset, CommentType_e comment_type, const const_string_ref& comment)
{
    if (xmlTextWriterStartElement(writer_.get(), BAD_CAST "comments") < 0)
    {
        throw "could not start comments element";
    }
    if (xmlTextWriterWriteAttribute(writer_.get(), BAD_CAST "offset", BAD_CAST get_uint_hex(offset).c_str()) < 0)
    {
        throw "could not add offset attribute to comments element";
    }
    if (xmlTextWriterWriteAttribute(writer_.get(), BAD_CAST "type", BAD_CAST get_comment_type_string(comment_type)) < 0)
    {
        throw "could not add type attribute to comments element";
    }
    if (xmlTextWriterWriteString(writer_.get(), BAD_CAST xml_escape(comment).c_str())  < 0)
    {
        throw "could not write offset comments content";
    }
    if (xmlTextWriterEndElement(writer_.get()) < 0)
    {
        throw "could not end comments element";
    }
}

void XMLExporter_common::visit_offset_valueview(offset_t offset, operand_t operand, const const_string_ref& view_value)
{

    if (xmlTextWriterStartElement(writer_.get(), BAD_CAST "valueview") < 0)
    {
        throw "could not start valueview element";
    }
    if (xmlTextWriterWriteAttribute(writer_.get(), BAD_CAST "offset", BAD_CAST get_uint_hex(offset).c_str()) < 0)
    {
        throw "could not add offset attribute to valueview element";
    }
    if (xmlTextWriterWriteAttribute(writer_.get(), BAD_CAST "operand", BAD_CAST get_uint_hex(operand).c_str()) < 0)
    {
        throw "could not add operand attribute to valueview element";
    }
    if (xmlTextWriterWriteString(writer_.get(), BAD_CAST view_value.value)  < 0)
    {
        throw "could not write valueview content";
    }
    if (xmlTextWriterEndElement(writer_.get()) < 0)
    {
        throw "could not end valueview element";
    }
}

void XMLExporter_common::visit_offset_registerview(offset_t offset, offset_t end_offset, const const_string_ref& register_name, const const_string_ref& register_new_name)
{

    if (xmlTextWriterStartElement(writer_.get(), BAD_CAST "registerview") < 0)
    {
        throw "could not start registerview element";
    }
    if (xmlTextWriterWriteAttribute(writer_.get(), BAD_CAST "offset", BAD_CAST get_uint_hex(offset).c_str()) < 0)
    {
        throw "could not add offset attribute to registerview element";
    }
    if (xmlTextWriterWriteAttribute(writer_.get(), BAD_CAST "end_offset", BAD_CAST get_uint_hex(end_offset).c_str()) < 0)
    {
        throw "could not add end_offset attribute to registerview element";
    }
    if (xmlTextWriterWriteAttribute(writer_.get(), BAD_CAST "register", BAD_CAST register_name.value) < 0)
    {
        throw "could not add register attribute to registerview element";
    }
    if (xmlTextWriterWriteString(writer_.get(), BAD_CAST register_new_name.value)  < 0)
    {
        throw "could not write registerview content";
    }
    if (xmlTextWriterEndElement(writer_.get()) < 0)
    {
        throw "could not end registerview element";
    }
}

void XMLExporter_common::visit_offset_hiddenarea(offset_t offset, offset_t area_size, const const_string_ref& hidden_area_value)
{

    if (xmlTextWriterStartElement(writer_.get(), BAD_CAST "hiddenarea") < 0)
    {
        throw "could not start hiddenarea element";
    }
    if (xmlTextWriterWriteAttribute(writer_.get(), BAD_CAST "offset", BAD_CAST get_uint_hex(offset).c_str()) < 0)
    {
        throw "could not add offset attribute to hiddenarea element";
    }
    if (xmlTextWriterWriteAttribute(writer_.get(), BAD_CAST "size", BAD_CAST get_uint_hex(area_size).c_str()) < 0)
    {
        throw "could not add size attribute to hiddenarea element";
    }
    if (xmlTextWriterWriteString(writer_.get(), BAD_CAST hidden_area_value.value)  < 0)
    {
        throw "could not write hiddenarea content";
    }
    if (xmlTextWriterEndElement(writer_.get()) < 0)
    {
        throw "could not end hiddenarea element";
    }
}

void XMLExporter_common::visit_start_xrefs()
{
    if (xmlTextWriterStartElement(writer_.get(), BAD_CAST"xrefs") < 0)
    {
        throw "could not start xrefs element";
    }
}

void XMLExporter_common::visit_end_xrefs()
{
    if (xmlTextWriterEndElement(writer_.get()) < 0)
    {
        throw "could not end xrefs element";
    }
}

void XMLExporter_common::visit_start_matching_systems()
{
    //if (xmlTextWriterStartElement(writer_.get(), BAD_CAST"matchingsystem") < 0)
    //{
    //  throw "could not start matchingsystem element";
    //}
}


void XMLExporter_common::visit_end_matching_systems()
{
    //if (xmlTextWriterEndElement(writer_) < 0)
    //{
    //  throw "could not end matchingsystem element";
    //}
}

void XMLExporter_common::visit_segments_start()
{

}

void XMLExporter_common::visit_segments_end()
{

}

void XMLExporter_common::visit_attribute(const const_string_ref& attr_name, const const_string_ref& attr_value)
{
    if (xmlTextWriterStartElement(writer_.get(), BAD_CAST"attribute") < 0)
    {
        throw "could not start attribute element";
    }

    if (xmlTextWriterWriteAttribute(writer_.get(), BAD_CAST"key", BAD_CAST attr_name.value) < 0)
    {
        throw "could not add key attribute to attribute";
    }

    if (xmlTextWriterWriteString(writer_.get(), BAD_CAST attr_value.value) < 0)
    {
        throw "could not add value content to attribute";
    }

    if(xmlTextWriterEndElement(writer_.get()) < 0)
    {
        throw "could not end attribute element";
    }
}

void XMLExporter_common::visit_start_xref(offset_t offset,
    YaToolObjectId offset_value, operand_t operand) {
    if (xmlTextWriterStartElement(writer_.get(), BAD_CAST"xref") < 0)
    {
        throw "could not start xref element";
    }
    string offset_str = "0x";
    offset_str += get_uint_hex(offset);

    if (xmlTextWriterWriteAttribute(writer_.get(), BAD_CAST"offset", BAD_CAST offset_str.c_str()) < 0)
    {
        throw "could not add offset attribute to xref";
    }
    if (operand != 0)
    {
        string operand_str = "0x";
        operand_str += get_uint_hex(operand);
        if (xmlTextWriterWriteAttribute(writer_.get(), BAD_CAST"operand", BAD_CAST operand_str.c_str()) < 0)
        {
            throw "could not add operand attribute to xref";
        }
    }
    // keep this value until we can write it (all attributes must be set before)
    char id_str[YATOOL_OBJECT_ID_STR_LEN+1];
    YaToolObjectId_To_String(id_str, YATOOL_OBJECT_ID_STR_LEN+1, offset_value);

    tmp_value_ = id_str;

}

void XMLExporter_common::visit_end_xref()
{
    if (xmlTextWriterWriteString(writer_.get(), BAD_CAST tmp_value_.c_str()) < 0)
    {
        throw "could not write xref offset id";
    }
    if (xmlTextWriterEndElement(writer_.get()) < 0)
    {
        throw "could not end xref element";
    }
}

void XMLExporter_common::visit_xref_attribute(const const_string_ref& attribute_key, const const_string_ref& attribute_value)
{
    if (xmlTextWriterWriteAttribute(writer_.get(), BAD_CAST attribute_key.value, BAD_CAST attribute_value.value) < 0)
    {
        throw "could not add attribute to xref";
    }
}

void XMLExporter_common::visit_start_matching_system(offset_t address)
{
    if (xmlTextWriterStartElement(writer_.get(), BAD_CAST"matchingsystem") < 0)
    {
        throw "could not start matchingsystem element";
    }
    if (address != UNKNOWN_ADDR)
    {
        if (xmlTextWriterWriteElement(writer_.get(), BAD_CAST"address", BAD_CAST get_uint_hex(address).c_str()) < 0)
        {
            throw "could not start address matchingsystem element";
        }
    }
}

void XMLExporter_common::visit_matching_system_description(const const_string_ref& description_key, const const_string_ref& description_value)
{
    if (xmlTextWriterWriteElement(writer_.get(), BAD_CAST description_key.value, BAD_CAST description_value.value) < 0)
    {
        throw "could not add system description system element";
    }
}

void XMLExporter_common::visit_end_matching_system()
{
    if (xmlTextWriterEndElement(writer_.get()) < 0)
    {
        throw "could not end matching system element";
    }
}

void XMLExporter_common::visit_blob(offset_t offset, const void* blob, size_t len)
{
    std::vector<char> buffer(len*2 + 1);

    buffer_to_hex(blob, len, &buffer[0]);
    buffer[len*2] = 0;

    if (xmlTextWriterStartElement(writer_.get(), BAD_CAST "blob") < 0)
        throw "could not start blob element";

    if (xmlTextWriterWriteAttribute(writer_.get(), BAD_CAST"offset", BAD_CAST get_uint_hex(offset).c_str()) < 0)
        throw "could not add key attribute to blob";

    if (xmlTextWriterWriteString(writer_.get(), BAD_CAST &buffer[0]) < 0)
    {
        static_assert(sizeof offset == sizeof(uint64_t), "bad static assert");
        YALOG_ERROR(nullptr, "bad blob at %" PRIXOFFSET " len=%zx\n", offset, len);
        YALOG_ERROR(nullptr, "content: %s\n", &buffer[0]);
        throw "could not add value content to blob";
    }

    if(xmlTextWriterEndElement(writer_.get()) < 0)
        throw "could not end blob element";
}

void XMLExporter_common::visit_flags(flags_t flags)
{
    if (flags == 0)
    {
        return;
    }
    char buffer[(sizeof(flags) + 3) * 2] = { 0 };
    sprintf(buffer, "0x%X", flags);
    if (xmlTextWriterWriteElement(writer_.get(), BAD_CAST "flags", BAD_CAST buffer) < 0)
    {
        throw "could not add flags element";
    }
}

static const std::vector<std::string> gFolders =
{
    "binary",
    "segment",
    "segment_chunk",
    "struc",
    "strucmember",
    "enum",
    "enum_member",
    "function",
    "stackframe",
    "stackframe_member",
    "basic_block",
    "data",
    "code",
    "reference_info",
};

//TODO "Add a static assert here"


const std::vector<std::string>& XMLExporter::getFolderNames()
{
    return gFolders;
}
