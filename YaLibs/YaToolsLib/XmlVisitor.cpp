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

#include "XmlVisitor.hpp"

#include "Yatools.hpp"
#include "Signature.hpp"
#include "IModelVisitor.hpp"
#include "BinHex.hpp"

#include <iostream>
#include <sstream>
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

#include <algorithm>
#include <fstream>

using namespace std;
using namespace std::experimental;

namespace
{
#define XML_ENCODING "iso-8859-15"
#define INDENT_STRING "  "

class XmlVisitor_common : public IModelVisitor
{
public:
    XmlVisitor_common();

    void visit_parent_id(YaToolObjectId object_id) override;
    void visit_address(offset_t address) override;
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
};

class XmlVisitor : public XmlVisitor_common
{
public:
    XmlVisitor(const std::string& path);
    void visit_start() override;
    void visit_end() override;
    void visit_deleted(YaToolObjectType_e type, YaToolObjectId id) override;
    void visit_start_version(YaToolObjectType_e type, YaToolObjectId id) override;
    void visit_end_version() override;

private:
    std::string path_;
    std::string current_xml_file_path_;
};

struct MemExporter
    : public XmlVisitor_common
{
    void visit_start() override;
    void visit_end() override;
    void visit_deleted(YaToolObjectType_e type, YaToolObjectId id) override;
    void visit_start_version(YaToolObjectType_e type, YaToolObjectId id) override;
    void visit_end_version() override;

    std::stringstream           stream_;
    std::shared_ptr<xmlBuffer>  buffer_;
};

struct FileXmlVisitor
    : public MemExporter
{
    FileXmlVisitor(const std::string& path);
    void visit_end() override;
    const std::string path_;
};

struct StringXmlVisitor
    : public MemExporter
{
    StringXmlVisitor(std::string& output);
    void visit_end() override;
    std::string& output_;
};
}

std::shared_ptr<IModelVisitor> MakeXmlVisitor(const std::string& path)
{
    return std::make_shared<XmlVisitor>(path);
}

std::shared_ptr<IModelVisitor> MakeFileXmlVisitor(const std::string& path)
{
    return std::make_shared<FileXmlVisitor>(path);
}

std::shared_ptr<IModelVisitor> MakeMemoryXmlVisitor(std::string& output)
{
    return std::make_shared<StringXmlVisitor>(output);
}

FileXmlVisitor::FileXmlVisitor(const std::string& path)
    : path_     (path)
{
}

XmlVisitor::XmlVisitor(const std::string& path)
    : path_     (path)
{
}

XmlVisitor_common::XmlVisitor_common()
    : object_type_  (OBJECT_TYPE_DATA)
{
}

void XmlVisitor::visit_start()
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

    for(const auto type : ordered_types)
    {
        filesystem::path sub_folder_path(root_folder);
        sub_folder_path /= get_object_type_string(type);
        if (filesystem::exists(sub_folder_path) == false)
        {
            filesystem::create_directory(sub_folder_path);
        }
    }
}

void XmlVisitor::visit_end()
{
}

void MemExporter::visit_start()
{
    if(writer_ != nullptr)
    {
        throw "could not start visiting reference object, last visit is not ended";
    }
    stream_ << "<?xml version=\"1.0\" encoding=\"" << XML_ENCODING << "\"?>\n<sigfile>\n";

}

void MemExporter::visit_end()
{
    stream_ << "</sigfile>";
}

void FileXmlVisitor::visit_end()
{
    MemExporter::visit_end();
    std::ofstream output;
    output.open(path_);
    output << stream_.str();
    output.close();
}

StringXmlVisitor::StringXmlVisitor(std::string& output)
    : output_(output)
{
}

void StringXmlVisitor::visit_end()
{
    MemExporter::visit_end();
    output_ = stream_.str();
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

std::string get_path(std::string& bufid, YaToolObjectType_e type, YaToolObjectId id, const filesystem::path& root)
{
    char buf[sizeof id * 2 + 1];
    to_hex<NullTerminate>(buf, id);
    bufid.assign(buf);
    return (root / get_object_type_string(type) / (bufid + ".xml")).string();
}
}

void XmlVisitor::visit_start_version(YaToolObjectType_e type, YaToolObjectId id)
{
    int rc = 0;
    object_type_ = type;
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
    start_element(*writer_, get_object_type_string(type));

    std::string bufid;
    current_xml_file_path_ = get_path(bufid, type, id, path_);
    add_element(*writer_, "id", bufid.data());
    start_element(*writer_, "version");
}

void XmlVisitor::visit_end_version()
{
    int rc = 0;

    end_element(*writer_, "version");
    end_element(*writer_, get_object_type_string(object_type_));
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

void XmlVisitor::visit_deleted(YaToolObjectType_e type, YaToolObjectId id)
{
    if(writer_)
        throw "could not start visiting reference object, last visit is not ended";

    std::string dummy;
    current_xml_file_path_ = get_path(dummy, type, id, path_);
    std::error_code ec;
    const auto ok = filesystem::remove(current_xml_file_path_, ec);
    if(!ok && ec && ec != std::errc::no_such_file_or_directory)
        YALOG_ERROR(nullptr, "warning: unable to delete %s\n", current_xml_file_path_.data());
}

void MemExporter::visit_start_version(YaToolObjectType_e type, YaToolObjectId id)
{
    buffer_.reset(xmlBufferCreate(), xmlBufferFree);
    writer_.reset(xmlNewTextWriterMemory(buffer_.get(), 0), xmlFreeTextWriter);
    xmlTextWriterSetIndentString(writer_.get(), BAD_CAST INDENT_STRING);
    xmlTextWriterSetIndent(writer_.get(), 1);
    start_element(*writer_, get_object_type_string(type));

    char buf[sizeof id * 2 + 1];
    to_hex<NullTerminate>(buf, id);
    add_element(*writer_, "id", buf);
    start_element(*writer_, "version");
}

void MemExporter::visit_end_version()
{
    end_element(*writer_, "version");
    end_element(*writer_, get_object_type_string(object_type_));

    writer_.reset();
    doc_.reset();

    stream_ << xmlBufferContent(buffer_.get());
    stream_.flush();
    buffer_.reset();
}

void MemExporter::visit_deleted(YaToolObjectType_e /*type*/, YaToolObjectId /*id*/)
{
}

void XmlVisitor_common::visit_parent_id(YaToolObjectId object_id)
{
    if(!object_id)
        return;

    char buf[sizeof object_id * 2 + 1];
    to_hex<NullTerminate>(buf, object_id);
    add_element(*writer_, "parent_id", buf);
}

void XmlVisitor_common::visit_address(offset_t address)
{
    if(!address)
        return;

    char buf[sizeof address * 2 + 1];
    const auto str = to_hex<RemovePadding | NullTerminate>(buf, address);
    add_element(*writer_, "address", str.value);
}

void XmlVisitor_common::visit_name(const const_string_ref& name, int flags)
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

void XmlVisitor_common::visit_size(offset_t size)
{
    char buf[2 + sizeof size * 2 + 1];
    to_hex<HexaPrefix | NullTerminate>(buf, size);
    add_element(*writer_, "size", buf);
}

void  XmlVisitor_common::visit_start_signatures()
{
    start_element(*writer_, "signatures");
}

void XmlVisitor_common::visit_signature(SignatureMethod_e method, SignatureAlgo_e algo, const const_string_ref& hex)
{
    start_element(*writer_, "signature");
    add_attribute(*writer_, "algo", get_signature_algo_string(algo));
    add_attribute(*writer_, "method", get_signature_method_string(method));
    write_string(*writer_, make_text(bufkey_, hex));
    end_element(*writer_, "signature");
}

void XmlVisitor_common::visit_end_signatures()
{
    end_element(*writer_, "signatures");
}

void XmlVisitor_common::visit_prototype(const const_string_ref& prototype)
{
    add_element(*writer_, "proto", make_text(bufkey_, prototype));
}

void XmlVisitor_common::visit_string_type(int str_type)
{
    char str_type_buffer[sizeof(str_type) * 2 + 2] = { 0 };
    sprintf(str_type_buffer, "%d", str_type);
    add_element(*writer_, "str_type", str_type_buffer);
}

namespace
{
    std::string xml_escape(const std::string& input)
    {
        auto output = input;
        std::transform(output.begin(), output.end(), output.begin(), [&](uint8_t c) -> char
        {
            return c >= 128 || c < 0x9 || (c > 0xd && c < 0x20) ? '?' : c;
        });
        return output;
    }
}

static std::string xml_escape(const const_string_ref& ref)
{
    return xml_escape(make_string(ref));
}

void XmlVisitor_common::visit_header_comment(bool repeatable, const const_string_ref& comment)
{
    const char* key = repeatable ? "repeatable_headercomment" : "nonrepeatable_headercomment";
    add_element(*writer_, key, xml_escape(comment).data());
}

void XmlVisitor_common::visit_start_offsets()
{
    start_element(*writer_, "offsets");
}

void XmlVisitor_common::visit_end_offsets()
{
    end_element(*writer_, "offsets");
}

void XmlVisitor_common::visit_offset_comments(offset_t offset, CommentType_e comment_type, const const_string_ref& comment)
{
    char buf[sizeof offset * 2 + 1];
    start_element(*writer_, "comments");
    add_attribute(*writer_, "offset", to_hex<NullTerminate>(buf, offset).value);
    add_attribute(*writer_, "type", get_comment_type_string(comment_type));
    write_string(*writer_, xml_escape(comment).data());
    end_element(*writer_, "comments");
}

void XmlVisitor_common::visit_offset_valueview(offset_t offset, operand_t operand, const const_string_ref& view_value)
{
    char offbuf[sizeof offset * 2 + 1];
    char opbuf[sizeof operand * 2 + 1];
    start_element(*writer_, "valueview");
    add_attribute(*writer_, "offset", to_hex<NullTerminate>(offbuf, offset).value);
    add_attribute(*writer_, "operand", to_hex<NullTerminate>(opbuf, static_cast<uint32_t>(operand)).value);
    write_string(*writer_, make_text(bufkey_, view_value));
    end_element(*writer_, "valueview");
}

void XmlVisitor_common::visit_offset_registerview(offset_t offset, offset_t end_offset, const const_string_ref& register_name, const const_string_ref& register_new_name)
{
    char buf[sizeof offset * 2 + 1];
    start_element(*writer_, "registerview");
    add_attribute(*writer_, "offset", to_hex<NullTerminate>(buf, offset).value);
    add_attribute(*writer_, "end_offset", to_hex<NullTerminate>(buf, end_offset).value);
    add_attribute(*writer_, "register", make_text(bufkey_, register_name));
    write_string(*writer_, make_text(bufkey_, register_new_name));
    end_element(*writer_, "registerview");
}

void XmlVisitor_common::visit_offset_hiddenarea(offset_t offset, offset_t area_size, const const_string_ref& hidden_area_value)
{
    char buf[sizeof offset * 2 + 1];
    start_element(*writer_, "hiddenarea");
    add_attribute(*writer_, "offset", to_hex<NullTerminate>(buf, offset).value);
    add_attribute(*writer_, "size", to_hex<NullTerminate>(buf, area_size).value);
    write_string(*writer_, make_text(bufkey_, hidden_area_value));
    end_element(*writer_, "hiddenarea");
}

void XmlVisitor_common::visit_start_xrefs()
{
    start_element(*writer_, "xrefs");
}

void XmlVisitor_common::visit_end_xrefs()
{
    end_element(*writer_, "xrefs");
}

void XmlVisitor_common::visit_segments_start()
{

}

void XmlVisitor_common::visit_segments_end()
{

}

void XmlVisitor_common::visit_attribute(const const_string_ref& attr_name, const const_string_ref& attr_value)
{
    start_element(*writer_, "attribute");
    add_attribute(*writer_, "key", make_text(bufkey_, attr_name));
    write_string(*writer_, make_text(bufkey_, attr_value));
    end_element(*writer_, "attribute");
}

void XmlVisitor_common::visit_start_xref(offset_t offset, YaToolObjectId offset_value, operand_t operand)
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

void XmlVisitor_common::visit_end_xref()
{
    write_string(*writer_, tmp_value_.data());
    end_element(*writer_, "xref");
}

void XmlVisitor_common::visit_xref_attribute(const const_string_ref& attribute_key, const const_string_ref& attribute_value)
{
    add_attribute(*writer_, make_text(bufkey_, attribute_key), make_text(bufval_, attribute_value));
}

void XmlVisitor_common::visit_blob(offset_t offset, const void* blob, size_t len)
{
    std::vector<char> buffer;
    buffer.resize(len * 2 + 1);
    buffer[len * 2] = 0;
    binhex(&buffer[0], hexchars_upper, blob, len);
    static_assert(sizeof offset == sizeof(uint64_t), "bad offset_t sizeof");
    char buf[sizeof offset * 2 + 1];
    start_element(*writer_, "blob");
    add_attribute(*writer_, "offset", to_hex<NullTerminate>(buf, offset).value);
    write_string(*writer_, &buffer[0]);
    end_element(*writer_, "blob");
}

void XmlVisitor_common::visit_flags(flags_t flags)
{
    if(!flags)
        return;

    char buffer[(sizeof(flags) + 3) * 2] = { 0 };
    sprintf(buffer, "0x%X", flags);
    add_element(*writer_, "flags", buffer);
}