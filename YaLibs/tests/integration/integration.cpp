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

#include "gtest/gtest.h"

#include "../Helpers.h"
#include "HVersion.hpp"
#include "YaToolReferencedObject.hpp"
#include "HObject.hpp"
#include "YaToolObjectId.hpp"
#include "XML/XMLExporter.hpp"
#include "StdModel.hpp"
#include "XML/XMLDatabaseModel.hpp"
#include "FileUtils.hpp"
#include "IVersionListener.hpp"
#include "IModelVisitor.hpp"
#include "DependencyResolverVisitor.hpp"
#include "FlatBufferDatabaseModel.hpp"
#include "FlatBufferExporter.hpp"
#include "../YaToolsLib_test/model.hpp"
#include "Yatools.h"
#include "Logger.h"

#include <functional>

#ifdef _MSC_VER
#   include <optional.hpp>
using namespace nonstd;
#else
#   include <experimental/optional>
using namespace std::experimental;
#endif

#ifdef _MSC_VER
#   include <filesystem>
#else
#   include <experimental/filesystem>
#endif

namespace fs = std::experimental::filesystem;

namespace
{
namespace
{
// initialize global logger instance
static const auto yaok = []
{
    auto pCtx = YATOOLS_Get();
    if(!YATOOLS_Init(pCtx))
        return false;
    auto pLogger = YATOOLS_GetLogger(pCtx);
    LOG_Cfg Cfg;
    memset(&Cfg, 0, sizeof Cfg);
    Cfg.Outputs[0] = {LOG_OUTPUT_FILE_HANDLE, stderr, nullptr};
    return LOG_Init(pLogger, &Cfg);
}();
}

class TestConfiguration : public testing::Test
{
    virtual void SetUp()
    {
        EXPECT_TRUE(yaok);
    }
};

typedef std::multiset<std::tuple<std::string, std::string, std::string, std::string>> StringModel;

StringModel walk_model(IModel& db)
{
    StringModel values;

    db.walk_objects([&](const YaToolObjectId& id, const HObject& href)
    {
        EXPECT_EQ(id, href.id());
        values.insert(std::make_tuple("object", str(href), "", ""));
        href.walk_versions([&](const HVersion& hver)
        {
            values.insert(std::make_tuple("version", str(hver), str(hver.address()), str(hver.parent_id())));
            hver.walk_signatures([&](const HSignature& hsig)
            {
                values.insert(std::make_tuple("signature", str(href), str(hver), str(hsig)));
                return WALK_CONTINUE;
            });
            hver.walk_systems([&](offset_t offset, HSystem_id_t sysid)
            {
                hver.walk_system_attributes(sysid, [&](const const_string_ref& key, const const_string_ref& val)
                {
                    const auto v = std::to_string(offset) + "_" + make_string(key) + "_" + make_string(val);
                    values.insert(std::make_tuple("sys_attr", str(href), str(hver), v));
                    return WALK_CONTINUE;
                });
                return WALK_CONTINUE;
            });
            hver.walk_xrefs_from([&](offset_t offset, operand_t operand, const HObject& obj)
            {
                const auto v = std::to_string(offset) + "_" + std::to_string(operand) + "_" + str(obj);
                values.insert(std::make_tuple("xref", str(href), str(hver), v));
                return WALK_CONTINUE;
            });
            hver.walk_xrefs_to([&](const HObject& from)
            {
                values.insert(std::make_tuple("xref_to", str(href), str(hver), str(from)));
                return WALK_CONTINUE;
            });
            hver.walk_xrefs([&](offset_t offset, operand_t operand, YaToolObjectId id, const XrefAttributes* hattr)
            {
                const auto v = std::to_string(offset) + "_" + std::to_string(operand) + "_" + str(id);
                values.insert(std::make_tuple("ref", str(href), str(hver), v));
                hver.walk_xref_attributes(hattr, [&](const const_string_ref& key, const const_string_ref& value)
                {
                    values.insert(std::make_tuple("ref", str(hver) + "_" + v, make_string(key), make_string(value)));
                    return WALK_CONTINUE;
                });
                return WALK_CONTINUE;
            });
            hver.walk_attributes([&](const const_string_ref& key, const const_string_ref& val)
            {
                values.insert(std::make_tuple("attr", str(hver), make_string(key), make_string(val)));
                return WALK_CONTINUE;
            });
            return WALK_CONTINUE;
        });
        return WALK_CONTINUE;
    });
    return values;
}

StringModel walk_fast_model(IModel& db)
{
    StringModel values;

    db.walk_objects([&](const YaToolObjectId&, const HObject& href)
    {
        href.walk_versions([&](const HVersion& hver)
        {
            values.insert(std::make_tuple("version", str(hver), str(hver.address()), str(hver.parent_id())));
            return WALK_CONTINUE;
        });
        return WALK_CONTINUE;
    });
    return values;
}

struct VersionListener : public IVersionListener
{
    VersionListener(IModelVisitor& visitor)
        : visitor(visitor)
    {
    }

    virtual void on_version(const HVersion& version)
    {
        visitor.visit_start_reference_object(version.type());
        visitor.visit_id(version.id());
        version.accept(visitor);
        visitor.visit_end_reference_object();
    }

    virtual void on_deleted(YaToolObjectId)
    {
    }

    virtual void on_default(YaToolObjectId)
    {
    }

    IModelVisitor& visitor;
};

struct TmpDir
{
    TmpDir()
        : path(CreateTemporaryDirectory("integration_tmp"))
    {
    }

    ~TmpDir()
    {
        std::error_code err;
        fs::remove_all(path, err);
    }

    fs::path path;
};

template<typename T>
static void CheckXmlToFbConversion(const char* input, const T& get_visitor)
{
    // generate dumb xml
    const TmpDir dir;
    const auto xml = (dir.path / "database.xml").string();
    MakeMultiFlatBufferDatabaseModel({input})->accept(*MakeFileXmlExporter({xml}));

    // get expected model by reading xml with full dependency resolver
    const auto expected = [&]
    {
        auto db = MakeStdModel();
        db.visitor->visit_start();
        VersionListener listener(*db.visitor);
        const auto visitor = MakeDependencyResolverVisitor(MakeVisitorFromListener(listener)).visitor;
        MakeXmlFilesDatabaseModel({xml})->accept(*visitor);
        db.visitor->visit_end();
        return walk_model(*db.model);
    }();

    // get model from reading xml through custom visitor & flatbuffer conversion
    auto model = [&]
    {
        const auto db = MakeStdModel();
        db.visitor->visit_start();
        VersionListener listener(*db.visitor);
        create_fbmodel_with([&](const auto& visitor)
        {
            MakeXmlFilesDatabaseModel({xml})->accept(*visitor);
        })->accept(*get_visitor(listener));
        db.visitor->visit_end();
        return walk_model(*db.model);
    }();

    // check our model is equal
    expect_eq(model, expected);
}

void CheckXmlToFbConversionWithDepRes(const char* input)
{
    CheckXmlToFbConversion(input, [&](IVersionListener& listener)
    {
        return MakeDependencyResolverVisitor(MakeVisitorFromListener(listener)).visitor;
    });
}

void CheckXmlToFbConversionWithoutDepRes(const char* input)
{
    CheckXmlToFbConversion(input, [&](IVersionListener& listener)
    {
        return MakeVisitorFromListener(listener);
    });
}

const char qt54svg[] = "../../testdata/qt54_svg/database/database.yadb";
const char qt57svg[] = "../../testdata/qt57_svg/database/database.yadb";
}

TEST(IntegrationTest, yadb_xml_mem_cycles_with_dependency_resolver_qt54svg) { CheckXmlToFbConversionWithDepRes(qt54svg); }
TEST(IntegrationTest, yadb_xml_mem_cycles_with_dependency_resolver_qt57svg) { CheckXmlToFbConversionWithDepRes(qt57svg); }
TEST(IntegrationTest, yadb_xml_mem_cycles_with_address_solver_qt54svg)      { CheckXmlToFbConversionWithoutDepRes(qt54svg); }
TEST(IntegrationTest, yadb_xml_mem_cycles_with_address_solver_qt57svg)      { CheckXmlToFbConversionWithoutDepRes(qt57svg); }

TEST(IntegrationText, export_absolute_address_and_parent_ids)
{
    for(const auto filename : {qt54svg, qt57svg})
    {
        // load flatbuffer model exported directly from ida
        const auto input = MakeFlatBufferDatabaseModel(filename);

        // pass it to DependencyResolver & ensure correct address & parent_id
        const auto output = [&]
        {
            auto dst = MakeFlatBufferExporter();
            dst->visit_start();
            VersionListener listener(*dst);
            const auto single = MakeVisitorFromListener(listener);
            const auto depres = MakeDependencyResolverVisitor(single);
            input->accept(*depres.visitor);
            dst->visit_end();

            const auto buf = dst->GetBuffer();
            const auto mmap = std::make_shared<Buffer>(buf.value, buf.size);
            return MakeFlatBufferDatabaseModel(mmap);
        }();

        // reload new fb model
        auto model = walk_fast_model(*input);
        const auto expected = walk_fast_model(*output);
        expect_eq(model, expected);
    }
}