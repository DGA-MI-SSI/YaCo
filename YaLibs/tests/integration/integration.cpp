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

#include "HVersion.hpp"
#include "XmlVisitor.hpp"
#include "MemoryModel.hpp"
#include "XmlModel.hpp"
#include "FileUtils.hpp"
#include "IModelSink.hpp"
#include "IModelVisitor.hpp"
#include "FlatBufferModel.hpp"
#include "FlatBufferVisitor.hpp"
#include "../YaToolsLib_test/test_model.hpp"
#include "Yatools.hpp"

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
    typedef std::multiset<std::tuple<std::string, std::string, std::string, std::string>> StringModel;

    StringModel walk_model(IModel& db)
    {
        StringModel values;

        db.walk([&](const HVersion& hver)
        {
            values.insert(std::make_tuple("version", str(hver), str(hver.address()), ""));
            hver.walk_signatures([&](const HSignature& hsig)
            {
                values.insert(std::make_tuple("signature", str(hver), str(hsig), ""));
                return WALK_CONTINUE;
            });
            hver.walk_xrefs_from([&](offset_t offset, operand_t operand, const HVersion& from)
            {
                const auto v = std::to_string(offset) + "_" + std::to_string(operand) + "_" + str(from);
                values.insert(std::make_tuple("xref", str(hver), v, ""));
                return WALK_CONTINUE;
            });
            hver.walk_xrefs_to([&](const HVersion& to)
            {
                values.insert(std::make_tuple("xref_to", str(hver), str(to), ""));
                return WALK_CONTINUE;
            });
            hver.walk_xrefs([&](offset_t offset, operand_t operand, YaToolObjectId id, const XrefAttributes* hattr)
            {
                const auto v = std::to_string(offset) + "_" + std::to_string(operand) + "_" + str(id);
                values.insert(std::make_tuple("ref", str(hver), v, ""));
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
        return values;
    }

    struct Listener
        : public IModelSink
    {
        Listener(IModelVisitor& visitor)
            : visitor(visitor)
        {
        }

        void update(const IModel& model) override
        {
            model.walk([&](const HVersion& hver)
            {
                hver.accept(visitor);
                return WALK_CONTINUE;
            });
        }

        void remove(const IModel&) override
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

    void CheckModelConversions(const char* input)
    {
        const auto expected_model = MakeMultiFlatBufferModel({input});
        const auto expected = walk_model(*expected_model);

        // check fb -> std conversions
        auto stdmodel = [&]
        {
            const auto db = MakeMemoryModel();
            expected_model->accept(*db);
            return walk_model(*db);
        }();
        expect_eq(stdmodel, expected);

        // check fb -> xml -> std conversions
        auto xmlmodel = [&]
        {
            const TmpDir dir;
            const auto xml = (dir.path / "database.xml").string();
            expected_model->accept(*MakeFileXmlVisitor({xml}));
            const auto db = MakeMemoryModel();
            db->visit_start();
            Listener listener(*db);
            listener.update(*create_fbmodel_with([&](auto& visitor)
            {
                MakeXmlFilesModel({xml})->accept(visitor);
            }));
            db->visit_end();
            return walk_model(*db);
        }();
        expect_eq(xmlmodel, expected);
    }

    const char qt54svg[] = "../../testdata/qt54_svg/database/database.yadb";
    const char qt57svg[] = "../../testdata/qt57_svg/database/database.yadb";
}

int main(int argc, char* argv[])
{
    globals::InitFileLogger(*globals::Get().logger, stdout);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

TEST(IntegrationTest, yadb_model_conversions_qt54)      { CheckModelConversions(qt54svg); }
TEST(IntegrationTest, yadb_model_conversions_qt57)      { CheckModelConversions(qt57svg); }
