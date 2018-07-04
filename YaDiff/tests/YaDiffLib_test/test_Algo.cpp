#include "YaTypes.hpp"
#include "BinHex.hpp"
#include "Configuration.hpp"
#include "FileUtils.hpp"
#include "FlatBufferModel.hpp"
#include "FlatBufferVisitor.hpp"
#include "Helpers.h"
#include "MemoryModel.hpp"
#include "Signature.hpp"
#include "VersionRelation.hpp"
#include "Yatools.hpp"

#include <YaDiff.hpp>
#include <Propagate.hpp>
#include <Algo/Algo.hpp>


#include "gtest/gtest.h"

using namespace std;
using namespace testing;
using namespace testing::internal;

#ifdef _MSC_VER
#   include <filesystem>
#else
#   include <experimental/filesystem>
#endif

using namespace std;
using namespace std::experimental;

namespace
{
//  TEST_F(TestYadiffAlgo, TestPrepareExternalMappingMatchAlgoInvalidInput) {
//    yadiff::AlgoCfg config;
//    config.Algo = yadiff::ALGO_EXTERNAL_MAPPING_MATCH;
//    filesystem::path data_test_path("../../YaDiff/tests/YaDiffLib_test/data");
//    filesystem::path json_file = data_test_path / "TestExternalMappingMatc" ; // invalid filename
//    config.ExternalMappingMatch.MappingFilePath = json_file.c_str();
//    auto algo = yadiff::MakeDiffAlgo(config);
//    auto db1 = MakeModel();
//    auto db2 = MakeModel();
//    EXPECT_FALSE(algo->Prepare(*db1.model, *db2.model));
//  }

//  TEST_F(TestYadiffAlgo, TestPrepareExternalMappingMatchAlgo) {
//    yadiff::AlgoCfg config;
//    config.Algo = yadiff::ALGO_EXTERNAL_MAPPING_MATCH;
//    filesystem::path data_test_path("../../YaDiff/tests/YaDiffLib_test/data");
//    filesystem::path json_file = data_test_path / "TestExternalMappingMatchAlgo.json" ;
//    config.ExternalMappingMatch.MappingFilePath = json_file.c_str();
//    auto algo = yadiff::MakeDiffAlgo(config);
//    auto db1 = MakeModel();
//    auto db2 = MakeModel();
//    EXPECT_TRUE(algo->Prepare(*db1.model, *db2.model));
//  }
}

int main(int argc, char* argv[])
{
    globals::InitFileLogger(*globals::Get().logger, stdout);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}