#include "Configuration.hpp"


#ifndef YALIB_TEST
#   define YALIB_TEST
#endif

#include "test_common.hpp"

#include "gtest/gtest.h"
#ifdef _MSC_VER
#   include <filesystem>
#else
#   include <experimental/filesystem>
#endif
using namespace std;
using namespace std::experimental;

static const std::string gEmpty;

TEST(TestConfiguration, GetOption)
{
    filesystem::path data_test_path("../../YaLibs/tests/data/");
    auto config = Configuration((data_test_path / "test_configuration.xml" ).string());

    EXPECT_EQ(std::string("value1_value"), config.GetOption("section1", "value1"));
    EXPECT_EQ(gEmpty, config.GetOption("section2", "value1"));
    EXPECT_EQ(gEmpty, config.GetOption("section1", "value2"));
    EXPECT_EQ(std::string("value2_value"), config.GetOption("section2", "value2"));
    EXPECT_EQ(gEmpty, config.GetOption("section3", "value1"));
}
