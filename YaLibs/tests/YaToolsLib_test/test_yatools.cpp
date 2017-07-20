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

#include "Hexa.h"

#include "gtest/gtest.h"

#include "Logger.h"
#include "Yatools.h"
#include "MultiplexerDelegatingVisitor.hpp"
#include "YaTypes.hpp"
#include "BinHex.hpp"

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

    class Fixture : public testing::Test
    {
    protected:
        virtual void SetUp()
        {
            EXPECT_TRUE(yaok);
        }
    };
}

TEST_F(Fixture, hex_to_buffer_deadbeef)
{
    char input[] = "deadbeef";
    unsigned char output[] = "\x00\x00\x00\x00";
    unsigned char output_ref[] = "\xde\xad\xbe\xef";
    EXPECT_EQ(sizeof(output_ref) - 1, hex_to_buffer(input, sizeof(output) - 1, output));
    EXPECT_STREQ((const char*)output, (const char*)output_ref);
}

TEST(yatools, hex_to_buffer_de0db1ef)
{
    char input[] = "de0db1ef";
    unsigned char output[] = "\x00\x00\x00\x00";
    unsigned char output_ref[] = "\xde\x0d\xb1\xef";
    EXPECT_EQ(sizeof(output_ref) - 1, hex_to_buffer(input, sizeof(output) - 1, output));
    EXPECT_STREQ((const char*)output, (const char*)output_ref);
}

TEST(yatools, hex_to_buffer_e0db1ef)
{
    char input[] = "e0db1ef";
    unsigned char output[] = "\x00\x00\x00\x00";
    unsigned char output_ref[] = "\x0e\x0d\xb1\xef";
    EXPECT_EQ(sizeof(output_ref) - 1, hex_to_buffer(input, sizeof(output) - 1, output));
    EXPECT_STREQ((const char*)output, (const char*)output_ref);
}

TEST(yatools, buffer_to_hex_deadbeef)
{
    unsigned char input[] = "\xde\xad\xbe\xef";
    char output_ref[] = "deadbeef";
    char output[10] = {0};
    EXPECT_EQ(sizeof(output_ref), buffer_to_hex(input, sizeof(input) - 1, output));
    EXPECT_STRCASEEQ(output, output_ref);
}

TEST(yatools, buffer_to_hex_de0db1ef)
{
    unsigned char input[] = "\xde\x0d\xb1\xef";
    char output_ref[] = "de0db1ef";
    char output[10] = {0};
    EXPECT_EQ(sizeof(output_ref), buffer_to_hex(input, sizeof(input) - 1, output));
    EXPECT_STRCASEEQ(output, output_ref);
}

TEST(yatools, test_is_default_name)
{
    static const struct { const char value[12]; bool is_default; } values[] =
    {
        {"loc_AE0",     true},
        {"locret_AE0",  true},
        {"sub_AE0",     true},
        {"asc_AE0",     true},
        {"byte_AE0",    true},
        {"word_AE0",    true},
        {"dword_AE0",   true},
        {"qword_AE0",   true},
        {"str_AE0",     true},
        {"unk_AE0",     true},
        {"def_AE0",     true},

        {" str_AE0",    false},
        {"str_AE0 ",    false},
        {"str_AE0G",    false},
        {"str_",        false},
        {"str_fez",     false},
        {"str",         false},
        {"",            false},
        {"stra",        false},
        {"foobar",      false},
    };
    for(const auto& it : values)
        EXPECT_EQ(it.is_default, IsDefaultName(make_string_ref(it.value)));
}

TEST(yatools, test_binhex)
{
    char prefix_buf_end[2 + 16 + 1];
    char prefix_buf[2 + 16];
    char buf_end[16 + 1];
    char buf[16];
    static const auto input = 0xCAFEBABEFull;
    static const auto zero = 0x0ull;

    EXPECT_EQ("0000000CAFEBABEF", make_string(to_hex(buf, input)));
    EXPECT_EQ("0000000CAFEBABEF", std::string(to_hex<NullTerminate>(buf_end, input).value));
    EXPECT_EQ("0x0000000CAFEBABEF", make_string(to_hex<HexaPrefix>(prefix_buf, input)));
    EXPECT_EQ("0x0000000CAFEBABEF", std::string(to_hex<HexaPrefix | NullTerminate>(prefix_buf_end, input).value));

    EXPECT_EQ("CAFEBABEF", make_string(to_hex<RemovePadding>(buf, input)));
    EXPECT_EQ("CAFEBABEF", std::string(to_hex<RemovePadding | NullTerminate>(buf_end, input).value));
    EXPECT_EQ("0xCAFEBABEF", make_string(to_hex<RemovePadding | HexaPrefix>(prefix_buf, input)));
    EXPECT_EQ("0xCAFEBABEF", std::string(to_hex<RemovePadding | HexaPrefix | NullTerminate>(prefix_buf_end, input).value));

    EXPECT_EQ("0000000000000000", make_string(to_hex(buf, zero)));
    EXPECT_EQ("0000000000000000", std::string(to_hex<NullTerminate>(buf_end, zero).value));
    EXPECT_EQ("0x0000000000000000", make_string(to_hex<HexaPrefix>(prefix_buf, zero)));
    EXPECT_EQ("0x0000000000000000", std::string(to_hex<HexaPrefix | NullTerminate>(prefix_buf_end, zero).value));

    EXPECT_EQ("0", make_string(to_hex<RemovePadding>(buf, zero)));
    EXPECT_EQ("0", std::string(to_hex<RemovePadding | NullTerminate>(buf_end, zero).value));
    EXPECT_EQ("0x0", make_string(to_hex<RemovePadding | HexaPrefix>(prefix_buf, zero)));
    EXPECT_EQ("0x0", std::string(to_hex<RemovePadding | HexaPrefix | NullTerminate>(prefix_buf_end, zero).value));
}

