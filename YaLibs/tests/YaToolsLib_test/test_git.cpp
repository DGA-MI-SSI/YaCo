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

#include <iostream>
#include <fstream>
#include <iso646.h>

#include "gtest/gtest.h"

#include <Git.hpp>
#include "Utils.hpp"
#include "test_common.hpp"

using namespace testing;
using namespace testing::internal;

#define UNUSED(X) ((void)(X))

class TestYaGitLib : public TestInTempFolder
{
    void SetUp() override
    {
        TestInTempFolder::SetUp();
    }
    void TearDown() override
    {
        TestInTempFolder::TearDown();
    }
};

namespace
{
    void set_user_config(IGit& repo)
    {
        if (repo.config_get_string("user.name") == "")
            repo.config_set_string("user.name", "test_user");
        if (repo.config_get_string("user.email") == "")
            repo.config_set_string("user.email", "test_email");
    }

    void write_file(const std::string& name, const std::string& data)
    {
        std::ofstream file(name);
        file << data << std::endl;
    }

    void commit_file(IGit& git, const std::string& path, const std::string& name, const std::string& msg, const std::string& content)
    {
        write_file(path + name, content);
        auto ok = git.add_file(name);
        EXPECT_TRUE(ok);
        ok = git.commit(msg);
        EXPECT_TRUE(ok);
    }

    void push_file(IGit& git, const std::string& path, const std::string& name, const std::string& msg, const std::string& content)
    {
        commit_file(git, path, name, msg, content);
        const auto ok = git.push("master", "origin", "master");
        EXPECT_TRUE(ok);
        git.flush();
    }

    void fetch_rebase(IGit& git, const std::string& remote, const std::string& branch, const std::tuple<std::string, std::string, fs::path>& expected = std::tuple<std::string, std::string, fs::path>())
    {
        auto ok = git.fetch(remote);
        EXPECT_TRUE(ok);
        ok = git.rebase(remote + "/" + branch, branch, [&](const std::string& left, const std::string& right, const std::string& path)
        {
            EXPECT_EQ(std::make_tuple(left, right, path), expected);
            return true;
        });
        EXPECT_TRUE(ok);
    }

    std::string read_file(const std::string& path)
    {
        std::ifstream ifs(path);
        std::string line;
        std::string data;
        while(std::getline(ifs, line))
            data += line + "\n";
        return data;
    }
}

TEST_F(TestYaGitLib, test_git_init)
{
    const auto repo = MakeGitAsync("test");
    set_user_config(*repo);
}

TEST_F (TestYaGitLib, test_git_commit)
{
    const auto repo = MakeGitAsync("test");
    set_user_config(*repo);
    commit_file(*repo, "test/", "file.txt", "first file", "content");
}

TEST_F (TestYaGitLib, test_git_get_modified_objects)
{
    const auto repo = MakeGitAsync("test");
    set_user_config(*repo);

    commit_file(*repo, "test/", "file1.txt", "add first file", "file1 content");
    commit_file(*repo, "test/", "file2.txt", "add second file", "file2 content");

    write_file("test/file2.txt", "file2 content\nfile2 content cont'd");
    std::set<std::string> files;
    const auto ok = repo->status("", [&](const char* name, const IGit::Status& status)
    {
        if(status.modified)
            files.insert(name);
    });
    EXPECT_TRUE(ok);
    std::set<std::string>ref({"file2.txt"});
    EXPECT_EQ(files, ref);
}

TEST_F (TestYaGitLib, test_git_status_with_path)
{
    const auto repo = MakeGitAsync("test");
    set_user_config(*repo);

    write_file("test/file1.txt", "file1 content");
    std::set<std::string> files;
    auto ok = repo->status("", [&](const char* name, const IGit::Status& status)
    {
        if(status.untracked)
            files.insert(name);
    });
    EXPECT_TRUE(ok);
    std::set<std::string> ref({"file1.txt"});
    EXPECT_EQ(files, ref);

    ok = repo->add_file("file1.txt");
    EXPECT_TRUE(ok);
    ok = repo->commit("add first file");
    EXPECT_TRUE(ok);

    std::error_code ec;
    fs::create_directories("test/subdir", ec);
    write_file("test/subdir/file2.txt", "file2 content");

    files.clear();
    ok = repo->status("subdir/", [&](const char* name, const IGit::Status& status)
    {
        if(status.untracked)
            files.insert(name);
    });
    EXPECT_TRUE(ok);
    std::set<std::string> ref2({"subdir/file2.txt"});
    EXPECT_EQ(files, ref2);
}

TEST_F (TestYaGitLib, test_git_rebase)
{
    // initialize upstream bare repository
    const auto c = MakeGitBare("c");
    auto ok = c->clone("a", IGit::CLONE_FULL);
    EXPECT_TRUE(ok);

    // create & fill first repo
    const auto a = MakeGitAsync("a");
    set_user_config(*a);
    push_file(*a, "a/", "file1.txt", "first file", "file1 content");

    // create second repo
    ok = c->clone("b", IGit::CLONE_FULL);
    EXPECT_TRUE(ok);
    const auto b = MakeGitAsync("b");
    set_user_config(*b);

    // empty rebase
    fetch_rebase(*b, "origin", "master");

    // rebase with one upstream commit
    push_file(*a, "a/", "file2.txt", "second file", "file2 content");
    fetch_rebase(*b, "origin", "master");

    // rebase with multiple commits on both sides
    commit_file(*a, "a/", "file3.txt", "third file", "file3 content");
    push_file(*a, "a/", "file4.txt", "fourth file", "file4 content");
    commit_file(*b, "b/", "file5.txt", "fifth file", "file5 content");
    commit_file(*b, "b/", "file6.txt", "sixth file", "file6 content");
    fetch_rebase(*b, "origin", "master");
    ok = b->push("master", "origin", "master");
    EXPECT_TRUE(ok);
    b->flush();

    // rebase with conflicting commits
    fetch_rebase(*a, "origin", "master");
    const auto left = "header\nmod a\nfooter\n";
    push_file(*a, "a/", "file3.txt", "third file a", left);
    const auto right = "header\nmod b\nfooter\n";
    commit_file(*b, "b/", "file3.txt", "third file b", right);
    fetch_rebase(*b, "origin", "master", std::make_tuple(left, right, "b/file3.txt"));

    const auto result = read_file("b/file3.txt");
    const auto expected = merge_strings(make_string_ref(left), "refs/remotes/origin/master", make_string_ref(right), "third file b") + "\n";
    EXPECT_EQ(expected, result);
}

TEST(yatools, test_check_yaco_version)
{
    const struct
    {
        const char  repo[255];
        const char  curr[255];
        ver::ECheck expected;
    } tests[] =
    {
        {"v2.1-15-g31d1b83a", "a",                          ver::INVALID},
        {"v2.1-15-g31d1b83a", "v2.1.15",                    ver::INVALID},
        {"v2.1-15-g31d1b83a", "v2.1-15",                    ver::INVALID},
        {"v2.1-15-g31d1b83a", "v2.1-15-z31d1b83a",          ver::INVALID},
        {"v2.1-15-g31d1b83a", "v2.1-15-g31d1b83g",          ver::INVALID},
        {"v2.1-15-g31d1b83a", "v2.1-15-g31d1b83a",          ver::OK},
        {"v2.1-15-g31d1b83a", "v2.1-2-g31d1b83a",           ver::NEWER},
        {"v2.1-15-g31d1b83a", "v2.1-20-g31d1b83a",          ver::OLDER},
        {"v2.1-15-g31d1b83a", "v2.1-15-g31d1b83a-dirty",    ver::OK}, // ok but dirty, ignore it
        {"v2.1-15-g31d1b83a", "v2.1-15-g1d1b83a3",          ver::OK}, // ok with mismatch, ignore it
    };
    for(const auto& t : tests)
        EXPECT_EQ(t.expected, ver::check(t.repo, t.curr));
}