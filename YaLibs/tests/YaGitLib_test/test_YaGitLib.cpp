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
#include <test_common.hpp>

using namespace std;
using namespace testing;
using namespace testing::internal;

#include <YaGitLib.hpp>
#include <utils.hpp>

int TestInTempFolder::index = 0;

class TestYaGitLib : public TestInTempFolder {
    void SetUp() override
    {
        TestInTempFolder::SetUp();
    }
    void TearDown() override
    {
        TestInTempFolder::TearDown();
    }
};

void set_user_config(GitRepo& repo)
{
    if (repo.config_get_string("user.name") == "")
    {
        repo.config_set_string("user.name", "test_user");
    }

    if (repo.config_get_string("user.email") == "")
    {
        repo.config_set_string("user.email", "test_email");
    }
}

TEST_F (TestYaGitLib, TestInit) {
    GitRepo repo{ "test" };
    repo.init();
    set_user_config(repo);
}

TEST_F (TestYaGitLib, CreateTag) {
    GitRepo repo{ "test" };
    repo.init();
    set_user_config(repo);
    std::ofstream test_file;
    test_file.open("test/file1.txt");
    test_file << "file1 content" << std::endl;
    test_file.close();
    repo.add_file("file1.txt");
    repo.commit("add first file");
    repo.create_tag("", "test_tag", "");
}

TEST_F (TestYaGitLib, ListTag) {
    GitRepo repo{ "test" };
    repo.init();
    set_user_config(repo);
    std::ofstream test_file;
    test_file.open("test/file1.txt");
    test_file << "file1 content" << std::endl;
    test_file.close();
    repo.add_file("file1.txt");
    repo.commit("add first file");
    repo.create_tag("", "test_tag", "");
    std::ofstream test_file2;
    test_file2.open("test/file2.txt");
    test_file2 << "file2 content" << std::endl;
    test_file2.close();
    repo.add_file("file2.txt");
    repo.commit("add second file");
    repo.create_tag("", "test_tag2", "");
    auto tags = repo.get_tags();
    std::set<std::string> ref_tags = {"test_tag2", "test_tag"};
    EXPECT_EQ(ref_tags, tags);
}

TEST_F (TestYaGitLib, RemoveTag) {
    GitRepo repo{ "test" };
    repo.init();
    set_user_config(repo);
    std::ofstream test_file;
    test_file.open("test/file1.txt");
    test_file << "file1 content" << std::endl;
    test_file.close();
    repo.add_file("file1.txt");
    repo.commit("add first file");
    repo.create_tag("", "test_tag", "");
    std::ofstream test_file2;
    test_file2.open("test/file2.txt");
    test_file2 << "file2 content" << std::endl;
    test_file2.close();
    repo.add_file("file2.txt");
    repo.commit("add second file");
    repo.create_tag("", "test_tag2", "");
    auto tags = repo.get_tags();
    std::set<std::string> ref_tags = {"test_tag2", "test_tag"};
    EXPECT_EQ(ref_tags, tags);

    repo.remove_tag("test_tag");
    std::set<std::string> ref_tags2 = {"test_tag2"};
    EXPECT_EQ(ref_tags2, repo.get_tags());
}


TEST_F (TestYaGitLib, test_get_modified_objects) {
    GitRepo repo{ "test" };
    repo.init();
    set_user_config(repo);
    std::ofstream test_file;
    test_file.open("test/file1.txt");
    test_file << "file1 content" << std::endl;
    test_file.close();
    repo.add_file("file1.txt");
    repo.commit("add first file");
    std::ofstream test_file2;
    test_file2.open("test/file2.txt");
    test_file2 << "file2 content" << std::endl;
    test_file2.close();
    repo.add_file("file2.txt");
    repo.commit("add second file");


    repo.create_tag("", "tag1", "");

    test_file2.open("test/file2.txt");
    test_file2 << "file2 content" << std::endl;
    test_file2 << "file2 content cont'd" << std::endl;
    test_file2.close();
    auto files = repo.get_modified_objects();
    std::set<std::string>ref({"file2.txt"});
    EXPECT_EQ(files, ref);
}

TEST_F (TestYaGitLib, get_commit) {
    GitRepo repo{ "test" };
    repo.init();
    set_user_config(repo);
    std::ofstream test_file;
    test_file.open("test/file1.txt");
    test_file << "file1 content" << std::endl;
    test_file.close();
    repo.add_file("file1.txt");
    repo.commit("add first file");
    std::ofstream test_file2;
    test_file2.open("test/file2.txt");
    test_file2 << "file2 content" << std::endl;
    test_file2.close();
    repo.add_file("file2.txt");
    repo.commit("add second file");

    auto commit_ref = repo.get_commit("master");


    test_file2.open("test/file2.txt");
    test_file2 << "file2 content" << std::endl;
    test_file2 << "file2 content cont'd" << std::endl;
    test_file2.close();
    repo.add_file("file2.txt");
    repo.commit("update file2");

    //  EXPECT_EQ(repo.get_commit("master"), repo.get_commit("HEAD"));
    std::set<std::string>ref({});
    std::set<std::string>ref2({"file2.txt"});

    EXPECT_EQ(ref, repo.get_modified_objects("master"));

    EXPECT_EQ(ref2, repo.get_modified_objects(commit_ref));

    EXPECT_EQ(ref2, repo.get_modified_objects(commit_ref, "master"));

    EXPECT_EQ(ref2, repo.get_modified_objects("master", commit_ref));

    EXPECT_EQ(ref, repo.get_modified_objects("HEAD", "master"));

    EXPECT_EQ(ref, repo.get_modified_objects("master", "HEAD"));

}

TEST_F(TestYaGitLib, create_temp_files)
{
    const auto f1 = CreateTempFile();
    EXPECT_TRUE(!!f1);
    const auto f2 = CreateTempFile();
    EXPECT_TRUE(!!f2);
}


//TEST_F (TestYaGitLib, test_get_modified_objects2) {
//  GitRepo repo{ "test" };
//  repo.init();
//  std::ofstream test_file;
//  test_file.open("test/file1.txt");
//  test_file << "file1 content" << std::endl;
//  test_file.close();
//  repo.add_file("file1.txt");
//  repo.commit("add first file");
//  std::ofstream test_file2;
//  test_file2.open("test/file2.txt");
//  test_file2 << "file2 content" << std::endl;
//  test_file2.close();
//  repo.add_file("file2.txt");
//  repo.commit("add second file");
//
//
//  repo.create_tag("", "tag1", "");
//
//  test_file2.open("test/file2.txt");
//  test_file2 << "file2 content" << std::endl;
//  test_file2 << "file2 content cont'd" << std::endl;
//  test_file2.close();
//  auto files = repo.get_modified_objects("refs/tags/tag1");
//  sleep(60);
//  std::set<std::string>ref({"file2.txt"});
//  EXPECT_EQ(files, ref);
//
//}
