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
    struct Patcher
        : public IPatcher
    {
        Patcher()
            : idx(0)
        {
        }

        void add(const char* path, const char* ptr, size_t size)
        {
            files.push_back({path, {ptr, size}});
        }

        void finish(const on_fixup_fn& on_fixup)
        {
            for(auto& f : files)
                on_fixup(f.path, f.data.data(), f.data.size());
            files.clear();
            ++idx;
        }

        using File = struct
        {
            std::string path;
            std::string data;
        };
        std::vector<File>   files;
        size_t              idx;
    };

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

    void delete_file(IGit& git, const std::string& path, const std::string& name, const std::string& msg)
    {
        auto ok = git.remove_file(name);
        EXPECT_TRUE(ok);
        std::error_code ec;
        fs::remove(path + name, ec);
        EXPECT_FALSE(ec);
        ok = git.commit(msg);
        EXPECT_TRUE(ok);
    }

    void push(IGit& git)
    {
        const auto ok = git.push("master", "origin", "master");
        EXPECT_TRUE(ok);
        git.flush();
    }

    void push_file(IGit& git, const std::string& path, const std::string& name, const std::string& msg, const std::string& content)
    {
        commit_file(git, path, name, msg, content);
        push(git);
    }

    using fixups_t      = std::multiset<std::tuple<size_t, fs::path, std::string>>;
    using conflicts_t   = std::multiset<std::tuple<size_t, std::string, std::string, fs::path>>;

    void fetch_rebase(IGit& git, const std::string& remote, const std::string& branch, const fixups_t& expected_fixups, const conflicts_t& expected_conflicts)
    {
        auto ok = git.fetch(remote);
        EXPECT_TRUE(ok);
        fixups_t got_fixups;
        conflicts_t got_conflicts;
        Patcher patcher;
        ok = git.rebase(remote + "/" + branch, branch, patcher, [&](std::string& path, const char* data, size_t size)
        {
            got_fixups.insert(std::make_tuple(patcher.idx, path, std::string(data, size)));
            return 0;
        }, [&](const std::string& left, const std::string& right, const std::string& path)
        {
            got_conflicts.insert(std::make_tuple(patcher.idx, left, right, path));
            return true;
        });
        EXPECT_EQ(expected_fixups, got_fixups);
        EXPECT_EQ(expected_conflicts, got_conflicts);
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
    const auto file1 = "file1 content";
    push_file(*a, "a/", "file1.txt", "first file", file1);

    // create second repo
    ok = c->clone("b", IGit::CLONE_FULL);
    EXPECT_TRUE(ok);
    const auto b = MakeGitAsync("b");
    set_user_config(*b);

    // empty rebase
    fetch_rebase(*b, "origin", "master", {}, {});

    // rebase with one upstream commit
    const auto file2 = std::string("file2 content");
    push_file(*a, "a/", "file2.txt", "second file", file2);
    fetch_rebase(*b, "origin", "master", {}, {});

    // rebase with multiple commits on both sides
    const auto file3 = std::string("file3 content");
    const auto file4 = std::string("file4 content");
    const auto file5 = std::string("file5 content");
    const auto file6 = std::string("file6 content");
    commit_file(*a, "a/", "file3.txt", "third file", file3);
    push_file(*a, "a/", "file4.txt", "fourth file",  file4);
    commit_file(*b, "b/", "file5.txt", "fifth file", file5);
    commit_file(*b, "b/", "file6.txt", "sixth file", file6);
    fetch_rebase(*b, "origin", "master",
    {
            {0, "file3.txt", file3 + "\n"},
            {0, "file4.txt", file4 + "\n"},
            {1, "file5.txt", file5 + "\n"},
            {2, "file6.txt", file6 + "\n"},
    }, {});
    ok = b->push("master", "origin", "master");
    EXPECT_TRUE(ok);
    b->flush();

    // rebase with conflicting commits
    fetch_rebase(*a, "origin", "master", {}, {});
    const auto left = std::string("header\nmod a\nfooter\n");
    push_file(*a, "a/", "file3.txt", "third file a", left);
    const auto right = std::string("header\nmod b\nfooter\n");
    commit_file(*b, "b/", "file3.txt", "third file b", right);
    fetch_rebase(*b, "origin", "master",
    {
        {0, "file3.txt", left + "\n"},
    },
    {
        {2, left + "\n", right + "\n", "b/file3.txt"},
    });

    const auto result = read_file("b/file3.txt");
    const auto expected = merge_strings(make_string_ref(left), "refs/remotes/origin/master", make_string_ref(right), "third file b") + "\n";
    EXPECT_EQ(expected, result);

    // rebase with delete from one side, update from the other side
    delete_file(*a, "a/", "file3.txt", "delete");
    push(*a);
    commit_file(*b, "b/", "file3.txt", "update", "updating!");
    fetch_rebase(*b, "origin", "master", {}, {});
    push(*b);

    // other side
    fetch_rebase(*a, "origin", "master", {}, {});
    const auto file2_2 = std::string("some content");
    push_file(*a, "a/", "file2.txt", "updating!", file2_2);
    delete_file(*b, "b/", "file2.txt", "deleting!");
    fetch_rebase(*b, "origin", "master",
    {
        {0, "file2.txt", file2_2 + "\n"},
    }, {});
    push(*b);

    // create same file on both sides independently
    fetch_rebase(*a, "origin", "master", {}, {});
    const auto file8 = std::string("aaaa!");
    push_file(*a, "a/", "file8.txt", "commit a", file8);
    commit_file(*b, "b/", "file8.txt", "commit b", "!bbbb");
    fetch_rebase(*b, "origin", "master",
    {
        {0, "file8.txt", file8 + "\n"},
    },
    {
        {2, "aaaa!\n", "!bbbb\n", "b/file8.txt"},
    });
    push(*b);
}

TEST_F (TestYaGitLib, test_git_rebase_fixup)
{
    // initialize upstream bare repository
    const auto c = MakeGitBare("c");
    auto ok = c->clone("a", IGit::CLONE_FULL);
    EXPECT_TRUE(ok);

    // create & fill first repo
    const auto a = MakeGitAsync("a");
    set_user_config(*a);
    const auto file1 = "file1 content";
    push_file(*a, "a/", "file1.txt", "first file", file1);

    // create second repo
    ok = c->clone("b", IGit::CLONE_FULL);
    EXPECT_TRUE(ok);
    const auto b = MakeGitAsync("b");
    set_user_config(*b);
    fetch_rebase(*b, "origin", "master", {}, {});

    // fixup file_a from a with file_b from b
    push_file(*a, "a/", "file2.txt",  "a1", "file 2 content");
    push_file(*a, "a/", "file_a.txt", "a2", "file a content");
    push_file(*a, "a/", "file3.txt",  "a3", "file 3 content");

    commit_file(*b, "b/", "file4.txt",  "b3", "file 4 content");
    commit_file(*b, "b/", "file_b.txt", "b4", "file b content");
    commit_file(*b, "b/", "file5.txt",  "b5", "file 5 content");

    ok = b->fetch("origin");
    EXPECT_TRUE(ok);
    b->flush();

    fixups_t fixups;
    conflicts_t conflicts;
    Patcher patcher;
    ok = b->rebase("origin/master", "master", patcher, [&](std::string& path, const char* data, size_t size)
    {
        fixups.insert(std::make_tuple(patcher.idx, path, std::string(reinterpret_cast<const char*>(data), size)));
        if(path != fs::path("file_b.txt"))
            return false;

        path = "file_a.txt";
        return true;
    }, [&](const std::string& left, const std::string& right, const std::string& path)
    {
        conflicts.insert(std::make_tuple(patcher.idx, left, right, path));
        std::fstream(fs::path("b") / path, std::fstream::out) << "z content";
        return true;
    });
    EXPECT_TRUE(ok);
    const fixups_t expected_fixups =
    {
        {0, "file2.txt",  "file 2 content\n"},
        {0, "file_a.txt", "file a content\n"},
        {0, "file3.txt",  "file 3 content\n"},
        {1, "file4.txt",  "file 4 content\n"},
        {2, "file_b.txt", "file b content\n"},
        {3, "file5.txt",  "file 5 content\n"},
    };
    EXPECT_EQ(expected_fixups, fixups);
    const conflicts_t expected_conflicts =
    {
        {2, "file b content\n", "file a content\n", "file_a.txt"},
    };
    EXPECT_EQ(expected_conflicts, conflicts);
    const auto file_b = read_file("b/file_b.txt");
    EXPECT_EQ("", file_b);
    const auto file_a = read_file("b/file_a.txt");
    EXPECT_EQ("z content\n", file_a);
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
        {"v2.2-13-g31d1b83a", "v2.2-15-g31d1b83a",          ver::INCOMPATIBLE},
    };
    for(const auto& t : tests)
        EXPECT_EQ(t.expected, ver::check(t.repo, t.curr));
}