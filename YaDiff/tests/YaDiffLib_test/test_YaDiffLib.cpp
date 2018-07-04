#include "XmlAccept.hpp"
#include "XmlVisitor.hpp"
#include "MemoryModel.hpp"
#include "FlatBufferVisitor.hpp"
#include "FlatBufferModel.hpp"
#include "Signature.hpp"
#include "FileUtils.hpp"
#include <Configuration.hpp>
#include <YaDiff.hpp>
#include <Propagate.hpp>
#include <Algo/Algo.hpp>
#include "VersionRelation.hpp"
#include "BinHex.hpp"

#include "Yatools.hpp"
#include "Helpers.h"

#include "gtest/gtest.h"

#include <iostream>
#include <fstream>
#include <iso646.h>
#include <chrono>
#include <sstream>

#ifdef _MSC_VER
#   include <filesystem>
#else
#   include <experimental/filesystem>
#endif

namespace fs = std::experimental::filesystem;

#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("xref", (FMT), ## __VA_ARGS__)

namespace
{
struct Buffer : public Mmap_ABC
{
    Buffer(const void* pdata, size_t szdata)
        : data(reinterpret_cast<const uint8_t*>(pdata), reinterpret_cast<const uint8_t*>(pdata) + szdata)
    {
    }

    const void* Get() const override
    {
        return &data[0];
    }

    size_t GetSize() const override
    {
        return data.size();
    }

    std::vector<uint8_t> data;
};

std::shared_ptr<IModel> ExportToYadb(const fs::path& path)
{
    auto exporter = MakeFlatBufferVisitor();
    AcceptXmlFiles(*exporter, {path.string()});
    const auto buf = exporter->GetBuffer();
    return MakeFlatBufferModel(std::make_shared<Buffer>(buf.value, buf.size));
}

std::pair<std::shared_ptr<IModel>, std::shared_ptr<IModel>> create_memorySignatureDB(const std::string& path1, const std::string& path2)
{

    fs::path data_test_path("../../YaDiff/tests/YaDiffLib_test/data/");
    std::vector<std::string> file1 { (data_test_path / path1 ).string() };
    std::vector<std::string> file2 { (data_test_path / path2).string() };

    auto db1 = MakeMemoryModel();
    auto db2 = MakeMemoryModel();

    AcceptXmlFiles(*db1, file1);
    AcceptXmlFiles(*db2, file2);
    return make_pair(db1, db2);
}

std::pair<std::shared_ptr<IModel>, std::shared_ptr<IModel>> create_flatBufferSignatureDB(const std::string& path1, const std::string& path2)
{
    fs::path data_test_path("../../YaDiff/tests/YaDiffLib_test/data/");
    auto db1 = ExportToYadb(data_test_path / path1);
    auto db2 = ExportToYadb(data_test_path / path2);
    return make_pair(db1, db2);
}

template<typename T>
void expect_eq(T& values, const T& expected)
{
    EXPECT_EQ(expected, values);
    values.clear();
}

std::string str(const HSignature& sig)
{
    const auto& v = sig.get();
    return std::string(v.buffer, v.size);
}

std::string str(YaToolObjectId id)
{
    char buf[sizeof id * 2];
    return make_string(to_hex(buf, id));
}

std::string str(const HVersion& hver)
{
    return get_object_type_string(hver.type()) + std::string("_") + str(hver.id());
}

const char* get_relation_type(RelationType_e value)
{
    switch(value)
    {
        case RELATION_TYPE_NONE:                return "none";
        case RELATION_TYPE_EXACT_MATCH:         return "exact_match";
        case RELATION_TYPE_DIFF:                return "diff";
        case RELATION_TYPE_DIFF_CALL:           return "diff_call";
        case RELATION_TYPE_ALTERNATIVE_TO_N:    return "alt_to_n";
        case RELATION_TYPE_ALTERNATIVE_FROM_N:  return "alt_from_n";
        case RELATION_TYPE_UNTRUSTABLE:         return "untrustable";
        default:                                return "invalid";
    }
}

const std::string get_confidence(RelationConfidence_T value)
{
    switch(value)
    {
        case RELATION_CONFIDENCE_MAX:   return "max";
        case RELATION_CONFIDENCE_MIN:   return "min";
        case RELATION_CONFIDENCE_BAD:   return "bad";
        case RELATION_CONFIDENCE_GOOD:  return "good";
        default:                        return std::to_string(value);
    }
}

const char* get_direction(RelationDirection_e value)
{
    switch(value)
    {
        case RELATION_DIRECTION_NONE:               return "none";
        case RELATION_DIRECTION_LOCAL_TO_REMOTE:    return "local_to_remote";
        case RELATION_DIRECTION_REMOTE_TO_LOCAL:    return "remote_to_local";
        case RELATION_DIRECTION_BOTH:               return "both";
        default:                                    return "invalid";
    }
}

std::string get_flags(uint32_t value)
{
    static const struct
    {
        yadiff::AlgoFlag_e  flag;
        const char          name[16];
    }
    flags[] =
    {
        {yadiff::AF_XREF_OFFSET_DONE, "xref_offset"},
        {yadiff::AF_CALLER_XREF_DONE, "caller_xref"},
    };
    bool all = true;
    uint32_t copy = value;
    std::string reply;
    const auto add_value = [&](uint32_t value, yadiff::AlgoFlag_e eflag, const char* name)
    {
        if(!(value & eflag))
            return false;;
        reply += reply.empty() ? "_" : "|";
        reply += name;
        return true;
    };
    for(size_t i = 0; i < COUNT_OF(flags); ++i)
    {
        const auto& f = flags[i];
        all &= add_value(copy, f.flag, f.name);
        copy &= ~f.flag;
    }
    // if something remain in copy, flags are invalid
    if(copy)
    {
        std::stringstream ss;
        ss << "_invalid_flags_" << std::hex << copy;
        return ss.str();
    }
    // if all flags are present, return all
    if(all)
        return "_all";
    return reply;
}

std::string str(const Relation& ydr)
{
    return get_confidence(ydr.confidence_) + "_"
         + get_relation_type(ydr.type_) + "_"
         + get_direction(ydr.direction_) + "_"
         + str(ydr.version1_) + "_"
         + str(ydr.version2_)
         + get_flags(ydr.flags_);
}

void expect_req(const std::vector<Relation>& relations, const std::multiset<std::string>& expected)
{
    std::multiset<std::string> values;
    for(const auto& relation: relations)
        values.insert(str(relation));
    expect_eq(values, expected);
}

void TestSigComp_Impl(std::pair<std::shared_ptr<IModel>, std::shared_ptr<IModel>> dbs)
{
    auto db1 = dbs.first;
    auto db2 = dbs.second;

    std::multiset<std::tuple<std::string, std::string, std::string, std::string>> values;
    db1->walk_uniques([&](const HVersion& hver1, const HSignature& sig1)
    {
        db2->walk_uniques([&](const HVersion& hver2, const HSignature& sig2)
        {
            values.insert(std::make_tuple(str(sig1), str(hver1), str(sig2), str(hver2)));
            return WALK_CONTINUE;
        });
        return WALK_CONTINUE;
    });
    expect_eq(values, {
        std::make_tuple("aabbccdd", "function_0000000000000001", "aabbccdd", "function_0000000000000002"),
    });
}
}

/**
 * Check the same sigs in different database match
 */
TEST(TestYaDiffLib, TestSigComp_mem)
{
    auto dbs = create_memorySignatureDB("TestSigComp1.xml", "TestSigComp2.xml");
    TestSigComp_Impl(dbs);
}
TEST(TestYaDiffLib, TestSigComp_fb)
{
    auto dbs = create_flatBufferSignatureDB("TestSigComp1.xml", "TestSigComp2.xml");
    TestSigComp_Impl(dbs);
}



/**
 * Test first association algo
 */
static void TestFirstAssociation_Impl(std::pair<std::shared_ptr<IModel>, std::shared_ptr<IModel>> dbs)
{
    auto db1 = dbs.first;
    auto db2 = dbs.second;
    std::vector<Relation> relations;

    // create YaDiff
    const auto config = Configuration("../../YaDiff/tests/YaDiffLib_test/data/config.xml");
    auto differ = yadiff::YaDiff(config);
    differ.MergeDatabases(*db1, *db2, relations);
    expect_req(relations, {
        "max_exact_match_both_function_0000000000000001_function_0000000000000002_all",
    });
}

TEST(TestYaDiffLib, TestFirstAssociation_mem)
{
    auto dbs = create_memorySignatureDB("TestSigComp1.xml", "TestSigComp2.xml");
    TestFirstAssociation_Impl(dbs);
}

TEST(TestYaDiffLib, TestFirstAssociation_fb)
{
    auto dbs = create_flatBufferSignatureDB("TestSigComp1.xml", "TestSigComp2.xml");
    TestFirstAssociation_Impl(dbs);
}

/**
 * Test basic block association
 */
static void TestBasicBlockAssociation_Impl(std::pair<std::shared_ptr<IModel>, std::shared_ptr<IModel>> dbs)
{
    auto db1 = dbs.first;
    auto db2 = dbs.second;
    std::vector<Relation> relations;

    // create YaDiff
    const auto config = Configuration("../../YaDiff/tests/YaDiffLib_test/data/config.xml");
    auto differ = yadiff::YaDiff(config);
    differ.MergeDatabases(*db1, *db2, relations);

    expect_req(relations, {
        "max_exact_match_both_function_0000000000000001_function_0000000000000002_all",
        "max_exact_match_both_basic_block_0000000000000010_basic_block_0000000000000020_all",
    });
}

TEST(TestYaDiffLib, TestBasicBlockAssociation_mem)
{
    auto dbs = create_memorySignatureDB("TestMatchBasicBlock1.xml", "TestMatchBasicBlock2.xml");
    TestBasicBlockAssociation_Impl(dbs);
}

TEST(TestYaDiffLib, TestBasicBlockAssociation_fb)
{
    auto dbs = create_flatBufferSignatureDB("TestMatchBasicBlock1.xml", "TestMatchBasicBlock2.xml");
    TestBasicBlockAssociation_Impl(dbs);
}

/**
 * Test struc association
 */
static void TestStructAssociation_Impl(std::pair<std::shared_ptr<IModel>, std::shared_ptr<IModel>> dbs)
{
    auto db1 = dbs.first;
    auto db2 = dbs.second;
    std::vector<Relation> relations;

    // create YaDiff
    const auto config = Configuration("../../YaDiff/tests/YaDiffLib_test/data/config.xml");
    auto differ = yadiff::YaDiff(config);
    differ.MergeDatabases(*db1, *db2, relations);

    expect_req(relations, {
        "max_exact_match_both_function_0000000000000001_function_0000000000000002_all",
        "max_exact_match_both_struc_0000000000000010_struc_0000000000000011_all",
    });
}

TEST(TestYaDiffLib, TestStructAssociation_mem)
{
    auto dbs = create_memorySignatureDB("TestMatchStruct1.xml", "TestMatchStruct2.xml");
    TestStructAssociation_Impl(dbs);
}

TEST(TestYaDiffLib, TestStructAssociation_fb)
{
    auto dbs = create_flatBufferSignatureDB("TestMatchStruct1.xml", "TestMatchStruct2.xml");
    TestStructAssociation_Impl(dbs);
}

/**
 * Test from xref association with data sig
 */
static void TestXrefOfDataMatch_Impl(std::pair<std::shared_ptr<IModel>, std::shared_ptr<IModel>> dbs)
{
    auto db1 = dbs.first;
    auto db2 = dbs.second;
    std::vector<Relation> relations;

    // create YaDiff
    const auto config = Configuration("../../YaDiff/tests/YaDiffLib_test/data/config.xml");
    auto differ = yadiff::YaDiff(config);
    differ.MergeDatabases(*db1, *db2, relations);

    expect_req(relations, {
        "max_diff_both_basic_block_0000000000000001_basic_block_0000000000000002_caller_xref",
        "max_diff_both_function_0000000000000040_function_0000000000000041_caller_xref",
        "max_exact_match_both_data_0000000000000020_data_0000000000000021_all",
    });
}

TEST(TestYaDiffLib, TestXrefOfDataMatch_mem)
{
    auto dbs = create_memorySignatureDB("TestXrefOfDataMatch1.xml", "TestXrefOfDataMatch2.xml");
    TestXrefOfDataMatch_Impl(dbs);
}

TEST(TestYaDiffLib, TestXrefOfDataMatch_fb)
{
    auto dbs = create_flatBufferSignatureDB("TestXrefOfDataMatch1.xml", "TestXrefOfDataMatch2.xml");
    TestXrefOfDataMatch_Impl(dbs);
}

/**
 * Test from xref association with data sig
 */
static void TestParentXrefOfDataMatch_Impl(std::pair<std::shared_ptr<IModel>, std::shared_ptr<IModel>> dbs)
{
    auto db1 = dbs.first;
    auto db2 = dbs.second;
    std::vector<Relation> relations;

    // create YaDiff
    const auto config = Configuration("../../YaDiff/tests/YaDiffLib_test/data/config.xml");
    auto differ = yadiff::YaDiff(config);
    differ.MergeDatabases(*db1, *db2, relations);

    expect_req(relations, {
        "max_diff_both_basic_block_0000000000000002_basic_block_0000000000000012_caller_xref",
        "max_diff_both_basic_block_0000000000000004_basic_block_0000000000000014_caller_xref",
        "max_diff_both_function_0000000000000001_function_0000000000000011_caller_xref",
        "max_diff_both_function_0000000000000003_function_0000000000000013_caller_xref",
        "max_exact_match_both_data_0000000000000005_data_0000000000000015_all",
    });
}

#if 1
TEST(TestYaDiffLib, TestParentXrefOfDataMatch_Impl)
{
    auto dbs = create_flatBufferSignatureDB("TestParentXrefOfDataMatch1.xml", "TestParentXrefOfDataMatch2.xml");
    TestParentXrefOfDataMatch_Impl(dbs);
}
#endif //0

namespace
{
void checkFilesContentEqual(std::string file1, fs::path file2)
{
    const auto get_content = [&](const std::string& path)
    {
        std::ifstream ifile(path, std::ifstream::binary);
        EXPECT_TRUE(ifile.is_open());
        if(!ifile.is_open())
            return std::string();

        ifile.seekg(0, ifile.end);
        const auto size = static_cast<size_t>(ifile.tellg());
        ifile.seekg(0, ifile.beg);

        std::vector<char> data;
        data.resize(size);
        ifile.read(&data[0], size);
        ifile.close();
        return std::string(&data[0], size);
    };
    EXPECT_EQ(get_content(file1), get_content(file2.string()));
}

template<typename T>
void propagate_to(yadiff::Propagate& propagater, IModelVisitor& v,
                  IModel& db1, IModel& db2, const T& relations)
{
    propagater.PropagateToDB(v, db1, db2, [&](const yadiff::OnRelationFn& on_relation)
    {
        for(const auto& relation : relations)
            on_relation(relation);
        return static_cast<int>(relations.size());
    });
}

struct TmpDir
{
    TmpDir()
        : path(CreateTemporaryDirectory("yadiff_tmp"))
    {
    }

    ~TmpDir()
    {
        std::error_code err;
        fs::remove_all(path, err);
    }

    fs::path path;
};

/**
 * Test name merge
 */
void TestMergeName_Impl(std::pair<std::shared_ptr<IModel>, std::shared_ptr<IModel>> dbs)
{
    auto db1 = dbs.first;
    auto db2 = dbs.second;
    std::vector<Relation> relations;

    // create YaDiff
    const auto config = Configuration("../../YaDiff/tests/YaDiffLib_test/data/config.xml");
    auto differ = yadiff::YaDiff(config);

    const TmpDir p;
    auto xml_exporter_repo2 = MakeXmlVisitor(p.path.string());

    differ.MergeDatabases(*db1, *db2, relations);
    auto propagater = yadiff::Propagate(config, yadiff::NoShowAssociations, nullptr);
    propagate_to(propagater, *xml_exporter_repo2, *db1, *db2, relations);

    expect_req(relations, {
        "max_exact_match_both_function_0000000000000001_function_0000000000000002_all",
    });

    checkFilesContentEqual("../../YaDiff/tests/YaDiffLib_test/data/merge/TestMergeName2Result.xml", p.path / "function" / "0000000000000002.xml");
}
}

#if 1
TEST(TestYaDiffLib, TestMergeName_fb)
{
    auto dbs = create_flatBufferSignatureDB("merge/TestMergeName1.xml", "merge/TestMergeName2.xml");
    TestMergeName_Impl(dbs);
}
#endif


/**
 * Test parent export
 */
static void TestParentsExport_Impl(std::pair<std::shared_ptr<IModel>, std::shared_ptr<IModel>> dbs)
{
    auto db1 = dbs.first;
    auto db2 = dbs.second;
    std::vector<Relation> relations;

    const TmpDir p;
    auto xml_exporter_repo2 = MakeXmlVisitor(p.path.string());

    // create YaDiff
    const auto config = Configuration("../../YaDiff/tests/YaDiffLib_test/data/config.xml");
    auto differ = yadiff::YaDiff(config);
    differ.MergeDatabases(*db1, *db2, relations);
    auto propagater = yadiff::Propagate(config, yadiff::NoShowAssociations, nullptr);
    propagate_to(propagater, *xml_exporter_repo2, *db1, *db2, relations);

    expect_req(relations, {
        "max_diff_both_function_0000000000000022_function_0000000000000011_caller_xref",
        "max_exact_match_both_function_0000000000000001_function_0000000000000002_all",
    });

    checkFilesContentEqual("../../YaDiff/tests/YaDiffLib_test/data/merge/TestMergeParentExportFunction2Result2.xml", p.path / "function" / "0000000000000002.xml");
    checkFilesContentEqual("../../YaDiff/tests/YaDiffLib_test/data/merge/TestMergeParentExportFunction11Result2.xml",   p.path / "function"    / "0000000000000011.xml");
}

#if 1
TEST(TestYaDiffLib, TestParentsExport_fb)
{
    auto dbs = create_flatBufferSignatureDB("merge/TestMergeParentExport1.xml", "merge/TestMergeParentExport2.xml");
    TestParentsExport_Impl(dbs);
}
#endif

/**
 * Test merge comments
 */
static void TestMergeComments_Impl(std::pair<std::shared_ptr<IModel>, std::shared_ptr<IModel>> dbs)
{
    auto db1 = dbs.first;
    auto db2 = dbs.second;
    std::vector<Relation> relations;

    const TmpDir p1;
    const TmpDir p2;
    auto xml_exporter_repo1 = MakeXmlVisitor(p1.path.string());
    auto xml_exporter_repo2 = MakeXmlVisitor(p2.path.string());

    // create YaDiff
    const auto config = Configuration("../../YaDiff/tests/YaDiffLib_test/data/config.xml");
    auto differ = yadiff::YaDiff(config);
    differ.MergeDatabases(*db1, *db2, relations);
    auto propagater = yadiff::Propagate(config, yadiff::NoShowAssociations, nullptr);
    propagate_to(propagater, *xml_exporter_repo2, *db1, *db2, relations);

    expect_req(relations, {
        "max_exact_match_both_function_0000000000000001_function_0000000000000002_all",
    });

    relations.clear();
    differ.MergeDatabases(*db2, *db1, relations);
    propagate_to(propagater, *xml_exporter_repo1, *db2, *db1, relations);

    expect_req(relations, {
        "max_exact_match_both_function_0000000000000002_function_0000000000000001_all",
    });

    checkFilesContentEqual("../../YaDiff/tests/YaDiffLib_test/data/merge/TestMergeCommentResult1.xml", p1.path / "function" / "0000000000000001.xml");
    checkFilesContentEqual("../../YaDiff/tests/YaDiffLib_test/data/merge/TestMergeCommentResult2.xml", p2.path / "function" / "0000000000000002.xml");
}

#if 1
TEST(TestYaDiffLib, TestMergeComments_fb)
{
    auto dbs = create_flatBufferSignatureDB("merge/TestMergeComment1.xml", "merge/TestMergeComment2.xml");
    TestMergeComments_Impl(dbs);
}
#endif

/**
 * Test merge attributes
 */
static void TestMergeAttributes_Impl(std::pair<std::shared_ptr<IModel>, std::shared_ptr<IModel>> dbs)
{
    auto db1 = dbs.first;
    auto db2 = dbs.second;
    std::vector<Relation> relations;

    const TmpDir p1;
    const TmpDir p2;
    auto xml_exporter_repo1 = MakeXmlVisitor(p1.path.string());
    auto xml_exporter_repo2 = MakeXmlVisitor(p2.path.string());

    // create YaDiff
    const auto config = Configuration("../../YaDiff/tests/YaDiffLib_test/data/config.xml");
    auto differ = yadiff::YaDiff(config);
    differ.MergeDatabases(*db1, *db2, relations);
    auto propagater = yadiff::Propagate(config, yadiff::NoShowAssociations, nullptr);
    propagate_to(propagater, *xml_exporter_repo2, *db1, *db2, relations);

    expect_req(relations, {
        "max_exact_match_both_function_0000000000000001_function_0000000000000002_all",
    });

    relations.clear();
    differ.MergeDatabases(*db2, *db1, relations);
    propagate_to(propagater, *xml_exporter_repo1, *db2, *db1, relations);

    expect_req(relations, {
        "max_exact_match_both_function_0000000000000002_function_0000000000000001_all",
    });

    checkFilesContentEqual("../../YaDiff/tests/YaDiffLib_test/data/merge/TestMergeAttributeResult1.xml", p1.path / "function" / "0000000000000001.xml");
    checkFilesContentEqual("../../YaDiff/tests/YaDiffLib_test/data/merge/TestMergeAttributeResult2.xml", p2.path / "function" / "0000000000000002.xml");
}

#if 1
TEST(TestYaDiffLib, TestMergeAttributes_fb)
{
    auto dbs = create_flatBufferSignatureDB("merge/TestMergeAttribute1.xml", "merge/TestMergeAttribute2.xml");
    TestMergeAttributes_Impl(dbs);
}
#endif

/**
 * Test merge xrefs
 */
static void TestMergeXrefs_Impl(std::pair<std::shared_ptr<IModel>, std::shared_ptr<IModel>> dbs)
{
    auto db1 = dbs.first;
    auto db2 = dbs.second;
    std::vector<Relation> relations;

    const TmpDir p1;
    const TmpDir p2;
    auto xml_exporter_repo1 = MakeXmlVisitor(p1.path.string());
    auto xml_exporter_repo2 = MakeXmlVisitor(p2.path.string());

    // create YaDiff
    const auto config = Configuration("../../YaDiff/tests/YaDiffLib_test/data/config.xml");
    auto differ = yadiff::YaDiff(config);
    differ.MergeDatabases(*db1, *db2, relations);
    auto propagater = yadiff::Propagate(config, yadiff::NoShowAssociations, nullptr);
    propagate_to(propagater, *xml_exporter_repo2, *db1, *db2, relations);

    expect_req(relations, {
        "max_exact_match_both_function_0000000000000001_function_0000000000000002_all",
    });

    relations.clear();
    differ.MergeDatabases(*db2, *db1, relations);
    propagate_to(propagater, *xml_exporter_repo1, *db2, *db1, relations);

    expect_req(relations, {
        "max_exact_match_both_function_0000000000000002_function_0000000000000001_all",
    });

    checkFilesContentEqual("../../YaDiff/tests/YaDiffLib_test/data/merge/TestMergeXrefsResult1.xml", p1.path / "function" / "0000000000000001.xml");
    checkFilesContentEqual("../../YaDiff/tests/YaDiffLib_test/data/merge/TestMergeXrefsResult2.xml", p2.path / "function" / "0000000000000002.xml");
}

#if 1
TEST(TestYaDiffLib, TestMergeXrefs_fb)
{
    auto dbs = create_flatBufferSignatureDB("merge/TestMergeXrefs1.xml", "merge/TestMergeXrefs2.xml");
    TestMergeXrefs_Impl(dbs);
}
#endif

/**
 * Test merge looping xrefs
 */
static void TestMergeLoopXrefs_Impl(std::pair<std::shared_ptr<IModel>, std::shared_ptr<IModel>> dbs)
{
    auto db1 = dbs.first;
    auto db2 = dbs.second;
    std::vector<Relation> relations;

    const TmpDir p1;
    const TmpDir p2;
    auto xml_exporter_repo1 = MakeXmlVisitor(p1.path.string());
    auto xml_exporter_repo2 = MakeXmlVisitor(p2.path.string());

    // create YaDiff
    const auto config = Configuration("../../YaDiff/tests/YaDiffLib_test/data/config.xml");
    auto differ = yadiff::YaDiff(config);
    differ.MergeDatabases(*db1, *db2, relations);
    auto propagater = yadiff::Propagate(config, yadiff::NoShowAssociations, nullptr);
    propagate_to(propagater, *xml_exporter_repo2, *db1, *db2, relations);

    expect_req(relations, {
        "max_exact_match_both_function_0000000000000001_function_0000000000000002_all",
    });

    checkFilesContentEqual("../../YaDiff/tests/YaDiffLib_test/data/merge/TestMergeXrefsLoopResult2.xml",   p2.path / "function" / "0000000000000002.xml");
    checkFilesContentEqual("../../YaDiff/tests/YaDiffLib_test/data/merge/TestMergeXrefsLoopResult11.xml",  p2.path / "struc"       / "0000000000000011.xml");
    checkFilesContentEqual("../../YaDiff/tests/YaDiffLib_test/data/merge/TestMergeXrefsLoopResult111.xml", p2.path / "strucmember" / "0000000000000111.xml");
}

#if 1
TEST(TestYaDiffLib, TestMergeLoopXrefs_fb)
{
    auto dbs = create_flatBufferSignatureDB("merge/TestMergeXrefsLoop1.xml", "merge/TestMergeXrefsLoop2.xml");
    TestMergeLoopXrefs_Impl(dbs);

}
#endif

/**
 * Test merge missing xrefs
 */
static void TestMergeMissingXrefs_Impl(std::pair<std::shared_ptr<IModel>, std::shared_ptr<IModel>> dbs)
{
    auto db1 = dbs.first;
    auto db2 = dbs.second;
    std::vector<Relation> relations;

    const TmpDir p1;
    const TmpDir p2;

    auto xml_exporter_repo1 = MakeXmlVisitor(p1.path.string());
    auto xml_exporter_repo2 = MakeXmlVisitor(p2.path.string());

    // create YaDiff
    const auto config = Configuration("../../YaDiff/tests/YaDiffLib_test/data/config.xml");
    auto differ = yadiff::YaDiff(config);
    differ.MergeDatabases(*db1, *db2, relations);
    auto propagater = yadiff::Propagate(config, yadiff::NoShowAssociations, nullptr);
    propagate_to(propagater, *xml_exporter_repo2, *db1, *db2, relations);

    expect_req(relations, {
        "max_exact_match_both_function_0000000000000001_function_0000000000000002_all",
    });

    relations.clear();
    differ.MergeDatabases(*db2, *db1, relations);
    propagate_to(propagater, *xml_exporter_repo1, *db2, *db1, relations);

    expect_req(relations, {
        "max_exact_match_both_function_0000000000000002_function_0000000000000001_all",
    });

    checkFilesContentEqual("../../YaDiff/tests/YaDiffLib_test/data/merge/TestMergeXrefsMissingResult1.xml",  p1.path / "function" / "0000000000000001.xml");
    checkFilesContentEqual("../../YaDiff/tests/YaDiffLib_test/data/merge/TestMergeXrefsMissingResult2.xml",  p2.path / "function" / "0000000000000002.xml");
}

#if 1
TEST(TestYaDiffLib, TestMergeMissingXrefs_Impl)
{
    auto dbs = create_flatBufferSignatureDB("merge/TestMergeXrefsMissing1.xml", "merge/TestMergeXrefsMissing2.xml");
    TestMergeMissingXrefs_Impl(dbs);
}
#endif

/**
 * Test merge missing xrefs
 */
static void TestMergeMultiStrucXrefs_Impl(std::pair<std::shared_ptr<IModel>, std::shared_ptr<IModel>> dbs)
{
    auto db1 = dbs.first;
    auto db2 = dbs.second;
    std::vector<Relation> relations;

    TmpDir p1;
    TmpDir p2;

    auto xml_exporter_repo1 = MakeXmlVisitor(p1.path.string());
    auto xml_exporter_repo2 = MakeXmlVisitor(p2.path.string());

    // create YaDiff
    const auto config = Configuration("../../YaDiff/tests/YaDiffLib_test/data/config.xml");
    auto differ = yadiff::YaDiff(config);
    differ.MergeDatabases(*db1, *db2, relations);
    auto propagater = yadiff::Propagate(config, yadiff::NoShowAssociations, nullptr);
    propagate_to(propagater, *xml_exporter_repo2, *db1, *db2, relations);

    expect_req(relations, {
        "max_exact_match_both_function_0000000000000001_function_0000000000000002_all",
    });

    relations.clear();
    differ.MergeDatabases(*db2, *db1, relations);
    propagate_to(propagater, *xml_exporter_repo1, *db2, *db1, relations);

    expect_req(relations, {
        "max_exact_match_both_function_0000000000000002_function_0000000000000001_all",
    });

    checkFilesContentEqual("../../YaDiff/tests/YaDiffLib_test/data/merge/TestMergeMultiStrucXrefsResult1.xml",  p1.path / "function" / "0000000000000001.xml");
    checkFilesContentEqual("../../YaDiff/tests/YaDiffLib_test/data/merge/TestMergeMultiStrucXrefsResult2.xml",  p2.path / "function" / "0000000000000002.xml");
}

#if 1
TEST(TestYaDiffLib, TestMergeMultiStrucXrefs_Impl)
{
    auto dbs = create_flatBufferSignatureDB("merge/TestMergeMultiStrucXrefs1.xml", "merge/TestMergeMultiStrucXrefs2.xml");
    TestMergeMultiStrucXrefs_Impl(dbs);
}
#endif

void LookupFunctionName(const_string_ref& name, const HVersion& fctVersion)
{
    // for all BB
    fctVersion.walk_xrefs_from([&](offset_t /*offset*/, operand_t /*operand*/, const HVersion& fctSonVersion)
    {
        if (fctSonVersion.type() != OBJECT_TYPE_BASIC_BLOCK)
            return WALK_CONTINUE;

        // Set the first BB + get function Name that is wirtten in its first BB
        if (fctSonVersion.address())
            return WALK_CONTINUE;

        name = fctSonVersion.username();
        if (name.size == 0 || name.value == NULL)
        {
            name.size = 7;
            name.value = "noName";
        }
        return WALK_STOP;
    });
}



int         giFunctionCounter = 0;
bool TestOutput(const Relation& relation)
{
    // Get Names
    const_string_ref fctName1;
    const_string_ref fctName2;
    LookupFunctionName(fctName1, relation.version1_);
    LookupFunctionName(fctName2, relation.version1_);


    // LOG
    LOG(INFO, "---> Function (%s, %jx) matches Function (%s, %jx) with confidence %d/4 \n",
        fctName1.value, relation.version1_.address(),
        fctName2.value, relation.version2_.address(),
        relation.confidence_
        );

    // Inc counter
    giFunctionCounter++;
    return true;
}


void TestVectorSign_Impl()
{
	// 2/ Get Database
	auto dbs = create_flatBufferSignatureDB("diff/tbf_small_c.xml", "diff/tbf_small_c.xml");
	const IModel& db1 = *dbs.first;

	// 3/ Get Algo
	struct yadiff::AlgoCfg cfg;
	memset(&cfg, 0, sizeof cfg);
	cfg.Algo = yadiff::ALGO_VECTOR_SIGN;
    auto algo = yadiff::MakeDiffAlgo(cfg);  // pLogger, yadiff::YADIFF_ALGO_VECTOR_SIGN, &cfg

    // 4/ Run Prepare (database)
    algo->Prepare(db1, db1);

    // 5/ Run Analyse (compare)
    const yadiff::RelationWalkerfn  input;
    algo->Analyse(TestOutput, input);

    // 6/ Check
    EXPECT_EQ(giFunctionCounter, 3);
}

#if 0
TEST_F (TestYaDiffLib, TestVectorSignFB_fb)
{
    TestVectorSign_Impl();
}
#endif


TEST(TestYaDiffLib, TestPrepareExternalMappingMatchAlgoInvalidInput)
{
    yadiff::AlgoCfg config;
    memset(&config, 0, sizeof config);
    config.Algo = yadiff::ALGO_EXTERNAL_MAPPING_MATCH;
    const fs::path data_test_path = "../../YaDiff/tests/YaDiffLib_test/data";
    const auto json_file = (data_test_path / "TestExternalMappingMatc").generic_string(); // invalid filename
    config.ExternalMappingMatch.MappingFilePath = json_file.data();
    auto algo = yadiff::MakeDiffAlgo(config);
    auto db1 = MakeMemoryModel();
    auto db2 = MakeMemoryModel();
    EXPECT_FALSE(algo->Prepare(*db1, *db2));
}

TEST(TestYaDiffLib, TestPrepareExternalMappingMatchAlgo)
{
    yadiff::AlgoCfg config;
    memset(&config, 0, sizeof config);
    config.Algo = yadiff::ALGO_EXTERNAL_MAPPING_MATCH;
    const fs::path data_test_path = "../../YaDiff/tests/YaDiffLib_test/data";
    const auto json_file = (data_test_path / "TestExternalMappingMatchAlgo.json").generic_string();
    config.ExternalMappingMatch.MappingFilePath = json_file.data();
    auto algo = yadiff::MakeDiffAlgo(config);
    auto db1 = MakeMemoryModel();
    auto db2 = MakeMemoryModel();
    EXPECT_TRUE(algo->Prepare(*db1, *db2));
}


static void TestExternalMappingMatch_Impl(std::pair<std::shared_ptr<IModel>, std::shared_ptr<IModel>> dbs)
{
    yadiff::AlgoCfg config;
    memset(&config, 0, sizeof config);
    config.Algo = yadiff::ALGO_EXTERNAL_MAPPING_MATCH;
    const fs::path data_test_path = "../../YaDiff/tests/YaDiffLib_test/data";
    const auto json_file = (data_test_path / "TestExternalMappingMatchAlgo.json").generic_string();
    config.ExternalMappingMatch.MappingFilePath = json_file.data();
    
    auto algo = yadiff::MakeDiffAlgo(config);
    std::vector<Relation> relations;
    EXPECT_TRUE(algo->Prepare(*dbs.first, *dbs.second));
    
    const yadiff::RelationWalkerfn input;
    const auto AddRelation = [&](const Relation& relation){
        relations.emplace_back(relation);
        return true;
    };
    EXPECT_TRUE(algo->Analyse(AddRelation, input));
    expect_req(relations, {
        "good_diff_both_basic_block_0000000022345678_basic_block_0000000022345688",
        "good_diff_both_basic_block_0000000032345678_basic_block_0000000032345688",
        "good_diff_both_basic_block_0000000042345678_basic_block_0000000042345688",
        "good_exact_match_both_basic_block_0000000012345678_basic_block_0000000012345688"
    });
}

TEST(TestYaDiffLib, TestAnalyseExternalMappingMatch)
{
    auto dbs = create_flatBufferSignatureDB("TestExternalMappingMatch1.xml", "TestExternalMappingMatch2.xml");
    TestExternalMappingMatch_Impl(dbs);
}

static void TestExternalMappingMatch2_Impl(std::pair<std::shared_ptr<IModel>, std::shared_ptr<IModel>> dbs)
{
    yadiff::AlgoCfg config;
    memset(&config, 0, sizeof config);
    config.Algo = yadiff::ALGO_EXTERNAL_MAPPING_MATCH;
    config.ExternalMappingMatch.CustomRelationConfidence = true;
    config.ExternalMappingMatch.RelationConfidence = RELATION_CONFIDENCE_BAD;
    const fs::path data_test_path = "../../YaDiff/tests/YaDiffLib_test/data";
    const auto json_file = (data_test_path / "TestExternalMappingMatchAlgo.json").generic_string();
    config.ExternalMappingMatch.MappingFilePath = json_file.data();
    auto algo = yadiff::MakeDiffAlgo(config);
    auto db1 = dbs.first;
    auto db2 = dbs.second;
    std::vector<Relation> relations;
    EXPECT_TRUE(algo->Prepare(*db1, *db2));
    const yadiff::RelationWalkerfn  input;
    const auto AddRelation = [&](const Relation& relation)
    {
        relations.emplace_back(relation);
        return true;
    };
    EXPECT_TRUE(algo->Analyse(AddRelation, input));
    expect_req(relations, {
        "bad_diff_both_basic_block_0000000022345678_basic_block_0000000022345688",
        "bad_diff_both_basic_block_0000000032345678_basic_block_0000000032345688",
        "bad_diff_both_basic_block_0000000042345678_basic_block_0000000042345688",
        "bad_exact_match_both_basic_block_0000000012345678_basic_block_0000000012345688"
    });
}

TEST(TestYaDiffLib, TestAnalyseExternalMappingMatch2)
{
    auto dbs = create_flatBufferSignatureDB("TestExternalMappingMatch1.xml", "TestExternalMappingMatch2.xml");
    TestExternalMappingMatch2_Impl(dbs);
}
