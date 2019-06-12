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

#ifndef YALIB_TEST
#   define YALIB_TEST
#endif

#include "Helpers.h"
#include "YaTypes.hpp"
#include "test_common.hpp"

#include "IModel.hpp"
#include "HVersion.hpp"
#include "ExporterValidatorVisitor.hpp"
#include "MemoryModel.hpp"
#include "FlatBufferModel.hpp"
#include "FlatBufferVisitor.hpp"
#include "FileUtils.hpp"

#include "test_model.hpp"

#include <functional>
#include <map>

#ifdef _MSC_VER
#   include <optional.hpp>
using namespace nonstd;
#else
#   include <experimental/optional>
using namespace std::experimental;
#endif


using namespace std;

class TestYaToolDatabaseModel
    : public testing::Test
{
};

static const std::string gEmpty;


void create_object(IModelVisitor& v, YaToolObjectId id,
                   const char* crc,
                   const std::vector<Xref>& xrefs)
{
    v.visit_start_version(OBJECT_TYPE_DATA, id);

    v.visit_size(0x20);
    v.visit_start_signatures();
    v.visit_signature(SIGNATURE_OPCODE_HASH, SIGNATURE_ALGORITHM_CRC32, make_string_ref(crc));
    v.visit_end_signatures();
    v.visit_start_xrefs();
    v.visit_end_xrefs();

    v.visit_start_xrefs();
    for(const auto& xref : xrefs)
    {
        v.visit_start_xref(xref.offset, xref.id, xref.operand);
        v.visit_end_xref();
    }
    v.visit_end_xrefs();

    v.visit_end_version();
}

void create_model(IModelVisitor& v)
{
    v.visit_start();
    v.visit_start_version(OBJECT_TYPE_CODE, 0xAAAAAAAA);
    v.visit_size(0x10);
    v.visit_start_signatures();
    v.visit_signature(SIGNATURE_OPCODE_HASH, SIGNATURE_ALGORITHM_CRC32, make_string_ref("BADBADBA"));
    v.visit_signature(SIGNATURE_FIRSTBYTE,   SIGNATURE_ALGORITHM_CRC32, make_string_ref("BADBAD00"));
    v.visit_end_signatures();
    v.visit_start_xrefs();
    v.visit_start_xref(0x10, 0xBBBBBBBB, 0);  v.visit_end_xref();
    v.visit_start_xref(0x20, 0xBBBBBBBB, 0);  v.visit_end_xref();
    v.visit_start_xref(0x20, 0xBBBBBBBB, 1);  v.visit_end_xref();
    v.visit_start_xref(0x30, 0xCCCCCCCC, 1);  v.visit_end_xref();
    v.visit_start_xref(0x30, 0xBBBBBBBB, 0);  v.visit_end_xref();
    v.visit_start_xref(0x30, 0xDDDDDDDD, 0);  v.visit_end_xref();
    v.visit_end_xrefs();

    v.visit_end_version();

    create_object(v, 0xBBBBBBBB, "11111111", {{{0xDDDDDDDD, 0x10, 0, 0}}});
    create_object(v, 0xDDDDDDDD, "22222222", {{{0xCCCCCCCC, 0x20, 1, 0}, {0xBBBBBBBB, 0x20, 2, 0}}});
    create_object(v, 0xCCCCCCCC, "22222222", {});
    v.visit_end();
}

std::shared_ptr<IModel> create_memorySignatureDB()
{
    auto db = MakeMemoryModel();
    create_model(*db);
    return db;
}

namespace
{
std::shared_ptr<IModel> create_FBSignatureDB()
{
    return create_fbmodel_with(&create_model);
}

class MockDatabase : public IModel
{
public:
    MockDatabase(){}
    virtual ~MockDatabase(){}

    // Define empty acceptors/walkers
    void        accept(IModelVisitor&) override {};
    void        walk(const OnVersionFn&) const override {};
    size_t      size() const override { return 0; };
    HVersion    get(YaToolObjectId) const override { return HVersion{ nullptr, 0 }; };
    bool        has(YaToolObjectId) const override { return false; };
    size_t      size_matching(const HSignature&) const override { return 0; };
    void        walk_matching(const HSignature&, const OnVersionFn&) const override {};
    void        walk_uniques(const OnSignatureFn&) const override {};
    void        walk_matching(const HVersion&, size_t, const OnVersionFn&) const override {};
};
}

TEST_F(TestYaToolDatabaseModel, model)
{
    /**
     * This test ensures that the model created with create_model is consistent and passes
     * validation through ExporterValidatorVisitor
     */
    create_model(*MakeExporterValidatorVisitor());
}

void ReferencedObjects_Impl(std::shared_ptr<IModel>db)
{
    std::multiset<std::pair<std::string, std::string>> values;
    db->walk([&](const HVersion& href)
    {
        values.insert(std::make_pair(str(href.id()), str(href)));
        return WALK_CONTINUE;
    });
    EXPECT_EQ(values.size(), db->size());
    expect_eq(values, {
        {"00000000AAAAAAAA", "code_00000000AAAAAAAA"},
        {"00000000BBBBBBBB", "data_00000000BBBBBBBB"},
        {"00000000CCCCCCCC", "data_00000000CCCCCCCC"},
        {"00000000DDDDDDDD", "data_00000000DDDDDDDD"},
    });
}

TEST_F(TestYaToolDatabaseModel, memoryModel_ReferencedObjects) {
    ReferencedObjects_Impl(create_memorySignatureDB());
}

TEST_F(TestYaToolDatabaseModel, FBModel_ReferencedObjects) {
    ReferencedObjects_Impl(create_FBSignatureDB());
}

class MockSignatureDatabase1
    : public MockDatabase
    , public ISignatures
{
public:
    MockSignatureDatabase1(const Signature& sig)
        : sig(sig)
    {
    }

    Signature get(HSignature_id_t) const override
    {
        return sig;
    }

private:
    Signature sig;
};

struct Ctx
{
    std::vector<std::shared_ptr<IModelAndVisitor>> models;
    std::vector<std::shared_ptr<MockSignatureDatabase1>> mocks;
};

static auto create_signature(Ctx& ctx, uint32_t value)
{
    char buf[32];
    sprintf(buf, "%X", value);
    const auto sig = MakeSignature(SIGNATURE_ALGORITHM_CRC32, SIGNATURE_OPCODE_HASH, make_string_ref(buf));
    ctx.mocks.push_back(std::make_shared<MockSignatureDatabase1>(sig));
    return HSignature{ctx.mocks.back().get(), 0};
}

void ReferencedObjectsBySignature_Impl(std::shared_ptr<IModel>db)
{
    Ctx ctx;
    const auto sigH = create_signature(ctx, 0x22222222);

    std::multiset<std::string> values;
    db->walk_matching(sigH, [&](const HVersion& href)
    {
        values.insert(str(href));
        return WALK_CONTINUE;
    });
    EXPECT_EQ(values.size(), db->size_matching(sigH));
    expect_eq(values, {"data_00000000CCCCCCCC", "data_00000000DDDDDDDD"});

    const auto sigH2 = create_signature(ctx, 0x11111111);
    db->walk_matching(sigH2, [&](const HVersion& href)
    {
        values.insert(str(href));
        return WALK_CONTINUE;
    });
    EXPECT_EQ(values.size(), db->size_matching(sigH2));
    expect_eq(values, {"data_00000000BBBBBBBB"});

    const auto sigH4 = create_signature(ctx, 0x55555555);
    db->walk_matching(sigH4, [&](const HVersion& href)
    {
        values.insert(str(href));
        return WALK_CONTINUE;
    });
    EXPECT_EQ(values.size(), db->size_matching(sigH4));
    expect_eq(values, {});

    const auto sigH5 = create_signature(ctx, 0xBADBADBA);
    db->walk_matching(sigH5, [&](const HVersion& href)
    {
        values.insert(str(href));
        return WALK_CONTINUE;
    });
    EXPECT_EQ(values.size(), db->size_matching(sigH5));
    expect_eq(values, {"code_00000000AAAAAAAA"});
}

TEST_F(TestYaToolDatabaseModel, memoryModel_ReferencedObjectsBySignature) {
    ReferencedObjectsBySignature_Impl(create_memorySignatureDB());
}

TEST_F(TestYaToolDatabaseModel, FBModel_ReferencedObjectsBySignature) {
    ReferencedObjectsBySignature_Impl(create_FBSignatureDB());
}

namespace
{
    struct Version
    {
        YaToolObjectId          id;
        size_t                  size;
        std::vector<Signature>  sigs;

        Version(YaToolObjectId id, uint32_t crc, size_t size);

        void add_signature(const Signature& sig);
        void accept(IModelVisitor& visitor);
    };

    struct Object
    {
        YaToolObjectId           id;
        std::shared_ptr<Version> version_;

        Object(YaToolObjectId id);

        void putVersion(const std::shared_ptr<Version>& version);
        void accept(IModelVisitor& visitor);
    };
}

Version::Version(YaToolObjectId id, uint32_t crc, size_t size)
    : id(id)
    , size(size)
{
    char buf[32];
    sprintf(buf, "%X", crc);
    add_signature(MakeSignature(SIGNATURE_ALGORITHM_CRC32, SIGNATURE_OPCODE_HASH, make_string_ref(buf)));
}

static std::shared_ptr<Version> create_version(YaToolObjectId id, uint32_t crc, size_t size)
{
    return std::make_shared<Version>(id, crc, size);
}

void Version::add_signature(const Signature& sig)
{
    sigs.push_back(sig);
}

void Version::accept(IModelVisitor& visitor)
{
    visitor.visit_start_version(OBJECT_TYPE_DATA, id);
    if(size)
        visitor.visit_size(size);
    visitor.visit_start_signatures();
    for(const auto& sig : sigs)
        visitor.visit_signature(sig.method, sig.algo, make_string_ref(sig));
    visitor.visit_end_signatures();
    visitor.visit_end_version();
}

static HVersion create_href(Ctx& ctx, Version& version)
{
    ctx.models.push_back(MakeMemoryModel());
    auto& db = ctx.models.back();
    db->visit_start();
    version.accept(*db);
    db->visit_end();
    return db->get(version.id);
}

void walkNoSignatureCollision_Impl(std::shared_ptr<IModel>db)
{
    std::multiset<std::pair<std::string, std::string>> values;
    db->walk_uniques([&](const HVersion& ov, const HSignature& sig)
    {
        values.insert(std::make_pair(str(sig), str(ov)));
        return WALK_CONTINUE;
    });
    expect_eq(values, {
        {"11111111", "data_00000000BBBBBBBB"},
        {"BADBAD00", "code_00000000AAAAAAAA"},
        {"BADBADBA", "code_00000000AAAAAAAA"},
    });
}

TEST_F(TestYaToolDatabaseModel, memoryModel_walkNoSignatureCollision) {
    walkNoSignatureCollision_Impl(create_memorySignatureDB());
}

TEST_F(TestYaToolDatabaseModel, FBModel_walkNoSignatureCollision) {
    walkNoSignatureCollision_Impl(create_FBSignatureDB());
}

enum FirstOnly_e {FirstOnly, Any};

static auto get_object_for_signature(Ctx ctx, IModel& db, uint32_t value, FirstOnly_e efirst)
{
    optional<HVersion> object;
    const auto sig = create_signature(ctx, value);
    size_t count = 0;
    db.walk_matching(sig, [&](const HVersion& obj)
    {
        ++count;
        object = obj;
        return efirst == FirstOnly ? WALK_STOP : WALK_CONTINUE;
    });
    EXPECT_EQ(1u, count);
    EXPECT_EQ(count, db.size_matching(sig));
    EXPECT_TRUE(!!object);
    return *object;
}

void walkObjectVersions_Impl(std::shared_ptr<IModel>db)
{
    Ctx ctx;
    const auto objH = get_object_for_signature(ctx, *db, 0x11111111, Any);
    EXPECT_TRUE(objH.is_valid());

    std::multiset<std::string> values;
    values.insert(str(objH));
    expect_eq(values, {
        {"data_00000000BBBBBBBB"},
    });

    const auto objH2 = get_object_for_signature(ctx, *db, 0xBADBADBA, Any);
    EXPECT_TRUE(objH2.is_valid());
    EXPECT_EQ(objH2.id(), 0xAAAAAAAA);
    EXPECT_EQ(objH2.type(), OBJECT_TYPE_CODE);
    values.insert(str(objH2));
    expect_eq(values, {
        {"code_00000000AAAAAAAA"}
    });
}

TEST_F(TestYaToolDatabaseModel, memoryModel_walkObjectVersions) {
    walkObjectVersions_Impl(create_memorySignatureDB());
}

TEST_F(TestYaToolDatabaseModel, FBModel_walkObjectVersions) {
    walkObjectVersions_Impl(create_FBSignatureDB());
}

static auto get_version_for_signature(Ctx& ctx, IModel& db, uint32_t value)
{
    return get_object_for_signature(ctx, db, value, FirstOnly);
}

void walkObjectVersionSignatures_Impl(std::shared_ptr<IModel>db)
{
    Ctx ctx;
    const auto objectVersionH = get_version_for_signature(ctx, *db, 0xBADBADBA);
    EXPECT_TRUE(objectVersionH.is_valid());

    EXPECT_EQ(objectVersionH.type(), OBJECT_TYPE_CODE);

    std::multiset<std::string> values;
    objectVersionH.walk_signatures([&](const HSignature& ov)
    {
        values.insert(str(ov));
        return WALK_CONTINUE;
    });
    expect_eq(values, {"BADBAD00", "BADBADBA"});
}

TEST_F(TestYaToolDatabaseModel, memoryModel_walkObjectVersionSignatures) {
    walkObjectVersionSignatures_Impl(create_memorySignatureDB());
}

TEST_F(TestYaToolDatabaseModel, FBModel_walkObjectVersionSignatures) {
    walkObjectVersionSignatures_Impl(create_FBSignatureDB());
}

void getReferencedObjectFromId_Impl(std::shared_ptr<IModel>db)
{
    std::vector<YaToolObjectId> ids = {0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD};
    for(auto id: ids)
    {
        EXPECT_EQ(id, db->get(id).id());
    }
}

TEST_F(TestYaToolDatabaseModel, memoryModel_getReferencedObjectFromId) {
    getReferencedObjectFromId_Impl(create_memorySignatureDB());
}

TEST_F(TestYaToolDatabaseModel, FBModel_getReferencedObjectFromId) {
    getReferencedObjectFromId_Impl(create_FBSignatureDB());
}

void getObjectType_Impl(std::shared_ptr<IModel>db)
{
    EXPECT_EQ(OBJECT_TYPE_CODE, db->get(0xAAAAAAAA).type());
    EXPECT_EQ(OBJECT_TYPE_DATA, db->get(0xBBBBBBBB).type());
    EXPECT_EQ(OBJECT_TYPE_DATA, db->get(0xCCCCCCCC).type());
    EXPECT_EQ(OBJECT_TYPE_DATA, db->get(0xDDDDDDDD).type());
}

TEST_F(TestYaToolDatabaseModel, memoryModel_getObjectType) {
    getObjectType_Impl(create_memorySignatureDB());
}

TEST_F(TestYaToolDatabaseModel, FBModel_getObjectType) {
    getObjectType_Impl(create_FBSignatureDB());
}

void getObjectId_Impl(std::shared_ptr<IModel>db)
{
    std::vector<YaToolObjectId> ids = {0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD};
    for(auto id: ids)
        EXPECT_EQ(id, db->get(id).id());
}

TEST_F(TestYaToolDatabaseModel, memoryModel_getObjectId) {
    getObjectId_Impl(create_memorySignatureDB());
}

TEST_F(TestYaToolDatabaseModel, FBModel_getObjectId) {
    getObjectId_Impl(create_FBSignatureDB());
}

void getObjectSignatureString_Impl(std::shared_ptr<IModel>db)
{
    Ctx ctx;
    const auto objVerH = get_version_for_signature(ctx, *db, 0x11111111);
    EXPECT_TRUE(objVerH.is_valid());
    std::multiset<std::string> values;
    objVerH.walk_signatures([&](const HSignature& ov)
    {
        values.insert(str(ov));
        return WALK_CONTINUE;
    });
    expect_eq(values, {"11111111"});
}

TEST_F(TestYaToolDatabaseModel, memoryModel_getObjectSignatureString) {
    getObjectSignatureString_Impl(create_memorySignatureDB());
}

TEST_F(TestYaToolDatabaseModel, FBModel_getObjectSignatureString) {
    getObjectSignatureString_Impl(create_FBSignatureDB());
}

void referencedObjectMatch_Impl(std::shared_ptr<IModel>db)
{
    Ctx ctx;

    //Fetch an object with its signature
    const auto foundObjectH = get_object_for_signature(ctx, *db, 0x11111111, Any);
    EXPECT_TRUE(foundObjectH.is_valid());
    EXPECT_EQ(foundObjectH.id(), 0xBBBBBBBB);
    EXPECT_EQ(foundObjectH.type(), OBJECT_TYPE_DATA);

    //create a local dummy object
    const auto ov1 = create_version(0xAAAA0000, 0x11110001, 0x8);
    const auto roH1 = create_href(ctx, *ov1);

    EXPECT_FALSE(roH1.match(foundObjectH));
    EXPECT_FALSE(foundObjectH.match(roH1));

    //Add an OV with same signature but bad size
    const auto ov2 = create_version(0xAAAA0000, 0x11111111, 0x10);
    const auto roH2 = create_href(ctx, *ov2);

    EXPECT_FALSE(roH2.match(foundObjectH));
    EXPECT_FALSE(foundObjectH.match(roH2));


    //Add an OV with different signature but same size
    const auto ov3 = create_version(0xAAAA0000, 0x11110002, 0x20);
    const auto roH3 = create_href(ctx, *ov3);

    EXPECT_FALSE(roH3.match(foundObjectH));
    EXPECT_FALSE(foundObjectH.match(roH3));

    //Add an OV with same signature and same size
    const auto ov4 = create_version(0xAAAA0000, 0x11111111, 0x20);
    const auto roH4 = create_href(ctx, *ov4);

    EXPECT_TRUE(roH4.match(foundObjectH));
    EXPECT_TRUE(foundObjectH.match(roH4));

    /*
     * Same thing but with 2 signatures in the found object
     */
    const auto foundObjectH2 = db->get(0xAAAAAAAA);
    EXPECT_EQ(foundObjectH2.id(), 0xAAAAAAAA);
    EXPECT_EQ(foundObjectH2.type(), OBJECT_TYPE_CODE);

    //create a local dummy object
    const auto ov2_1 = create_version(0xBBBB0000, 0x22222222, 0x8);
    const auto roH2_1 = create_href(ctx, *ov2_1);

    EXPECT_FALSE(roH2_1.match(foundObjectH2));
    EXPECT_FALSE(foundObjectH2.match(roH2_1));

    //Add an OV with same signature but bad size
    const auto ov2_2 = create_version(0xBBBB0000, 0xBADBADBA, 0x100);
    const auto roH2_2 = create_href(ctx, *ov2_2);

    EXPECT_FALSE(roH2_2.match(foundObjectH2));
    EXPECT_FALSE(foundObjectH2.match(roH2_2));

    //Add an OV with different signature but same size
    const auto ov2_3 = create_version(0xBBBB0000, 0x33333333, 0x10);
    const auto roH2_3 = create_href(ctx, *ov2_3);

    EXPECT_FALSE(roH2_3.match(foundObjectH2));
    EXPECT_FALSE(foundObjectH2.match(roH2_3));

    //Add an OV with same signature and same size, but 1 missing signature
    const auto ov2_4 = create_version(0xBBBB0000, 0xBADBADBA, 0x10);
    const auto roH2_4 = create_href(ctx, *ov2_4);

    EXPECT_FALSE(roH2_4.match(foundObjectH2));
    EXPECT_FALSE(foundObjectH2.match(roH2_4));

    //Add an OV with same signatureS and same size
    const auto ov2_5 = create_version(0xBBBB0000, 0xBADBADBA, 0x10);
    ov2_5->add_signature(MakeSignature(SIGNATURE_ALGORITHM_CRC32, SIGNATURE_FIRSTBYTE, make_string_ref("BADBAD00")));
    const auto roH2_5 = create_href(ctx, *ov2_5);

    EXPECT_TRUE(roH2_5.match(foundObjectH2));
    EXPECT_TRUE(foundObjectH2.match(roH2_5));

}

TEST_F(TestYaToolDatabaseModel, memoryModel_referencedObjectMatch) {
    referencedObjectMatch_Impl(create_memorySignatureDB());
}

TEST_F(TestYaToolDatabaseModel, FBModel_referencedObjectMatch) {
    referencedObjectMatch_Impl(create_FBSignatureDB());
}

void walkXrefsFromReferencedObject_Impl(std::shared_ptr<IModel>db)
{
    std::multiset<std::tuple<std::string, offset_t, operand_t, std::string>> values;
    db->walk([&](const HVersion& href)
    {
        href.walk_xrefs_from([&](offset_t offset, operand_t operand, const HVersion& xref)
        {
            values.insert(std::make_tuple(str(href), offset, operand, str(xref)));
            return WALK_CONTINUE;
        });
        return WALK_CONTINUE;
    });
    expect_eq(values, {
        std::make_tuple("code_00000000AAAAAAAA", 16, 0, "data_00000000BBBBBBBB"),
        std::make_tuple("code_00000000AAAAAAAA", 32, 0, "data_00000000BBBBBBBB"),
        std::make_tuple("code_00000000AAAAAAAA", 32, 1, "data_00000000BBBBBBBB"),
        std::make_tuple("code_00000000AAAAAAAA", 48, 0, "data_00000000BBBBBBBB"),
        std::make_tuple("code_00000000AAAAAAAA", 48, 0, "data_00000000DDDDDDDD"),
        std::make_tuple("code_00000000AAAAAAAA", 48, 1, "data_00000000CCCCCCCC"),
        std::make_tuple("data_00000000BBBBBBBB", 16, 0, "data_00000000DDDDDDDD"),
        std::make_tuple("data_00000000DDDDDDDD", 32, 1, "data_00000000CCCCCCCC"),
        std::make_tuple("data_00000000DDDDDDDD", 32, 2, "data_00000000BBBBBBBB"),
    });
}

TEST_F(TestYaToolDatabaseModel, memoryModel_walkXrefsFromReferencedObject) {
    walkXrefsFromReferencedObject_Impl(create_memorySignatureDB());
}

TEST_F(TestYaToolDatabaseModel, FBModel_walkXrefsFromReferencedObject) {
    walkXrefsFromReferencedObject_Impl(create_FBSignatureDB());
}

void walkXrefsToReferencedObject_Impl(std::shared_ptr<IModel>db)
{
    std::multiset<std::pair<std::string, std::string>> values;
    db->walk([&](const HVersion& href)
    {
        href.walk_xrefs_to([&](const HVersion& xref)
        {
            values.insert(std::make_pair(str(href), str(xref)));
            return WALK_CONTINUE;
        });
        return WALK_CONTINUE;
    });
    expect_eq(values, {
        {"data_00000000BBBBBBBB", "code_00000000AAAAAAAA"},
        {"data_00000000BBBBBBBB", "data_00000000DDDDDDDD"},
        {"data_00000000CCCCCCCC", "code_00000000AAAAAAAA"},
        {"data_00000000CCCCCCCC", "data_00000000DDDDDDDD"},
        {"data_00000000DDDDDDDD", "code_00000000AAAAAAAA"},
        {"data_00000000DDDDDDDD", "data_00000000BBBBBBBB"},
    });
}

TEST_F(TestYaToolDatabaseModel, memoryModel_walkXrefsToReferencedObject) {
    walkXrefsToReferencedObject_Impl(create_memorySignatureDB());
}

TEST_F(TestYaToolDatabaseModel, FBModel_walkXrefsToReferencedObject) {
    walkXrefsToReferencedObject_Impl(create_FBSignatureDB());
}

void walkXrefsFromObjectVersion_Impl(std::shared_ptr<IModel>db)
{
    std::multiset<std::tuple<std::string, std::string, offset_t, operand_t, std::string>> values;
    db->walk([&](const HVersion& hver)
    {
        hver.walk_xrefs_from([&](offset_t offset, operand_t operand, const HVersion& xref)
        {
            values.insert(std::make_tuple(str(hver), str(hver), offset, operand, str(xref)));
            return WALK_CONTINUE;
        });
        return WALK_CONTINUE;
    });
    expect_eq(values, {
        std::make_tuple("code_00000000AAAAAAAA", "code_00000000AAAAAAAA", 16, 0, "data_00000000BBBBBBBB"),
        std::make_tuple("code_00000000AAAAAAAA", "code_00000000AAAAAAAA", 32, 0, "data_00000000BBBBBBBB"),
        std::make_tuple("code_00000000AAAAAAAA", "code_00000000AAAAAAAA", 32, 1, "data_00000000BBBBBBBB"),
        std::make_tuple("code_00000000AAAAAAAA", "code_00000000AAAAAAAA", 48, 0, "data_00000000BBBBBBBB"),
        std::make_tuple("code_00000000AAAAAAAA", "code_00000000AAAAAAAA", 48, 0, "data_00000000DDDDDDDD"),
        std::make_tuple("code_00000000AAAAAAAA", "code_00000000AAAAAAAA", 48, 1, "data_00000000CCCCCCCC"),
        std::make_tuple("data_00000000BBBBBBBB", "data_00000000BBBBBBBB", 16, 0, "data_00000000DDDDDDDD"),
        std::make_tuple("data_00000000DDDDDDDD", "data_00000000DDDDDDDD", 32, 1, "data_00000000CCCCCCCC"),
        std::make_tuple("data_00000000DDDDDDDD", "data_00000000DDDDDDDD", 32, 2, "data_00000000BBBBBBBB"),
    });
}

TEST_F(TestYaToolDatabaseModel, memoryModel_walkXrefsFromObjectVersion) {
    walkXrefsFromObjectVersion_Impl(create_memorySignatureDB());
}

TEST_F(TestYaToolDatabaseModel, FBModel_walkXrefsFromObjectVersion) {
    walkXrefsFromObjectVersion_Impl(create_FBSignatureDB());
}

void walkXrefsToObjectVersion_Impl(std::shared_ptr<IModel>db)
{
    std::multiset<std::tuple<std::string, std::string, std::string>> values;
    db->walk([&](const HVersion& hver)
    {
        hver.walk_xrefs_to([&](const HVersion& xref)
        {
            values.insert(std::make_tuple(str(hver), str(hver), str(xref)));
            return WALK_CONTINUE;
        });
        return WALK_CONTINUE;
    });
    expect_eq(values, {
        std::make_tuple("data_00000000BBBBBBBB", "data_00000000BBBBBBBB", "code_00000000AAAAAAAA"),
        std::make_tuple("data_00000000BBBBBBBB", "data_00000000BBBBBBBB", "data_00000000DDDDDDDD"),
        std::make_tuple("data_00000000CCCCCCCC", "data_00000000CCCCCCCC", "code_00000000AAAAAAAA"),
        std::make_tuple("data_00000000CCCCCCCC", "data_00000000CCCCCCCC", "data_00000000DDDDDDDD"),
        std::make_tuple("data_00000000DDDDDDDD", "data_00000000DDDDDDDD", "code_00000000AAAAAAAA"),
        std::make_tuple("data_00000000DDDDDDDD", "data_00000000DDDDDDDD", "data_00000000BBBBBBBB"),
    });
}

TEST_F(TestYaToolDatabaseModel, memoryModel_walkXrefsToObjectVersion) {
    walkXrefsToObjectVersion_Impl(create_memorySignatureDB());
}

TEST_F(TestYaToolDatabaseModel, FBModel_walkXrefsToObjectVersion) {
    walkXrefsToObjectVersion_Impl(create_FBSignatureDB());
}

void getObjectVersionId_Impl(std::shared_ptr<IModel>db)
{
    Ctx ctx;
    const auto object1 = get_version_for_signature(ctx, *db, 0xBADBADBA);
    EXPECT_TRUE(object1.is_valid());
    EXPECT_EQ(object1.id(), 0xAAAAAAAA);
    const auto object2 = get_version_for_signature(ctx, *db, 0x11111111);
    EXPECT_TRUE(object2.is_valid());
    EXPECT_EQ(object2.id(), 0xBBBBBBBB);
}

TEST_F(TestYaToolDatabaseModel, memoryModel_getObjectVersionId) {
    getObjectVersionId_Impl(create_memorySignatureDB());
}

TEST_F(TestYaToolDatabaseModel, FBModel_getObjectVersionId) {
    getObjectVersionId_Impl(create_FBSignatureDB());
}

void getObjectVersionSize_Impl(std::shared_ptr<IModel>db)
{
    Ctx ctx;
    const auto object1 = get_version_for_signature(ctx, *db, 0xBADBADBA);
    EXPECT_TRUE(object1.is_valid());
    EXPECT_EQ(object1.size(), (size_t)0x10);
    const auto object2 = get_version_for_signature(ctx, *db, 0x11111111);
    EXPECT_TRUE(object2.is_valid());
    EXPECT_EQ(object2.size(), (size_t)0x20);
}

TEST_F(TestYaToolDatabaseModel, memoryModel_getObjectVersionSize) {
    getObjectVersionSize_Impl(create_memorySignatureDB());
}

TEST_F(TestYaToolDatabaseModel, FBModel_getObjectVersionSize) {
    getObjectVersionSize_Impl(create_FBSignatureDB());
}

static void create_model_objects_without_versions(IModelVisitor& visitor)
{
    visitor.visit_start();
    visitor.visit_start_version(OBJECT_TYPE_CODE, 0xAAAAAAAA);
    visitor.visit_end_version();
    visitor.visit_end();
}

static void testObjectWithoutVersion(IModel& db)
{
    std::multiset<std::pair<std::string, std::string>> values;
    std::vector<std::pair<YaToolObjectId, HVersion>> ids;
    db.walk([&](const HVersion& href)
    {
        const auto id = href.id();
        values.insert(std::make_pair(str(id), str(href)));
        ids.push_back({id, href});
        return WALK_CONTINUE;
    });
    EXPECT_EQ(values.size(), db.size());
    expect_eq(values, {{"00000000AAAAAAAA", "code_00000000AAAAAAAA"}});

    for(const auto& p : ids)
        EXPECT_EQ(p.first, db.get(p.first).id());
}

TEST_F(TestYaToolDatabaseModel, memoryModel_objectWithoutVersion)
{
    const auto db = MakeMemoryModel();
    create_model_objects_without_versions(*db);
    testObjectWithoutVersion(*db);
}

TEST_F(TestYaToolDatabaseModel, FBModel_objectWithoutVersion)
{
    const auto model = create_fbmodel_with(&create_model_objects_without_versions);
    testObjectWithoutVersion(*model);
}

TEST_F(TestYaToolDatabaseModel, test_model_get_object_with_invalid_id)
{
    const auto model = create_fbmodel_with(&create_model);
    const auto hobj1 = model->get(~0u);
    EXPECT_EQ(hobj1.is_valid(), false);
    const auto hobj2 = model->get(0);
    EXPECT_EQ(hobj2.is_valid(), false);
    model->walk([&](const HVersion& hobj)
    {
        const auto hobj3 = model->get(hobj.id() + 1);
        EXPECT_EQ(hobj3.is_valid(), false);
        return WALK_CONTINUE;
    });
}