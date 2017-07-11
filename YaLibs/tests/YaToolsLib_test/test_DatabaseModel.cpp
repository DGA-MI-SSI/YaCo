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

#include "test_common.hpp"
#include "../Helpers.h"

#include "HVersion.hpp"
#include "HObject.hpp"
#include "YaToolObjectId.hpp"
#include "PathDebuggerVisitor.hpp"
#include "ExporterValidatorVisitor.hpp"
#include "DelegatingVisitor.hpp"
#include "MatchingSystem.hpp"
#include "Model.hpp"
#include "FlatBufferDatabaseModel.hpp"
#include "FlatBufferExporter.hpp"
#include "FileUtils.hpp"

#include "test_model.hpp"

#include <functional>

#ifdef _MSC_VER
#   include <optional.hpp>
using namespace nonstd;
#else
#   include <experimental/optional>
using namespace std::experimental;
#endif

#define USE_PATH_DEBUGGER false

using namespace std;

class TestYaToolDatabaseModel: public testing::Test {
protected:
    virtual void SetUp() {
    }

    virtual void TearDown() {
    }
};

static const std::string gEmpty;

MatchingSystem sysA(0xa, {{"os", "os1"}, {"equipment", "eq1"}});
MatchingSystem sysB(0xb, {{"os", "os2"}, {"equipment", "eq2"}});

struct Xref
{
    offset_t        offset;
    operand_t       operand;
    YaToolObjectId  id;
};

void create_object(std::shared_ptr<IModelVisitor> visitor, YaToolObjectId id,
                   const std::vector<const char*>& crcVals,
                   const std::vector<MatchingSystem>& systems,
                   const std::vector<std::vector<Xref>>& xrefs)
{
    visitor->visit_start_reference_object(OBJECT_TYPE_DATA);
    visitor->visit_id(id);

    EXPECT_EQ(crcVals.size(), systems.size());
    uint32_t i;
    for(i=0; i<crcVals.size(); i++)
    {
        auto crcVal = crcVals[i];
        auto system = systems[i];
        visitor->visit_start_object_version();
        visitor->visit_size(0x20);
        visitor->visit_start_signatures();
        visitor->visit_signature(SIGNATURE_OPCODE_HASH, SIGNATURE_ALGORITHM_CRC32, make_string_ref(crcVal));
        visitor->visit_end_signatures();
        visitor->visit_start_xrefs();
        visitor->visit_end_xrefs();

        visitor->visit_start_matching_systems();
        visitor->visit_start_matching_system(i);
        system.accept(*visitor);
        visitor->visit_end_matching_system();
        visitor->visit_end_matching_systems();

        visitor->visit_start_xrefs();
        if(i < xrefs.size())
            for(const auto& xref : xrefs[i])
            {
                visitor->visit_start_xref(xref.offset, xref.id, xref.operand);
                visitor->visit_end_xref();
            }
        visitor->visit_end_xrefs();

        visitor->visit_end_object_version();
    }
    visitor->visit_end_reference_object();
}

void create_model(std::shared_ptr<IModelVisitor> visitor)
{

    visitor->visit_start();
    visitor->visit_start_reference_object(OBJECT_TYPE_CODE);
    visitor->visit_id(0xAAAAAAAA);
    visitor->visit_start_object_version();
    visitor->visit_size(0x10);
    visitor->visit_start_signatures();
    visitor->visit_signature(SIGNATURE_OPCODE_HASH, SIGNATURE_ALGORITHM_CRC32, make_string_ref("BADBADBA"));
    visitor->visit_signature(SIGNATURE_FIRSTBYTE,   SIGNATURE_ALGORITHM_CRC32, make_string_ref("BADBAD00"));
    visitor->visit_end_signatures();
    visitor->visit_start_xrefs();
    visitor->visit_start_xref(0x10, 0xBBBBBBBB, 0);  visitor->visit_end_xref();
    visitor->visit_start_xref(0x20, 0xBBBBBBBB, 0);  visitor->visit_end_xref();
    visitor->visit_start_xref(0x20, 0xBBBBBBBB, 1);  visitor->visit_end_xref();
    visitor->visit_start_xref(0x30, 0xCCCCCCCC, 1);  visitor->visit_end_xref();
    visitor->visit_start_xref(0x30, 0xBBBBBBBB, 0);  visitor->visit_end_xref();
    visitor->visit_start_xref(0x30, 0xDDDDDDDD, 0);  visitor->visit_end_xref();
    visitor->visit_end_xrefs();

    visitor->visit_start_matching_systems();
    visitor->visit_start_matching_system(0x1);
    sysB.accept(*visitor);
    visitor->visit_end_matching_system();
    visitor->visit_start_matching_system(0x2);
    sysA.accept(*visitor);
    visitor->visit_end_matching_system();
    visitor->visit_end_matching_systems();

    visitor->visit_end_object_version();
    visitor->visit_end_reference_object();

    create_object(visitor, 0xBBBBBBBB, {"11111111"}, {sysA}, {{{0x10, 0, 0xDDDDDDDD}}});
    create_object(visitor, 0xDDDDDDDD, {"22222222", "44444444"}, {sysA, sysB}, {{{0x20, 1, 0xCCCCCCCC}, {0x20, 2, 0xBBBBBBBB}}});
    create_object(visitor, 0xCCCCCCCC, {"22222222", "33333333"}, {sysA, sysB}, {});
    visitor->visit_end();
}

std::shared_ptr<IModel> create_memorySignatureDB()
{
    auto db = MakeModel();
    create_model(db.visitor);
    return db.model;
}

namespace
{
std::shared_ptr<IModel> create_FBSignatureDB()
{
    return create_fbmodel_with([&](std::shared_ptr<IModelVisitor> visitor)
    {
        create_model(visitor);
    });
}

class MockDatabase : public IModel
{
public:
    MockDatabase(){}
    virtual ~MockDatabase(){}

    virtual void        accept(IModelVisitor&) {};
    virtual void        walk_objects(const OnObjectAndIdFn&) const {};
    virtual size_t      num_objects() const { return 0; };
    virtual void        walk_objects_with_signature(const HSignature&, const OnObjectFn&) const {};
    virtual size_t      num_objects_with_signature(const HSignature&) const { return 0; };
    virtual void        walk_versions_with_signature(const HSignature&, const OnVersionFn&) const {};
    virtual void        walk_matching_objects(const HObject&, const OnObjectFn&) const {};
    virtual size_t      num_matching_objects(const HObject&) const { return 0; };
    virtual HObject     get_object(YaToolObjectId) const { return HObject{nullptr, 0}; };
    virtual bool        has_object(YaToolObjectId) const { return false; };
    virtual void        walk_versions_without_collision(const OnSigAndVersionFn&) const {};
    virtual void        walk_systems(const OnSystemFn&) const {};
    virtual void        walk_matching_versions(const HObject&, size_t, const OnVersionPairFn&) const {};
};
}

TEST_F(TestYaToolDatabaseModel, model) {
    /**
     * This test ensures that the model created with create_model is consistent and passes
     * validation through ExporterValidatorVisitor
     */
    auto db = MakeModel();
    auto validator = MakeExporterValidatorVisitor();
    auto exporter = make_shared<DelegatingVisitor>();
    exporter->add_delegate(db.visitor);

    if(USE_PATH_DEBUGGER)
    {
        auto pathdebugger = MakePathDebuggerVisitor("SaveValidator", validator, PrintValues);

        exporter->add_delegate(pathdebugger);
        create_model(exporter);
    }
    else
    {
        exporter->add_delegate(validator);
        create_model(exporter);
    }
}

void ReferencedObjects_Impl(std::shared_ptr<IModel>db)
{
    std::multiset<std::pair<std::string, std::string>> values;
    db->walk_objects([&](const YaToolObjectId& id, const HObject& href)
    {
        values.insert(std::make_pair(str(id), str(href)));
        return WALK_CONTINUE;
    });
    EXPECT_EQ(values.size(), db->num_objects());
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

void MatchingSystems_Impl(std::shared_ptr<IModel>db)
{
    std::multiset<HSystem_id_t> systems;
    db->walk_systems([&](HSystem_id_t system)
    {
        systems.insert(system);
        return WALK_CONTINUE;
    });
    expect_eq(systems, {0, 1});

    std::multiset<std::tuple<std::string, offset_t, std::string, std::string>> values;
    const auto checkobj = [&](auto id)
    {
        const auto hobj = db->get_object(id);
        EXPECT_EQ(id, hobj.id());
        hobj.walk_versions([&](const HVersion& hver)
        {
            EXPECT_EQ(id, hver.id());
            hver.walk_systems([&](offset_t offset, HSystem_id_t sysid)
            {
                hver.walk_system_attributes(sysid, [&](const const_string_ref& key, const const_string_ref& val)
                {
                    values.insert(std::make_tuple(str(id), offset, make_string(key), make_string(val)));
                    return WALK_CONTINUE;
                });
                return WALK_CONTINUE;
            });
            return WALK_CONTINUE;
        });
    };
    checkobj(0xAAAAAAAA);
    checkobj(0xBBBBBBBB);
    checkobj(0xCCCCCCCC);
    checkobj(0xDDDDDDDD);
    expect_eq(values, {
        std::make_tuple("00000000AAAAAAAA", 1, "equipment", "eq2"),
        std::make_tuple("00000000AAAAAAAA", 1, "os", "os2"),
        std::make_tuple("00000000AAAAAAAA", 2, "equipment", "eq1"),
        std::make_tuple("00000000AAAAAAAA", 2, "os", "os1"),
        std::make_tuple("00000000BBBBBBBB", 0, "equipment", "eq1"),
        std::make_tuple("00000000BBBBBBBB", 0, "os", "os1"),
        std::make_tuple("00000000CCCCCCCC", 0, "equipment", "eq1"),
        std::make_tuple("00000000CCCCCCCC", 0, "os", "os1"),
        std::make_tuple("00000000CCCCCCCC", 1, "equipment", "eq2"),
        std::make_tuple("00000000CCCCCCCC", 1, "os", "os2"),
        std::make_tuple("00000000DDDDDDDD", 0, "equipment", "eq1"),
        std::make_tuple("00000000DDDDDDDD", 0, "os", "os1"),
        std::make_tuple("00000000DDDDDDDD", 1, "equipment", "eq2"),
        std::make_tuple("00000000DDDDDDDD", 1, "os", "os2"),
    });
}

TEST_F(TestYaToolDatabaseModel, memoryModel_MatchingSystems) {
    MatchingSystems_Impl(create_memorySignatureDB());
}

TEST_F(TestYaToolDatabaseModel, FBModel_MatchingSystems) {
    MatchingSystems_Impl(create_FBSignatureDB());
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

    virtual Signature get(HSignature_id_t) const
    {
        return sig;
    }

private:
    Signature sig;
};

struct Ctx
{
    std::vector<ModelAndVisitor> models;
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
    db->walk_objects_with_signature(sigH, [&](const HObject& href)
    {
        values.insert(str(href));
        return WALK_CONTINUE;
    });
    EXPECT_EQ(values.size(), db->num_objects_with_signature(sigH));
    expect_eq(values, {"data_00000000CCCCCCCC", "data_00000000DDDDDDDD"});

    const auto sigH2 = create_signature(ctx, 0x11111111);
    db->walk_objects_with_signature(sigH2, [&](const HObject& href)
    {
        values.insert(str(href));
        return WALK_CONTINUE;
    });
    EXPECT_EQ(values.size(), db->num_objects_with_signature(sigH2));
    expect_eq(values, {"data_00000000BBBBBBBB"});

    const auto sigH3 = create_signature(ctx, 0x33333333);
    db->walk_objects_with_signature(sigH3, [&](const HObject& href)
    {
        values.insert(str(href));
        return WALK_CONTINUE;
    });
    EXPECT_EQ(values.size(), db->num_objects_with_signature(sigH3));
    expect_eq(values, {"data_00000000CCCCCCCC"});

    const auto sigH4 = create_signature(ctx, 0x55555555);
    db->walk_objects_with_signature(sigH4, [&](const HObject& href)
    {
        values.insert(str(href));
        return WALK_CONTINUE;
    });
    EXPECT_EQ(values.size(), db->num_objects_with_signature(sigH4));
    expect_eq(values, {});

    const auto sigH5 = create_signature(ctx, 0xBADBADBA);
    db->walk_objects_with_signature(sigH5, [&](const HObject& href)
    {
        values.insert(str(href));
        return WALK_CONTINUE;
    });
    EXPECT_EQ(values.size(), db->num_objects_with_signature(sigH5));
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
        YaToolObjectId  id;
        std::vector<std::shared_ptr<Version>> versions;

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
    visitor.visit_start_object_version();
    if(size)
        visitor.visit_size(size);
    visitor.visit_start_signatures();
    for(const auto& sig : sigs)
        visitor.visit_signature(sig.method, sig.algo, make_string_ref(sig));
    visitor.visit_end_signatures();
    visitor.visit_end_object_version();
}

Object::Object(YaToolObjectId id)
    : id(id)
{
}

static std::shared_ptr<Object> create_object(YaToolObjectId id)
{
    return std::make_shared<Object>(id);
}

void Object::putVersion(const std::shared_ptr<Version>& version)
{
    versions.push_back(version);
}

void Object::accept(IModelVisitor& visitor)
{
    visitor.visit_start_reference_object(OBJECT_TYPE_DATA);
    visitor.visit_id(id);
    for(const auto& version : versions)
        version->accept(visitor);
    visitor.visit_end_reference_object();
}

static HObject create_href(Ctx& ctx, Object& object)
{
    ctx.models.push_back(MakeModel());
    auto& db = ctx.models.back();
    db.visitor->visit_start();
    object.accept(*db.visitor);
    db.visitor->visit_end();
    return db.model->get_object(object.id);
}

void walkMatchingVersions_Impl(std::shared_ptr<IModel> db)
{
    const auto ov1 = create_version(0xAAAAAAAA, 0x11111111, 0x20);
    const auto ov2 = create_version(0xAAAA0000, 0x11110001, 0x8);

    const auto ro = create_object(0xAAAA0000);
    ro->putVersion(ov1);
    ro->putVersion(ov2);

    Ctx ctx;
    const auto roH = create_href(ctx, *ro);
    EXPECT_TRUE(roH.is_valid());

    std::multiset<std::pair<std::string, std::string>> values;
    db->walk_matching_versions(roH, 0x10, [&](const HVersion& v1, const HVersion& v2)
    {
        values.insert(std::make_pair(str(v1), str(v2)));
        return WALK_CONTINUE;
    });
    expect_eq(values, {{"data_00000000BBBBBBBB", "data_00000000AAAA0000"}});

    const auto ov3 = create_version(0xAAAA0000, 0x11111111, 0x30);
    ro->putVersion(ov3);
    const auto roH2 = create_href(ctx, *ro);
    EXPECT_TRUE(roH2.is_valid());

    db->walk_matching_versions(roH2, 0x10, [&](const HVersion& v1, const HVersion& v2)
    {
        values.insert(std::make_pair(str(v1), str(v2)));
        return WALK_CONTINUE;
    });
    expect_eq(values, {{"data_00000000BBBBBBBB", "data_00000000AAAA0000"}});

    const auto ov4 = create_version(0xAAAA0000, 0x22222222, 0x20);
    ro->putVersion(ov4);
    const auto roH3 = create_href(ctx, *ro);
    EXPECT_TRUE(roH3.is_valid());

    db->walk_matching_versions(roH3, 0x10, [&](const HVersion& v1, const HVersion& v2)
    {
        values.insert(std::make_pair(str(v1), str(v2)));
        return WALK_CONTINUE;
    });
    expect_eq(values, {
        {"data_00000000BBBBBBBB", "data_00000000AAAA0000"},
        {"data_00000000CCCCCCCC", "data_00000000AAAA0000"},
        {"data_00000000DDDDDDDD", "data_00000000AAAA0000"},
    });

    db->walk_matching_versions(roH3, 0x40, [&](const HVersion& v1, const HVersion& v2)
    {
        values.insert(std::make_pair(str(v1), str(v2)));
        return WALK_CONTINUE;
    });
    expect_eq(values, {{"data_00000000BBBBBBBB", "data_00000000AAAA0000"}});
}

TEST_F(TestYaToolDatabaseModel, memoryModel_walkMatchingVersions) {
    walkMatchingVersions_Impl(create_memorySignatureDB());
}

TEST_F(TestYaToolDatabaseModel, FBModel_walkMatchingVersions) {
    walkMatchingVersions_Impl(create_FBSignatureDB());
}

void walkNoSignatureCollision_Impl(std::shared_ptr<IModel>db)
{
    std::multiset<std::pair<std::string, std::string>> values;
    db->walk_versions_without_collision([&](const HSignature& sig, const HVersion& ov)
    {
        values.insert(std::make_pair(str(sig), str(ov)));
        return WALK_CONTINUE;
    });
    expect_eq(values, {
        {"11111111", "data_00000000BBBBBBBB"},
        {"33333333", "data_00000000CCCCCCCC"},
        {"44444444", "data_00000000DDDDDDDD"},
        {"BADBAD00", "code_00000000AAAAAAAA"},
        {"BADBADBA", "code_00000000AAAAAAAA"},
    });

    /*
    int count = 0;
    db->walkNoSignatureCollisionReferencedObjects([&](const HSignature& sig, const HVersion& ov){
        EXPECT_TRUE(sig.toString() == "0x11111111" || sig.toString() == "0xBADBADBA");
        count ++;
        return WALK_CONTINUE;
    });
    EXPECT_EQ(2, count);
    */
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
    optional<HObject> object;
    const auto sig = create_signature(ctx, value);
    size_t count = 0;
    db.walk_objects_with_signature(sig, [&](const HObject& obj)
    {
        ++count;
        object = obj;
        return efirst == FirstOnly ? WALK_STOP : WALK_CONTINUE;
    });
    EXPECT_EQ(1u, count);
    EXPECT_EQ(count, db.num_objects_with_signature(sig));
    EXPECT_TRUE(!!object);
    return *object;
}

void walkObjectVersions_Impl(std::shared_ptr<IModel>db)
{
    Ctx ctx;
    const auto objH = get_object_for_signature(ctx, *db, 0x33333333, Any);
    EXPECT_TRUE(objH.is_valid());

    std::multiset<std::string> values;
    objH.walk_versions([&](const HVersion& ov)
    {
        values.insert(str(ov));
        return WALK_CONTINUE;
    });
    expect_eq(values, {
        {"data_00000000CCCCCCCC"},
        {"data_00000000CCCCCCCC"},
    });

    const auto objH2 = get_object_for_signature(ctx, *db, 0xBADBADBA, Any);
    EXPECT_TRUE(objH2.is_valid());
    EXPECT_EQ(objH2.id(), 0xAAAAAAAA);
    EXPECT_EQ(objH2.type(), OBJECT_TYPE_CODE);
    objH2.walk_versions([&](const HVersion& ov)
    {
        values.insert(str(ov));
        return WALK_CONTINUE;
    });
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
    const auto object = get_object_for_signature(ctx, db, value, FirstOnly);
    optional<HVersion> hver;
    object.walk_versions([&](const HVersion& h)
    {
        EXPECT_TRUE(!hver);
        hver = h;
        return WALK_CONTINUE;
    });
    EXPECT_TRUE(!!hver);
    return *hver;
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
        EXPECT_EQ(id, db->get_object(id).id());
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
    EXPECT_EQ(OBJECT_TYPE_CODE, db->get_object(0xAAAAAAAA).type());
    EXPECT_EQ(OBJECT_TYPE_DATA, db->get_object(0xBBBBBBBB).type());
    EXPECT_EQ(OBJECT_TYPE_DATA, db->get_object(0xCCCCCCCC).type());
    EXPECT_EQ(OBJECT_TYPE_DATA, db->get_object(0xDDDDDDDD).type());
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
    {
        EXPECT_EQ(id, db->get_object(id).id());
    }
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
    const auto ro = create_object(0xAAAA0000);
    ro->putVersion(ov1);
    const auto roH1 = create_href(ctx, *ro);

    EXPECT_FALSE(roH1.match(foundObjectH));
    EXPECT_FALSE(foundObjectH.match(roH1));

    //Add an OV with same signature but bad size
    const auto ov2 = create_version(0xAAAA0000, 0x11111111, 0x10);
    ro->putVersion(ov2);
    const auto roH2 = create_href(ctx, *ro);

    EXPECT_FALSE(roH2.match(foundObjectH));
    EXPECT_FALSE(foundObjectH.match(roH2));


    //Add an OV with different signature but same size
    const auto ov3 = create_version(0xAAAA0000, 0x11110002, 0x20);
    ro->putVersion(ov3);
    const auto roH3 = create_href(ctx, *ro);

    EXPECT_FALSE(roH3.match(foundObjectH));
    EXPECT_FALSE(foundObjectH.match(roH3));

    //Add an OV with same signature and same size
    const auto ov4 = create_version(0xAAAA0000, 0x11111111, 0x20);
    ro->putVersion(ov4);
    const auto roH4 = create_href(ctx, *ro);

    EXPECT_TRUE(roH4.match(foundObjectH));
    EXPECT_TRUE(foundObjectH.match(roH4));



    /*
     * Same thing but with 2 signatures in the found object
     */
    HObject foundObjectH2 = db->get_object(0xAAAAAAAA);
    EXPECT_EQ(foundObjectH2.id(), 0xAAAAAAAA);
    EXPECT_EQ(foundObjectH2.type(), OBJECT_TYPE_CODE);

    //create a local dummy object
    const auto ov2_1 = create_version(0xBBBB0000, 0x22222222, 0x8);
    const auto ro2 = create_object(0xBBBB0000);
    ro2->putVersion(ov2_1);
    const auto roH2_1 = create_href(ctx, *ro2);

    EXPECT_FALSE(roH2_1.match(foundObjectH2));
    EXPECT_FALSE(foundObjectH2.match(roH2_1));

    //Add an OV with same signature but bad size
    const auto ov2_2 = create_version(0xBBBB0000, 0xBADBADBA, 0x100);
    ro2->putVersion(ov2_2);
    const auto roH2_2 = create_href(ctx, *ro2);

    EXPECT_FALSE(roH2_2.match(foundObjectH2));
    EXPECT_FALSE(foundObjectH2.match(roH2_2));

    //Add an OV with different signature but same size
    const auto ov2_3 = create_version(0xBBBB0000, 0x33333333, 0x10);
    ro2->putVersion(ov2_3);
    const auto roH2_3 = create_href(ctx, *ro2);

    EXPECT_FALSE(roH2_3.match(foundObjectH2));
    EXPECT_FALSE(foundObjectH2.match(roH2_3));

    //Add an OV with same signature and same size, but 1 missing signature
    const auto ov2_4 = create_version(0xBBBB0000, 0xBADBADBA, 0x10);
    ro2->putVersion(ov2_4);
    const auto roH2_4 = create_href(ctx, *ro2);

    EXPECT_FALSE(roH2_4.match(foundObjectH2));
    EXPECT_FALSE(foundObjectH2.match(roH2_4));

    //Add an OV with same signatureS and same size
    const auto ov2_5 = create_version(0xBBBB0000, 0xBADBADBA, 0x10);
    ov2_5->add_signature(MakeSignature(SIGNATURE_ALGORITHM_CRC32, SIGNATURE_FIRSTBYTE, make_string_ref("BADBAD00")));
    ro2->putVersion(ov2_5);
    const auto roH2_5 = create_href(ctx, *ro2);

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
    db->walk_objects([&](YaToolObjectId, const HObject& href)
    {
        href.walk_xrefs_from([&](offset_t offset, operand_t operand, const HObject& xref)
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
    db->walk_objects([&](YaToolObjectId, const HObject& href)
    {
        href.walk_xrefs_to([&](const HObject& xref)
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
    db->walk_objects([&](YaToolObjectId, const HObject& href)
    {
        href.walk_versions([&](const HVersion& hver)
        {
            hver.walk_xrefs_from([&](offset_t offset, operand_t operand, const HObject& xref)
            {
                values.insert(std::make_tuple(str(href), str(hver), offset, operand, str(xref)));
                return WALK_CONTINUE;
            });
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
    db->walk_objects([&](YaToolObjectId, const HObject& href)
    {
        href.walk_versions([&](const HVersion& hver)
        {
            hver.walk_xrefs_to([&](const HObject& xref)
            {
                values.insert(std::make_tuple(str(href), str(hver), str(xref)));
                return WALK_CONTINUE;
            });
            return WALK_CONTINUE;
        });
        return WALK_CONTINUE;
    });
    expect_eq(values, {
        std::make_tuple("data_00000000BBBBBBBB", "data_00000000BBBBBBBB", "code_00000000AAAAAAAA"),
        std::make_tuple("data_00000000BBBBBBBB", "data_00000000BBBBBBBB", "data_00000000DDDDDDDD"),
        std::make_tuple("data_00000000CCCCCCCC", "data_00000000CCCCCCCC", "code_00000000AAAAAAAA"),
        std::make_tuple("data_00000000CCCCCCCC", "data_00000000CCCCCCCC", "code_00000000AAAAAAAA"),
        std::make_tuple("data_00000000CCCCCCCC", "data_00000000CCCCCCCC", "data_00000000DDDDDDDD"),
        std::make_tuple("data_00000000CCCCCCCC", "data_00000000CCCCCCCC", "data_00000000DDDDDDDD"),
        std::make_tuple("data_00000000DDDDDDDD", "data_00000000DDDDDDDD", "code_00000000AAAAAAAA"),
        std::make_tuple("data_00000000DDDDDDDD", "data_00000000DDDDDDDD", "code_00000000AAAAAAAA"),
        std::make_tuple("data_00000000DDDDDDDD", "data_00000000DDDDDDDD", "data_00000000BBBBBBBB"),
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
    visitor.visit_start_reference_object(OBJECT_TYPE_CODE);
    visitor.visit_id(0xAAAAAAAA);
    visitor.visit_end_reference_object();
    visitor.visit_end();
}

static void testObjectWithoutVersion(IModel& db)
{
    std::multiset<std::pair<std::string, std::string>> values;
    std::vector<std::pair<YaToolObjectId, HObject>> ids;
    db.walk_objects([&](const YaToolObjectId& id, const HObject& href)
    {
        values.insert(std::make_pair(str(id), str(href)));
        ids.push_back({id, href});
        return WALK_CONTINUE;
    });
    EXPECT_EQ(values.size(), db.num_objects());
    expect_eq(values, {{"00000000AAAAAAAA", "code_00000000AAAAAAAA"}});

    for(const auto& p : ids)
        EXPECT_EQ(p.first, db.get_object(p.first).id());
}

TEST_F(TestYaToolDatabaseModel, memoryModel_objectWithoutVersion)
{
    const auto db = MakeModel();
    create_model_objects_without_versions(*db.visitor);
    testObjectWithoutVersion(*db.model);
}

TEST_F(TestYaToolDatabaseModel, FBModel_objectWithoutVersion)
{
    const auto model = create_fbmodel_with([&](std::shared_ptr<IModelVisitor> visitor)
    {
        create_model_objects_without_versions(*visitor);
    });
    testObjectWithoutVersion(*model);
}