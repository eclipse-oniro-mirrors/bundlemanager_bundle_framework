/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#define private public
#include "rdb_data_manager.h"
#undef private
#include "mock_app_provision_info.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

void MockGetRdbStore(std::shared_ptr<OHOS::NativeRdb::RdbStore> mockRdbStore);

namespace OHOS {
namespace {
const std::string DB_PATH = "/data/test/";
const std::string DB_NAME = "rdbTestDb.db";
const std::string TABLE_NAME = "rdbTestTable";
const std::string KEY_ONE = "KEY_ONE";
const std::string VALUE_ONE = "VALUE_ONE";
const std::string BMS_BACK_UP_RDB_NAME = "bms-backup.db";
const std::string BMS_KEY = "KEY";
const std::string BMS_VALUE = "VALUE";
} // namespace

class BmsBundleRdbDataManagerTest : public testing::Test {
public:
    BmsBundleRdbDataManagerTest();
    ~BmsBundleRdbDataManagerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<RdbDataManager> OpenDbAndTable();
};

BmsBundleRdbDataManagerTest::BmsBundleRdbDataManagerTest()
{}

BmsBundleRdbDataManagerTest::~BmsBundleRdbDataManagerTest()
{}

void BmsBundleRdbDataManagerTest::SetUpTestCase()
{}

void BmsBundleRdbDataManagerTest::TearDownTestCase()
{}

void BmsBundleRdbDataManagerTest::SetUp()
{}

void BmsBundleRdbDataManagerTest::TearDown()
{}

std::shared_ptr<RdbDataManager> BmsBundleRdbDataManagerTest::OpenDbAndTable()
{
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbPath = DB_PATH;
    bmsRdbConfig.dbName = DB_NAME;
    bmsRdbConfig.tableName = TABLE_NAME;
    auto rdbDataManager = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager->CreateTable();
    return rdbDataManager;
}

/**
 * @tc.number: RdbDataManager_0100
 * @tc.name: Test InsertData
 * @tc.desc: 1.InsertData
 */
HWTEST_F(BmsBundleRdbDataManagerTest, RdbDataManager_0100, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    rdbDataManager->ClearCache();
    MockGetRdbStore(nullptr);
    rdbDataManager->rdbStore_ = nullptr;
    auto ret = rdbDataManager->InsertData(KEY_ONE, VALUE_ONE);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: RdbDataManager_0200
 * @tc.name: Test InsertData
 * @tc.desc: 1.InsertData
 */
HWTEST_F(BmsBundleRdbDataManagerTest, RdbDataManager_0200, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    MockGetRdbStore(nullptr);
    rdbDataManager->rdbStore_ = nullptr;
    rdbDataManager->BackupRdb();
    NativeRdb::ValuesBucket valuesBucket;
    auto ret = rdbDataManager->InsertData(valuesBucket);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: RdbDataManager_0300
 * @tc.name: Test BatchInsert
 * @tc.desc: 1.BatchInsert
 */
HWTEST_F(BmsBundleRdbDataManagerTest, RdbDataManager_0300, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    MockGetRdbStore(nullptr);
    rdbDataManager->rdbStore_ = nullptr;
    int64_t outInsertNum = 0;
    std::vector<NativeRdb::ValuesBucket> valuesBuckets;
    bool ret = rdbDataManager->BatchInsert(outInsertNum, valuesBuckets);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: RdbDataManager_0400
 * @tc.name: Test UpdateData
 * @tc.desc: 1.UpdateData
 */
HWTEST_F(BmsBundleRdbDataManagerTest, RdbDataManager_0400, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    MockGetRdbStore(nullptr);
    rdbDataManager->rdbStore_ = nullptr;
    bool ret = rdbDataManager->UpdateData(KEY_ONE, VALUE_ONE);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: RdbDataManager_0500
 * @tc.name: Test UpdateData
 * @tc.desc: 1.UpdateData
 */
HWTEST_F(BmsBundleRdbDataManagerTest, RdbDataManager_0500, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    MockGetRdbStore(nullptr);
    rdbDataManager->rdbStore_ = nullptr;
    NativeRdb::ValuesBucket valuesBucket;
    NativeRdb::AbsRdbPredicates absRdbPredicates(KEY_ONE);
    bool ret = rdbDataManager->UpdateData(valuesBucket, absRdbPredicates);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: RdbDataManager_0600
 * @tc.name: Test UpdateOrInsertData
 * @tc.desc: 1.UpdateOrInsertData
 */
HWTEST_F(BmsBundleRdbDataManagerTest, RdbDataManager_0600, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    rdbDataManager->rdbStore_ = nullptr;
    MockGetRdbStore(nullptr);
    NativeRdb::ValuesBucket valuesBucket;
    NativeRdb::AbsRdbPredicates absRdbPredicates(KEY_ONE);
    bool ret = rdbDataManager->UpdateOrInsertData(valuesBucket, absRdbPredicates);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: RdbDataManager_0700
 * @tc.name: Test DeleteData
 * @tc.desc: 1.DeleteData
 */
HWTEST_F(BmsBundleRdbDataManagerTest, RdbDataManager_0700, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    rdbDataManager->rdbStore_ = nullptr;
    MockGetRdbStore(nullptr);
    bool ret = rdbDataManager->DeleteData(KEY_ONE);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: RdbDataManager_0800
 * @tc.name: Test QueryData
 * @tc.desc: 1.QueryData
 */
HWTEST_F(BmsBundleRdbDataManagerTest, RdbDataManager_0800, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    rdbDataManager->rdbStore_ = nullptr;
    MockGetRdbStore(nullptr);
    std::string value;
    bool ret = rdbDataManager->QueryData(KEY_ONE, value);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: RdbDataManager_0900
 * @tc.name: Test QueryData
 * @tc.desc: 1.QueryData
 */
HWTEST_F(BmsBundleRdbDataManagerTest, RdbDataManager_0900, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    rdbDataManager->rdbStore_ = nullptr;
    MockGetRdbStore(nullptr);
    NativeRdb::AbsRdbPredicates absRdbPredicates(KEY_ONE);
    auto ret = rdbDataManager->QueryData(absRdbPredicates);
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.number: RdbDataManager_1000
 * @tc.name: Test QueryAllData
 * @tc.desc: 1.QueryAllData
 */
HWTEST_F(BmsBundleRdbDataManagerTest, RdbDataManager_1000, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    rdbDataManager->rdbStore_ = nullptr;
    MockGetRdbStore(nullptr);
    std::map<std::string, std::string> datas;
    bool ret = rdbDataManager->QueryAllData(datas);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: RdbDataManager_1100
 * @tc.name: Test QueryByStep
 * @tc.desc: 1.QueryByStep
 */
HWTEST_F(BmsBundleRdbDataManagerTest, RdbDataManager_1100, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    rdbDataManager->rdbStore_ = nullptr;
    MockGetRdbStore(nullptr);
    NativeRdb::AbsRdbPredicates absRdbPredicates(KEY_ONE);
    auto ret = rdbDataManager->QueryByStep(absRdbPredicates);
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.number: RdbDataManager_1200
 * @tc.name: Test GetRdbStore
 * @tc.desc: 1.GetRdbStore
 */
HWTEST_F(BmsBundleRdbDataManagerTest, RdbDataManager_1200, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    auto store = std::make_shared<MockAppProvisionInfo>();
    rdbDataManager->rdbStore_ = store;
    auto ret = rdbDataManager->GetRdbStore();
    ASSERT_EQ(ret, store);
}

/**
 * @tc.number: RdbDataManager_1300
 * @tc.name: Test GetRdbStore
 * @tc.desc: 1.GetRdbStore
 */
HWTEST_F(BmsBundleRdbDataManagerTest, RdbDataManager_1300, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    rdbDataManager->rdbStore_ = nullptr;
    rdbDataManager->bmsRdbConfig_.dbName = "";
    auto ret = rdbDataManager->GetRdbStore();
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.number: RdbDataManager_1400
 * @tc.name: Test GetRdbStore
 * @tc.desc: 1.GetRdbStore
 */
HWTEST_F(BmsBundleRdbDataManagerTest, RdbDataManager_1400, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    rdbDataManager->rdbStore_ = nullptr;
    rdbDataManager->bmsRdbConfig_.dbName = BMS_BACK_UP_RDB_NAME;
    auto ret = rdbDataManager->GetRdbStore();
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.number: RdbDataManager_1500
 * @tc.name: Test GetRdbStore
 * @tc.desc: 1.GetRdbStore
 */
HWTEST_F(BmsBundleRdbDataManagerTest, RdbDataManager_1500, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    rdbDataManager->rdbStore_ = nullptr;
    auto store = std::make_shared<MockAppProvisionInfo>();
    MockGetRdbStore(store);
    rdbDataManager->bmsRdbConfig_.dbName = BMS_BACK_UP_RDB_NAME;
    auto ret = rdbDataManager->GetRdbStore();
    ASSERT_NE(ret, nullptr);
}

/**
 * @tc.number: RdbDataManager_1600
 * @tc.name: Test GetRdbStore
 * @tc.desc: 1.GetRdbStore
 */
HWTEST_F(BmsBundleRdbDataManagerTest, RdbDataManager_1600, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    rdbDataManager->rdbStore_ = nullptr;
    auto store = std::make_shared<MockAppProvisionInfo>();
    MockGetRdbStore(store);
    rdbDataManager->bmsRdbConfig_.dbName = BMS_BACK_UP_RDB_NAME;
    rdbDataManager->isInitial_ = false;
    auto ret = rdbDataManager->GetRdbStore();
    ASSERT_NE(ret, nullptr);
}

/**
 * @tc.number: RdbDataManager_1700
 * @tc.name: Test InsertData
 * @tc.desc: 1.InsertData
 */
HWTEST_F(BmsBundleRdbDataManagerTest, RdbDataManager_1700, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    rdbDataManager->ClearCache();
    auto store = std::make_shared<MockAppProvisionInfo>();
    MockGetRdbStore(store);
    auto ret = rdbDataManager->InsertData(KEY_ONE, VALUE_ONE);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.number: RdbDataManager_1800
 * @tc.name: Test InsertData
 * @tc.desc: 1.InsertData
 */
HWTEST_F(BmsBundleRdbDataManagerTest, RdbDataManager_1800, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    rdbDataManager->ClearCache();
    auto store = std::make_shared<MockAppProvisionInfo>();
    MockGetRdbStore(store);
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(BMS_KEY, KEY_ONE);
    valuesBucket.PutString(BMS_VALUE, VALUE_ONE);
    auto ret = rdbDataManager->InsertData(valuesBucket);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.number: RdbDataManager_1900
 * @tc.name: Test BatchInsert
 * @tc.desc: 1.BatchInsert
 */
HWTEST_F(BmsBundleRdbDataManagerTest, RdbDataManager_1900, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    auto store = std::make_shared<MockAppProvisionInfo>();
    MockGetRdbStore(store);
    int64_t outInsertNum = 0;
    std::vector<NativeRdb::ValuesBucket> valuesBuckets;
    bool ret = rdbDataManager->BatchInsert(outInsertNum, valuesBuckets);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.number: RdbDataManager_2000
 * @tc.name: Test UpdateData
 * @tc.desc: 1.UpdateData
 */
HWTEST_F(BmsBundleRdbDataManagerTest, RdbDataManager_2000, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    auto store = std::make_shared<MockAppProvisionInfo>();
    MockGetRdbStore(store);
    bool ret = rdbDataManager->UpdateData(KEY_ONE, VALUE_ONE);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.number: RdbDataManager_2100
 * @tc.name: Test UpdateData
 * @tc.desc: 1.UpdateData
 */
HWTEST_F(BmsBundleRdbDataManagerTest, RdbDataManager_2100, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    auto store = std::make_shared<MockAppProvisionInfo>();
    MockGetRdbStore(store);
    NativeRdb::ValuesBucket valuesBucket;
    NativeRdb::AbsRdbPredicates absRdbPredicates(KEY_ONE);
    bool ret = rdbDataManager->UpdateData(valuesBucket, absRdbPredicates);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: RdbDataManager_2200
 * @tc.name: Test UpdateData
 * @tc.desc: 1.UpdateData
 */
HWTEST_F(BmsBundleRdbDataManagerTest, RdbDataManager_2200, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    auto store = std::make_shared<MockAppProvisionInfo>();
    MockGetRdbStore(store);
    NativeRdb::ValuesBucket valuesBucket;
    NativeRdb::AbsRdbPredicates absRdbPredicates(TABLE_NAME);
    bool ret = rdbDataManager->UpdateData(valuesBucket, absRdbPredicates);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.number: RdbDataManager_2300
 * @tc.name: Test UpdateOrInsertData
 * @tc.desc: 1.UpdateOrInsertData
 */
HWTEST_F(BmsBundleRdbDataManagerTest, RdbDataManager_2300, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    auto store = std::make_shared<MockAppProvisionInfo>();
    MockGetRdbStore(store);
    NativeRdb::ValuesBucket valuesBucket;
    NativeRdb::AbsRdbPredicates absRdbPredicates(KEY_ONE);
    bool ret = rdbDataManager->UpdateOrInsertData(valuesBucket, absRdbPredicates);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: RdbDataManager_2400
 * @tc.name: Test UpdateOrInsertData
 * @tc.desc: 1.UpdateOrInsertData
 */
HWTEST_F(BmsBundleRdbDataManagerTest, RdbDataManager_2400, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    auto store = std::make_shared<MockAppProvisionInfo>();
    MockGetRdbStore(store);
    NativeRdb::ValuesBucket valuesBucket;
    NativeRdb::AbsRdbPredicates absRdbPredicates(KEY_ONE);
    bool ret = rdbDataManager->UpdateOrInsertData(valuesBucket, absRdbPredicates);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.number: BmsRdbOpenCallback_0100
 * @tc.name: Test OnUpgrade
 * @tc.desc: 1.OnUpgrade
 */
HWTEST_F(BmsBundleRdbDataManagerTest, BmsRdbOpenCallback_0100, Function | SmallTest | Level1)
{
    BmsRdbConfig bmsRdbConfig;
    BmsRdbOpenCallback callback(bmsRdbConfig);
    MockAppProvisionInfo Store;
    int currentVersion = 1;
    int targetVersion = 2;
    auto ret = callback.OnUpgrade(Store, currentVersion, targetVersion);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.number: BmsRdbOpenCallback_0200
 * @tc.name: Test OnDowngrade
 * @tc.desc: 1.OnDowngrade
 */
HWTEST_F(BmsBundleRdbDataManagerTest, BmsRdbOpenCallback_0200, Function | SmallTest | Level1)
{
    BmsRdbConfig bmsRdbConfig;
    BmsRdbOpenCallback callback(bmsRdbConfig);
    MockAppProvisionInfo Store;
    int currentVersion = 1;
    int targetVersion = 2;
    auto ret = callback.OnDowngrade(Store, currentVersion, targetVersion);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.number: BmsRdbOpenCallback_0300
 * @tc.name: Test onCorruption
 * @tc.desc: 1.onCorruption
 */
HWTEST_F(BmsBundleRdbDataManagerTest, BmsRdbOpenCallback_0300, Function | SmallTest | Level1)
{
    BmsRdbConfig bmsRdbConfig;
    BmsRdbOpenCallback callback(bmsRdbConfig);
    auto ret = callback.onCorruption(TABLE_NAME);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.number: BmsRdbOpenCallback_0400
 * @tc.name: Test OnCreate
 * @tc.desc: 1.OnCreate
 */
HWTEST_F(BmsBundleRdbDataManagerTest, BmsRdbOpenCallback_0400, Function | SmallTest | Level1)
{
    BmsRdbConfig bmsRdbConfig;
    BmsRdbOpenCallback callback(bmsRdbConfig);
    MockAppProvisionInfo Store;
    auto ret = callback.OnCreate(Store);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.number: BmsRdbOpenCallback_0500
 * @tc.name: Test OnCreate
 * @tc.desc: 1.OnCreate
 */
HWTEST_F(BmsBundleRdbDataManagerTest, BmsRdbOpenCallback_0500, Function | SmallTest | Level1)
{
    BmsRdbConfig bmsRdbConfig;
    BmsRdbOpenCallback callback(bmsRdbConfig);
    MockAppProvisionInfo Store;
    auto ret = callback.OnOpen(Store);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}
} // OHOS