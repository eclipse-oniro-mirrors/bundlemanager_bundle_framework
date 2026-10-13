/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#define private public

#include <atomic>
#include <fcntl.h>
#include <fstream>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include <gtest/gtest.h>

#include "bundle_constants.h"
#include "bundle_data_storage_rdb.h"
#include "bundle_mgr_service.h"
#include "bundle_service_constants.h"
#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
#include "default_app_rdb.h"
#endif
#include "first_install_data_mgr_storage_rdb.h"
#include "preinstall_data_storage_rdb.h"
#include "rdb_data_manager.h"
#include "rdb_recover_manager.h"
#include "scope_guard.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using namespace OHOS;

namespace {
const std::string DB_PATH = "/data/test/";
const std::string DB_NAME = "rdbTestDb.db";
const std::string TABLE_NAME = "rdbTestTable";
const std::string KEY_ONE = "KEY_ONE";
const std::string VALUE_ONE = "VALUE_ONE";
const std::string KEY_TWO = "KEY_TWO";
const std::string VALUE_TWO = "VALUE_TWO";
const std::string KEY_THREE = "KEY_THREE";
const std::string VALUE_THREE = "VALUE_THREE";
const std::string TEST_BUNDLE_NAME = "com.test.rdbone";
const std::string TEST_NAME = "NameOne";
const uint32_t TEST_VERSION = 1;
const std::string TEST_BUNDLE_NAME_TWO = "com.test.rdbtwo";
const std::string TEST_NAME_TWO = "NameTwo";
const uint32_t TEST_VERSION_TWO = 2;
const std::string UPSERT_RACE_TABLE = "rdbUpsertRaceTable";
const std::string UPSERT_RACE_COLUMN_NAME = "NAME";
const std::string UPSERT_RACE_COLUMN_VALUE = "VALUE";
const std::string UPSERT_RACE_KEY = "raceKeyOne";
const std::string UPSERT_RACE_VALUE = "raceValueOne";
const std::string MARK_DB_PATH = "/data/test";
// salvage recovery test scenario constants
constexpr int32_t CORRUPT_TEST_ROW_COUNT = 150;
constexpr size_t CORRUPT_TEST_VALUE_LEN = 90;
// bounded polling: 300 tries of 10ms = 3s budget, above the 2s busy timeout
constexpr int32_t POLL_MAX_TRIES = 300;
constexpr int32_t POLL_INTERVAL_MS = 10;
// bounded retry loop for the downgrade poll (any counter start < 3 converges)
constexpr int32_t DOWNGRADE_POLL_MAX_TRIES = 10;
constexpr int32_t SNAPSHOT_EXPLICIT_ID = 100;
const std::string SNAPSHOT_ID_COLUMN = "ID";
const std::string SNAPSHOT_KEY_ONE = "snapshotKeyOne";
const std::string SNAPSHOT_VALUE_ONE = "snapshotValueOne";
const std::string SNAPSHOT_KEY_TWO = "snapshotKeyTwo";
const std::string SNAPSHOT_VALUE_TWO = "snapshotValueTwo";
const std::string SNAPSHOT_RACE_NAME = "snapshotRaceName";
const std::string SNAPSHOT_RACE_VALUE = "snapshotRaceValue";
const std::string SNAPSHOT_RACE_NAME_NEXT = "snapshotRaceNameNext";
const std::string SNAPSHOT_RACE_VALUE_NEXT = "snapshotRaceValueNext";
#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
const int32_t TEST_USERID = 500;
const std::string TEST_DEFAULT_APP_TYPE = "IMAGE";
#endif

class BmsRdbDataManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<RdbDataManager> OpenDbAndTable();
    void CloseDb();
    std::shared_ptr<RdbDataManager> OpenUpsertRaceTable();
private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsRdbDataManagerTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

void BmsRdbDataManagerTest::SetUpTestCase()
{}

void BmsRdbDataManagerTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsRdbDataManagerTest::SetUp()
{}

void BmsRdbDataManagerTest::TearDown()
{}

std::shared_ptr<RdbDataManager> BmsRdbDataManagerTest::OpenDbAndTable()
{
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbPath = DB_PATH;
    bmsRdbConfig.dbName = DB_NAME;
    bmsRdbConfig.tableName = TABLE_NAME;
    auto rdbDataManager = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager->CreateTable();
    return rdbDataManager;
}

void BmsRdbDataManagerTest::CloseDb()
{
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(DB_PATH + DB_NAME);
}

std::shared_ptr<RdbDataManager> BmsRdbDataManagerTest::OpenUpsertRaceTable()
{
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbPath = DB_PATH;
    bmsRdbConfig.dbName = DB_NAME;
    bmsRdbConfig.tableName = UPSERT_RACE_TABLE;
    bmsRdbConfig.createTableSql = "CREATE TABLE IF NOT EXISTS " + UPSERT_RACE_TABLE
        + "(ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, VALUE TEXT NOT NULL);";
    auto rdbDataManager = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager->CreateTable();
    return rdbDataManager;
}

/**
 * @tc.number: RdbDataManager_0100
 * @tc.name: insert query delete
 * @tc.desc: 1.insert data
 *           2.query data
 *           3.delete data
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_0100, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    EXPECT_TRUE(rdbDataManager != nullptr);

    bool ret = rdbDataManager->InsertData(KEY_ONE, VALUE_ONE);
    EXPECT_TRUE(ret);

    std::string value;
    ret = rdbDataManager->QueryData(KEY_ONE, value);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(value == VALUE_ONE);

    ret = rdbDataManager->UpdateData(KEY_ONE, VALUE_TWO);
    EXPECT_TRUE(ret);

    ret = rdbDataManager->QueryData(KEY_ONE, value);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(value == VALUE_TWO);

    ret = rdbDataManager->DeleteData(KEY_ONE);
    EXPECT_TRUE(ret);

    ret = rdbDataManager->QueryData(KEY_ONE, value);
    EXPECT_FALSE(ret);
    CloseDb();
}

/**
 * @tc.number: RdbDataManager_0200
 * @tc.name: insert queryAll
 * @tc.desc: 1.insert data
 *           2.queryAll data
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_0200, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    EXPECT_TRUE(rdbDataManager != nullptr);

    bool ret = rdbDataManager->InsertData(KEY_ONE, VALUE_ONE);
    EXPECT_TRUE(ret);

    ret = rdbDataManager->InsertData(KEY_TWO, VALUE_TWO);
    EXPECT_TRUE(ret);

    ret = rdbDataManager->InsertData(KEY_THREE, VALUE_THREE);
    EXPECT_TRUE(ret);

    std::map<std::string, std::string> datas;
    ret = rdbDataManager->QueryAllData(datas);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(datas[KEY_ONE] == VALUE_ONE);
    EXPECT_TRUE(datas[KEY_TWO] == VALUE_TWO);
    EXPECT_TRUE(datas[KEY_THREE] == VALUE_THREE);
    CloseDb();
}

/**
 * @tc.number: BundleDataStorageRdb_0100
 * @tc.name: save and delete
 * @tc.desc: 1.SaveStorageBundleInfo
 *           2.DeleteStorageBundleInfo
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, BundleDataStorageRdb_0100, Function | SmallTest | Level1)
{
    std::unique_ptr<IBundleDataStorage> dataStorage = std::make_unique<BundleDataStorageRdb>();
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = TEST_BUNDLE_NAME;
    applicationInfo.label = TEST_NAME;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    bool ret = dataStorage->SaveStorageBundleInfo(innerBundleInfo);
    EXPECT_TRUE(ret);

    ret = dataStorage->DeleteStorageBundleInfo(innerBundleInfo);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BundleDataStorageRdb_0200
 * @tc.name: LoadAllData
 * @tc.desc: 1.LoadAllData
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, BundleDataStorageRdb_0200, Function | SmallTest | Level1)
{
    std::shared_ptr<IBundleDataStorage> dataStorage = std::make_shared<BundleDataStorageRdb>();
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = TEST_BUNDLE_NAME;
    applicationInfo.name = TEST_NAME;
    InnerBundleInfo innerBundleInfo1;
    innerBundleInfo1.SetBaseApplicationInfo(applicationInfo);
    bool ret = dataStorage->SaveStorageBundleInfo(innerBundleInfo1);
    EXPECT_TRUE(ret);

    applicationInfo.bundleName = TEST_BUNDLE_NAME_TWO;
    applicationInfo.name = TEST_NAME_TWO;
    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo2.SetBaseApplicationInfo(applicationInfo);
    ret = dataStorage->SaveStorageBundleInfo(innerBundleInfo2);
    EXPECT_TRUE(ret);

    std::map<std::string, InnerBundleInfo> infos;
    ret = dataStorage->LoadAllData(infos);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(infos.empty());
    EXPECT_TRUE(infos[TEST_BUNDLE_NAME].GetApplicationName() == TEST_NAME);
    EXPECT_TRUE(infos[TEST_BUNDLE_NAME_TWO].GetApplicationName() == TEST_NAME_TWO);
    dataStorage->DeleteStorageBundleInfo(innerBundleInfo1);
    dataStorage->DeleteStorageBundleInfo(innerBundleInfo2);
}

/**
 * @tc.number: BundleDataStorageRdb_0300
 * @tc.name: LoadAllData
 * @tc.desc: 1.LoadAllData
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, BundleDataStorageRdb_0300, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleDataStorageRdb> dataStorage = std::make_shared<BundleDataStorageRdb>();
    ASSERT_NE(dataStorage, nullptr);
    dataStorage->rdbDataManager_ = nullptr;

    std::map<std::string, std::string> datas;
    std::map<std::string, InnerBundleInfo> infos;
    dataStorage->TransformStrToInfo(datas, infos);

    dataStorage->UpdateDataBase(infos);

    bool ret = dataStorage->LoadAllData(infos);
    EXPECT_FALSE(ret);

    dataStorage = std::make_shared<BundleDataStorageRdb>();
    ASSERT_NE(dataStorage, nullptr);
    dataStorage->UpdateDataBase(infos);

    ret = dataStorage->LoadAllData(infos);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BundleDataStorageRdb_0400
 * @tc.name: ResetKvStore
 * @tc.desc: 1.ResetKvStore
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, BundleDataStorageRdb_0400, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleDataStorageRdb> dataStorage = std::make_shared<BundleDataStorageRdb>();
    ASSERT_NE(dataStorage, nullptr);
    InnerBundleInfo innerBundleInfo;
    bool ret = dataStorage->SaveStorageBundleInfo(innerBundleInfo);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: SaveStorageBundleInfo_0100
 * @tc.name: SaveStorageBundleInfo_0100
 * @tc.desc: 1.SaveStorageBundleInfo_0100
 * @tc.require: SaveStorageBundleInfo_0100
 */
HWTEST_F(BmsRdbDataManagerTest, SaveStorageBundleInfo_0100, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleDataStorageRdb> dataStorage = std::make_shared<BundleDataStorageRdb>();
    ASSERT_NE(dataStorage, nullptr);
    InnerBundleInfo innerBundleInfo;
    bool ret = dataStorage->SaveStorageBundleInfo(innerBundleInfo);
    EXPECT_TRUE(ret);

    ErrCode errCode = dataStorage->SaveStorageBundleInfoWithCode(innerBundleInfo);
    EXPECT_EQ(errCode, ERR_OK);

    innerBundleInfo.baseBundleInfo_->description = "\xC4\xE3\xBA\xCA";
    ret = dataStorage->SaveStorageBundleInfo(innerBundleInfo);
    EXPECT_FALSE(ret);

    errCode = dataStorage->SaveStorageBundleInfoWithCode(innerBundleInfo);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: BundleDataStorageRdb_0500
 * @tc.name: DeleteStorageBundleInfo
 * @tc.desc: 1.DeleteStorageBundleInfo
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, BundleDataStorageRdb_0500, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleDataStorageRdb> dataStorage = std::make_shared<BundleDataStorageRdb>();
    ASSERT_NE(dataStorage, nullptr);
    InnerBundleInfo innerBundleInfo;
    bool ret = dataStorage->DeleteStorageBundleInfo(innerBundleInfo);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BundleDataStorageRdb_0700
 * @tc.name: SaveStorageBundleInfo
 * @tc.desc: 1.SaveStorageBundleInfo
 */
HWTEST_F(BmsRdbDataManagerTest, BundleDataStorageRdb_0700, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleDataStorageRdb> dataStorage = std::make_shared<BundleDataStorageRdb>();
    ASSERT_NE(dataStorage, nullptr);
    dataStorage->rdbDataManager_ = nullptr;
    InnerBundleInfo innerBundleInfo;
    bool ret = dataStorage->SaveStorageBundleInfo(innerBundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BundleDataStorageRdb_0800
 * @tc.name: DeleteStorageBundleInfo
 * @tc.desc: 1.DeleteStorageBundleInfo
 */
HWTEST_F(BmsRdbDataManagerTest, BundleDataStorageRdb_0800, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleDataStorageRdb> dataStorage = std::make_shared<BundleDataStorageRdb>();
    ASSERT_NE(dataStorage, nullptr);
    dataStorage->rdbDataManager_ = nullptr;
    InnerBundleInfo innerBundleInfo;
    bool ret = dataStorage->DeleteStorageBundleInfo(innerBundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: PreInstallDataStorageRdb_0100
 * @tc.name: save and delete
 * @tc.desc: 1.SavePreInstallStorageBundleInfo
 *           2.DeletePreInstallStorageBundleInfo
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, PreInstallDataStorageRdb_0100, Function | SmallTest | Level1)
{
    std::unique_ptr<IPreInstallDataStorage> preInstallDataStorage =
        std::make_unique<PreInstallDataStorageRdb>();
    PreInstallBundleInfo preInstallBundleInfo;
    preInstallBundleInfo.SetBundleName(TEST_BUNDLE_NAME);
    preInstallBundleInfo.SetVersionCode(TEST_VERSION);
    bool ret = preInstallDataStorage->SavePreInstallStorageBundleInfo(preInstallBundleInfo);
    EXPECT_TRUE(ret);
    ret = preInstallDataStorage->DeletePreInstallStorageBundleInfo(preInstallBundleInfo);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: PreInstallDataStorageRdb_0200
 * @tc.name: LoadAllPreInstallBundleInfos
 * @tc.desc: 1.LoadAllPreInstallBundleInfos
 * @tc.require: issueI56WB8
 */
HWTEST_F(BmsRdbDataManagerTest, PreInstallDataStorageRdb_0200, Function | SmallTest | Level1)
{
    std::unique_ptr<IPreInstallDataStorage> preInstallDataStorage =
        std::make_unique<PreInstallDataStorageRdb>();
    PreInstallBundleInfo preInstallBundleInfo1;
    preInstallBundleInfo1.SetBundleName(TEST_BUNDLE_NAME);
    preInstallBundleInfo1.SetVersionCode(TEST_VERSION);
    bool ret = preInstallDataStorage->SavePreInstallStorageBundleInfo(preInstallBundleInfo1);
    EXPECT_TRUE(ret);

    PreInstallBundleInfo preInstallBundleInfo2;
    preInstallBundleInfo2.SetBundleName(TEST_BUNDLE_NAME_TWO);
    preInstallBundleInfo2.SetVersionCode(TEST_VERSION_TWO);
    ret = preInstallDataStorage->SavePreInstallStorageBundleInfo(preInstallBundleInfo2);
    EXPECT_TRUE(ret);

    std::vector<PreInstallBundleInfo> preInstallBundleInfos;
    ret = preInstallDataStorage->LoadAllPreInstallBundleInfos(preInstallBundleInfos);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: PreInstallDataStorageRdb_0300
 * @tc.name: LoadPreInstallBundleInfo
 * @tc.desc: 1.LoadPreInstallBundleInfo
 * @tc.require: issueI56WB8
 */
HWTEST_F(BmsRdbDataManagerTest, PreInstallDataStorageRdb_0300, Function | SmallTest | Level1)
{
    std::unique_ptr<IPreInstallDataStorage> preInstallDataStorage =
        std::make_unique<PreInstallDataStorageRdb>();
    PreInstallBundleInfo preInstallBundleInfo1;
    preInstallBundleInfo1.SetBundleName(TEST_BUNDLE_NAME);
    preInstallBundleInfo1.SetVersionCode(TEST_VERSION);
    bool ret = preInstallDataStorage->SavePreInstallStorageBundleInfo(preInstallBundleInfo1);
    EXPECT_TRUE(ret);

    std::string bundleName;
    PreInstallBundleInfo preInstallBundleInfo;
    ret = preInstallDataStorage->LoadPreInstallBundleInfo(bundleName, preInstallBundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: FirstInstallDataStorageRdb_0100
 * @tc.name: IsExistFirstInstallBundleInfo
 * @tc.desc: 1.IsExistFirstInstallBundleInfo
 */
HWTEST_F(BmsRdbDataManagerTest, FirstInstallDataStorageRdb_0100, Function | SmallTest | Level1)
{
    std::shared_ptr<FirstInstallDataMgrStorageRdb> firstInstallDataMgr =
        std::make_shared<FirstInstallDataMgrStorageRdb>();
    FirstInstallBundleInfo firstInstallBundleInfo;
    firstInstallBundleInfo.firstInstallTime = 1106274594;
    bool ret = firstInstallDataMgr->AddFirstInstallBundleInfo(TEST_BUNDLE_NAME, 200, firstInstallBundleInfo);
    EXPECT_TRUE(ret);
    ret = firstInstallDataMgr->IsExistFirstInstallBundleInfo(TEST_BUNDLE_NAME, 200);
    EXPECT_TRUE(ret);
    ret = firstInstallDataMgr->IsExistFirstInstallBundleInfo(TEST_BUNDLE_NAME, 300);
    EXPECT_FALSE(ret);
    ret = firstInstallDataMgr->DeleteFirstInstallBundleInfo(200);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: FirstInstallDataStorageRdb_0200
 * @tc.name: AddFirstInstallBundleInfo
 * @tc.desc: 1.AddFirstInstallBundleInfo
 */
HWTEST_F(BmsRdbDataManagerTest, FirstInstallDataStorageRdb_0200, Function | SmallTest | Level1)
{
    std::shared_ptr<FirstInstallDataMgrStorageRdb> firstInstallDataMgr =
        std::make_shared<FirstInstallDataMgrStorageRdb>();
    FirstInstallBundleInfo firstInstallBundleInfo;
    firstInstallBundleInfo.firstInstallTime = 1106274594;
    FirstInstallBundleInfo firstInstallBundleInfo2;
    firstInstallBundleInfo2.firstInstallTime = 1103878594;
    bool ret = firstInstallDataMgr->AddFirstInstallBundleInfo(TEST_BUNDLE_NAME, 200, firstInstallBundleInfo);
    EXPECT_TRUE(ret);
    ret = firstInstallDataMgr->AddFirstInstallBundleInfo(TEST_BUNDLE_NAME, 300, firstInstallBundleInfo2);
    EXPECT_TRUE(ret);
    ret = firstInstallDataMgr->IsExistFirstInstallBundleInfo(TEST_BUNDLE_NAME, 200);
    EXPECT_TRUE(ret);
    ret = firstInstallDataMgr->IsExistFirstInstallBundleInfo(TEST_BUNDLE_NAME, 300);
    EXPECT_TRUE(ret);
    ret = firstInstallDataMgr->DeleteFirstInstallBundleInfo(200);
    EXPECT_TRUE(ret);
    ret = firstInstallDataMgr->DeleteFirstInstallBundleInfo(300);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: FirstInstallDataStorageRdb_0300
 * @tc.name: GetFirstInstallBundleInfo
 * @tc.desc: 1.GetFirstInstallBundleInfo
 */
HWTEST_F(BmsRdbDataManagerTest, FirstInstallDataStorageRdb_0300, Function | SmallTest | Level1)
{
    std::shared_ptr<FirstInstallDataMgrStorageRdb> firstInstallDataMgr =
        std::make_shared<FirstInstallDataMgrStorageRdb>();
    FirstInstallBundleInfo firstInstallBundleInfo;
    firstInstallBundleInfo.firstInstallTime = 1106274594;
    bool ret = firstInstallDataMgr->AddFirstInstallBundleInfo(TEST_BUNDLE_NAME, 200, firstInstallBundleInfo);
    EXPECT_TRUE(ret);
    ret = firstInstallDataMgr->AddFirstInstallBundleInfo("", 200, firstInstallBundleInfo);
    EXPECT_FALSE(ret);
    FirstInstallBundleInfo firstInstallBundleInfoRes;
    ret = firstInstallDataMgr->GetFirstInstallBundleInfo(TEST_BUNDLE_NAME, 200, firstInstallBundleInfoRes);
    EXPECT_TRUE(ret);
    ret = firstInstallDataMgr->GetFirstInstallBundleInfo("", 200, firstInstallBundleInfoRes);
    EXPECT_FALSE(ret);
    EXPECT_EQ(firstInstallBundleInfoRes.firstInstallTime, 1106274594);
    ret = firstInstallDataMgr->DeleteFirstInstallBundleInfo(200);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: FirstInstallDataStorageRdb_0400
 * @tc.name: DeleteFirstInstallBundleInfo
 * @tc.desc: 1.DeleteFirstInstallBundleInfo
 */
HWTEST_F(BmsRdbDataManagerTest, FirstInstallDataStorageRdb_0400, Function | SmallTest | Level1)
{
    std::shared_ptr<FirstInstallDataMgrStorageRdb> firstInstallDataMgr =
        std::make_shared<FirstInstallDataMgrStorageRdb>();
    FirstInstallBundleInfo firstInstallBundleInfo;
    firstInstallBundleInfo.firstInstallTime = 1106274594;
    bool ret = firstInstallDataMgr->AddFirstInstallBundleInfo(TEST_BUNDLE_NAME, 200, firstInstallBundleInfo);
    EXPECT_TRUE(ret);
    ret = firstInstallDataMgr->IsExistFirstInstallBundleInfo(TEST_BUNDLE_NAME, 200);
    EXPECT_TRUE(ret);
    ret = firstInstallDataMgr->DeleteFirstInstallBundleInfo(200);
    EXPECT_TRUE(ret);
    ret = firstInstallDataMgr->IsExistFirstInstallBundleInfo(TEST_BUNDLE_NAME, 200);
    EXPECT_FALSE(ret);
    ret = firstInstallDataMgr->IsExistFirstInstallBundleInfo("", 200);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: FirstInstallDataStorageRdb_0500
 * @tc.name: AddFirstInstallBundleInfo
 * @tc.desc: 1.AddFirstInstallBundleInfo
 */
HWTEST_F(BmsRdbDataManagerTest, FirstInstallDataStorageRdb_0500, Function | SmallTest | Level1)
{
    std::shared_ptr<FirstInstallDataMgrStorageRdb> firstInstallDataMgr =
        std::make_shared<FirstInstallDataMgrStorageRdb>();
    ASSERT_NE(firstInstallDataMgr, nullptr);
    firstInstallDataMgr->rdbDataManager_ = nullptr;
    FirstInstallBundleInfo firstInstallBundleInfo;
    firstInstallBundleInfo.firstInstallTime = 1106274594;
    bool ret = firstInstallDataMgr->AddFirstInstallBundleInfo(TEST_BUNDLE_NAME, 200, firstInstallBundleInfo);
    EXPECT_FALSE(ret);
    ret = firstInstallDataMgr->AddFirstInstallBundleInfo("", 200, firstInstallBundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: FirstInstallDataStorageRdb_0600
 * @tc.name: AddFirstInstallBundleInfo
 * @tc.desc: 1.AddFirstInstallBundleInfo
 */
HWTEST_F(BmsRdbDataManagerTest, FirstInstallDataStorageRdb_0600, Function | SmallTest | Level1)
{
    std::shared_ptr<FirstInstallDataMgrStorageRdb> firstInstallDataMgr =
        std::make_shared<FirstInstallDataMgrStorageRdb>();
    ASSERT_NE(firstInstallDataMgr, nullptr);
    firstInstallDataMgr->rdbDataManager_ = nullptr;
    FirstInstallBundleInfo firstInstallBundleInfo;
    firstInstallBundleInfo.firstInstallTime = 1106274594;
    bool ret = firstInstallDataMgr->AddFirstInstallBundleInfo(TEST_BUNDLE_NAME, 200, firstInstallBundleInfo);
    EXPECT_FALSE(ret);
    ret = firstInstallDataMgr->IsExistFirstInstallBundleInfo(TEST_BUNDLE_NAME, 200);
    EXPECT_FALSE(ret);
    ret = firstInstallDataMgr->GetFirstInstallBundleInfo(TEST_BUNDLE_NAME, 200, firstInstallBundleInfo);
    EXPECT_FALSE(ret);
    ret = firstInstallDataMgr->DeleteFirstInstallBundleInfo(200);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: RdbDataManager_0300
 * @tc.name: test ClearCache
 * @tc.desc: 1.test the interface of RdbDataManager
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_0300, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);

    int64_t outInsertNum = 0;
    std::vector<NativeRdb::ValuesBucket> valuesBuckets;
    bool ret = rdbDataManager->BatchInsert(outInsertNum, valuesBuckets);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: RdbDataManager_0400
 * @tc.name: test ClearCache
 * @tc.desc: 1.test the interface of RdbDataManager
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_0400, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);

    NativeRdb::ValuesBucket valuesBucket;
    NativeRdb::AbsRdbPredicates absRdbPredicates("TableName");
    bool ret = rdbDataManager->UpdateData(valuesBucket, absRdbPredicates);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: RdbDataManager_0500
 * @tc.name: test ClearCache
 * @tc.desc: 1.test the interface of RdbDataManager
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_0500, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);

    NativeRdb::AbsRdbPredicates absRdbPredicates("TableName");
    bool ret = rdbDataManager->DeleteData(absRdbPredicates);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: RdbDataManager_0600
 * @tc.name: test ClearCache
 * @tc.desc: 1.test the interface of RdbDataManager
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_0600, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);

    bool ret = rdbDataManager->CreateTable();
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: RdbDataManager_0700
 * @tc.name: test ClearCache
 * @tc.desc: 1.test the interface of RdbDataManager
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_0700, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);

    NativeRdb::AbsRdbPredicates absRdbPredicates("TableName");
    auto ret = rdbDataManager->QueryByStep(absRdbPredicates);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.number: RdbDataManager_0800
 * @tc.name: test ClearCache
 * @tc.desc: 1.test the interface of RdbDataManager
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_0800, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);

    NativeRdb::ValuesBucket valuesBucket;
    NativeRdb::AbsRdbPredicates absRdbPredicates("TableName");
    bool ret = rdbDataManager->UpdateOrInsertData(valuesBucket, absRdbPredicates);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: RdbDataManager_0900
 * @tc.name: test ClearCache
 * @tc.desc: 1.test the interface of RdbDataManager
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_0900, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    ErrCode result = ERR_OK;
    auto ret = rdbDataManager->GetRdbStore(result);
    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.number: RdbDataManager_1000
 * @tc.name: test ClearCache
 * @tc.desc: 1.test the interface of RdbDataManager
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_1000, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);

    NativeRdb::AbsRdbPredicates absRdbPredicates("TableName");
    auto ret = rdbDataManager->QueryData(absRdbPredicates);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.number: RdbDataManager_1100
 * @tc.name: test insert with retry
 * @tc.desc: 1.test the interface of RdbDataManager
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_1100, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    ErrCode result = ERR_OK;
    auto rdbStore = rdbDataManager->GetRdbStore(result);
    ASSERT_NE(rdbStore, nullptr);

    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString("key", KEY_ONE);
    valuesBucket.PutString("value", VALUE_ONE);
    int64_t rowId = -1;

    auto ret = rdbDataManager->InsertWithRetry(rdbStore, rowId, valuesBucket);
    EXPECT_EQ(ret, NativeRdb::E_OK);
}

/**
 * @tc.number: RdbDataManager_1200
 * @tc.name: test GetRdbStore
 * @tc.desc: 1.test GetRdbStore
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_1200, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);
    ErrCode result = ERR_OK;
    auto rdbStore = rdbDataManager->GetRdbStore(result);
    ASSERT_NE(rdbStore, nullptr);

    std::string path = DB_PATH + DB_NAME;
    auto res = BundleUtil::DeleteDir(path);
    EXPECT_TRUE(res);
    result = ERR_OK;
    rdbStore = rdbDataManager->GetRdbStore(result);
    ASSERT_NE(rdbStore, nullptr);
}

/**
 * @tc.number: RdbDataManager_1300
 * @tc.name: insert queryAll
 * @tc.desc: 1.insert data
 *           2.queryAll data
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_1300, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    EXPECT_TRUE(rdbDataManager != nullptr);

    ErrCode ret = rdbDataManager->InsertDataWithCode(KEY_ONE, VALUE_ONE);
    EXPECT_EQ(ret, ERR_OK);

    ret = rdbDataManager->InsertDataWithCode(KEY_TWO, VALUE_TWO);
    EXPECT_EQ(ret, ERR_OK);

    ret = rdbDataManager->InsertDataWithCode(KEY_THREE, VALUE_THREE);
    EXPECT_EQ(ret, ERR_OK);

    std::map<std::string, std::string> datas;
    bool ret2 = rdbDataManager->QueryAllData(datas);
    EXPECT_TRUE(ret2);
    EXPECT_TRUE(datas[KEY_ONE] == VALUE_ONE);
    EXPECT_TRUE(datas[KEY_TWO] == VALUE_TWO);
    EXPECT_TRUE(datas[KEY_THREE] == VALUE_THREE);
    CloseDb();
}

/**
 * @tc.number: RdbDataManager_1400
 * @tc.name: query data with specified columns
 * @tc.desc: 1.insert data
 *           2.query data with specified columns
 *           3.verify only requested column is returned
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_1400, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);

    bool ret = rdbDataManager->InsertData(KEY_ONE, VALUE_ONE);
    EXPECT_TRUE(ret);

    NativeRdb::AbsRdbPredicates absRdbPredicates(TABLE_NAME);
    absRdbPredicates.EqualTo("KEY", KEY_ONE);
    std::vector<std::string> columns = { "VALUE" };
    auto resultSet = rdbDataManager->QueryData(absRdbPredicates, columns);
    ASSERT_NE(resultSet, nullptr);
    ScopeGuard stateGuard([&resultSet] { resultSet->Close(); });

    EXPECT_EQ(resultSet->GoToFirstRow(), NativeRdb::E_OK);
    std::string value;
    EXPECT_EQ(resultSet->GetString(0, value), NativeRdb::E_OK);
    EXPECT_EQ(value, VALUE_ONE);
    CloseDb();
}

/**
 * @tc.number: RdbDataManager_1500
 * @tc.name: query data with specified columns invalid table
 * @tc.desc: 1.query data with specified columns on invalid table
 *           2.expect nullptr returned
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_1500, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);

    NativeRdb::AbsRdbPredicates absRdbPredicates("InvalidTable");
    std::vector<std::string> columns = { "VALUE" };
    auto resultSet = rdbDataManager->QueryData(absRdbPredicates, columns);
    EXPECT_EQ(resultSet, nullptr);
    CloseDb();
}

/**
 * @tc.number: RdbDataManager_1600
 * @tc.name: query data with empty columns default behavior
 * @tc.desc: 1.insert data
 *           2.query data with empty columns vector
 *           3.verify all columns returned (backward compatibility)
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_1600, Function | SmallTest | Level1)
{
    auto rdbDataManager = OpenDbAndTable();
    ASSERT_NE(rdbDataManager, nullptr);

    bool ret = rdbDataManager->InsertData(KEY_ONE, VALUE_ONE);
    EXPECT_TRUE(ret);

    NativeRdb::AbsRdbPredicates absRdbPredicates(TABLE_NAME);
    absRdbPredicates.EqualTo("KEY", KEY_ONE);
    auto resultSet = rdbDataManager->QueryData(absRdbPredicates, {});
    ASSERT_NE(resultSet, nullptr);
    ScopeGuard stateGuard([&resultSet] { resultSet->Close(); });

    EXPECT_EQ(resultSet->GoToFirstRow(), NativeRdb::E_OK);
    std::string value;
    EXPECT_EQ(resultSet->GetString(1, value), NativeRdb::E_OK);
    EXPECT_EQ(value, VALUE_ONE);
    CloseDb();
}

#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
/**
 * @tc.number: DefaultAppRdb_0100
 * @tc.name: save get and delete
 * @tc.desc: 1.SetDefaultApplicationInfo
 *           2.GetDefaultApplicationInfo
 *           3.DeleteDefaultApplicationInfos
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, DefaultAppRdb_0100, Function | SmallTest | Level1)
{
    std::unique_ptr<IDefaultAppDb> defaultAppDb = std::make_unique<DefaultAppRdb>();
    Element element1;
    element1.bundleName = TEST_BUNDLE_NAME;
    bool ret = defaultAppDb->SetDefaultApplicationInfo(TEST_USERID, TEST_DEFAULT_APP_TYPE, element1);
    EXPECT_TRUE(ret);

    Element element2;
    ret = defaultAppDb->GetDefaultApplicationInfo(TEST_USERID, TEST_DEFAULT_APP_TYPE, element2);
    EXPECT_TRUE(ret);

    ret = defaultAppDb->DeleteDefaultApplicationInfos(TEST_USERID);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: DefaultAppRdb_0200
 * @tc.name: save get and delete
 * @tc.desc: 1.SetDefaultApplicationInfos
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, DefaultAppRdb_0200, Function | SmallTest | Level1)
{
    DefaultAppRdb defaultAppRdb;
    std::map<std::string, Element> infos;
    defaultAppRdb.rdbDataManager_ = nullptr;
    bool ret = defaultAppRdb.SetDefaultApplicationInfos(Constants::INVALID_UID, infos);
    EXPECT_FALSE(ret);
    ret = defaultAppRdb.DeleteDefaultApplicationInfos(Constants::INVALID_UID);
    EXPECT_FALSE(ret);
    ret = defaultAppRdb.DeleteDefaultApplicationInfo(Constants::INVALID_UID, "");
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: DefaultAppRdb_0300
 * @tc.name: save get and delete
 * @tc.desc: 1.SetDefaultApplicationInfos
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, DefaultAppRdb_0300, Function | SmallTest | Level1)
{
    DefaultAppRdb defaultAppRdb;
    std::map<std::string, Element> infos;
    Element element;
    element.bundleName = TEST_BUNDLE_NAME;
    defaultAppRdb.rdbDataManager_ = nullptr;
    bool ret = defaultAppRdb.SetDefaultApplicationInfo(Constants::INVALID_UID, "", element);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: DefaultAppRdb_0400
 * @tc.name: save get and delete
 * @tc.desc: 1.SetDefaultApplicationInfo
 *           2.GetDefaultApplicationInfo
 *           3.DeleteDefaultApplicationInfos
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, DefaultAppRdb_0400, Function | SmallTest | Level1)
{
    std::unique_ptr<IDefaultAppDb> defaultAppDb = std::make_unique<DefaultAppRdb>();
    Element element1;
    element1.bundleName = TEST_BUNDLE_NAME;
    bool ret = defaultAppDb->SetDefaultApplicationInfo(TEST_USERID, TEST_DEFAULT_APP_TYPE, element1);
    EXPECT_TRUE(ret);

    Element element2;
    ret = defaultAppDb->GetDefaultApplicationInfo(TEST_USERID, TEST_DEFAULT_APP_TYPE, element2);
    EXPECT_TRUE(ret);

    bool isDefaultApp = false;
    ErrCode res = DefaultAppMgr::GetInstance().IsDefaultApplication(TEST_USERID, TEST_DEFAULT_APP_TYPE, isDefaultApp);
    EXPECT_EQ(res, ERR_OK);

    ret = defaultAppDb->DeleteDefaultApplicationInfos(TEST_USERID);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: DefaultAppRdb_0600
 * @tc.name: save get and delete
 * @tc.desc: 1.SetDefaultApplicationInfo
 *           2.GetDefaultApplicationInfo
 *           3.DeleteDefaultApplicationInfos
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, DefaultAppRdb_0500, Function | SmallTest | Level1)
{
    std::unique_ptr<IDefaultAppDb> defaultAppDb = std::make_unique<DefaultAppRdb>();
    Element element1;
    element1.bundleName = TEST_BUNDLE_NAME;
    bool ret = defaultAppDb->SetDefaultApplicationInfo(TEST_USERID, TEST_DEFAULT_APP_TYPE, element1);
    EXPECT_TRUE(ret);

    Element element2;
    ret = defaultAppDb->GetDefaultApplicationInfo(TEST_USERID, TEST_DEFAULT_APP_TYPE, element2);
    EXPECT_TRUE(ret);

    DefaultAppMgr::GetInstance().HandleUninstallBundle(TEST_USERID, "", 0);
    ret = defaultAppDb->DeleteDefaultApplicationInfos(TEST_USERID);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: DefaultAppRdb_0600
 * @tc.name: save get and delete
 * @tc.desc: 1.SetDefaultApplicationInfo
 *           2.GetDefaultApplicationInfo
 *           3.DeleteDefaultApplicationInfos
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, DefaultAppRdb_0600, Function | SmallTest | Level1)
{
    std::unique_ptr<IDefaultAppDb> defaultAppDb = std::make_unique<DefaultAppRdb>();
    Element element1;
    element1.bundleName = TEST_BUNDLE_NAME;
    bool ret = defaultAppDb->SetDefaultApplicationInfo(TEST_USERID, TEST_DEFAULT_APP_TYPE, element1);
    EXPECT_TRUE(ret);

    Element element2;
    ret = defaultAppDb->GetDefaultApplicationInfo(TEST_USERID, TEST_DEFAULT_APP_TYPE, element2);
    EXPECT_TRUE(ret);

    BundleInfo bundleInfo;
    ErrCode res = DefaultAppMgr::GetInstance().GetBundleInfoByAppType(TEST_USERID, TEST_DEFAULT_APP_TYPE, bundleInfo);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_DEFAULT_APP_NOT_EXIST);

    ret = defaultAppDb->DeleteDefaultApplicationInfos(TEST_USERID);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: DefaultAppRdb_0700
 * @tc.name: save get and delete
 * @tc.desc: 1.SetDefaultApplicationInfos
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, DefaultAppRdb_0700, Function | SmallTest | Level1)
{
    DefaultAppRdb defaultAppRdb;
    Element element;
    bool ret = defaultAppRdb.SetDefaultApplicationInfo(100, TEST_DEFAULT_APP_TYPE, element);
    EXPECT_TRUE(ret);
}
#endif

/**
 * @tc.number: TransformStrToInfo_Parallel_0100
 * @tc.name: TransformStrToInfo with empty dataset
 * @tc.desc: Test parallel processing with empty input data
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, TransformStrToInfo_Parallel_0100, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleDataStorageRdb> dataStorage = std::make_shared<BundleDataStorageRdb>();
    ASSERT_NE(dataStorage, nullptr);

    std::map<std::string, std::string> emptyDatas;
    std::map<std::string, InnerBundleInfo> infos;

    // Should handle empty data gracefully
    dataStorage->TransformStrToInfo(emptyDatas, infos);

    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.number: TransformStrToInfo_Parallel_0200
 * @tc.name: TransformStrToInfo with single bundle
 * @tc.desc: Test parallel processing with single bundle
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, TransformStrToInfo_Parallel_0200, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleDataStorageRdb> dataStorage = std::make_shared<BundleDataStorageRdb>();
    ASSERT_NE(dataStorage, nullptr);

    // Create test bundle info
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = TEST_BUNDLE_NAME;
    applicationInfo.name = TEST_NAME;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    // Save to get JSON string
    bool ret = dataStorage->SaveStorageBundleInfo(innerBundleInfo);
    EXPECT_TRUE(ret);

    // Query saved data
    std::map<std::string, std::string> datas;
    ret = dataStorage->rdbDataManager_->QueryAllData(datas);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(datas.empty());

    // Test TransformStrToInfo
    std::map<std::string, InnerBundleInfo> infos;
    dataStorage->TransformStrToInfo(datas, infos);

    EXPECT_FALSE(infos.empty());
    EXPECT_EQ(infos[TEST_BUNDLE_NAME].GetApplicationName(), TEST_NAME);

    // Cleanup
    dataStorage->DeleteStorageBundleInfo(innerBundleInfo);
}

/**
 * @tc.number: TransformStrToInfo_Parallel_0300
 * @tc.name: TransformStrToInfo with multiple bundles
 * @tc.desc: Test parallel processing with multiple bundles (10 apps)
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, TransformStrToInfo_Parallel_0300, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleDataStorageRdb> dataStorage = std::make_shared<BundleDataStorageRdb>();
    ASSERT_NE(dataStorage, nullptr);

    const int bundleCount = 10;
    std::vector<InnerBundleInfo> savedBundles;

    // Create and save multiple bundles
    for (int i = 0; i < bundleCount; i++) {
        ApplicationInfo applicationInfo;
        applicationInfo.bundleName = "com.test.bundle" + std::to_string(i);
        applicationInfo.name = "TestName" + std::to_string(i);

        InnerBundleInfo innerBundleInfo;
        innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

        bool ret = dataStorage->SaveStorageBundleInfo(innerBundleInfo);
        EXPECT_TRUE(ret);
        savedBundles.push_back(innerBundleInfo);
    }

    // Query all saved data
    std::map<std::string, std::string> datas;
    bool ret = dataStorage->rdbDataManager_->QueryAllData(datas);
    EXPECT_TRUE(ret);
    EXPECT_GE(datas.size(), bundleCount);

    // Test TransformStrToInfo with parallel processing
    std::map<std::string, InnerBundleInfo> infos;
    dataStorage->TransformStrToInfo(datas, infos);

    EXPECT_GE(infos.size(), bundleCount);

    // Verify all bundles are correctly loaded
    for (int i = 0; i < bundleCount; i++) {
        std::string bundleName = "com.test.bundle" + std::to_string(i);
        std::string expectedName = "TestName" + std::to_string(i);
        EXPECT_EQ(infos[bundleName].GetApplicationName(), expectedName);
    }

    // Cleanup
    for (const auto &bundle : savedBundles) {
        dataStorage->DeleteStorageBundleInfo(bundle);
    }
}

/**
 * @tc.number: TransformStrToInfo_Parallel_0400
 * @tc.name: TransformStrToInfo with large dataset
 * @tc.desc: Test parallel processing with large dataset (50 apps)
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, TransformStrToInfo_Parallel_0400, Function | MediumTest | Level1)
{
    std::shared_ptr<BundleDataStorageRdb> dataStorage = std::make_shared<BundleDataStorageRdb>();
    ASSERT_NE(dataStorage, nullptr);

    const int bundleCount = 50;
    std::vector<InnerBundleInfo> savedBundles;

    // Create and save multiple bundles
    for (int i = 0; i < bundleCount; i++) {
        ApplicationInfo applicationInfo;
        applicationInfo.bundleName = "com.test.large" + std::to_string(i);
        applicationInfo.name = "LargeTest" + std::to_string(i);

        InnerBundleInfo innerBundleInfo;
        innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

        bool ret = dataStorage->SaveStorageBundleInfo(innerBundleInfo);
        EXPECT_TRUE(ret);
        savedBundles.push_back(innerBundleInfo);
    }

    // Query all saved data
    std::map<std::string, std::string> datas;
    bool ret = dataStorage->rdbDataManager_->QueryAllData(datas);
    EXPECT_TRUE(ret);
    EXPECT_GE(datas.size(), bundleCount);

    // Test TransformStrToInfo with parallel processing
    std::map<std::string, InnerBundleInfo> infos;
    dataStorage->TransformStrToInfo(datas, infos);

    EXPECT_GE(infos.size(), bundleCount);

    // Verify all bundles are correctly loaded
    for (int i = 0; i < bundleCount; i++) {
        std::string bundleName = "com.test.large" + std::to_string(i);
        EXPECT_TRUE(infos.find(bundleName) != infos.end());
    }

    // Cleanup
    for (const auto &bundle : savedBundles) {
        dataStorage->DeleteStorageBundleInfo(bundle);
    }
}

/**
 * @tc.number: TransformStrToInfo_Parallel_0500
 * @tc.name: TransformStrToInfo with corrupted JSON
 * @tc.desc: Test parallel processing handles corrupted JSON data
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, TransformStrToInfo_Parallel_0500, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleDataStorageRdb> dataStorage = std::make_shared<BundleDataStorageRdb>();
    ASSERT_NE(dataStorage, nullptr);

    std::map<std::string, std::string> datas;

    // Add valid data
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = TEST_BUNDLE_NAME;
    applicationInfo.name = TEST_NAME;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    dataStorage->SaveStorageBundleInfo(innerBundleInfo);

    // Query to get valid JSON
    std::map<std::string, std::string> allData;
    dataStorage->rdbDataManager_->QueryAllData(allData);

    // Add corrupted JSON data
    datas[TEST_BUNDLE_NAME] = allData[TEST_BUNDLE_NAME];  // Valid
    datas["corrupted_bundle"] = "{invalid json content";   // Invalid
    datas["another_bad"] = "not a json at all";           // Invalid

    // Test TransformStrToInfo
    std::map<std::string, InnerBundleInfo> infos;
    dataStorage->TransformStrToInfo(datas, infos);

    // Should only load the valid bundle
    EXPECT_TRUE(infos.find(TEST_BUNDLE_NAME) != infos.end());
    EXPECT_EQ(infos[TEST_BUNDLE_NAME].GetApplicationName(), TEST_NAME);

    // Cleanup
    dataStorage->DeleteStorageBundleInfo(innerBundleInfo);
}

/**
 * @tc.number: TransformStrToInfo_Parallel_0600
 * @tc.name: TransformStrToInfo result consistency
 * @tc.desc: Verify parallel processing produces same results as serial
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, TransformStrToInfo_Parallel_0600, Function | MediumTest | Level1)
{
    std::shared_ptr<BundleDataStorageRdb> dataStorage = std::make_shared<BundleDataStorageRdb>();
    ASSERT_NE(dataStorage, nullptr);

    const int bundleCount = 20;
    std::vector<InnerBundleInfo> savedBundles;

    // Create and save bundles with different properties
    for (int i = 0; i < bundleCount; i++) {
        ApplicationInfo applicationInfo;
        applicationInfo.bundleName = "com.test.consistency" + std::to_string(i);
        applicationInfo.name = "ConsistencyTest" + std::to_string(i);
        applicationInfo.label = "Label" + std::to_string(i);
        applicationInfo.description = "Description" + std::to_string(i);

        InnerBundleInfo innerBundleInfo;
        innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

        bool ret = dataStorage->SaveStorageBundleInfo(innerBundleInfo);
        EXPECT_TRUE(ret);
        savedBundles.push_back(innerBundleInfo);
    }

    // Query all saved data
    std::map<std::string, std::string> datas;
    bool ret = dataStorage->rdbDataManager_->QueryAllData(datas);
    EXPECT_TRUE(ret);
    EXPECT_GE(datas.size(), bundleCount);

    // Test TransformStrToInfo
    std::map<std::string, InnerBundleInfo> infos;
    dataStorage->TransformStrToInfo(datas, infos);

    // Verify consistency: all bundles loaded
    EXPECT_GE(infos.size(), bundleCount);

    // Verify each bundle's properties are preserved correctly
    for (int i = 0; i < bundleCount; i++) {
        std::string bundleName = "com.test.consistency" + std::to_string(i);
        auto it = infos.find(bundleName);
        EXPECT_TRUE(it != infos.end());

        if (it != infos.end()) {
            EXPECT_EQ(it->second.GetApplicationName(), "ConsistencyTest" + std::to_string(i));
        }
    }

    // Cleanup
    for (const auto &bundle : savedBundles) {
        dataStorage->DeleteStorageBundleInfo(bundle);
    }
}

/**
 * @tc.number: TransformStrToInfo_Parallel_0700
 * @tc.name: TransformStrToInfo with null rdbDataManager
 * @tc.desc: Test parallel processing handles null database manager
 * @tc.require: issueI56W8B
 */
HWTEST_F(BmsRdbDataManagerTest, TransformStrToInfo_Parallel_0700, Function | SmallTest | Level1)
{
    std::shared_ptr<BundleDataStorageRdb> dataStorage = std::make_shared<BundleDataStorageRdb>();
    ASSERT_NE(dataStorage, nullptr);
    dataStorage->rdbDataManager_ = nullptr;

    std::map<std::string, std::string> datas;
    datas["test_key"] = "test_value";

    std::map<std::string, InnerBundleInfo> infos;

    // Should handle null database manager gracefully
    dataStorage->TransformStrToInfo(datas, infos);

    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.number: RdbDataManager_1700
 * @tc.name: concurrent UpdateOrInsertData with same instance
 * @tc.desc: 1.concurrent UpdateOrInsertData for same key, only one row exists
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_1700, Function | MediumTest | Level1)
{
    auto rdbDataManager = OpenUpsertRaceTable();
    ASSERT_NE(rdbDataManager, nullptr);
    NativeRdb::AbsRdbPredicates cleanPredicates(UPSERT_RACE_TABLE);
    cleanPredicates.EqualTo(UPSERT_RACE_COLUMN_NAME, UPSERT_RACE_KEY);
    rdbDataManager->DeleteData(cleanPredicates);

    constexpr int32_t threadCount = 8;
    std::atomic<bool> startFlag {false};
    std::vector<std::thread> threads;
    for (int32_t i = 0; i < threadCount; i++) {
        threads.emplace_back([&rdbDataManager, &startFlag]() {
            while (!startFlag.load()) {
                std::this_thread::yield();
            }
            NativeRdb::ValuesBucket valuesBucket;
            valuesBucket.PutString(UPSERT_RACE_COLUMN_NAME, UPSERT_RACE_KEY);
            valuesBucket.PutString(UPSERT_RACE_COLUMN_VALUE, UPSERT_RACE_VALUE);
            NativeRdb::AbsRdbPredicates absRdbPredicates(UPSERT_RACE_TABLE);
            absRdbPredicates.EqualTo(UPSERT_RACE_COLUMN_NAME, UPSERT_RACE_KEY);
            rdbDataManager->UpdateOrInsertData(valuesBucket, absRdbPredicates);
        });
    }
    startFlag.store(true);
    for (auto &worker : threads) {
        worker.join();
    }

    auto resultSet = rdbDataManager->QueryData(cleanPredicates);
    ASSERT_NE(resultSet, nullptr);
    ScopeGuard guard([resultSet] { resultSet->Close(); });
    int32_t rowCount = 0;
    if (resultSet->GoToFirstRow() == NativeRdb::E_OK) {
        do {
            rowCount++;
        } while (resultSet->GoToNextRow() == NativeRdb::E_OK);
    }
    EXPECT_EQ(rowCount, 1);

    rdbDataManager->DeleteData(cleanPredicates);
}

/**
 * @tc.number: RdbDataManager_1800
 * @tc.name: concurrent UpdateOrInsertData with two instances
 * @tc.desc: 1.concurrent UpdateOrInsertData on same table from two instances, only one row exists
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_1800, Function | MediumTest | Level1)
{
    auto rdbDataManagerFirst = OpenUpsertRaceTable();
    ASSERT_NE(rdbDataManagerFirst, nullptr);
    auto rdbDataManagerSecond = OpenUpsertRaceTable();
    ASSERT_NE(rdbDataManagerSecond, nullptr);
    NativeRdb::AbsRdbPredicates cleanPredicates(UPSERT_RACE_TABLE);
    cleanPredicates.EqualTo(UPSERT_RACE_COLUMN_NAME, UPSERT_RACE_KEY);
    rdbDataManagerFirst->DeleteData(cleanPredicates);

    auto upsertFunc = [](std::shared_ptr<RdbDataManager> rdbDataManager, const std::atomic<bool> *startFlag) {
        while (!startFlag->load()) {
            std::this_thread::yield();
        }
        NativeRdb::ValuesBucket valuesBucket;
        valuesBucket.PutString(UPSERT_RACE_COLUMN_NAME, UPSERT_RACE_KEY);
        valuesBucket.PutString(UPSERT_RACE_COLUMN_VALUE, UPSERT_RACE_VALUE);
        NativeRdb::AbsRdbPredicates absRdbPredicates(UPSERT_RACE_TABLE);
        absRdbPredicates.EqualTo(UPSERT_RACE_COLUMN_NAME, UPSERT_RACE_KEY);
        rdbDataManager->UpdateOrInsertData(valuesBucket, absRdbPredicates);
    };
    constexpr int32_t threadCountPerMgr = 4;
    std::atomic<bool> startFlag {false};
    std::vector<std::thread> threads;
    for (int32_t i = 0; i < threadCountPerMgr; i++) {
        threads.emplace_back(upsertFunc, rdbDataManagerFirst, &startFlag);
    }
    for (int32_t i = 0; i < threadCountPerMgr; i++) {
        threads.emplace_back(upsertFunc, rdbDataManagerSecond, &startFlag);
    }
    startFlag.store(true);
    for (auto &worker : threads) {
        worker.join();
    }

    auto resultSet = rdbDataManagerFirst->QueryData(cleanPredicates);
    ASSERT_NE(resultSet, nullptr);
    ScopeGuard guard([resultSet] { resultSet->Close(); });
    int32_t rowCount = 0;
    if (resultSet->GoToFirstRow() == NativeRdb::E_OK) {
        do {
            rowCount++;
        } while (resultSet->GoToNextRow() == NativeRdb::E_OK);
    }
    EXPECT_EQ(rowCount, 1);

    rdbDataManagerFirst->DeleteData(cleanPredicates);
}

namespace {
int32_t CountTableRows(const std::shared_ptr<RdbDataManager> &mgr, const std::string &table)
{
    if (mgr == nullptr || mgr->rdbStore_ == nullptr) {
        return -1;
    }
    auto rs = mgr->rdbStore_->QuerySql("SELECT COUNT(1) FROM " + table);
    if (rs == nullptr) {
        return -1;
    }
    ScopeGuard guard([rs] { rs->Close(); });
    if (rs->GoToFirstRow() != NativeRdb::E_OK) {
        return -1;
    }
    int32_t count = 0;
    if (rs->GetInt(0, count) != NativeRdb::E_OK) {
        return -1;
    }
    return count;
}

std::string QueryStringValue(const std::shared_ptr<RdbDataManager> &mgr, const std::string &sql)
{
    std::string value;
    if (mgr == nullptr || mgr->rdbStore_ == nullptr) {
        return value;
    }
    auto rs = mgr->rdbStore_->QuerySql(sql);
    if (rs == nullptr) {
        return value;
    }
    ScopeGuard guard([rs] { rs->Close(); });
    if (rs->GoToFirstRow() != NativeRdb::E_OK) {
        return value;
    }
    rs->GetString(0, value);
    return value;
}

void RemoveSnapshotFiles(const std::string &dbFile)
{
    unlink((dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX).c_str());
    unlink((dbFile + ServiceConstants::RDB_SNAPSHOT_TMP_SUFFIX).c_str());
    unlink((dbFile + ServiceConstants::RDB_SNAPSHOT_FAILED_SUFFIX).c_str());
}
}  // namespace

/**
 * @tc.number: RdbDataManager_1900
 * @tc.name: snapshot salvage and resume recovery
 * @tc.desc: 1.export a snapshot from the db with key/value and autoincrement tables
 *           2.delete db files while keeping the snapshot (interrupted recovery)
 *           3.the next open resumes the recovery, restores all tables with explicit
 *             ids, removes the snapshot and keeps the autoincrement sequence
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_1900, Function | MediumTest | Level1)
{
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(DB_PATH + DB_NAME);
    auto keyMgr = OpenDbAndTable();
    ASSERT_NE(keyMgr, nullptr);
    EXPECT_TRUE(keyMgr->InsertData(SNAPSHOT_KEY_ONE, SNAPSHOT_VALUE_ONE));
    auto autoMgr = OpenUpsertRaceTable();
    ASSERT_NE(autoMgr, nullptr);
    NativeRdb::ValuesBucket autoRow;
    autoRow.PutString(UPSERT_RACE_COLUMN_NAME, SNAPSHOT_RACE_NAME);
    autoRow.PutString(UPSERT_RACE_COLUMN_VALUE, SNAPSHOT_RACE_VALUE);
    EXPECT_TRUE(autoMgr->InsertData(autoRow));
    NativeRdb::ValuesBucket explicitRow;
    explicitRow.PutInt(SNAPSHOT_ID_COLUMN, SNAPSHOT_EXPLICIT_ID);
    explicitRow.PutString(UPSERT_RACE_COLUMN_NAME, SNAPSHOT_RACE_NAME + "Explicit");
    explicitRow.PutString(UPSERT_RACE_COLUMN_VALUE, SNAPSHOT_RACE_VALUE + "Explicit");
    EXPECT_TRUE(autoMgr->InsertData(explicitRow));

    std::string dbFile = DB_PATH + DB_NAME;
    std::string snapshotPath = dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX;
    RemoveSnapshotFiles(dbFile);
    // trigger the open so that rdbStore_ is ready for exporting
    std::string value;
    EXPECT_TRUE(keyMgr->QueryData(SNAPSHOT_KEY_ONE, value));
    BmsRdbConfig snapshotConfig;
    snapshotConfig.dbPath = DB_PATH;
    snapshotConfig.dbName = DB_NAME;
    snapshotConfig.tableName = TABLE_NAME;
    EXPECT_TRUE(RdbRecoverManager::WriteSnapshotFile(snapshotConfig, keyMgr->rdbStore_, snapshotPath));
    EXPECT_EQ(access(snapshotPath.c_str(), F_OK), 0);

    // interrupted recovery: db files are gone but the snapshot survives
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(dbFile);
    RdbRecoverManager::CleanDbLeftoverFiles(dbFile);
    EXPECT_NE(access(dbFile.c_str(), F_OK), 0);
    EXPECT_EQ(access(snapshotPath.c_str(), F_OK), 0);

    // the next open must resume and finish the recovery before serving data
    auto recoverMgr = OpenDbAndTable();
    ASSERT_NE(recoverMgr, nullptr);
    std::string recovered;
    EXPECT_TRUE(recoverMgr->QueryData(SNAPSHOT_KEY_ONE, recovered));
    EXPECT_EQ(recovered, SNAPSHOT_VALUE_ONE);
    EXPECT_EQ(access(snapshotPath.c_str(), F_OK), -1);

    // explicit ids are restored and the autoincrement sequence continues after them
    auto upsertMgr = OpenUpsertRaceTable();
    ASSERT_NE(upsertMgr, nullptr);
    NativeRdb::ValuesBucket nextRow;
    nextRow.PutString(UPSERT_RACE_COLUMN_NAME, SNAPSHOT_RACE_NAME_NEXT);
    nextRow.PutString(UPSERT_RACE_COLUMN_VALUE, SNAPSHOT_RACE_VALUE_NEXT);
    EXPECT_TRUE(upsertMgr->InsertData(nextRow));
    NativeRdb::AbsRdbPredicates predicates(UPSERT_RACE_TABLE);
    predicates.EqualTo(UPSERT_RACE_COLUMN_NAME, SNAPSHOT_RACE_NAME_NEXT);
    auto rs = upsertMgr->QueryData(predicates);
    ASSERT_NE(rs, nullptr);
    ScopeGuard guard([rs] { rs->Close(); });
    EXPECT_EQ(rs->GoToFirstRow(), NativeRdb::E_OK);
    int32_t id = 0;
    EXPECT_EQ(rs->GetInt(0, id), NativeRdb::E_OK);
    EXPECT_EQ(id, SNAPSHOT_EXPLICIT_ID + 1);
    CloseDb();
}

/**
 * @tc.number: RdbDataManager_2000
 * @tc.name: snapshot restore replay is idempotent
 * @tc.desc: 1.restore the same snapshot twice
 *           2.row counts stay the same and no duplicate autoincrement rows appear
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_2000, Function | MediumTest | Level1)
{
    auto keyMgr = OpenDbAndTable();
    ASSERT_NE(keyMgr, nullptr);
    EXPECT_TRUE(keyMgr->InsertData(SNAPSHOT_KEY_TWO, SNAPSHOT_VALUE_TWO));
    auto autoMgr = OpenUpsertRaceTable();
    ASSERT_NE(autoMgr, nullptr);
    constexpr int32_t raceRowCount = 3;
    for (int32_t i = 0; i < raceRowCount; i++) {
        NativeRdb::ValuesBucket row;
        row.PutString(UPSERT_RACE_COLUMN_NAME, SNAPSHOT_RACE_NAME + std::to_string(i));
        row.PutString(UPSERT_RACE_COLUMN_VALUE, SNAPSHOT_RACE_VALUE + std::to_string(i));
        EXPECT_TRUE(autoMgr->InsertData(row));
    }

    std::string dbFile = DB_PATH + DB_NAME;
    std::string snapshotPath = dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX;
    std::string snapshotCopy = dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX + ".copy";
    RemoveSnapshotFiles(dbFile);
    unlink(snapshotCopy.c_str());
    std::string value;
    EXPECT_TRUE(keyMgr->QueryData(SNAPSHOT_KEY_TWO, value));
    BmsRdbConfig snapshotConfig;
    snapshotConfig.dbPath = DB_PATH;
    snapshotConfig.dbName = DB_NAME;
    snapshotConfig.tableName = TABLE_NAME;
    EXPECT_TRUE(RdbRecoverManager::WriteSnapshotFile(snapshotConfig, keyMgr->rdbStore_, snapshotPath));
    // keep a copy for the second replay
    {
        std::ifstream in(snapshotPath, std::ios::binary);
        std::ofstream out(snapshotCopy, std::ios::binary);
        out << in.rdbuf();
    }

    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(dbFile);
    RdbRecoverManager::CleanDbLeftoverFiles(dbFile);
    auto recoverMgr = OpenDbAndTable();
    ASSERT_NE(recoverMgr, nullptr);
    EXPECT_TRUE(recoverMgr->QueryData(SNAPSHOT_KEY_TWO, value));
    EXPECT_EQ(CountTableRows(recoverMgr, UPSERT_RACE_TABLE), raceRowCount);

    // replay the same snapshot again, the final state must not change
    bool snapshotInvalid = false;
    int32_t replayErrCode = NativeRdb::E_OK;
    EXPECT_TRUE(RdbRecoverManager::RestoreFromSnapshotFile(recoverMgr->bmsRdbConfig_.dbName,
        recoverMgr->bmsRdbConfig_.version, recoverMgr->rdbStore_, snapshotCopy, snapshotInvalid,
        replayErrCode));
    EXPECT_FALSE(snapshotInvalid);
    EXPECT_EQ(CountTableRows(recoverMgr, UPSERT_RACE_TABLE), raceRowCount);
    EXPECT_EQ(QueryStringValue(recoverMgr,
        "SELECT VALUE FROM " + UPSERT_RACE_TABLE + " WHERE NAME = '" + SNAPSHOT_RACE_NAME + "0'"),
        SNAPSHOT_RACE_VALUE + "0");
    unlink(snapshotCopy.c_str());
    CloseDb();
}

/**
 * @tc.number: RdbDataManager_2100
 * @tc.name: invalid snapshot is moved to failed and the db stays usable
 * @tc.desc: 1.craft a broken snapshot file next to the db
 *           2.the open renames it to .recover.failed instead of deleting it
 *           3.the db is still served
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_2100, Function | SmallTest | Level1)
{
    auto keyMgr = OpenDbAndTable();
    ASSERT_NE(keyMgr, nullptr);
    EXPECT_TRUE(keyMgr->InsertData("invalidSnapKey", "invalidSnapValue"));
    std::string dbFile = DB_PATH + DB_NAME;
    std::string snapshotPath = dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX;
    std::string failedPath = dbFile + ServiceConstants::RDB_SNAPSHOT_FAILED_SUFFIX;
    RemoveSnapshotFiles(dbFile);
    {
        std::ofstream out(snapshotPath);
        out << "garbage not a snapshot";
    }

    auto mgr = OpenDbAndTable();
    ASSERT_NE(mgr, nullptr);
    std::string value;
    EXPECT_TRUE(mgr->QueryData("invalidSnapKey", value));
    EXPECT_EQ(value, "invalidSnapValue");
    EXPECT_EQ(access(snapshotPath.c_str(), F_OK), -1);
    EXPECT_EQ(access(failedPath.c_str(), F_OK), 0);
    RemoveSnapshotFiles(dbFile);
    CloseDb();
}

/**
 * @tc.number: RdbDataManager_2200
 * @tc.name: db leftover files cleanup
 * @tc.desc: 1.create framework leftovers and unrelated files next to the db
 *           2.only leftovers with the db prefix are removed
 *           3.snapshot artifacts and json files are kept
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_2200, Function | SmallTest | Level1)
{
    std::string dbFile = DB_PATH + DB_NAME;
    std::string masterCorrupted = DB_PATH + "rdbTestDb_master_corrupted.db";
    std::string legacyBak = DB_PATH + "rdbTestDb.db.bak";
    std::string slaveMarker = DB_PATH + "rdbTestDb.db-slaveFailure";
    std::string binlogDir = DB_PATH + "rdbTestDb.db_binlog";
    std::string snapshotFile = dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX;
    std::string snapshotTmp = dbFile + ServiceConstants::RDB_SNAPSHOT_TMP_SUFFIX;
    std::string snapshotFailed = dbFile + ServiceConstants::RDB_SNAPSHOT_FAILED_SUFFIX;
    std::string jsonFile = DB_PATH + "rdbTestDb_notes.json";
    std::string otherFile = DB_PATH + "otherFile.db";
    std::string evilTargetDir = DB_PATH + "evilTargetDir";
    std::string evilTargetFile = evilTargetDir + "/keep.txt";
    // an unrelated name that merely shares the db stem is NOT a framework
    // artifact and must be kept, even as a symlink
    std::string evilLink = DB_PATH + "rdbTestDbEvilLink";
    // a whitelisted artifact name placed as a symlink must be unlinked itself
    std::string artifactLink = DB_PATH + "rdbTestDb.db.bak";
    std::string evilNestedDir = DB_PATH + "evilNestedDir";
    std::string evilNestedFile = evilNestedDir + "/keep.txt";
    std::string nestedLink = binlogDir + "/nestedLink";

    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(dbFile);
    {
        std::ofstream(masterCorrupted) << "x";
        std::ofstream(legacyBak) << "x";
        std::ofstream(slaveMarker) << "x";
        std::ofstream(snapshotFile) << "x";
        std::ofstream(snapshotTmp) << "x";
        std::ofstream(snapshotFailed) << "x";
        std::ofstream(jsonFile) << "x";
        std::ofstream(otherFile) << "x";
        mkdir(binlogDir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        // a symlink matching the db prefix must be removed without following it,
        // and a symlink nested in a removed directory must not be followed either
        mkdir(evilTargetDir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        std::ofstream(evilTargetFile) << "x";
        mkdir(evilNestedDir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        std::ofstream(evilNestedFile) << "x";
        symlink(evilTargetDir.c_str(), evilLink.c_str());
        symlink(evilTargetDir.c_str(), artifactLink.c_str());
        symlink(evilNestedDir.c_str(), nestedLink.c_str());
    }

    RdbRecoverManager::CleanDbLeftoverFiles(dbFile);

    EXPECT_EQ(access(masterCorrupted.c_str(), F_OK), -1);
    EXPECT_EQ(access(legacyBak.c_str(), F_OK), -1);
    EXPECT_EQ(access(slaveMarker.c_str(), F_OK), -1);
    EXPECT_EQ(access(binlogDir.c_str(), F_OK), -1);
    EXPECT_EQ(access(snapshotFile.c_str(), F_OK), 0);
    EXPECT_EQ(access(snapshotTmp.c_str(), F_OK), 0);
    EXPECT_EQ(access(snapshotFailed.c_str(), F_OK), 0);
    EXPECT_EQ(access(jsonFile.c_str(), F_OK), 0);
    EXPECT_EQ(access(otherFile.c_str(), F_OK), 0);
    EXPECT_EQ(access(evilLink.c_str(), F_OK), 0);
    EXPECT_EQ(access(artifactLink.c_str(), F_OK), -1);
    EXPECT_EQ(access(evilTargetFile.c_str(), F_OK), 0);
    EXPECT_EQ(access(evilNestedFile.c_str(), F_OK), 0);
    RemoveSnapshotFiles(dbFile);
    unlink(jsonFile.c_str());
    unlink(otherFile.c_str());
    unlink(evilTargetFile.c_str());
    unlink(evilNestedFile.c_str());
    rmdir(evilTargetDir.c_str());
    rmdir(evilNestedDir.c_str());
}

/**
 * @tc.number: RdbDataManager_2300
 * @tc.name: incomplete core table sets the db rebuild mark for bms db
 * @tc.desc: 1.craft a snapshot with an incomplete installed_bundle for the bms db
 *           2.the restore writes dbRebuildMark into bms_param
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_2300, Function | SmallTest | Level1)
{
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbPath = MARK_DB_PATH;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = TABLE_NAME;
    std::string dbFile = MARK_DB_PATH + ServiceConstants::BUNDLE_RDB_NAME;
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(dbFile);
    auto mgr = std::make_shared<RdbDataManager>(bmsRdbConfig);
    mgr->CreateTable();
    std::string snapshotPath = dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX;
    RemoveSnapshotFiles(dbFile);
    std::string snapshot = "BMS_SNAPSHOT_V1\n"
        "DBINFO\t" + std::string(ServiceConstants::BUNDLE_RDB_NAME) +
        "\t" + std::to_string(ServiceConstants::BUNDLE_RDB_VERSION) + "\n"
        "TABLE\tinstalled_bundle\t2\n"
        "SCHEMA\tCREATE TABLE IF NOT EXISTS installed_bundle"
        "(KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL);\n"
        "COLS\tKEY\tVALUE\n"
        "R\tcom.test.snapshotMark\tmarkValue\n"
        "END\tinstalled_bundle\t1\t0\n"
        "EOF\t1\t1\n";
    {
        std::ofstream out(snapshotPath);
        out << snapshot;
    }

    bool snapshotInvalid = false;
    int32_t replayErrCode = NativeRdb::E_OK;
    EXPECT_TRUE(RdbRecoverManager::RestoreFromSnapshotFile(mgr->bmsRdbConfig_.dbName,
        mgr->bmsRdbConfig_.version, mgr->rdbStore_, snapshotPath, snapshotInvalid, replayErrCode));
    EXPECT_FALSE(snapshotInvalid);
    EXPECT_EQ(QueryStringValue(mgr,
        "SELECT VALUE FROM installed_bundle WHERE KEY = 'com.test.snapshotMark'"), "markValue");
    EXPECT_EQ(QueryStringValue(mgr,
        "SELECT VALUE FROM bms_param WHERE KEY = '" +
        std::string(ServiceConstants::DB_REBUILD_MARK) + "'"),
        ServiceConstants::DB_REBUILD_MARK_DOING);
    RemoveSnapshotFiles(dbFile);
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(dbFile);
}

/**
 * @tc.number: RdbDataManager_2400
 * @tc.name: loss of non-rebuildable tables does not set the db rebuild mark
 * @tc.desc: 1.craft a snapshot where only app_control is partially salvaged and
 *             shortcut_info is missing, while installed_bundle is complete
 *           2.no db rebuild mark is written: the install dir rescan cannot
 *             recover these tables and must not be triggered
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_2400, Function | SmallTest | Level1)
{
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbPath = MARK_DB_PATH;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = TABLE_NAME;
    std::string dbFile = MARK_DB_PATH + ServiceConstants::BUNDLE_RDB_NAME;
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(dbFile);
    auto mgr = std::make_shared<RdbDataManager>(bmsRdbConfig);
    mgr->CreateTable();
    std::string snapshotPath = dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX;
    RemoveSnapshotFiles(dbFile);
    std::string snapshot = "BMS_SNAPSHOT_V1\n"
        "DBINFO\t" + std::string(ServiceConstants::BUNDLE_RDB_NAME) +
        "\t" + std::to_string(ServiceConstants::BUNDLE_RDB_VERSION) + "\n"
        "MISSING\tshortcut_info\n"
        "TABLE\tinstalled_bundle\t2\n"
        "SCHEMA\tCREATE TABLE IF NOT EXISTS installed_bundle"
        "(KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL);\n"
        "COLS\tKEY\tVALUE\n"
        "R\tcom.test.noMark\tnoMarkValue\n"
        "END\tinstalled_bundle\t1\t1\n"
        "TABLE\tapp_control\t2\n"
        "SCHEMA\tCREATE TABLE IF NOT EXISTS app_control"
        "(ID INTEGER PRIMARY KEY AUTOINCREMENT, A TEXT);\n"
        "COLS\tID\tA\n"
        "R\t5\tfoo\n"
        "END\tapp_control\t1\t0\n"
        "EOF\t2\t1\n";
    {
        std::ofstream out(snapshotPath);
        out << snapshot;
    }

    bool snapshotInvalid = false;
    int32_t replayErrCode = NativeRdb::E_OK;
    EXPECT_TRUE(RdbRecoverManager::RestoreFromSnapshotFile(mgr->bmsRdbConfig_.dbName,
        mgr->bmsRdbConfig_.version, mgr->rdbStore_, snapshotPath, snapshotInvalid, replayErrCode));
    EXPECT_FALSE(snapshotInvalid);
    EXPECT_EQ(QueryStringValue(mgr,
        "SELECT VALUE FROM installed_bundle WHERE KEY = 'com.test.noMark'"), "noMarkValue");
    EXPECT_EQ(CountTableRows(mgr, "app_control"), 1);
    // a MISSING table is not created by the restore
    EXPECT_EQ(CountTableRows(mgr, "shortcut_info"), -1);
    EXPECT_EQ(QueryStringValue(mgr,
        "SELECT VALUE FROM bms_param WHERE KEY = '" +
        std::string(ServiceConstants::DB_REBUILD_MARK) + "'"), "");
    RemoveSnapshotFiles(dbFile);
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(dbFile);
}

/**
 * @tc.number: RdbDataManager_2500
 * @tc.name: incomplete app_provision_info also sets the db rebuild mark
 * @tc.desc: 1.craft a snapshot where installed_bundle is complete but
 *             app_provision_info is not
 *           2.the mark is set: provision info is re-parsed from the installed
 *             packages during the install dir rescan
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_2500, Function | SmallTest | Level1)
{
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbPath = MARK_DB_PATH;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = TABLE_NAME;
    std::string dbFile = MARK_DB_PATH + ServiceConstants::BUNDLE_RDB_NAME;
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(dbFile);
    auto mgr = std::make_shared<RdbDataManager>(bmsRdbConfig);
    mgr->CreateTable();
    std::string snapshotPath = dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX;
    RemoveSnapshotFiles(dbFile);
    std::string snapshot = "BMS_SNAPSHOT_V1\n"
        "DBINFO\t" + std::string(ServiceConstants::BUNDLE_RDB_NAME) +
        "\t" + std::to_string(ServiceConstants::BUNDLE_RDB_VERSION) + "\n"
        "TABLE\tinstalled_bundle\t2\n"
        "SCHEMA\tCREATE TABLE IF NOT EXISTS installed_bundle"
        "(KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL);\n"
        "COLS\tKEY\tVALUE\n"
        "R\tcom.test.provision\tprovisionValue\n"
        "END\tinstalled_bundle\t1\t1\n"
        "TABLE\tapp_provision_info\t2\n"
        "SCHEMA\tCREATE TABLE IF NOT EXISTS app_provision_info"
        "(KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL);\n"
        "COLS\tKEY\tVALUE\n"
        "R\tcom.test.provision\tprovisionInfoValue\n"
        "END\tapp_provision_info\t1\t0\n"
        "EOF\t2\t1\n";
    {
        std::ofstream out(snapshotPath);
        out << snapshot;
    }

    bool snapshotInvalid = false;
    int32_t replayErrCode = NativeRdb::E_OK;
    EXPECT_TRUE(RdbRecoverManager::RestoreFromSnapshotFile(mgr->bmsRdbConfig_.dbName,
        mgr->bmsRdbConfig_.version, mgr->rdbStore_, snapshotPath, snapshotInvalid, replayErrCode));
    EXPECT_FALSE(snapshotInvalid);
    EXPECT_EQ(QueryStringValue(mgr,
        "SELECT VALUE FROM app_provision_info WHERE KEY = 'com.test.provision'"), "provisionInfoValue");
    EXPECT_EQ(QueryStringValue(mgr,
        "SELECT VALUE FROM bms_param WHERE KEY = '" +
        std::string(ServiceConstants::DB_REBUILD_MARK) + "'"),
        ServiceConstants::DB_REBUILD_MARK_DOING);
    RemoveSnapshotFiles(dbFile);
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(dbFile);
}

/**
 * @tc.number: RdbDataManager_2600
 * @tc.name: rebuild with snapshot keeps the data
 * @tc.desc: 1.fill the db with key/value and autoincrement rows
 *           2.call RebuildDbWithSnapshot directly: export, delete, re-open, replay
 *           3.data is restored, the snapshot removed and the db serves again
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_2600, Function | MediumTest | Level1)
{
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(DB_PATH + DB_NAME);
    auto keyMgr = OpenDbAndTable();
    ASSERT_NE(keyMgr, nullptr);
    EXPECT_TRUE(keyMgr->InsertData(SNAPSHOT_KEY_ONE, SNAPSHOT_VALUE_ONE));
    auto autoMgr = OpenUpsertRaceTable();
    ASSERT_NE(autoMgr, nullptr);
    NativeRdb::ValuesBucket explicitRow;
    explicitRow.PutInt(SNAPSHOT_ID_COLUMN, SNAPSHOT_EXPLICIT_ID);
    explicitRow.PutString(UPSERT_RACE_COLUMN_NAME, SNAPSHOT_RACE_NAME + "Explicit");
    explicitRow.PutString(UPSERT_RACE_COLUMN_VALUE, SNAPSHOT_RACE_VALUE + "Explicit");
    EXPECT_TRUE(autoMgr->InsertData(explicitRow));

    std::string dbFile = DB_PATH + DB_NAME;
    std::string snapshotPath = dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX;
    RemoveSnapshotFiles(dbFile);
    // trigger the open so that rdbStore_ is ready for exporting
    std::string value;
    EXPECT_TRUE(keyMgr->QueryData(SNAPSHOT_KEY_ONE, value));
    NativeRdb::RdbStoreConfig rdbStoreConfig(dbFile);
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbPath = DB_PATH;
    bmsRdbConfig.dbName = DB_NAME;
    bmsRdbConfig.tableName = TABLE_NAME;
    EXPECT_EQ(RdbRecoverManager::RebuildDbWithSnapshot(bmsRdbConfig, rdbStoreConfig,
        keyMgr->rdbStore_, 0), ERR_OK);
    EXPECT_NE(access(snapshotPath.c_str(), F_OK), 0);

    std::string recovered;
    EXPECT_TRUE(keyMgr->QueryData(SNAPSHOT_KEY_ONE, recovered));
    EXPECT_EQ(recovered, SNAPSHOT_VALUE_ONE);
    // the autoincrement table survives the rebuild through the snapshot replay
    auto raceMgr = OpenUpsertRaceTable();
    ASSERT_NE(raceMgr, nullptr);
    EXPECT_EQ(CountTableRows(raceMgr, UPSERT_RACE_TABLE), 1);
    CloseDb();
}

/**
 * @tc.number: RdbDataManager_2700
 * @tc.name: rebuild keeps the db as-is when the snapshot export fails
 * @tc.desc: 1.block the snapshot tmp path with a directory
 *           2.RebuildDbWithSnapshot fails with E_SQLITE_IOERR
 *           3.the db file keeps its data and stays queryable
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_2700, Function | SmallTest | Level1)
{
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(DB_PATH + DB_NAME);
    auto keyMgr = OpenDbAndTable();
    ASSERT_NE(keyMgr, nullptr);
    EXPECT_TRUE(keyMgr->InsertData(SNAPSHOT_KEY_TWO, SNAPSHOT_VALUE_TWO));
    std::string dbFile = DB_PATH + DB_NAME;
    std::string snapshotPath = dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX;
    std::string tmpPath = dbFile + ServiceConstants::RDB_SNAPSHOT_TMP_SUFFIX;
    RemoveSnapshotFiles(dbFile);
    // trigger the open so that rdbStore_ is ready for exporting
    std::string value;
    EXPECT_TRUE(keyMgr->QueryData(SNAPSHOT_KEY_TWO, value));
    // a directory occupies the tmp path: open(tmp, O_WRONLY|O_CREAT|O_TRUNC) fails
    ASSERT_EQ(mkdir(tmpPath.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH), 0);
    NativeRdb::RdbStoreConfig rdbStoreConfig(dbFile);
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbPath = DB_PATH;
    bmsRdbConfig.dbName = DB_NAME;
    bmsRdbConfig.tableName = TABLE_NAME;
    EXPECT_EQ(RdbRecoverManager::RebuildDbWithSnapshot(bmsRdbConfig, rdbStoreConfig,
        keyMgr->rdbStore_, 0), NativeRdb::E_SQLITE_IOERR);
    // the db was not deleted and still serves its data
    EXPECT_EQ(access(dbFile.c_str(), F_OK), 0);
    std::string kept;
    EXPECT_TRUE(keyMgr->QueryData(SNAPSHOT_KEY_TWO, kept));
    EXPECT_EQ(kept, SNAPSHOT_VALUE_TWO);
    rmdir(tmpPath.c_str());
    RemoveSnapshotFiles(dbFile);
    CloseDb();
}

/**
 * @tc.number: RdbDataManager_2800
 * @tc.name: persistent replay failure downgrades to an empty db
 * @tc.desc: 1.craft a snapshot whose rows violate the primary key
 *           2.the first opens replay it, fail and keep it for retry
 *           3.after MAX_SNAPSHOT_REPLAY_ATTEMPTS failures the snapshot is renamed
 *             to .recover.failed and an empty db is served again
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_2800, Function | MediumTest | Level1)
{
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(DB_PATH + DB_NAME);
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbPath = DB_PATH;
    bmsRdbConfig.dbName = DB_NAME;
    bmsRdbConfig.tableName = TABLE_NAME;
    std::string dbFile = DB_PATH + DB_NAME;
    std::string snapshotPath = dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX;
    std::string failedPath = dbFile + ServiceConstants::RDB_SNAPSHOT_FAILED_SUFFIX;
    RemoveSnapshotFiles(dbFile);
    std::string snapshot = "BMS_SNAPSHOT_V1\n"
        "DBINFO\t" + DB_NAME + "\t" + std::to_string(bmsRdbConfig.version) + "\n"
        "TABLE\trdbTestTable\t2\n"
        "SCHEMA\tCREATE TABLE rdbTestTable(KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL)\n"
        "COLS\tKEY\tVALUE\n"
        "R\tdupKey\tvalueOne\n"
        "R\tdupKey\tvalueTwo\n"
        "END\trdbTestTable\t2\t1\n"
        "EOF\t1\t1\n";
    {
        std::ofstream out(snapshotPath);
        out << snapshot;
    }

    auto mgr = std::make_shared<RdbDataManager>(bmsRdbConfig);
    std::string value;
    // every open replays the snapshot and fails while the snapshot survives;
    // the attempt counter is process-wide per db and its starting point must
    // not matter, so poll until the downgrade happens
    EXPECT_FALSE(mgr->QueryData("dupKey", value));
    EXPECT_EQ(access(snapshotPath.c_str(), F_OK), 0);
    bool downgraded = false;
    for (int32_t i = 0; i < DOWNGRADE_POLL_MAX_TRIES; i++) {
        if (mgr->InsertData("afterDowngrade", "valueAfter")) {
            downgraded = true;
            break;
        }
    }
    EXPECT_TRUE(downgraded);
    // the downgrade renamed the snapshot to .recover.failed and re-created an
    // empty db, so it serves again
    std::string recovered;
    EXPECT_TRUE(mgr->QueryData("afterDowngrade", recovered));
    EXPECT_EQ(recovered, "valueAfter");
    EXPECT_NE(access(snapshotPath.c_str(), F_OK), 0);
    EXPECT_EQ(access(failedPath.c_str(), F_OK), 0);
    EXPECT_EQ(CountTableRows(mgr, TABLE_NAME), 1);
    RemoveSnapshotFiles(dbFile);
    CloseDb();
}

/**
 * @tc.number: RdbDataManager_2900
 * @tc.name: snapshot schema must be a plain CREATE TABLE statement
 * @tc.desc: 1.craft a snapshot whose SCHEMA line carries a trigger definition
 *           2.the restore rejects it as an invalid snapshot instead of executing it
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_2900, Function | SmallTest | Level1)
{
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(DB_PATH + DB_NAME);
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbPath = DB_PATH;
    bmsRdbConfig.dbName = DB_NAME;
    bmsRdbConfig.tableName = TABLE_NAME;
    auto mgr = std::make_shared<RdbDataManager>(bmsRdbConfig);
    // warm up the store without creating any table
    std::string value;
    EXPECT_FALSE(mgr->QueryData("warmup", value));
    std::string dbFile = DB_PATH + DB_NAME;
    std::string snapshotPath = dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX;
    RemoveSnapshotFiles(dbFile);
    std::string snapshot = "BMS_SNAPSHOT_V1\n"
        "DBINFO\t" + DB_NAME + "\t" + std::to_string(bmsRdbConfig.version) + "\n"
        "TABLE\trdbTestTable\t2\n"
        "SCHEMA\tCREATE TRIGGER evilTrigger BEGIN DELETE FROM rdbTestTable; END\n"
        "COLS\tKEY\tVALUE\n"
        "R\tgoodKey\tgoodValue\n"
        "END\trdbTestTable\t1\t1\n"
        "EOF\t1\t1\n";
    {
        std::ofstream out(snapshotPath);
        out << snapshot;
    }

    bool snapshotInvalid = false;
    int32_t replayErrCode = NativeRdb::E_OK;
    EXPECT_TRUE(RdbRecoverManager::RestoreFromSnapshotFile(mgr->bmsRdbConfig_.dbName,
        mgr->bmsRdbConfig_.version, mgr->rdbStore_, snapshotPath, snapshotInvalid, replayErrCode));
    EXPECT_TRUE(snapshotInvalid);
    // the trigger must not have been created and the db stays usable
    EXPECT_EQ(CountTableRows(mgr, "sqlite_master WHERE type='trigger' AND name='evilTrigger'"), 0);
    EXPECT_TRUE(mgr->CreateTable());
    EXPECT_TRUE(mgr->InsertData("afterReject", "valueAfter"));
    RemoveSnapshotFiles(dbFile);
    CloseDb();
}

/**
 * @tc.number: RdbDataManager_3000
 * @tc.name: interrupted snapshot export tmp is discarded on the next open
 * @tc.desc: 1.craft a complete but stale snapshot tmp next to a healthy db,
 *             simulating an export interrupted right before the atomic rename
 *           2.the next open discards the tmp instead of promoting it: the db was
 *             never deleted, its data keeps serving and the stale tmp never
 *             rolls it back
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_3000, Function | SmallTest | Level1)
{
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(DB_PATH + DB_NAME);
    auto keyMgr = OpenDbAndTable();
    ASSERT_NE(keyMgr, nullptr);
    EXPECT_TRUE(keyMgr->InsertData(SNAPSHOT_KEY_ONE, SNAPSHOT_VALUE_ONE));
    std::string dbFile = DB_PATH + DB_NAME;
    std::string snapshotPath = dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX;
    std::string tmpPath = dbFile + ServiceConstants::RDB_SNAPSHOT_TMP_SUFFIX;
    RemoveSnapshotFiles(dbFile);
    // trigger the open so that rdbStore_ is ready
    std::string value;
    EXPECT_TRUE(keyMgr->QueryData(SNAPSHOT_KEY_ONE, value));
    // simulate an export interrupted after a full write but before the atomic
    // rename: the tmp holds a stale view of the data
    std::string snapshot = "BMS_SNAPSHOT_V1\n"
        "TABLE\trdbTestTable\t2\n"
        "SCHEMA\tCREATE TABLE rdbTestTable(KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL)\n"
        "COLS\tKEY\tVALUE\n"
        "R\t" + SNAPSHOT_KEY_ONE + "\tstaleValue\n"
        "END\trdbTestTable\t1\t1\n"
        "EOF\t1\t1\n";
    {
        std::ofstream out(tmpPath);
        out << snapshot;
    }

    // the next open discards the stale tmp and keeps serving the db data
    auto mgr = OpenDbAndTable();
    ASSERT_NE(mgr, nullptr);
    std::string kept;
    EXPECT_TRUE(mgr->QueryData(SNAPSHOT_KEY_ONE, kept));
    EXPECT_EQ(kept, SNAPSHOT_VALUE_ONE);
    EXPECT_EQ(access(tmpPath.c_str(), F_OK), -1);
    EXPECT_EQ(access(snapshotPath.c_str(), F_OK), -1);
    RemoveSnapshotFiles(dbFile);
    CloseDb();
}

/**
 * @tc.number: RdbDataManager_3100
 * @tc.name: invalid snapshot formats are rejected
 * @tc.desc: craft a set of malformed snapshots (db info mismatch, bad escape,
 *           header/field/count violations, truncated eof) and verify each one
 *           is judged invalid instead of being replayed
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_3100, Function | MediumTest | Level1)
{
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(DB_PATH + DB_NAME);
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbPath = DB_PATH;
    bmsRdbConfig.dbName = DB_NAME;
    bmsRdbConfig.tableName = TABLE_NAME;
    auto mgr = std::make_shared<RdbDataManager>(bmsRdbConfig);
    // warm up the store without creating any table
    std::string value;
    EXPECT_FALSE(mgr->QueryData("warmup", value));
    std::string dbFile = DB_PATH + DB_NAME;
    std::string snapshotPath = dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX;

    std::vector<std::pair<std::string, std::string>> cases = {
        {"db info of another db", "BMS_SNAPSHOT_V1\nDBINFO\tother.db\t1\nEOF\t0\t1\n"},
        {"db info of another version", "BMS_SNAPSHOT_V1\nDBINFO\t" + DB_NAME + "\t9999\nEOF\t0\t1\n"},
        {"bad escape in table header", "BMS_SNAPSHOT_V1\nTABLE\tbad\\\t2\n"},
        {"eof count mismatch", "BMS_SNAPSHOT_V1\nEOF\t5\t1\n"},
        {"db info line missing",
            "BMS_SNAPSHOT_V1\nTABLE\tnegG\t2\n"
            "SCHEMA\tCREATE TABLE negG(KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL)\n"
            "COLS\tKEY\tVALUE\nR\tk\tv\nEND\tnegG\t1\t1\nEOF\t1\t1\n"},
        {"sqlite internal table",
            "BMS_SNAPSHOT_V1\nDBINFO\t" + DB_NAME + "\t" +
            std::to_string(bmsRdbConfig.version) + "\nTABLE\tsqlite_sequence\t2\n"
            "SCHEMA\tCREATE TABLE sqlite_sequence(name, seq)\n"
            "COLS\tname\tseq\nR\tt\t1\nEND\tsqlite_sequence\t1\t1\nEOF\t1\t1\n"},
        {"eof count not numeric", "BMS_SNAPSHOT_V1\nEOF\tabc\t1\n"},
        {"table column count not numeric", "BMS_SNAPSHOT_V1\nTABLE\tnegA\tabc\n"},
        {"table header field count", "BMS_SNAPSHOT_V1\nTABLE\tnegC\n"},
        {"schema line missing", "BMS_SNAPSHOT_V1\nTABLE\tnegD\t2\nEOF\t0\t1\n"},
        {"end row count mismatch",
            "BMS_SNAPSHOT_V1\nTABLE\tnegE\t2\n"
            "SCHEMA\tCREATE TABLE negE(KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL)\n"
            "COLS\tKEY\tVALUE\nR\tk\tv\nEND\tnegE\t5\t1\nEOF\t1\t1\n"},
        {"eof line missing",
            "BMS_SNAPSHOT_V1\nTABLE\tnegF\t2\n"
            "SCHEMA\tCREATE TABLE negF(KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL)\n"
            "COLS\tKEY\tVALUE\nR\tk\tv\nEND\tnegF\t1\t1\n"},
    };
    for (const auto &item : cases) {
        RemoveSnapshotFiles(dbFile);
        {
            std::ofstream out(snapshotPath);
            out << item.second;
        }
        bool snapshotInvalid = false;
        int32_t replayErrCode = NativeRdb::E_OK;
        EXPECT_TRUE(RdbRecoverManager::RestoreFromSnapshotFile(bmsRdbConfig.dbName,
            bmsRdbConfig.version, mgr->rdbStore_, snapshotPath, snapshotInvalid, replayErrCode))
            << "case: " << item.first;
        EXPECT_TRUE(snapshotInvalid) << "case: " << item.first;
    }
    RemoveSnapshotFiles(dbFile);
    CloseDb();
}

/**
 * @tc.number: RdbDataManager_3200
 * @tc.name: escaped fields survive the snapshot roundtrip
 * @tc.desc: a value containing tab, newline, backslash and carriage return must
 *           be exported and replayed byte for byte
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_3200, Function | MediumTest | Level1)
{
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(DB_PATH + DB_NAME);
    // NUL is deliberately excluded from this roundtrip: the RdbDataManager
    // QueryData path (QueryByStep -> SharedBlock::CellUnit::GetString) builds
    // the result std::string from a const char* and truncates at the first
    // embedded NUL (relational_store shared_block.cpp). The \0 escape itself
    // is covered by the parser-level crafted-snapshot cases in 3100.
    std::string specialValue = "tab\tnewline\nbackslash\\return\rend中文";
    auto keyMgr = OpenDbAndTable();
    ASSERT_NE(keyMgr, nullptr);
    EXPECT_TRUE(keyMgr->InsertData("escapeKey", specialValue));
    std::string dbFile = DB_PATH + DB_NAME;
    std::string snapshotPath = dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX;
    RemoveSnapshotFiles(dbFile);
    BmsRdbConfig snapshotConfig;
    snapshotConfig.dbPath = DB_PATH;
    snapshotConfig.dbName = DB_NAME;
    snapshotConfig.tableName = TABLE_NAME;
    std::string value;
    EXPECT_TRUE(keyMgr->QueryData("escapeKey", value));
    EXPECT_TRUE(RdbRecoverManager::WriteSnapshotFile(snapshotConfig, keyMgr->rdbStore_, snapshotPath));

    // simulate the interrupted recovery: the db is gone but the snapshot survives
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(dbFile);
    auto recoverMgr = OpenDbAndTable();
    ASSERT_NE(recoverMgr, nullptr);
    std::string recovered;
    EXPECT_TRUE(recoverMgr->QueryData("escapeKey", recovered));
    EXPECT_EQ(recovered, specialValue);
    RemoveSnapshotFiles(dbFile);
    CloseDb();
}

/**
 * @tc.number: RdbDataManager_3300
 * @tc.name: data operations fail fast while another instance recovers the db
 * @tc.desc: 1.hold the exclusive operation lock and start a recovery on a
 *             second manager: it blocks inside its recovery scope
 *           2.queries of the first manager return false during that window
 *             (the recovering fast-fail of the cached-store path)
 *           3.after the lock is released the recovery replays and finishes,
 *             serving resumes and the snapshot is committed away
 *           note: the RdbOpGuard recovering branch cannot be observed
 *           black-box: its shared lock is mutually exclusive with the
 *           recovery exclusive hold, so by the time a guard can run the
 *           recovery has always finished; the branch reads the same
 *           IsRecovering state verified here.
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_3300, Function | MediumTest | Level1)
{
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(DB_PATH + DB_NAME);
    auto mgrA = OpenDbAndTable();
    ASSERT_NE(mgrA, nullptr);
    EXPECT_TRUE(mgrA->InsertData(SNAPSHOT_KEY_ONE, SNAPSHOT_VALUE_ONE));
    std::string value;
    EXPECT_TRUE(mgrA->QueryData(SNAPSHOT_KEY_ONE, value));
    std::string dbFile = DB_PATH + DB_NAME;
    std::string snapshotPath = dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX;
    RemoveSnapshotFiles(dbFile);
    BmsRdbConfig snapshotConfig;
    snapshotConfig.dbPath = DB_PATH;
    snapshotConfig.dbName = DB_NAME;
    snapshotConfig.tableName = TABLE_NAME;
    std::string snapshot = "BMS_SNAPSHOT_V1\n"
        "DBINFO\t" + DB_NAME + "\t" + std::to_string(snapshotConfig.version) + "\n"
        "TABLE\trdbTestTable\t2\n"
        "SCHEMA\tCREATE TABLE rdbTestTable(KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL)\n"
        "COLS\tKEY\tVALUE\n"
        "R\t" + SNAPSHOT_KEY_ONE + "\t" + SNAPSHOT_VALUE_ONE + "\n"
        "END\trdbTestTable\t1\t1\n"
        "EOF\t1\t1\n";
    {
        std::ofstream out(snapshotPath);
        out << snapshot;
    }

    // hold the exclusive operation lock: the second manager's recovery enters
    // its scope (the recovering state becomes visible) and blocks on this lock
    std::unique_lock<std::shared_mutex> dbOpLock(RdbRecoverManager::GetDbOpMutex(DB_NAME));
    BmsRdbConfig recoverConfig;
    recoverConfig.dbPath = DB_PATH;
    recoverConfig.dbName = DB_NAME;
    recoverConfig.tableName = TABLE_NAME;
    std::thread recoverThread([&recoverConfig]() {
        auto mgrB = std::make_shared<RdbDataManager>(recoverConfig);
        std::string ignored;
        mgrB->QueryData("warmup", ignored);
    });
    // wait until the recovery is inside its scope
    bool recovering = false;
    for (int32_t i = 0; i < POLL_MAX_TRIES; i++) {
        if (RdbRecoverManager::IsRecovering(DB_NAME)) {
            recovering = true;
            break;
        }
        usleep(POLL_INTERVAL_MS * 1000);
    }
    EXPECT_TRUE(recovering);
    // the cached-store query must fail fast instead of interleaving with the
    // pending replay
    EXPECT_FALSE(mgrA->QueryData(SNAPSHOT_KEY_ONE, value));
    // release: the recovery replays the snapshot and finishes
    dbOpLock.unlock();
    recoverThread.join();
    // the replay thread itself walked past the commit point
    EXPECT_EQ(access(snapshotPath.c_str(), F_OK), -1);
    std::string recovered;
    EXPECT_TRUE(mgrA->QueryData(SNAPSHOT_KEY_ONE, recovered));
    EXPECT_EQ(recovered, SNAPSHOT_VALUE_ONE);
    RemoveSnapshotFiles(dbFile);
    CloseDb();
}

/**
 * @tc.number: RdbDataManager_3400
 * @tc.name: a stale handle of a rebuilt db is re-opened via the generation check
 * @tc.desc: 1.two managers cache their stores of the same db
 *           2.the second manager rebuilds the db directly, bumping the generation
 *           3.the first manager's next query must re-open the new db and see the
 *             data written after the rebuild
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_3400, Function | MediumTest | Level1)
{
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(DB_PATH + DB_NAME);
    auto mgrA = OpenDbAndTable();
    ASSERT_NE(mgrA, nullptr);
    EXPECT_TRUE(mgrA->InsertData(SNAPSHOT_KEY_TWO, SNAPSHOT_VALUE_TWO));
    auto mgrB = OpenDbAndTable();
    ASSERT_NE(mgrB, nullptr);
    std::string value;
    EXPECT_TRUE(mgrA->QueryData(SNAPSHOT_KEY_TWO, value));
    EXPECT_TRUE(mgrB->QueryData(SNAPSHOT_KEY_TWO, value));

    std::string dbFile = DB_PATH + DB_NAME;
    BmsRdbConfig rebuildConfig;
    rebuildConfig.dbPath = DB_PATH;
    rebuildConfig.dbName = DB_NAME;
    rebuildConfig.tableName = TABLE_NAME;
    NativeRdb::RdbStoreConfig rdbStoreConfig(dbFile);
    EXPECT_EQ(RdbRecoverManager::RebuildDbWithSnapshot(rebuildConfig, rdbStoreConfig,
        mgrB->rdbStore_, 0), ERR_OK);
    // data written to the rebuilt db through the fresh store
    EXPECT_TRUE(mgrB->InsertData("afterRebuild", "valueAfterRebuild"));

    // mgrA's cached handle belongs to the deleted file: the next query must
    // detect the generation change, re-open the db and see the new data
    std::string fresh;
    EXPECT_TRUE(mgrA->QueryData("afterRebuild", fresh));
    EXPECT_EQ(fresh, "valueAfterRebuild");
    std::string old;
    EXPECT_TRUE(mgrA->QueryData(SNAPSHOT_KEY_TWO, old));
    EXPECT_EQ(old, SNAPSHOT_VALUE_TWO);
    CloseDb();
}

/**
 * @tc.number: RdbDataManager_3500
 * @tc.name: an incompletely enumerated snapshot sets the db rebuild mark
 * @tc.desc: the EOF enumerated flag 0 means sqlite_master could not be fully
 *           read, so the core tables may be incomplete and the mark must be set
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_3500, Function | SmallTest | Level1)
{
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbPath = MARK_DB_PATH;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = TABLE_NAME;
    std::string dbFile = MARK_DB_PATH + ServiceConstants::BUNDLE_RDB_NAME;
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(dbFile);
    auto mgr = std::make_shared<RdbDataManager>(bmsRdbConfig);
    mgr->CreateTable();
    std::string snapshotPath = dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX;
    RemoveSnapshotFiles(dbFile);
    std::string snapshot = "BMS_SNAPSHOT_V1\n"
        "DBINFO\t" + std::string(ServiceConstants::BUNDLE_RDB_NAME) +
        "\t" + std::to_string(ServiceConstants::BUNDLE_RDB_VERSION) + "\n"
        "TABLE\tinstalled_bundle\t2\n"
        "SCHEMA\tCREATE TABLE IF NOT EXISTS installed_bundle"
        "(KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL);\n"
        "COLS\tKEY\tVALUE\n"
        "R\tcom.test.enumerated\tenumeratedValue\n"
        "END\tinstalled_bundle\t1\t1\n"
        "EOF\t1\t0\n";
    {
        std::ofstream out(snapshotPath);
        out << snapshot;
    }

    bool snapshotInvalid = false;
    int32_t replayErrCode = NativeRdb::E_OK;
    EXPECT_TRUE(RdbRecoverManager::RestoreFromSnapshotFile(mgr->bmsRdbConfig_.dbName,
        mgr->bmsRdbConfig_.version, mgr->rdbStore_, snapshotPath, snapshotInvalid, replayErrCode));
    EXPECT_FALSE(snapshotInvalid);
    EXPECT_EQ(QueryStringValue(mgr,
        "SELECT VALUE FROM bms_param WHERE KEY = '" +
        std::string(ServiceConstants::DB_REBUILD_MARK) + "'"),
        ServiceConstants::DB_REBUILD_MARK_DOING);
    RemoveSnapshotFiles(dbFile);
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(dbFile);
}

/**
 * @tc.number: RdbDataManager_3600
 * @tc.name: operation guard and integrity retry flag semantics
 * @tc.desc: 1.a guard constructed with the current generation is usable, one
 *             constructed with a stale generation is not
 *           2.the needIntegrityCheck_ flag set by a failed rebuild is consumed
 *             by the next open and serving continues
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_3600, Function | SmallTest | Level1)
{
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(DB_PATH + DB_NAME);
    auto mgr = OpenDbAndTable();
    ASSERT_NE(mgr, nullptr);
    EXPECT_TRUE(mgr->InsertData(SNAPSHOT_KEY_ONE, SNAPSHOT_VALUE_ONE));
    std::string value;
    EXPECT_TRUE(mgr->QueryData(SNAPSHOT_KEY_ONE, value));

    // the guard accepts the current generation and refuses a stale one
    uint64_t generation = RdbRecoverManager::GetDbGeneration(DB_NAME);
    RdbOpGuard freshGuard(DB_NAME, generation);
    EXPECT_TRUE(freshGuard.IsUsable());
    RdbOpGuard staleGuard(DB_NAME, generation - 1);
    EXPECT_FALSE(staleGuard.IsUsable());

    // a failed rebuild sets the retry flag; the next cold open must consume it
    // and re-run the integrity check (healthy db: serving simply continues)
    mgr->needIntegrityCheck_ = true;
    mgr->rdbStore_ = nullptr; // force the next query through the open path
    std::string recovered;
    EXPECT_TRUE(mgr->QueryData(SNAPSHOT_KEY_ONE, recovered));
    EXPECT_EQ(recovered, SNAPSHOT_VALUE_ONE);
    EXPECT_FALSE(mgr->needIntegrityCheck_);
    // a normal open leaves the flag clear
    mgr->rdbStore_ = nullptr;
    EXPECT_TRUE(mgr->QueryData(SNAPSHOT_KEY_ONE, recovered));
    EXPECT_FALSE(mgr->needIntegrityCheck_);
    CloseDb();
}

/**
 * @tc.number: RdbDataManager_3700
 * @tc.name: db is salvaged through the leftover snapshot on a forced re-check
 * @tc.desc: 1.fill the db, export a snapshot, then delete the db files
 *             (simulating a corrupted db whose salvage rebuild was interrupted
 *             after the export, before the replay committed)
 *           2.the retry flag (set by a failed rebuild in production) forces the
 *             integrity re-check on the next open (the process-wide first-open
 *             latch alone would skip the check)
 *           3.the leftover snapshot recovery restores the data and serves again
 *           4.the retry flag is consumed and the snapshot cleaned at the
 *             commit point
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_3700, Function | MediumTest | Level1)
{
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(DB_PATH + DB_NAME);
    auto mgr = OpenDbAndTable();
    ASSERT_NE(mgr, nullptr);
    std::string longValue(CORRUPT_TEST_VALUE_LEN, 'x');
    for (int32_t i = 0; i < CORRUPT_TEST_ROW_COUNT; i++) {
        EXPECT_TRUE(mgr->InsertData("corruptKey" + std::to_string(i), longValue));
    }
    std::string value;
    EXPECT_TRUE(mgr->QueryData("corruptKey0", value));

    std::string dbFile = DB_PATH + DB_NAME;
    std::string snapshotPath = dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX;
    RemoveSnapshotFiles(dbFile);
    // export a valid snapshot before destroying the db
    BmsRdbConfig snapshotConfig;
    snapshotConfig.dbPath = DB_PATH;
    snapshotConfig.dbName = DB_NAME;
    snapshotConfig.tableName = TABLE_NAME;
    EXPECT_TRUE(RdbRecoverManager::WriteSnapshotFile(snapshotConfig, mgr->rdbStore_, snapshotPath));
    EXPECT_EQ(access(snapshotPath.c_str(), F_OK), 0);

    // simulate a corrupted db that needs a rebuild: delete the db files but
    // keep the snapshot (the leftover recovery path picks it up on the next
    // open). this exercises the rebuild entry deterministically without relying
    // on file corruption hitting a data page (page layout is a sqlite
    // implementation detail that varies with page size and build options)
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(dbFile);
    // the next open must re-check: the process-wide first-open latch would
    // skip it, the retry flag (production: set by a failed rebuild at
    // rdb_data_manager.cpp) forces the check
    BmsRdbConfig salvageConfig;
    salvageConfig.dbPath = DB_PATH;
    salvageConfig.dbName = DB_NAME;
    salvageConfig.tableName = TABLE_NAME;
    auto salvageMgr = std::make_shared<RdbDataManager>(salvageConfig);
    salvageMgr->needIntegrityCheck_ = true;
    // the open replays the leftover snapshot before any data is served
    EXPECT_TRUE(salvageMgr->CreateTable());
    std::string recovered;
    EXPECT_TRUE(salvageMgr->QueryData("corruptKey0", recovered));
    EXPECT_EQ(recovered, longValue);
    // the forced re-check consumed the retry flag
    EXPECT_FALSE(salvageMgr->needIntegrityCheck_);
    // the leftover snapshot was consumed and cleaned at the commit point
    EXPECT_EQ(access(snapshotPath.c_str(), F_OK), -1);
    RemoveSnapshotFiles(dbFile);
    CloseDb();
}

/**
 * @tc.number: RdbDataManager_3800
 * @tc.name: downgrade on the main db sets the rebuild mark and the failed snapshot
 * @tc.desc: 1.craft an unsalvageable snapshot for the bms db
 *           2.after the downgrade the dbRebuildMark is set and the .failed file
 *             exists exactly at the path the event handler computes
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_3800, Function | MediumTest | Level1)
{
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbPath = MARK_DB_PATH;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = TABLE_NAME;
    std::string dbFile = MARK_DB_PATH + ServiceConstants::BUNDLE_RDB_NAME;
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(dbFile);
    // no CreateTable here: it would warm the store cache and the first poll
    // insert would succeed through it, never reaching the snapshot replay
    auto mgr = std::make_shared<RdbDataManager>(bmsRdbConfig);
    std::string snapshotPath = dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX;
    RemoveSnapshotFiles(dbFile);
    std::string snapshot = "BMS_SNAPSHOT_V1\n"
        "DBINFO\t" + std::string(ServiceConstants::BUNDLE_RDB_NAME) +
        "\t" + std::to_string(bmsRdbConfig.version) + "\n"
        "TABLE\tinstalled_bundle\t2\n"
        "SCHEMA\tCREATE TABLE installed_bundle(KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL)\n"
        "COLS\tKEY\tVALUE\n"
        "R\tdupKey\tvalueOne\n"
        "R\tdupKey\tvalueTwo\n"
        "END\tinstalled_bundle\t2\t1\n"
        "EOF\t1\t1\n";
    {
        std::ofstream out(snapshotPath);
        out << snapshot;
    }

    // poll until the downgrade happens, the counter starting point is irrelevant
    bool downgraded = false;
    std::string value;
    for (int32_t i = 0; i < DOWNGRADE_POLL_MAX_TRIES; i++) {
        if (mgr->InsertData("afterDowngrade", "valueAfter")) {
            downgraded = true;
            break;
        }
    }
    EXPECT_TRUE(downgraded);
    // the mark tells the boot path to rescan the install dirs
    EXPECT_EQ(QueryStringValue(mgr,
        "SELECT VALUE FROM bms_param WHERE KEY = '" +
        std::string(ServiceConstants::DB_REBUILD_MARK) + "'"),
        ServiceConstants::DB_REBUILD_MARK_DOING);
    // the failed snapshot exists exactly where the event handler looks for it:
    // this pins the writer/reader path contract
    std::string failedPath = RdbRecoverManager::BuildFailedSnapshotPath(
        MARK_DB_PATH, ServiceConstants::BUNDLE_RDB_NAME);
    EXPECT_EQ(failedPath, dbFile + ServiceConstants::RDB_SNAPSHOT_FAILED_SUFFIX);
    EXPECT_EQ(access(failedPath.c_str(), F_OK), 0);
    RemoveSnapshotFiles(dbFile);
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(dbFile);
}

/**
 * @tc.number: RdbDataManager_3900
 * @tc.name: commit point stops serving when the snapshot cannot be removed
 * @tc.desc: 1.craft a valid leftover snapshot and block the tmp path with a
 *             directory so the commit point unlink fails with EISDIR
 *           2.the recovery stops serving the db instead of leaving the
 *             "not committed" marker behind
 *           3.after the blockage is removed the next open serves the data
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_3900, Function | SmallTest | Level1)
{
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(DB_PATH + DB_NAME);
    auto keyMgr = OpenDbAndTable();
    ASSERT_NE(keyMgr, nullptr);
    EXPECT_TRUE(keyMgr->InsertData(SNAPSHOT_KEY_ONE, SNAPSHOT_VALUE_ONE));
    std::string value;
    EXPECT_TRUE(keyMgr->QueryData(SNAPSHOT_KEY_ONE, value));
    BmsRdbConfig snapshotConfig;
    snapshotConfig.dbPath = DB_PATH;
    snapshotConfig.dbName = DB_NAME;
    snapshotConfig.tableName = TABLE_NAME;
    std::string dbFile = DB_PATH + DB_NAME;
    std::string snapshotPath = dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX;
    std::string tmpPath = dbFile + ServiceConstants::RDB_SNAPSHOT_TMP_SUFFIX;
    RemoveSnapshotFiles(dbFile);
    EXPECT_TRUE(RdbRecoverManager::WriteSnapshotFile(snapshotConfig, keyMgr->rdbStore_, snapshotPath));
    // a directory occupying the tmp path makes unlink fail with EISDIR at the
    // commit point while the replay itself is unaffected
    ASSERT_EQ(mkdir(tmpPath.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH), 0);

    auto mgr = std::make_shared<RdbDataManager>(snapshotConfig);
    std::string ignored;
    // the open replays successfully but must refuse to serve: the snapshot
    // marker could not be cleared
    EXPECT_FALSE(mgr->QueryData(SNAPSHOT_KEY_ONE, ignored));
    // remove the blockage: the next open replays the (still present) snapshot
    // data or serves the already replayed db
    ASSERT_EQ(rmdir(tmpPath.c_str()), 0);
    std::string recovered;
    EXPECT_TRUE(mgr->QueryData(SNAPSHOT_KEY_ONE, recovered));
    EXPECT_EQ(recovered, SNAPSHOT_VALUE_ONE);
    RemoveSnapshotFiles(dbFile);
    CloseDb();
}

/**
 * @tc.number: RdbDataManager_4000
 * @tc.name: invalid snapshot is deleted when the rename to failed fails
 * @tc.desc: 1.craft a garbage snapshot and block the .recover.failed path with
 *             a directory so the forensics rename fails
 *           2.the fallback deletes the snapshot instead of leaving it behind
 *             to be replayed on every open
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_4000, Function | SmallTest | Level1)
{
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(DB_PATH + DB_NAME);
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbPath = DB_PATH;
    bmsRdbConfig.dbName = DB_NAME;
    bmsRdbConfig.tableName = TABLE_NAME;
    auto mgr = std::make_shared<RdbDataManager>(bmsRdbConfig);
    std::string value;
    EXPECT_FALSE(mgr->QueryData("warmup", value));
    // drop the warmed cache so the next query goes through the open path and
    // actually processes the leftover snapshot
    mgr->rdbStore_ = nullptr;
    std::string dbFile = DB_PATH + DB_NAME;
    std::string snapshotPath = dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX;
    std::string failedPath = dbFile + ServiceConstants::RDB_SNAPSHOT_FAILED_SUFFIX;
    RemoveSnapshotFiles(dbFile);
    {
        std::ofstream out(snapshotPath);
        out << "garbage not a snapshot";
    }
    // a directory occupying the failed path makes the rename fail
    ASSERT_EQ(mkdir(failedPath.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH), 0);

    std::string ignored;
    EXPECT_FALSE(mgr->QueryData("warmup", ignored));
    // the fallback deleted the snapshot: no leftover marker replays on opens
    EXPECT_EQ(access(snapshotPath.c_str(), F_OK), -1);
    // the db serves again once the blockage is removed
    ASSERT_EQ(rmdir(failedPath.c_str()), 0);
    EXPECT_TRUE(mgr->CreateTable());
    EXPECT_TRUE(mgr->InsertData("afterFallback", "valueAfter"));
    RemoveSnapshotFiles(dbFile);
    CloseDb();
}

/**
 * @tc.number: RdbDataManager_4100
 * @tc.name: a failed salvage rebuild sets the retry flag, the next open retries
 * @tc.desc: 1.block the snapshot export with a directory on the tmp path
 *           2.a salvage rebuild on the live store fails on the export and the
 *             production failure branch stops serving the db and marks it
 *             corrupted for the whole process
 *           3.after the blockage is removed the next open (carrying the retry
 *             flag the failed rebuild set in production) re-checks the
 *             integrity, clears the corruption refusal and serves the intact
 *             data again
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_4100, Function | MediumTest | Level1)
{
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(DB_PATH + DB_NAME);
    auto mgr = OpenDbAndTable();
    ASSERT_NE(mgr, nullptr);
    std::string longValue(CORRUPT_TEST_VALUE_LEN, 'x');
    for (int32_t i = 0; i < CORRUPT_TEST_ROW_COUNT; i++) {
        EXPECT_TRUE(mgr->InsertData("retryKey" + std::to_string(i), longValue));
    }
    std::string value;
    EXPECT_TRUE(mgr->QueryData("retryKey0", value));

    std::string dbFile = DB_PATH + DB_NAME;
    std::string snapshotPath = dbFile + ServiceConstants::RDB_SNAPSHOT_SUFFIX;
    std::string tmpPath = dbFile + ServiceConstants::RDB_SNAPSHOT_TMP_SUFFIX;
    RemoveSnapshotFiles(dbFile);
    // block the export with a directory on the tmp path: the salvage rebuild
    // fails deterministically on the export, no file corruption needed
    ASSERT_EQ(mkdir(tmpPath.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH), 0);

    BmsRdbConfig retryConfig;
    retryConfig.dbPath = DB_PATH;
    retryConfig.dbName = DB_NAME;
    retryConfig.tableName = TABLE_NAME;
    NativeRdb::RdbStoreConfig rdbStoreConfig(dbFile);
    auto retryMgr = std::make_shared<RdbDataManager>(retryConfig);
    // warm the store of the retry manager through the regular open path
    EXPECT_TRUE(retryMgr->CreateTable());
    // the salvage rebuild fails on the blocked export: the production failure
    // branch nulls the store and marks the db corrupted for the whole process
    ErrCode ret = RdbRecoverManager::RebuildDbWithSnapshot(retryConfig, rdbStoreConfig,
        retryMgr->rdbStore_, 0);
    EXPECT_EQ(ret, NativeRdb::E_SQLITE_IOERR);
    EXPECT_EQ(retryMgr->rdbStore_, nullptr);
    EXPECT_TRUE(RdbRecoverManager::IsCorruptionDetected(DB_NAME));
    // the failed rebuild set the retry flag through the open path in production
    // (GetRdbStoreFromNative), plant it the same way for the retry below
    retryMgr->needIntegrityCheck_ = true;
    // remove the blockage: the next open retries and the db serves again
    ASSERT_EQ(rmdir(tmpPath.c_str()), 0);
    std::string recovered;
    EXPECT_TRUE(retryMgr->QueryData("retryKey0", recovered));
    EXPECT_EQ(recovered, longValue);
    // the re-check consumed the retry flag and the healthy db cleared the
    // corruption refusal
    EXPECT_FALSE(retryMgr->needIntegrityCheck_);
    EXPECT_FALSE(RdbRecoverManager::IsCorruptionDetected(DB_NAME));
    RemoveSnapshotFiles(dbFile);
    CloseDb();
}

/**
 * @tc.number: RdbDataManager_4200
 * @tc.name: other instances refuse the db while corruption is detected
 * @tc.desc: 1.warm a cached store on a healthy db
 *           2.plant the process-wide corruption flag the way another
 *             instance's failed salvage export would (the natural set path is
 *             covered by 4100; planting it directly is the only deterministic
 *             construction, because a second manager would share this warm
 *             write connection and its page cache, making the integrity check
 *             see the pre-corruption pages)
 *           3.the cached-store operation is rejected and the handle dropped
 *           4.the next cold open re-runs the integrity check on the healthy
 *             db, clears the flag and serving resumes
 */
HWTEST_F(BmsRdbDataManagerTest, RdbDataManager_4200, Function | SmallTest | Level1)
{
    OHOS::NativeRdb::RdbHelper::DeleteRdbStore(DB_PATH + DB_NAME);
    auto mgrA = OpenDbAndTable();
    ASSERT_NE(mgrA, nullptr);
    EXPECT_TRUE(mgrA->InsertData(SNAPSHOT_KEY_ONE, SNAPSHOT_VALUE_ONE));
    std::string value;
    EXPECT_TRUE(mgrA->QueryData(SNAPSHOT_KEY_ONE, value));

    // simulate another instance's failed salvage export
    RdbRecoverManager::MarkCorruptionDetected(DB_NAME);
    EXPECT_TRUE(RdbRecoverManager::IsCorruptionDetected(DB_NAME));
    // the cached-store operation must be rejected instead of serving the db
    // that another instance reported as corrupted
    EXPECT_FALSE(mgrA->QueryData(SNAPSHOT_KEY_ONE, value));
    EXPECT_EQ(mgrA->rdbStore_, nullptr);
    // the flag is still set: the next cold open re-runs the integrity check,
    // the healthy db clears the flag ("healthy again" path) and serves
    std::string recovered;
    EXPECT_TRUE(mgrA->QueryData(SNAPSHOT_KEY_ONE, recovered));
    EXPECT_EQ(recovered, SNAPSHOT_VALUE_ONE);
    EXPECT_FALSE(RdbRecoverManager::IsCorruptionDetected(DB_NAME));
    CloseDb();
}

}  // namespace
