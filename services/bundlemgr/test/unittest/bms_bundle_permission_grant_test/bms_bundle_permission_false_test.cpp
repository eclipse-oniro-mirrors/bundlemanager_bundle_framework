/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "errors.h"
#define private public

#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>

#include "bundle_info.h"
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_verify_mgr.h"
#include "inner_bundle_info.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "mock_clean_cache.h"
#include "mock_bundle_status.h"
#include "mock_status_receiver.h"
#include "permission_define.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "bundlName";
const std::string ABILITY_NAME = "abilityName";
const std::string MOUDLE_NAME = "moduleName";
const std::string APPID = "appId";
const std::string HAP_FILE_PATH = "/data/test/resource/bms/permission_bundle/";
const std::string HAP_FILE_PATH1 = "/data/test/resource/bms/bundle_kit/test.hap";
const std::string DEFAULT_APP_VIDEO = "VIDEO";
const int32_t USERID = 100;
const int32_t FLAGS = 0;
const int32_t UID = 0;
const int32_t WAIT_TIME = 5; // init mocked bms
constexpr int PERMISSION_NOT_GRANTED = -1;
}  // namespace

class BmsBundlePermissionFalseTest : public testing::Test {
public:
    BmsBundlePermissionFalseTest();
    ~BmsBundlePermissionFalseTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    void StartInstalldService() const;
    void StartBundleService();
private:
    std::shared_ptr<BundleMgrHostImpl> bundleMgrHostImpl_ = std::make_unique<BundleMgrHostImpl>();
    std::shared_ptr<BundleInstallerHost> bundleInstallerHost_ = std::make_unique<BundleInstallerHost>();
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundlePermissionFalseTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundlePermissionFalseTest::installdService_ =
    std::make_shared<InstalldService>();

BmsBundlePermissionFalseTest::BmsBundlePermissionFalseTest()
{}

BmsBundlePermissionFalseTest::~BmsBundlePermissionFalseTest()
{}

void BmsBundlePermissionFalseTest::SetUpTestCase()
{}

void BmsBundlePermissionFalseTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundlePermissionFalseTest::SetUp()
{
    StartInstalldService();
    StartBundleService();
}

void BmsBundlePermissionFalseTest::TearDown()
{}

void BmsBundlePermissionFalseTest::StartInstalldService() const
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsBundlePermissionFalseTest::StartBundleService()
{
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

const std::shared_ptr<BundleDataMgr> BmsBundlePermissionFalseTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_0100
 * @tc.name: test GetApplicationInfo of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetApplicationInfo false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_0100, Function | SmallTest | Level0)
{
    ApplicationInfo appInfo;
    bool ret = bundleMgrHostImpl_->GetApplicationInfo(BUNDLE_NAME, FLAGS, USERID, appInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_0200
 * @tc.name: test GetApplicationInfoV9 of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetApplicationInfoV9 false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_0200, Function | SmallTest | Level0)
{
    ApplicationInfo appInfo;
    ErrCode ret = bundleMgrHostImpl_->GetApplicationInfoV9(BUNDLE_NAME, FLAGS, USERID, appInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_0300
 * @tc.name: test GetApplicationInfos of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetApplicationInfos false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_0300, Function | SmallTest | Level0)
{
    std::vector<ApplicationInfo> appInfos;
    bool ret = bundleMgrHostImpl_->GetApplicationInfos(FLAGS, USERID, appInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_0400
 * @tc.name: test GetApplicationInfosV9 of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetApplicationInfosV9 false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_0400, Function | SmallTest | Level0)
{
    std::vector<ApplicationInfo> appInfos;
    ErrCode ret = bundleMgrHostImpl_->GetApplicationInfosV9(FLAGS, USERID, appInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_0500
 * @tc.name: test GetBundleInfo of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetBundleInfo false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_0500, Function | SmallTest | Level0)
{
    BundleInfo bundleInfo;
    bool ret = bundleMgrHostImpl_->GetBundleInfo(BUNDLE_NAME, FLAGS, bundleInfo, USERID);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_0600
 * @tc.name: test GetBaseSharedBundleInfos of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetBaseSharedBundleInfos false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_0600, Function | SmallTest | Level0)
{
    std::vector<BaseSharedBundleInfo> baseSharedBundleInfos;
    ErrCode ret = bundleMgrHostImpl_->GetBaseSharedBundleInfos(BUNDLE_NAME, baseSharedBundleInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_0700
 * @tc.name: test GetBundleInfoV9 of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetBundleInfoV9 false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_0700, Function | SmallTest | Level0)
{
    BundleInfo bundleInfo;
    ErrCode ret = bundleMgrHostImpl_->GetBundleInfoV9(BUNDLE_NAME, FLAGS, bundleInfo, USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_0800
 * @tc.name: test GetBundlePackInfo of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetBundlePackInfo false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_0800, Function | SmallTest | Level0)
{
    BundlePackInfo bundlePackInfo;
    ErrCode ret = bundleMgrHostImpl_->GetBundlePackInfo(BUNDLE_NAME, FLAGS, bundlePackInfo, USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_0900
 * @tc.name: test GetBundleInfos of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetBundleInfos false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_0900, Function | SmallTest | Level0)
{
    std::vector<BundleInfo> bundleInfos;
    bool ret = bundleMgrHostImpl_->GetBundleInfos(FLAGS, bundleInfos, USERID);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_1000
 * @tc.name: test GetBundleInfos of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetBundleInfos false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_1000, Function | SmallTest | Level0)
{
    std::vector<BundleInfo> bundleInfos;
    ErrCode ret = bundleMgrHostImpl_->GetBundleInfosV9(FLAGS, bundleInfos, USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_1100
 * @tc.name: test GetNameForUid of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetNameForUid false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_1100, Function | SmallTest | Level0)
{
    std::string name;
    ErrCode ret = bundleMgrHostImpl_->GetNameForUid(UID, name);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_1200
 * @tc.name: test GetBundleInfosByMetaData of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetBundleInfosByMetaData false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_1200, Function | SmallTest | Level0)
{
    std::vector<BundleInfo> bundleInfos;
    bool ret = bundleMgrHostImpl_->GetBundleInfosByMetaData(BUNDLE_NAME, bundleInfos);
    EXPECT_EQ(ret, false);
}

#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL

/**
 * @tc.number: BmsBundlePermissionFalseTest_1300
 * @tc.name: test QueryAbilityInfo of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. QueryAbilityInfo false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_1300, Function | SmallTest | Level0)
{
    Want want;
    AbilityInfo abilityInfo;
    bool ret = bundleMgrHostImpl_->QueryAbilityInfo(want, FLAGS, USERID, abilityInfo, nullptr);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_1400
 * @tc.name: test CheckAbilityEnableInstall of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. CheckAbilityEnableInstall false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_1400, Function | SmallTest | Level0)
{
    Want want;
    int32_t missionId = 0;
    bool ret = bundleMgrHostImpl_->CheckAbilityEnableInstall(want, missionId, USERID, nullptr);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_1500
 * @tc.name: test ProcessPreload of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. ProcessPreload false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_1500, Function | SmallTest | Level0)
{
    Want want;
    bool ret = bundleMgrHostImpl_->ProcessPreload(want);
    EXPECT_EQ(ret, false);
}
#endif

/**
 * @tc.number: BmsBundlePermissionFalseTest_1600
 * @tc.name: test QueryAbilityInfo of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. QueryAbilityInfo false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_1600, Function | SmallTest | Level0)
{
    Want want;
    AbilityInfo abilityInfo;
    bool ret = bundleMgrHostImpl_->QueryAbilityInfo(want, FLAGS, USERID, abilityInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_1700
 * @tc.name: test QueryAbilityInfos of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. QueryAbilityInfos false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_1700, Function | SmallTest | Level0)
{
    Want want;
    std::vector<AbilityInfo> abilityInfos;
    bool ret = bundleMgrHostImpl_->QueryAbilityInfos(want, FLAGS, USERID, abilityInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_1800
 * @tc.name: test QueryAbilityInfosV9 of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. QueryAbilityInfosV9 false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_1800, Function | SmallTest | Level0)
{
    Want want;
    std::vector<AbilityInfo> abilityInfos;
    ErrCode ret = bundleMgrHostImpl_->QueryAbilityInfosV9(want, FLAGS, USERID, abilityInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_1900
 * @tc.name: test QueryAllAbilityInfos of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. QueryAllAbilityInfos false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_1900, Function | SmallTest | Level0)
{
    Want want;
    std::vector<AbilityInfo> abilityInfos;
    bool ret = bundleMgrHostImpl_->QueryAllAbilityInfos(want, USERID, abilityInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_2000
 * @tc.name: test QueryAbilityInfoByUri of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. QueryAbilityInfoByUri false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_2000, Function | SmallTest | Level0)
{
    AbilityInfo abilityInfo;
    bool ret = bundleMgrHostImpl_->QueryAbilityInfoByUri(BUNDLE_NAME, abilityInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_2100
 * @tc.name: test QueryAbilityInfoByUri of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. QueryAbilityInfoByUri false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_2100, Function | SmallTest | Level0)
{
    AbilityInfo abilityInfo;
    bool ret = bundleMgrHostImpl_->QueryAbilityInfoByUri(BUNDLE_NAME, USERID, abilityInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_2200
 * @tc.name: test QueryKeepAliveBundleInfos of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. QueryKeepAliveBundleInfos false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_2200, Function | SmallTest | Level0)
{
    std::vector<BundleInfo> bundleInfos;
    bool ret = bundleMgrHostImpl_->QueryKeepAliveBundleInfos(bundleInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_2300
 * @tc.name: test GetAbilityLabel of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetAbilityLabel false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_2300, Function | SmallTest | Level0)
{
    std::string ret = bundleMgrHostImpl_->GetAbilityLabel(BUNDLE_NAME, ABILITY_NAME);
    EXPECT_EQ(ret, Constants::EMPTY_STRING);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_2400
 * @tc.name: test GetAbilityLabel of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetAbilityLabel false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_2400, Function | SmallTest | Level0)
{
    std::string label;
    ErrCode ret = bundleMgrHostImpl_->GetAbilityLabel(BUNDLE_NAME, MOUDLE_NAME, ABILITY_NAME, label);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_2500
 * @tc.name: test GetBundleArchiveInfoV9 of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetBundleArchiveInfoV9 false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_2500, Function | SmallTest | Level0)
{
    BundleInfo bundleInfo;
    ErrCode ret = bundleMgrHostImpl_->GetBundleArchiveInfoV9(HAP_FILE_PATH, FLAGS, bundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_2600
 * @tc.name: test GetHapModuleInfo of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetHapModuleInfo false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_2600, Function | SmallTest | Level0)
{
    AbilityInfo abilityInfo;
    abilityInfo.bundleName = ABILITY_NAME;
    HapModuleInfo hapModuleInfo;
    bool ret = bundleMgrHostImpl_->GetHapModuleInfo(abilityInfo, USERID, hapModuleInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_2700
 * @tc.name: test GetLaunchWantForBundle of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetLaunchWantForBundle false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_2700, Function | SmallTest | Level0)
{
    Want want;
    ErrCode ret = bundleMgrHostImpl_->GetLaunchWantForBundle(BUNDLE_NAME, want, USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_2800
 * @tc.name: test GetPermissionDef of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetPermissionDef false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_2800, Function | SmallTest | Level0)
{
    PermissionDef permissionDef;
    ErrCode ret = bundleMgrHostImpl_->GetPermissionDef(BUNDLE_NAME, permissionDef);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_2900
 * @tc.name: test CleanBundleCacheFiles of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. CleanBundleCacheFiles false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_2900, Function | SmallTest | Level0)
{
    sptr<MockCleanCache> cleanCache = new (std::nothrow) MockCleanCache();
    ErrCode ret = bundleMgrHostImpl_->CleanBundleCacheFiles(BUNDLE_NAME, cleanCache, USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_3000
 * @tc.name: test CleanBundleDataFiles of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. CleanBundleDataFiles false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_3000, Function | SmallTest | Level0)
{
    bool ret = bundleMgrHostImpl_->CleanBundleDataFiles(BUNDLE_NAME, USERID);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_3100
 * @tc.name: test RegisterBundleStatusCallback of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. RegisterBundleStatusCallback false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_3100, Function | SmallTest | Level0)
{
    sptr<MockBundleStatus> bundleStatusCallback = new (std::nothrow) MockBundleStatus();
    bool ret = bundleMgrHostImpl_->RegisterBundleStatusCallback(bundleStatusCallback);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_3200
 * @tc.name: test ClearBundleStatusCallback of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. ClearBundleStatusCallback false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_3200, Function | SmallTest | Level0)
{
    sptr<MockBundleStatus> bundleStatusCallback = new (std::nothrow) MockBundleStatus();
    bool ret = bundleMgrHostImpl_->ClearBundleStatusCallback(bundleStatusCallback);
    EXPECT_EQ(ret, false);
    bundleMgrHostImpl_->UnregisterBundleStatusCallback();
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_3300
 * @tc.name: test DumpInfos of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. DumpInfos false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_3300, Function | SmallTest | Level0)
{
    std::string result;
    bool ret = bundleMgrHostImpl_->DumpInfos(DumpFlag::DUMP_BUNDLE_LIST, BUNDLE_NAME, USERID, result);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_3400
 * @tc.name: test IsModuleRemovable of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. IsModuleRemovable false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_3400, Function | SmallTest | Level0)
{
    bool isRemovable = false;
    ErrCode ret = bundleMgrHostImpl_->IsModuleRemovable(BUNDLE_NAME, MOUDLE_NAME, isRemovable);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_3500
 * @tc.name: test SetModuleRemovable of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. SetModuleRemovable false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_3500, Function | SmallTest | Level0)
{
    bool isEnable = false;
    bool ret = bundleMgrHostImpl_->SetModuleRemovable(BUNDLE_NAME, MOUDLE_NAME, isEnable);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_3600
 * @tc.name: test GetModuleUpgradeFlag of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetModuleUpgradeFlag false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_3600, Function | SmallTest | Level0)
{
    bool ret = bundleMgrHostImpl_->GetModuleUpgradeFlag(BUNDLE_NAME, MOUDLE_NAME);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_3700
 * @tc.name: test SetModuleUpgradeFlag of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. SetModuleUpgradeFlag false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_3700, Function | SmallTest | Level0)
{
    bool upgradeFlag = false;
    ErrCode ret = bundleMgrHostImpl_->SetModuleUpgradeFlag(BUNDLE_NAME, MOUDLE_NAME, upgradeFlag);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_3800
 * @tc.name: test SetApplicationEnabled of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. SetApplicationEnabled false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_3800, Function | SmallTest | Level0)
{
    bool isEnable = false;
    ErrCode ret = bundleMgrHostImpl_->SetApplicationEnabled(BUNDLE_NAME, isEnable, USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_3900
 * @tc.name: test SetAbilityEnabled of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. SetAbilityEnabled false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_3900, Function | SmallTest | Level0)
{
    bool isEnable = false;
    AbilityInfo abilityInfo;
    ErrCode ret = bundleMgrHostImpl_->SetAbilityEnabled(abilityInfo, isEnable, USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_4000
 * @tc.name: test GetAllFormsInfo of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetAllFormsInfo false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_4000, Function | SmallTest | Level0)
{
    std::vector<FormInfo> formInfos;
    bool ret = bundleMgrHostImpl_->GetAllFormsInfo(formInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_4100
 * @tc.name: test GetFormsInfoByApp of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetFormsInfoByApp false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_4100, Function | SmallTest | Level0)
{
    std::vector<FormInfo> formInfos;
    bool ret = bundleMgrHostImpl_->GetFormsInfoByApp(BUNDLE_NAME, formInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_4200
 * @tc.name: test GetFormsInfoByModule of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetFormsInfoByModule false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_4200, Function | SmallTest | Level0)
{
    std::vector<FormInfo> formInfos;
    bool ret = bundleMgrHostImpl_->GetFormsInfoByModule(BUNDLE_NAME, MOUDLE_NAME, formInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_4300
 * @tc.name: test GetShortcutInfos of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetShortcutInfos false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_4300, Function | SmallTest | Level0)
{
    std::vector<ShortcutInfo> shortcutInfos;
    bool ret = bundleMgrHostImpl_->GetShortcutInfos(BUNDLE_NAME, USERID, shortcutInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_4400
 * @tc.name: test GetShortcutInfos of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetShortcutInfos false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_4400, Function | SmallTest | Level0)
{
    std::vector<ShortcutInfo> shortcutInfos;
    ErrCode ret = bundleMgrHostImpl_->GetShortcutInfoV9(BUNDLE_NAME, shortcutInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_4500
 * @tc.name: test GetAllCommonEventInfo of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetAllCommonEventInfo false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_4500, Function | SmallTest | Level0)
{
    std::vector<CommonEventInfo> commonEventInfos;
    bool ret = bundleMgrHostImpl_->GetAllCommonEventInfo(BUNDLE_NAME, commonEventInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_4600
 * @tc.name: test QueryExtensionAbilityInfos of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. QueryExtensionAbilityInfos false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_4600, Function | SmallTest | Level0)
{
    Want want;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    bool ret = bundleMgrHostImpl_->QueryExtensionAbilityInfos(want, FLAGS, USERID, extensionInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_4700
 * @tc.name: test QueryExtensionAbilityInfosV9 of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. QueryExtensionAbilityInfosV9 false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_4700, Function | SmallTest | Level0)
{
    Want want;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    ErrCode ret = bundleMgrHostImpl_->QueryExtensionAbilityInfosV9(want, FLAGS, USERID, extensionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);

    ret = bundleMgrHostImpl_->QueryExtensionAbilityInfosV9(
        want, ExtensionAbilityType::FORM, FLAGS, USERID, extensionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_4800
 * @tc.name: test QueryExtensionAbilityInfos of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. QueryExtensionAbilityInfos false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_4800, Function | SmallTest | Level0)
{
    Want want;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    bool ret = bundleMgrHostImpl_->QueryExtensionAbilityInfos(
        want, ExtensionAbilityType::FORM, FLAGS, USERID, extensionInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_4900
 * @tc.name: test QueryExtensionAbilityInfos of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. QueryExtensionAbilityInfos false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_4900, Function | SmallTest | Level0)
{
    Want want;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    bool ret = bundleMgrHostImpl_->QueryExtensionAbilityInfos(
        want, ExtensionAbilityType::FORM, FLAGS, USERID, extensionInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_5000
 * @tc.name: test QueryExtensionAbilityInfos of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. QueryExtensionAbilityInfos false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_5000, Function | SmallTest | Level0)
{
    std::vector<ExtensionAbilityInfo> extensionInfos;
    bool ret = bundleMgrHostImpl_->QueryExtensionAbilityInfos(ExtensionAbilityType::FORM, USERID, extensionInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_5100
 * @tc.name: test QueryExtensionAbilityInfoByUri of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. QueryExtensionAbilityInfoByUri false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_5100, Function | SmallTest | Level0)
{
    ExtensionAbilityInfo extensionAbilityInfo;
    bool ret = bundleMgrHostImpl_->QueryExtensionAbilityInfoByUri(HAP_FILE_PATH, USERID, extensionAbilityInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_5200
 * @tc.name: test GetAppIdByBundleName of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetAppIdByBundleName false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_5200, Function | SmallTest | Level0)
{
    std::string ret = bundleMgrHostImpl_->GetAppIdByBundleName(BUNDLE_NAME, USERID);
    EXPECT_EQ(ret, Constants::EMPTY_STRING);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_5300
 * @tc.name: test GetAppType of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetAppType false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_5300, Function | SmallTest | Level0)
{
    std::string ret = bundleMgrHostImpl_->GetAppType(BUNDLE_NAME);
    EXPECT_EQ(ret, Constants::EMPTY_STRING);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_5400
 * @tc.name: test GetUidByBundleName of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetUidByBundleName false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_5400, Function | SmallTest | Level0)
{
    int ret = bundleMgrHostImpl_->GetUidByBundleName(BUNDLE_NAME, USERID);
    EXPECT_EQ(ret, Constants::INVALID_UID);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_5500
 * @tc.name: test ImplicitQueryInfoByPriority of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. ImplicitQueryInfoByPriority false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_5500, Function | SmallTest | Level0)
{
    Want want;
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionInfo;
    bool ret = bundleMgrHostImpl_->ImplicitQueryInfoByPriority(want, FLAGS, USERID, abilityInfo, extensionInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_5600
 * @tc.name: test ImplicitQueryInfos of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. ImplicitQueryInfos false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_5600, Function | SmallTest | Level0)
{
    Want want;
    std::vector<AbilityInfo> abilityInfos;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    bool findDefaultApp = false;
    bundleMgrHostImpl_->UpgradeAtomicService(want, USERID);
    bool ret = bundleMgrHostImpl_->ImplicitQueryInfos(want, FLAGS, USERID, true, abilityInfos, extensionInfos,
        findDefaultApp);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(findDefaultApp, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_5700
 * @tc.name: test GetAllDependentModuleNames of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetAllDependentModuleNames false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_5700, Function | SmallTest | Level0)
{
    std::vector<std::string> dependentModuleNames;
    bool ret = bundleMgrHostImpl_->GetAllDependentModuleNames(BUNDLE_NAME, MOUDLE_NAME, dependentModuleNames);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_5800
 * @tc.name: test GetSandboxBundleInfo of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetSandboxBundleInfo false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_5800, Function | SmallTest | Level0)
{
    int32_t appIndex = Constants::INITIAL_SANDBOX_APP_INDEX + 1;
    BundleInfo info;
    ErrCode ret = bundleMgrHostImpl_->GetSandboxBundleInfo(BUNDLE_NAME, appIndex, USERID, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_5900
 * @tc.name: test GetBundleStats of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetBundleStats false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_5900, Function | SmallTest | Level0)
{
    std::vector<int64_t> bundleStats;
    bool ret = bundleMgrHostImpl_->GetBundleStats(BUNDLE_NAME, USERID, bundleStats);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_5900
 * @tc.name: test GetIconById of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetIconById false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_6000, Function | SmallTest | Level0)
{
    uint32_t resId = 0;
    uint32_t density = 0;
    std::string ret = bundleMgrHostImpl_->GetIconById(BUNDLE_NAME, MOUDLE_NAME, resId, density, USERID);
    EXPECT_EQ(ret, Constants::EMPTY_STRING);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_6100
 * @tc.name: test GetSandboxAbilityInfo of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetSandboxAbilityInfo false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_6100, Function | SmallTest | Level0)
{
    int32_t appIndex = Constants::INITIAL_SANDBOX_APP_INDEX + 1;
    Want want;
    AbilityInfo info;
    ErrCode ret = bundleMgrHostImpl_->GetSandboxAbilityInfo(want, appIndex, FLAGS, USERID, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_6200
 * @tc.name: test GetSandboxExtAbilityInfos of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetSandboxExtAbilityInfos false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_6200, Function | SmallTest | Level0)
{
    int32_t appIndex = Constants::INITIAL_SANDBOX_APP_INDEX + 1;
    Want want;
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode ret = bundleMgrHostImpl_->GetSandboxExtAbilityInfos(want, appIndex, FLAGS, USERID, infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_6300
 * @tc.name: test CleanBundleCacheFilesAutomatic of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. CleanBundleCacheFilesAutomatic false by cacheSize is 0
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_6300, Function | SmallTest | Level0)
{
    uint64_t cacheSize = 0;
    ErrCode ret = bundleMgrHostImpl_->CleanBundleCacheFilesAutomatic(cacheSize);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_6400
 * @tc.name: test GetAppProvisionInfo of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetAppProvisionInfo false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_6400, Function | SmallTest | Level0)
{
    AppProvisionInfo appProvisionInfo;
    ErrCode ret = bundleMgrHostImpl_->GetAppProvisionInfo(BUNDLE_NAME, USERID, appProvisionInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_6500
 * @tc.name: test GetProvisionMetadata of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetProvisionMetadata false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_6500, Function | SmallTest | Level0)
{
    std::vector<Metadata> provisionMetadatas;
    ErrCode ret = bundleMgrHostImpl_->GetProvisionMetadata(BUNDLE_NAME, USERID, provisionMetadatas);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_6600
 * @tc.name: test GetAllSharedBundleInfo of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetAllSharedBundleInfo false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_6600, Function | SmallTest | Level0)
{
    std::vector<SharedBundleInfo> sharedBundles;
    ErrCode ret = bundleMgrHostImpl_->GetAllSharedBundleInfo(sharedBundles);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_6700
 * @tc.name: test GetSharedBundleInfo of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetSharedBundleInfo false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_6700, Function | SmallTest | Level0)
{
    std::vector<SharedBundleInfo> sharedBundles;
    ErrCode ret = bundleMgrHostImpl_->GetSharedBundleInfo(BUNDLE_NAME, MOUDLE_NAME, sharedBundles);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_6800
 * @tc.name: test GetSharedDependencies of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetSharedDependencies false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_6800, Function | SmallTest | Level0)
{
    std::vector<Dependency> dependencies;
    ErrCode ret = bundleMgrHostImpl_->GetSharedDependencies(BUNDLE_NAME, MOUDLE_NAME, dependencies);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_6900
 * @tc.name: test GetMediaData of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetMediaData false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_6900, Function | SmallTest | Level0)
{
    std::unique_ptr<uint8_t[]> mediaDataPtr;
    size_t len = 0;
    ErrCode ret = bundleMgrHostImpl_->GetMediaData(BUNDLE_NAME, MOUDLE_NAME, ABILITY_NAME, mediaDataPtr, len, USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_7000
 * @tc.name: test Install of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. Install false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_7000, Function | SmallTest | Level0)
{
    InstallParam installParam;
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    bool ret = bundleInstallerHost_->Install(HAP_FILE_PATH, installParam, receiver);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_7100
 * @tc.name: test Install of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. Install false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_7100, Function | SmallTest | Level0)
{
    InstallParam installParam;
    std::vector<std::string> bundleFilePaths;
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    bool ret = bundleInstallerHost_->Install(bundleFilePaths, installParam, receiver);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_7200
 * @tc.name: test InstallByBundleName of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. InstallByBundleName false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_7200, Function | SmallTest | Level0)
{
    InstallParam installParam;
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    bool ret = bundleInstallerHost_->InstallByBundleName(BUNDLE_NAME, installParam, receiver);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_7300
 * @tc.name: test InstallSandboxApp of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. InstallSandboxApp false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_7300, Function | SmallTest | Level0)
{
    int32_t dplType = 1;
    int32_t appIndex = 1;
    ErrCode ret1 = bundleInstallerHost_->InstallSandboxApp(BUNDLE_NAME, dplType, USERID, appIndex);
    ErrCode ret2 = bundleInstallerHost_->UninstallSandboxApp(BUNDLE_NAME, appIndex, USERID);
    EXPECT_EQ(ret1, ERR_APPEXECFWK_PERMISSION_DENIED);
    EXPECT_EQ(ret2, ERR_APPEXECFWK_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_7400
 * @tc.name: test CreateStreamInstaller of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. CreateStreamInstaller false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_7400, Function | SmallTest | Level0)
{
    InstallParam installParam;
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    std::vector<std::string> originHapPaths;
    sptr<IBundleStreamInstaller> ret = bundleInstallerHost_->CreateStreamInstaller(
        installParam, receiver, originHapPaths);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_7500
 * @tc.name: test DestoryBundleStreamInstaller of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. DestoryBundleStreamInstaller false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_7500, Function | SmallTest | Level0)
{
    uint32_t streamInstallerId = 0;
    bool ret = bundleInstallerHost_->DestoryBundleStreamInstaller(streamInstallerId);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_7600
 * @tc.name: test Uninstall of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. Uninstall false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_7600, Function | SmallTest | Level0)
{
    UninstallParam uninstallParam;
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    bool ret = bundleInstallerHost_->Uninstall(uninstallParam, receiver);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_7700
 * @tc.name: test Recover of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. Recover false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_7700, Function | SmallTest | Level0)
{
    InstallParam installParam;
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    bool ret = bundleInstallerHost_->Recover(BUNDLE_NAME, installParam, receiver);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_7800
 * @tc.name: test Uninstall of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. Uninstall false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_7800, Function | SmallTest | Level0)
{
    InstallParam installParam;
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    bool ret = bundleInstallerHost_->Uninstall(BUNDLE_NAME, installParam, receiver);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_7900
 * @tc.name: test Uninstall of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. Uninstall false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_7900, Function | SmallTest | Level0)
{
    InstallParam installParam;
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    bool ret = bundleInstallerHost_->Uninstall(BUNDLE_NAME, ABILITY_NAME, installParam, receiver);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_8000
 * @tc.name: test GetDependentBundleInfo of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetDependentBundleInfo false
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_8000, Function | SmallTest | Level0)
{
    BundleInfo sharedBundleInfo;
    ErrCode ret = bundleMgrHostImpl_->GetDependentBundleInfo(BUNDLE_NAME, sharedBundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_8100
 * @tc.name: test CheckInstallParam of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. CheckInstallParam false
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_8100, Function | SmallTest | Level0)
{
    InstallParam installParam;
    installParam.userId = Constants::UNSPECIFIED_USERID;
    InstallParam ret = bundleInstallerHost_->CheckInstallParam(installParam);
    EXPECT_EQ(ret.userId, BundleUtil::GetUserIdByCallingUid());
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_8200
 * @tc.name: test UninstallSandboxApp of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. UninstallSandboxApp false
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_8200, Function | SmallTest | Level0)
{
    int32_t appIndex = -1;
    ErrCode ret = bundleInstallerHost_->UninstallSandboxApp("", appIndex, USERID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);

    ret = bundleInstallerHost_->UninstallSandboxApp(BUNDLE_NAME, appIndex, USERID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);

    appIndex = 1 + Constants::MAX_SANDBOX_APP_INDEX;
    ret = bundleInstallerHost_->UninstallSandboxApp(BUNDLE_NAME, appIndex, USERID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_8300
 * @tc.name: test CreateStream of BundleStreamInstallerHostImpl
 * @tc.desc: 1. system running normally
 *           2. CreateStream false
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_8300, Function | SmallTest | Level0)
{
    uint32_t installerId = 1;
    int32_t installedUid = 100;
    BundleStreamInstallerHostImpl impl(installerId, installedUid);
    int ret = impl.CreateStream(BUNDLE_NAME);
    EXPECT_EQ(ret, PERMISSION_NOT_GRANTED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_8400
 * @tc.name: test CreateSharedBundleStream of BundleStreamInstallerHostImpl
 * @tc.desc: 1. system running normally
 *           2. CreateSharedBundleStream false
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_8400, Function | SmallTest | Level0)
{
    uint32_t installerId = 1;
    int32_t installedUid = 100;
    BundleStreamInstallerHostImpl impl(installerId, installedUid);
    int ret = impl.CreateSharedBundleStream(BUNDLE_NAME, UID);
    EXPECT_EQ(ret, PERMISSION_NOT_GRANTED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_8700
 * @tc.name: test GetSandboxHapModuleInfo of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetSandboxHapModuleInfo false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_8700, Function | SmallTest | Level0)
{
    int32_t appIndex = 1 + Constants::INITIAL_SANDBOX_APP_INDEX;
    AbilityInfo abilityInfo;
    HapModuleInfo info;
    auto ret = bundleMgrHostImpl_->GetSandboxHapModuleInfo(abilityInfo, appIndex, USERID, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_8800
 * @tc.name: test QueryLauncherAbilityInfos
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_8800, Function | SmallTest | Level1)
{
    AAFwk::Want want;
    std::vector<AbilityInfo> abilityInfos;
    ErrCode testRet = bundleMgrHostImpl_->QueryLauncherAbilityInfos(want, USERID, abilityInfos);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_8900
 * @tc.name: test AppControlManagerHostImpl
 * @tc.desc: 1.SetDisposedStatus test
 *           2.GetDisposedStatus test
 *           3.DeleteDisposedStatus test
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_8900, Function | SmallTest | Level1)
{
    auto impl = std::make_shared<AppControlManagerHostImpl>();
    Want want;
    ErrCode res = impl->SetDisposedStatus(APPID, want, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);

    res = impl->GetDisposedStatus(APPID, want, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);

    res = impl->DeleteDisposedStatus(APPID, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_9000
 * @tc.name: test GetSpecifiedDistributionType
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_9000, Function | SmallTest | Level1)
{
    std::string specifiedDistributionType;
    ErrCode ret = bundleMgrHostImpl_->GetSpecifiedDistributionType("", specifiedDistributionType);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_9100
 * @tc.name: test GetAdditionalInfo
 * @tc.desc: 1.system run normally
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_9100, Function | SmallTest | Level1)
{
    std::string additionalInfo;
    ErrCode ret = bundleMgrHostImpl_->GetAdditionalInfo("", additionalInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_9200
 * @tc.name: test Install of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. Install false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_9200, Function | SmallTest | Level0)
{
    InstallParam installParam;
    sptr<IStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();
    EXPECT_NE(statusReceiver, nullptr);
    bundleInstallerHost_->Init();
    bool ret = bundleInstallerHost_->Install(HAP_FILE_PATH, installParam, statusReceiver);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_9300
 * @tc.name: test Install of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. Install false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_9300, Function | SmallTest | Level0)
{
    InstallParam installParam;
    sptr<IStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();
    EXPECT_NE(statusReceiver, nullptr);
    bundleInstallerHost_->Init();
    std::vector<std::string> bundleFilePaths;
    bundleFilePaths.push_back(HAP_FILE_PATH);
    bool ret = bundleInstallerHost_->Install(bundleFilePaths, installParam, statusReceiver);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_9400
 * @tc.name: test Recover of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. Recover false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_9400, Function | SmallTest | Level0)
{
    InstallParam installParam;
    sptr<IStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();
    EXPECT_NE(statusReceiver, nullptr);
    bundleInstallerHost_->Init();
    bool ret = bundleInstallerHost_->Recover(BUNDLE_NAME, installParam, statusReceiver);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_9500
 * @tc.name: test Uninstall of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. Uninstall false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_9500, Function | SmallTest | Level0)
{
    InstallParam installParam;
    sptr<IStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();
    EXPECT_NE(statusReceiver, nullptr);
    bundleInstallerHost_->Init();
    bool ret = bundleInstallerHost_->Uninstall(BUNDLE_NAME, installParam, statusReceiver);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_9600
 * @tc.name: test Uninstall of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. Uninstall false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_9600, Function | SmallTest | Level0)
{
    InstallParam installParam;
    sptr<IStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();
    EXPECT_NE(statusReceiver, nullptr);
    bundleInstallerHost_->Init();
    bool ret = bundleInstallerHost_->Uninstall(BUNDLE_NAME, installParam, statusReceiver);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_9700
 * @tc.name: test Uninstall of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. Uninstall false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_9700, Function | SmallTest | Level0)
{
    InstallParam installParam;
    sptr<IStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();
    EXPECT_NE(statusReceiver, nullptr);
    bundleInstallerHost_->Init();
    bool ret = bundleInstallerHost_->Uninstall(BUNDLE_NAME, "", installParam, statusReceiver);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_9800
 * @tc.name: test Uninstall of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. Uninstall false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_9800, Function | SmallTest | Level0)
{
    UninstallParam uninstallParam;
    sptr<IStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();
    EXPECT_NE(statusReceiver, nullptr);
    bundleInstallerHost_->Init();
    bool ret = bundleInstallerHost_->Uninstall(uninstallParam, statusReceiver);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_9900
 * @tc.name: test InstallByBundleName of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. InstallByBundleName false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_9900, Function | SmallTest | Level0)
{
    InstallParam installParam;
    sptr<IStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();
    EXPECT_NE(statusReceiver, nullptr);
    bundleInstallerHost_->Init();
    bool ret = bundleInstallerHost_->InstallByBundleName(BUNDLE_NAME, installParam, statusReceiver);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_10000
 * @tc.name: test CreateStreamInstaller of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. CreateStreamInstaller false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_10000, Function | SmallTest | Level0)
{
    InstallParam installParam;
    sptr<IStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();
    EXPECT_NE(statusReceiver, nullptr);
    bundleInstallerHost_->Init();
    std::vector<std::string> originHapPaths;
    sptr<IBundleStreamInstaller> ret = bundleInstallerHost_->CreateStreamInstaller(
        installParam, statusReceiver, originHapPaths);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_11000
 * @tc.name: test GetAppPrivilegeLevel
 * @tc.desc: 1.system run normally
 *           2.GetAppPrivilegeLevel is empty
*/
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_11000, Function | SmallTest | Level1)
{
    std::string testRet = bundleMgrHostImpl_->GetAppPrivilegeLevel("", USERID);
    EXPECT_EQ(testRet, Constants::EMPTY_STRING);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_12000
 * @tc.name: test GetDefaultApplication
 * @tc.desc: 1. GetDefaultApplication failed
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_12000, Function | SmallTest | Level1)
{
    BundleInfo bundleInfo;
    auto dataMgr = bundleMgrService_->GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    dataMgr->multiUserIdsSet_.insert(USERID);
    ErrCode ret = DefaultAppMgr::GetInstance().GetDefaultApplication(
        USERID, DEFAULT_APP_VIDEO, bundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_13000
 * @tc.name: test GetDefaultApplication
 * @tc.desc: 1. GetDefaultApplication failed
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_13000, Function | SmallTest | Level1)
{
    Element element;
    auto dataMgr = bundleMgrService_->GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    dataMgr->multiUserIdsSet_.insert(USERID);
    ErrCode ret = DefaultAppMgr::GetInstance().SetDefaultApplication(
        USERID, DEFAULT_APP_VIDEO, element);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_14000
 * @tc.name: test ResetDefaultApplication
 * @tc.desc: 1. ResetDefaultApplication failed
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_14000, Function | SmallTest | Level1)
{
    BundleInfo bundleInfo;
    auto dataMgr = bundleMgrService_->GetDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    dataMgr->multiUserIdsSet_.insert(USERID);
    ErrCode ret = DefaultAppMgr::GetInstance().ResetDefaultApplication(
        USERID, DEFAULT_APP_VIDEO);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_15000
 * @tc.name: test IsElementValid
 * @tc.desc: 1. IsElementValid failed
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_15000, Function | SmallTest | Level1)
{
    Element element;
    bool ret = DefaultAppMgr::GetInstance().IsElementValid(
        USERID, DEFAULT_APP_VIDEO, element);
    EXPECT_EQ(ret, false);

    element.bundleName = BUNDLE_NAME;
    ret = DefaultAppMgr::GetInstance().IsElementValid(
        USERID, DEFAULT_APP_VIDEO, element);
    EXPECT_EQ(ret, false);

    element.moduleName = BUNDLE_NAME;
    ret = DefaultAppMgr::GetInstance().IsElementValid(
        USERID, DEFAULT_APP_VIDEO, element);
    EXPECT_EQ(ret, false);

    element.abilityName = BUNDLE_NAME;
    element.extensionName = BUNDLE_NAME;
    ret = DefaultAppMgr::GetInstance().IsElementValid(
        USERID, DEFAULT_APP_VIDEO, element);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_16000
 * @tc.name: test IsElementValid
 * @tc.desc: 1. IsElementValid failed
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_16000, Function | SmallTest | Level1)
{
    Element element;
    element.bundleName = BUNDLE_NAME;
    element.moduleName = BUNDLE_NAME;
    element.abilityName = BUNDLE_NAME;
    element.extensionName = "";
    bool ret = DefaultAppMgr::GetInstance().IsElementValid(
        USERID, DEFAULT_APP_VIDEO, element);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_17000
 * @tc.name: test GetAppPrivilegeLevel
 * @tc.desc: 1.system run normally
 *           2.GetAppPrivilegeLevel is empty
*/
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_17000, Function | SmallTest | Level1)
{
    std::vector<AbilityInfo> abilityInfos;
    bool testRet = bundleMgrHostImpl_->QueryAbilityInfosByUri("", abilityInfos);
    EXPECT_EQ(testRet, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_18000
 * @tc.name: test RegisterBundleStatusCallback
 * @tc.desc: 1.system run normally
 *           2.RegisterBundleStatusCallback failed
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_18000, Function | SmallTest | Level1)
{
    sptr<MockBundleStatus> bundleStatusCallback = new (std::nothrow) MockBundleStatus();
    bundleStatusCallback->SetBundleName(HAP_FILE_PATH1);
    bool result = bundleMgrHostImpl_->RegisterBundleStatusCallback(bundleStatusCallback);
    EXPECT_EQ(result, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_21000
 * @tc.name: test SetAdditionalInfo
 * @tc.desc: 1.system run normally
 *           2.SetAdditionalInfo failed
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_21000, Function | SmallTest | Level1)
{
    std::string additionalInfo = "abc";
    ErrCode ret = bundleMgrHostImpl_->SetAdditionalInfo("", additionalInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_22000
 * @tc.name: test BmsBundlePermissionTokenTest of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. BmsBundlePermissionTokenTest false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_22000, Function | SmallTest | Level0)
{
    std::vector<ProxyData> proxyDatas;
    auto ret = bundleMgrHostImpl_->GetProxyDataInfos("", "", proxyDatas);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_23000
 * @tc.name: test GetAllProxyDataInfos of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetAllProxyDataInfos false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_23000, Function | SmallTest | Level0)
{
    std::vector<ProxyData> proxyDatas;
    auto ret = bundleMgrHostImpl_->GetAllProxyDataInfos(proxyDatas);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_24000
 * @tc.name: test SetExtNameOrMIMEToApp
 * @tc.desc: 1.SetExtNameOrMIMEToApp
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_24000, Function | MediumTest | Level1)
{
    ErrCode ret = bundleMgrHostImpl_->SetExtNameOrMIMEToApp("", "", "", "", "");
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_25000
 * @tc.name: test DelExtNameOrMIMEToApp
 * @tc.desc: 1.DelExtNameOrMIMEToApp
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_25000, Function | MediumTest | Level1)
{
    ErrCode ret = bundleMgrHostImpl_->DelExtNameOrMIMEToApp("", "", "", "", "");
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_26000
 * @tc.name: test UninstallAndRecover of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. UninstallAndRecover false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_26000, Function | SmallTest | Level0)
{
    InstallParam installParam;
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    bool ret = bundleInstallerHost_->UninstallAndRecover(BUNDLE_NAME, installParam, receiver);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_27000
 * @tc.name: test UninstallAndRecover of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. UninstallAndRecover false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_27000, Function | SmallTest | Level0)
{
    InstallParam installParam;
    sptr<IStatusReceiver> statusReceiver = new (std::nothrow) MockStatusReceiver();
    EXPECT_NE(statusReceiver, nullptr);
    bundleInstallerHost_->Init();
    bool ret = bundleInstallerHost_->UninstallAndRecover(BUNDLE_NAME, installParam, statusReceiver);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_28000
 * @tc.name: test GetLauncherAbilityInfoSync
 * @tc.desc: 1.system run normally
 *           2.bundleInfos is empty
*/
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_28000, Function | SmallTest | Level1)
{
    std::vector<AbilityInfo> abilityInfos;
    ErrCode testRet = bundleMgrHostImpl_->GetLauncherAbilityInfoSync("", USERID, abilityInfos);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: IsBundleInstalled_0001
 * @tc.name: test IsBundleInstalled
 * @tc.desc: 1.system run normal
 */
HWTEST_F(BmsBundlePermissionFalseTest, IsBundleInstalled_0001, Function | SmallTest | Level1)
{
    bool isInstalled = false;
    auto testRet = bundleMgrHostImpl_->IsBundleInstalled(BUNDLE_NAME, 0, 0, isInstalled);
    EXPECT_EQ(testRet, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
    EXPECT_FALSE(isInstalled);
}
} // OHOS