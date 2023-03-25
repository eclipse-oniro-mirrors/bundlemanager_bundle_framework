/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
const std::string HAP_FILE_PATH = "/data/test/resource/bms/permission_bundle/";
const int32_t USERID = 100;
const int32_t FLAGS = 0;
const int32_t UID = 0;
const int32_t WAIT_TIME = 5; // init mocked bms
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
    std::shared_ptr<InstalldService> installdService_ = std::make_shared<InstalldService>();
    std::shared_ptr<BundleMgrService> bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
};

BmsBundlePermissionFalseTest::BmsBundlePermissionFalseTest()
{}

BmsBundlePermissionFalseTest::~BmsBundlePermissionFalseTest()
{}

void BmsBundlePermissionFalseTest::SetUpTestCase()
{}

void BmsBundlePermissionFalseTest::TearDownTestCase()
{}

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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    ApplicationInfo appInfo;
    bool ret = hostImpl->GetApplicationInfo(BUNDLE_NAME, FLAGS, USERID, appInfo);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    ApplicationInfo appInfo;
    ErrCode ret = hostImpl->GetApplicationInfoV9(BUNDLE_NAME, FLAGS, USERID, appInfo);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::vector<ApplicationInfo> appInfos;
    bool ret = hostImpl->GetApplicationInfos(FLAGS, USERID, appInfos);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::vector<ApplicationInfo> appInfos;
    ErrCode ret = hostImpl->GetApplicationInfosV9(FLAGS, USERID, appInfos);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    BundleInfo bundleInfo;
    bool ret = hostImpl->GetBundleInfo(BUNDLE_NAME, FLAGS, bundleInfo, USERID);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::vector<BaseSharedBundleInfo> baseSharedBundleInfos;
    ErrCode ret = hostImpl->GetBaseSharedBundleInfos(BUNDLE_NAME, baseSharedBundleInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_0700
 * @tc.name: test GetBundleInfoV9 of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetBundleInfoV9 false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_0700, Function | SmallTest | Level0)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    BundleInfo bundleInfo;
    ErrCode ret = hostImpl->GetBundleInfoV9(BUNDLE_NAME, FLAGS, bundleInfo, USERID);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    BundlePackInfo bundlePackInfo;
    ErrCode ret = hostImpl->GetBundlePackInfo(BUNDLE_NAME, FLAGS, bundlePackInfo, USERID);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::vector<BundleInfo> bundleInfos;
    bool ret = hostImpl->GetBundleInfos(FLAGS, bundleInfos, USERID);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::vector<BundleInfo> bundleInfos;
    ErrCode ret = hostImpl->GetBundleInfosV9(FLAGS, bundleInfos, USERID);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::string name;
    ErrCode ret = hostImpl->GetNameForUid(UID, name);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::vector<BundleInfo> bundleInfos;
    bool ret = hostImpl->GetBundleInfosByMetaData(BUNDLE_NAME, bundleInfos);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    Want want;
    AbilityInfo abilityInfo;
    hostImpl->UpgradeAtomicService(want, USERID);
    bool ret = hostImpl->QueryAbilityInfo(want, FLAGS, USERID, abilityInfo, nullptr);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    Want want;
    int32_t missionId = 0;
    bool ret = hostImpl->CheckAbilityEnableInstall(want, missionId, USERID, nullptr);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    Want want;
    bool ret = hostImpl->ProcessPreload(want);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    Want want;
    AbilityInfo abilityInfo;
    bool ret = hostImpl->QueryAbilityInfo(want, FLAGS, USERID, abilityInfo);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    Want want;
    std::vector<AbilityInfo> abilityInfos;
    bool ret = hostImpl->QueryAbilityInfos(want, FLAGS, USERID, abilityInfos);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    Want want;
    std::vector<AbilityInfo> abilityInfos;
    ErrCode ret = hostImpl->QueryAbilityInfosV9(want, FLAGS, USERID, abilityInfos);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    Want want;
    std::vector<AbilityInfo> abilityInfos;
    bool ret = hostImpl->QueryAllAbilityInfos(want, USERID, abilityInfos);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    AbilityInfo abilityInfo;
    bool ret = hostImpl->QueryAbilityInfoByUri(BUNDLE_NAME, abilityInfo);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    AbilityInfo abilityInfo;
    bool ret = hostImpl->QueryAbilityInfoByUri(BUNDLE_NAME, USERID, abilityInfo);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::vector<BundleInfo> bundleInfos;
    bool ret = hostImpl->QueryKeepAliveBundleInfos(bundleInfos);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::string ret = hostImpl->GetAbilityLabel(BUNDLE_NAME, ABILITY_NAME);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::string label;
    ErrCode ret = hostImpl->GetAbilityLabel(BUNDLE_NAME, MOUDLE_NAME, ABILITY_NAME, label);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    BundleInfo bundleInfo;
    ErrCode ret = hostImpl->GetBundleArchiveInfoV9(HAP_FILE_PATH, FLAGS, bundleInfo);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    AbilityInfo abilityInfo;
    abilityInfo.bundleName = ABILITY_NAME;
    HapModuleInfo hapModuleInfo;
    bool ret = hostImpl->GetHapModuleInfo(abilityInfo, USERID, hapModuleInfo);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    Want want;
    ErrCode ret = hostImpl->GetLaunchWantForBundle(BUNDLE_NAME, want, USERID);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    PermissionDef permissionDef;
    ErrCode ret = hostImpl->GetPermissionDef(BUNDLE_NAME, permissionDef);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    sptr<MockCleanCache> cleanCache = new (std::nothrow) MockCleanCache();
    ErrCode ret = hostImpl->CleanBundleCacheFiles(BUNDLE_NAME, cleanCache, USERID);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    bool ret = hostImpl->CleanBundleDataFiles(BUNDLE_NAME, USERID);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    sptr<MockBundleStatus> bundleStatusCallback = new (std::nothrow) MockBundleStatus();
    bool ret = hostImpl->RegisterBundleStatusCallback(bundleStatusCallback);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    sptr<MockBundleStatus> bundleStatusCallback = new (std::nothrow) MockBundleStatus();
    bool ret = hostImpl->ClearBundleStatusCallback(bundleStatusCallback);
    EXPECT_EQ(ret, false);
    hostImpl->UnregisterBundleStatusCallback();
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_3300
 * @tc.name: test DumpInfos of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. DumpInfos false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_3300, Function | SmallTest | Level0)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::string result;
    bool ret = hostImpl->DumpInfos(DumpFlag::DUMP_BUNDLE_LIST, BUNDLE_NAME, USERID, result);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    bool isRemovable = false;
    ErrCode ret = hostImpl->IsModuleRemovable(BUNDLE_NAME, MOUDLE_NAME, isRemovable);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    bool isEnable = false;
    bool ret = hostImpl->SetModuleRemovable(BUNDLE_NAME, MOUDLE_NAME, isEnable);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    bool ret = hostImpl->GetModuleUpgradeFlag(BUNDLE_NAME, MOUDLE_NAME);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    bool upgradeFlag = false;
    ErrCode ret = hostImpl->SetModuleUpgradeFlag(BUNDLE_NAME, MOUDLE_NAME, upgradeFlag);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    bool isEnable = false;
    ErrCode ret = hostImpl->SetApplicationEnabled(BUNDLE_NAME, isEnable, USERID);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    bool isEnable = false;
    AbilityInfo abilityInfo;
    ErrCode ret = hostImpl->SetAbilityEnabled(abilityInfo, isEnable, USERID);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::vector<FormInfo> formInfos;
    bool ret = hostImpl->GetAllFormsInfo(formInfos);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::vector<FormInfo> formInfos;
    bool ret = hostImpl->GetFormsInfoByApp(BUNDLE_NAME, formInfos);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::vector<FormInfo> formInfos;
    bool ret = hostImpl->GetFormsInfoByModule(BUNDLE_NAME, MOUDLE_NAME, formInfos);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::vector<ShortcutInfo> shortcutInfos;
    bool ret = hostImpl->GetShortcutInfos(BUNDLE_NAME, USERID, shortcutInfos);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::vector<ShortcutInfo> shortcutInfos;
    ErrCode ret = hostImpl->GetShortcutInfoV9(BUNDLE_NAME, shortcutInfos);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::vector<CommonEventInfo> commonEventInfos;
    bool ret = hostImpl->GetAllCommonEventInfo(BUNDLE_NAME, commonEventInfos);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    Want want;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    bool ret = hostImpl->QueryExtensionAbilityInfos(want, FLAGS, USERID, extensionInfos);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    Want want;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    ErrCode ret = hostImpl->QueryExtensionAbilityInfosV9(want, FLAGS, USERID, extensionInfos);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    Want want;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    bool ret = hostImpl->QueryExtensionAbilityInfos(want, ExtensionAbilityType::FORM, FLAGS, USERID, extensionInfos);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    Want want;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    bool ret = hostImpl->QueryExtensionAbilityInfos(
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::vector<ExtensionAbilityInfo> extensionInfos;
    bool ret = hostImpl->QueryExtensionAbilityInfos(ExtensionAbilityType::FORM, USERID, extensionInfos);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    ExtensionAbilityInfo extensionAbilityInfo;
    bool ret = hostImpl->QueryExtensionAbilityInfoByUri(HAP_FILE_PATH, USERID, extensionAbilityInfo);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::string ret = hostImpl->GetAppIdByBundleName(BUNDLE_NAME, USERID);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::string ret = hostImpl->GetAppType(BUNDLE_NAME);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    int ret = hostImpl->GetUidByBundleName(BUNDLE_NAME, USERID);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    Want want;
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionInfo;
    bool ret = hostImpl->ImplicitQueryInfoByPriority(want, FLAGS, USERID, abilityInfo, extensionInfo);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    Want want;
    std::vector<AbilityInfo> abilityInfos;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    bool ret = hostImpl->ImplicitQueryInfos(want, FLAGS, USERID, abilityInfos, extensionInfos);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_5700
 * @tc.name: test GetAllDependentModuleNames of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetAllDependentModuleNames false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_5700, Function | SmallTest | Level0)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::vector<std::string> dependentModuleNames;
    bool ret = hostImpl->GetAllDependentModuleNames(BUNDLE_NAME, MOUDLE_NAME, dependentModuleNames);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    int32_t appIndex = 1;
    BundleInfo info;
    ErrCode ret = hostImpl->GetSandboxBundleInfo(BUNDLE_NAME, appIndex, USERID, info);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::vector<int64_t> bundleStats;
    bool ret = hostImpl->GetBundleStats(BUNDLE_NAME, USERID, bundleStats);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    uint32_t resId = 0;
    uint32_t density = 0;
    std::string ret = hostImpl->GetIconById(BUNDLE_NAME, MOUDLE_NAME, resId, density, USERID);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    int32_t appIndex = 1;
    Want want;
    AbilityInfo info;
    ErrCode ret = hostImpl->GetSandboxAbilityInfo(want, appIndex, FLAGS, USERID, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_6200
 * @tc.name: test GetSandboxExtAbilityInfos of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetSandboxExtAbilityInfos false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_6200, Function | SmallTest | Level0)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    int32_t appIndex = 1;
    Want want;
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode ret = hostImpl->GetSandboxExtAbilityInfos(want, appIndex, FLAGS, USERID, infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_6300
 * @tc.name: test GetSandboxHapModuleInfo of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetSandboxHapModuleInfo false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_6300, Function | SmallTest | Level0)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    int32_t appIndex = 1;
    AbilityInfo abilityInfo;
    HapModuleInfo info;
    ErrCode ret = hostImpl->GetSandboxHapModuleInfo(abilityInfo, appIndex, USERID, info);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_6400
 * @tc.name: test GetAppProvisionInfo of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetAppProvisionInfo false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_6400, Function | SmallTest | Level0)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    AppProvisionInfo appProvisionInfo;
    ErrCode ret = hostImpl->GetAppProvisionInfo(BUNDLE_NAME, USERID, appProvisionInfo);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::vector<Metadata> provisionMetadatas;
    ErrCode ret = hostImpl->GetProvisionMetadata(BUNDLE_NAME, USERID, provisionMetadatas);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::vector<SharedBundleInfo> sharedBundles;
    ErrCode ret = hostImpl->GetAllSharedBundleInfo(sharedBundles);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::vector<SharedBundleInfo> sharedBundles;
    ErrCode ret = hostImpl->GetSharedBundleInfo(BUNDLE_NAME, MOUDLE_NAME, sharedBundles);
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
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::vector<Dependency> dependencies;
    ErrCode ret = hostImpl->GetSharedDependencies(BUNDLE_NAME, MOUDLE_NAME, dependencies);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_6900
 * @tc.name: test GetSandboxHapModuleInfo of BundleMgrHostImpl
 * @tc.desc: 1. system running normally
 *           2. GetSandboxHapModuleInfo false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_6900, Function | SmallTest | Level0)
{
    auto hostImpl = std::make_unique<BundleMgrHostImpl>();

    std::unique_ptr<uint8_t[]> mediaDataPtr;
    size_t len = 0;
    ErrCode ret = hostImpl->GetMediaData(BUNDLE_NAME, MOUDLE_NAME, ABILITY_NAME, mediaDataPtr, len, USERID);
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
    auto hostImpl = std::make_unique<BundleInstallerHost>();

    InstallParam installParam;
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    bool ret = hostImpl->Install(HAP_FILE_PATH, installParam, receiver);
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
    auto hostImpl = std::make_unique<BundleInstallerHost>();

    InstallParam installParam;
    std::vector<std::string> bundleFilePaths;
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    bool ret = hostImpl->Install(bundleFilePaths, installParam, receiver);
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
    auto hostImpl = std::make_unique<BundleInstallerHost>();

    InstallParam installParam;
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    bool ret = hostImpl->InstallByBundleName(BUNDLE_NAME, installParam, receiver);
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
    auto hostImpl = std::make_unique<BundleInstallerHost>();

    int32_t dplType = 1;
    int32_t appIndex = 1;
    ErrCode ret1 = hostImpl->InstallSandboxApp(BUNDLE_NAME, dplType, USERID, appIndex);
    ErrCode ret2 = hostImpl->UninstallSandboxApp(BUNDLE_NAME, appIndex, USERID);
    EXPECT_EQ(ret1, false);
    EXPECT_EQ(ret2, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_7400
 * @tc.name: test CreateStreamInstaller of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. CreateStreamInstaller false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_7400, Function | SmallTest | Level0)
{
    auto hostImpl = std::make_unique<BundleInstallerHost>();

    InstallParam installParam;
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    sptr<IBundleStreamInstaller> ret = hostImpl->CreateStreamInstaller(installParam, receiver);
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
    auto hostImpl = std::make_unique<BundleInstallerHost>();

    uint32_t streamInstallerId = 0;
    bool ret = hostImpl->DestoryBundleStreamInstaller(streamInstallerId);
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
    auto hostImpl = std::make_unique<BundleInstallerHost>();

    UninstallParam uninstallParam;
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    bool ret = hostImpl->Uninstall(uninstallParam, receiver);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BmsBundlePermissionFalseTest_7700
 * @tc.name: test Install of BundleInstallerHost
 * @tc.desc: 1. system running normally
 *           2. Install false by no permission
 */
HWTEST_F(BmsBundlePermissionFalseTest, BmsBundlePermissionFalseTest_7700, Function | SmallTest | Level0)
{
    auto hostImpl = std::make_unique<BundleInstallerHost>();

    InstallParam installParam;
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    bool ret = hostImpl->Recover(BUNDLE_NAME, installParam, receiver);
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
    auto hostImpl = std::make_unique<BundleInstallerHost>();

    InstallParam installParam;
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    bool ret = hostImpl->Uninstall(BUNDLE_NAME, installParam, receiver);
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
    auto hostImpl = std::make_unique<BundleInstallerHost>();

    InstallParam installParam;
    sptr<MockStatusReceiver> receiver = new (std::nothrow) MockStatusReceiver();
    bool ret = hostImpl->Uninstall(BUNDLE_NAME, ABILITY_NAME, installParam, receiver);
    EXPECT_EQ(ret, false);
}
} // OHOS