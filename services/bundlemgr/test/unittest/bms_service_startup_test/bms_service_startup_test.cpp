/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include <fstream>

#include "app_log_wrapper.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;
using OHOS::DelayedSingleton;

namespace {
const int32_t WAIT_TIME = 5; // init mocked bms
} // namespace

class BmsServiceStartupTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BmsServiceStartupTest::SetUpTestCase()
{}

void BmsServiceStartupTest::TearDownTestCase()
{}

void BmsServiceStartupTest::SetUp()
{}

void BmsServiceStartupTest::TearDown()
{
    DelayedSingleton<BundleMgrService>::DestroyInstance();
}

/**
* @tc.number: Startup_0100
* @tc.name: test the start function of the BMS service when service is not ready
* @tc.desc: 1. the service is not initialized
*           2. the non initialized BMS service can be started
*/
HWTEST_F(BmsServiceStartupTest, Startup_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleMgrService> bms = DelayedSingleton<BundleMgrService>::GetInstance();
    bool ready = bms->IsServiceReady();
    EXPECT_EQ(false, ready);
    bms->OnStart();
    std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    ready = bms->IsServiceReady();
    EXPECT_EQ(true, ready);
}

/**
* @tc.number: Startup_0200
* @tc.name: test the stop function of the BMS service when service is ready
* @tc.desc: 1. the service is already initialized
*           2. the initialized BMS service can be stopped
*/
HWTEST_F(BmsServiceStartupTest, Startup_0200, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleMgrService> bms = DelayedSingleton<BundleMgrService>::GetInstance();
    bms->OnStart();
    std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    bool ready = bms->IsServiceReady();
    EXPECT_EQ(true, ready);
    bms->OnStop();
    ready = bms->IsServiceReady();
    EXPECT_EQ(false, ready);
}

/**
* @tc.number: Startup_0300
* @tc.name:  test the restart function of the BMS service
* @tc.desc: 1. the service is already initialized
*           2. the stopped BMS service can be restarted
*/
HWTEST_F(BmsServiceStartupTest, Startup_0300, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleMgrService> bms = DelayedSingleton<BundleMgrService>::GetInstance();
    bms->OnStart();
    std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    bool ready = bms->IsServiceReady();
    EXPECT_EQ(true, ready);
    bms->OnStop();
    ready = bms->IsServiceReady();
    EXPECT_EQ(false, ready);
    bms->OnStart();
    std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    ready = bms->IsServiceReady();
    EXPECT_EQ(true, ready);
    bms->OnStop();
}

/**
* @tc.number: Startup_0400
* @tc.name:  test the restart function of the BMS service which is already initialized
* @tc.desc: 1. the service is already initialized
*           2. the recall start function will not affect the initialized BMS service
*/
HWTEST_F(BmsServiceStartupTest, Startup_0400, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleMgrService> bms = DelayedSingleton<BundleMgrService>::GetInstance();
    bms->OnStart();
    std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    bool ready = bms->IsServiceReady();
    EXPECT_EQ(true, ready);
    bms->OnStart();
    ready = bms->IsServiceReady();
    EXPECT_EQ(true, ready);
    bms->OnStop();
}

/**
* @tc.number: GetDataMgr_0100
* @tc.name:  test the dataMgr can be obtained
* @tc.desc: 1. the service is already initialized
*           2. the dataMgr can be obtained
*/
HWTEST_F(BmsServiceStartupTest, GetDataMgr_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleMgrService> bms = DelayedSingleton<BundleMgrService>::GetInstance();
    bms->OnStart();
    std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    auto dataMgr = bms->GetDataMgr();
    EXPECT_NE(nullptr, dataMgr);
    bms->OnStop();
}

/**
* @tc.number: GetBundleInstaller_0100
* @tc.name:  test the installer can be obtained
* @tc.desc: 1. the service is already initialized
*           2. the installer can be obtained
*/
HWTEST_F(BmsServiceStartupTest, GetBundleInstaller_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleMgrService> bms = DelayedSingleton<BundleMgrService>::GetInstance();
    bms->OnStart();
    std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    auto installer = bms->GetBundleInstaller();
    EXPECT_NE(nullptr, installer);
    bms->OnStop();
}

/**
* @tc.number: GuardAgainst_001
* @tc.name: Guard against install infos lossed strategy
* @tc.desc: 1. the service is not initialized
* @tc.require: issueI56WA0
*/
HWTEST_F(BmsServiceStartupTest, GuardAgainst_001, Function | SmallTest | Level0)
{
    std::shared_ptr<BundleMgrService> bms = DelayedSingleton<BundleMgrService>::GetInstance();
    bool ready = bms->IsServiceReady();
    EXPECT_EQ(false, ready);
    bms->OnStart();
    std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    ready = bms->IsServiceReady();
    EXPECT_EQ(true, ready);
}

/**
* @tc.number: GuardAgainst_002
* @tc.name: Guard against install infos lossed strategy
* @tc.desc: 1. ScanAndAnalyzeUserDatas
* @tc.require: issueI56WA0
*/
HWTEST_F(BmsServiceStartupTest, GuardAgainst_002, Function | SmallTest | Level0)
{
    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
    std::map<std::string, std::vector<InnerBundleUserInfo>> innerBundleUserInfoMaps;
    handler->ScanAndAnalyzeUserDatas(innerBundleUserInfoMaps);
    EXPECT_EQ(true, innerBundleUserInfoMaps.empty());
}

/**
* @tc.number: GuardAgainst_003
* @tc.name: Guard against install infos lossed strategy
* @tc.desc: 1. ScanAndAnalyzeInstallInfos
* @tc.require: issueI56WA0
*/
HWTEST_F(BmsServiceStartupTest, GuardAgainst_003, Function | SmallTest | Level0)
{
    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
    std::map<std::string, std::vector<InnerBundleInfo>> installInfos;
    handler->ScanAndAnalyzeInstallInfos(installInfos);
    EXPECT_EQ(false, installInfos.empty());
}

/**
* @tc.number: PreInstall_001
* @tc.name: Preset application whitelist mechanism
* @tc.desc: 1. GetBundleDirFromScan
* @tc.require: issueI56W8O
*/
HWTEST_F(BmsServiceStartupTest, PreInstall_001, Function | SmallTest | Level0)
{
    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
    std::list<std::string> bundleDirs;
    handler->GetBundleDirFromScan(bundleDirs);
    EXPECT_EQ(false, bundleDirs.empty());
}

/**
* @tc.number: PreInstall_002
* @tc.name: Preset application whitelist mechanism
* @tc.desc: 1. LoadPreInstallProFile
* @tc.require: issueI56W8O
*/
HWTEST_F(BmsServiceStartupTest, PreInstall_002, Function | SmallTest | Level0)
{
    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
    handler->ClearPreInstallCache();
    bool ret = handler->LoadPreInstallProFile();
    EXPECT_EQ(true, ret);
    ret = BMSEventHandler::HasPreInstallProfile();
    EXPECT_EQ(true, ret);
}

/**
 * @tc.number: BundlePermissionMgr_0100
 * @tc.name: test ConvertPermissionDef
 * @tc.desc: 1.test ConvertPermissionDef of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_0100, Function | SmallTest | Level0)
{
    bool res = BundlePermissionMgr::Init();
    EXPECT_EQ(res, true);
    AccessToken::PermissionDef permDef;
    OHOS::AppExecFwk::PermissionDef permissionDef;
    permissionDef.label = "$string: entry_MainAbility";
    BundlePermissionMgr::ConvertPermissionDef(permDef, permissionDef);
    EXPECT_TRUE(permissionDef.label == permDef.label);
}

/**
 * @tc.number: BundlePermissionMgr_0200
 * @tc.name: test GrantPermission
 * @tc.desc: 1.test GrantPermission of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_0200, Function | SmallTest | Level0)
{
    bool ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    AccessToken::AccessTokenID tokenId = 0;
    std::string permissionName;
    AccessToken::PermissionFlag flag =
        AccessToken::PermissionFlag::PERMISSION_DEFAULT_FLAG;
    std::string bundleName;
    ret = BundlePermissionMgr::GrantPermission(
        tokenId, permissionName, flag, bundleName);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: BundlePermissionMgr_0300
 * @tc.name: test CheckGrantPermission
 * @tc.desc: 1.test CheckGrantPermission of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_0300, Function | SmallTest | Level0)
{
    bool ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    AccessToken::PermissionDef permDef;
    std::string apl;
    std::vector<std::string> acls;
    permDef.provisionEnable = true;
    ret = BundlePermissionMgr::CheckGrantPermission(permDef, apl, acls);
    EXPECT_EQ(ret, false);

    permDef.availableLevel = AccessToken::ATokenAplEnum::APL_NORMAL;
    ret = BundlePermissionMgr::CheckGrantPermission(permDef, apl, acls);
    EXPECT_EQ(ret, true);

    permDef.availableLevel = AccessToken::ATokenAplEnum::APL_SYSTEM_BASIC;
    apl = Profile::AVAILABLELEVEL_SYSTEM_BASIC;
    ret = BundlePermissionMgr::CheckGrantPermission(permDef, apl, acls);
    EXPECT_EQ(ret, true);
    apl = Profile::AVAILABLELEVEL_SYSTEM_CORE;
    ret = BundlePermissionMgr::CheckGrantPermission(permDef, apl, acls);
    EXPECT_EQ(ret, true);
    apl = "";
    ret = BundlePermissionMgr::CheckGrantPermission(permDef, apl, acls);
    EXPECT_EQ(ret, false);

    permDef.availableLevel = AccessToken::ATokenAplEnum::APL_SYSTEM_CORE;
    apl = Profile::AVAILABLELEVEL_SYSTEM_CORE;
    ret = BundlePermissionMgr::CheckGrantPermission(permDef, apl, acls);
    EXPECT_EQ(ret, true);
    ret = BundlePermissionMgr::CheckGrantPermission(permDef, apl, acls);
    apl = "";
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: BundlePermissionMgr_0400
 * @tc.name: test VerifyPermission
 * @tc.desc: 1.test VerifyPermission of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_0400, Function | SmallTest | Level0)
{
    bool res = BundlePermissionMgr::Init();
    EXPECT_EQ(res, true);
    std::string bundleName;
    std::string permissionName;
    int32_t userId = 100;
    int32_t ret = BundlePermissionMgr::VerifyPermission(bundleName, permissionName, userId);
    EXPECT_EQ(ret, OHOS::ERR_OK);
}

/**
 * @tc.number: BundlePermissionMgr_0500
 * @tc.name: test CheckPermissionInDefaultPermissions
 * @tc.desc: 1.test CheckPermissionInDefaultPermissions of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_0500, Function | SmallTest | Level0)
{
    bool ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    DefaultPermission defaultPermission;
    PermissionInfo info;
    info.name = "default";
    defaultPermission.grantPermission.emplace_back(info);
    auto permissionName = info.name;
    bool userCancellable;
    ret = BundlePermissionMgr::CheckPermissionInDefaultPermissions(
        defaultPermission, permissionName, userCancellable);
    EXPECT_EQ(ret, true);

    permissionName = "";
    ret = BundlePermissionMgr::CheckPermissionInDefaultPermissions(
        defaultPermission, permissionName, userCancellable);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: BundlePermissionMgr_0600
 * @tc.name: test GetDefaultPermission
 * @tc.desc: 1.test GetDefaultPermission of BundlePermissionMgr
 */
HWTEST_F(BmsServiceStartupTest, BundlePermissionMgr_0600, Function | SmallTest | Level0)
{
    bool ret = BundlePermissionMgr::Init();
    EXPECT_EQ(ret, true);
    std::string bundleName = "com.ohos.tes1";
    DefaultPermission permission;
    ret = BundlePermissionMgr::GetDefaultPermission(bundleName, permission);
    EXPECT_EQ(ret, false);
    BundlePermissionMgr::defaultPermissions_.try_emplace("com.ohos.tes1", permission);
    ret = BundlePermissionMgr::GetDefaultPermission(bundleName, permission);
    EXPECT_EQ(ret, true);
}