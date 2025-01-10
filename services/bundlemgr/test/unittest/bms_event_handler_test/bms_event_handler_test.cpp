/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include <fstream>

#include "app_log_wrapper.h"
#define private public
#include "bundle_mgr_service.h"
#include "bundle_mgr_service_event_handler.h"
#include "bundle_permission_mgr.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "common_event_subscriber.h"
#include "want.h"
#include "user_unlocked_event_subscriber.h"
#undef private

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;
using OHOS::DelayedSingleton;

namespace OHOS {
namespace {
    const std::string CALL_MOCK_BUNDLE_DIR_SUCCESS = "callMockBundleDirSuccess";
    const std::string CALL_MOCK_BUNDLE_DIR_FAILED = "callMockBundleDirFailed";
    const std::string RETURN_MOCK_BUNDLE_DIR_SUCCESS = "mockSuccess";
    const std::string RETURN_MOCK_BUNDLE_DIR_FAILED = "mockFailed";
    const std::string BUNDLE_NAME = "bundleName";
    const std::string BUNDLE_NAME_ONE = "bundleName01";
    const std::string TEST_BUNDLE_NAME = "bundleName02";
    const std::string MODULE_NAME = "module1";
    const std::string MODULE_NAME_TWO = "module2";
    const std::string BUILD_HASH = "8670157ae28ac2dc08075c4a9364e320898b4aaf4c1ab691df6afdb854a6811b";
    const std::string UNEXIST_SHARED_LIBRARY = "/unexistpath/unexist.hsp";
    const std::string HOT_PATCH_METADATA = "ohos.app.quickfix";
    const std::string BUNDLE_PATH = "/data/app/el1/bundle/public/";
    const std::string BUNDLE_TEST_NAME = "bundleTestName";
    const std::string BUNDLE_TEST_PATH = "/data/app/el1/bundle/public/test/";
    const std::string MODULE_UPDATE_PATH = "/module_update/test/";
    constexpr const char* SYSTEM_RESOURCES_CAMERA_PATH = "/system/app/Camera";
    constexpr const char* SYSTEM_RESOURCES_APP_PATH = "/system/app/ohos.global.systemres";
}
class BmsEventHandlerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    bool CreateBundleDataDir(const BundleInfo &bundleInfo, int32_t userId);

private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsEventHandlerTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

void BmsEventHandlerTest::SetUpTestCase()
{}

void BmsEventHandlerTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsEventHandlerTest::SetUp()
{}

void BmsEventHandlerTest::TearDown()
{}

bool BmsEventHandlerTest::CreateBundleDataDir(const BundleInfo &bundleInfo, int32_t userId)
{
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
    OHOS::EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    auto subscriberPtr = std::make_shared<UserUnlockedEventSubscriber>(subscribeInfo);
    UpdateAppDataMgr::UpdateAppDataDirSelinuxLabel(userId);
    return UpdateAppDataMgr::CreateBundleDataDir(bundleInfo, userId, ServiceConstants::DIR_EL2);
}

/**
 * @tc.number: BeforeBmsStart_0100
 * @tc.name: BeforeBmsStart
 * @tc.desc: test BeforeBmsStart running normally
 */
HWTEST_F(BmsEventHandlerTest, BeforeBmsStart_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    handler->needNotifyBundleScanStatus_ = true;
    handler->BeforeBmsStart();
    EXPECT_TRUE(handler->needNotifyBundleScanStatus_ == false);
    EXPECT_TRUE(BundlePermissionMgr::Init());
}

/**
 * @tc.number: OnBmsStarting_0100
 * @tc.name: OnBmsStarting
 * @tc.desc: test OnBmsStarting running normally
 */
HWTEST_F(BmsEventHandlerTest, OnBmsStarting_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    handler->OnBmsStarting();
    EXPECT_TRUE(handler->needRebootOta_ == true);
}

/**
 * @tc.number: AfterBmsStart_0100
 * @tc.name: AfterBmsStart
 * @tc.desc: test AfterBmsStart with false needNotifyBundleScanStatus_
 */
HWTEST_F(BmsEventHandlerTest, AfterBmsStart_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    handler->needNotifyBundleScanStatus_ = false;
    handler->hasLoadAllPreInstallBundleInfosFromDb_ = true;
    handler->AfterBmsStart();
    EXPECT_FALSE(handler->hasLoadAllPreInstallBundleInfosFromDb_);
}

/**
 * @tc.number: AfterBmsStart_0200
 * @tc.name: AfterBmsStart
 * @tc.desc: test AfterBmsStart with true needNotifyBundleScanStatus_
 */
HWTEST_F(BmsEventHandlerTest, AfterBmsStart_0200, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    handler->needNotifyBundleScanStatus_ = true;
    handler->hasLoadAllPreInstallBundleInfosFromDb_ = true;
    handler->AfterBmsStart();
    EXPECT_FALSE(handler->hasLoadAllPreInstallBundleInfosFromDb_);
}

/**
 * @tc.number: AfterBmsStart_0300
 * @tc.name: AfterBmsStart
 * @tc.desc: test AfterBmsStart with true needNotifyBundleScanStatus_
 */
HWTEST_F(BmsEventHandlerTest, AfterBmsStart_0300, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    handler->hasLoadAllPreInstallBundleInfosFromDb_ = true;
    bool res = handler->LoadAllPreInstallBundleInfos();
    EXPECT_TRUE(res);
    handler->ClearCache();
}

/**
 * @tc.number: GetPreInstallDirFromLoadProFile_0100
 * @tc.name: GetPreInstallDirFromLoadProFile
 * @tc.desc: test GetPreInstallDirFromLoadProFile success
 */
HWTEST_F(BmsEventHandlerTest, GetPreInstallDirFromLoadProFile_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    std::vector<std::string> bundleDirs;
    handler->LoadPreInstallProFile();
    handler->GetPreInstallDirFromLoadProFile(bundleDirs);
    EXPECT_NE(bundleDirs.size(), 0);
}

/**
 * @tc.number: AgingHandlerTest_0001
 * @tc.name: test ProcessBundle of RecentlyUnuseBundleAgingHandler
 * @tc.desc: Process is false
 */
HWTEST_F(BmsEventHandlerTest, AgingHandlerTest_0001, Function | SmallTest | Level0)
{
    RecentlyUnuseBundleAgingHandler bundleAgingMgr;
    AgingRequest request;
    request.SetAgingCleanType(AgingCleanType::CLEAN_CACHE);
    AgingBundleInfo agingBundleInfo;
    bool res = bundleAgingMgr.AgingClean(agingBundleInfo, request);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: GetPreInstallCapability_0100
 * @tc.name: GetPreInstallCapability
 * @tc.desc: test GetPreInstallCapability with null bundleName
 */
HWTEST_F(BmsEventHandlerTest, GetPreInstallCapability_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    PreBundleConfigInfo preBundleConfigInfo;
    EXPECT_TRUE(handler->LoadPreInstallProFile());
    EXPECT_FALSE(handler->GetPreInstallCapability(preBundleConfigInfo));
}

/**
 * @tc.number: GetPreInstallCapability_0200
 * @tc.name: GetPreInstallCapability
 * @tc.desc: test GetPreInstallCapability but bundleName no has preinstall capability.
 */
HWTEST_F(BmsEventHandlerTest, GetPreInstallCapability_0200, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    PreBundleConfigInfo preBundleConfigInfo;
    preBundleConfigInfo.bundleName = BUNDLE_NAME;
    EXPECT_TRUE(handler->LoadPreInstallProFile());
    EXPECT_FALSE(handler->GetPreInstallCapability(preBundleConfigInfo));
}

/**
 * @tc.number: SaveInstallInfoToCache_0100
 * @tc.name: SaveInstallInfoToCache
 * @tc.desc: test SaveInstallInfoToCache running normally
 */
HWTEST_F(BmsEventHandlerTest, SaveInstallInfoToCache_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    DelayedSingleton<BundleMgrService>::GetInstance()->InitBundleDataMgr();
    InnerBundleInfo info;
    handler->SaveInstallInfoToCache(info);
    EXPECT_EQ(info.GetAppCodePath(), std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR);
}

/**
 * @tc.number: CombineBundleInfoAndUserInfo_0100
 * @tc.name: CombineBundleInfoAndUserInfo
 * @tc.desc: test CombineBundleInfoAndUserInfo with null bundleInfos
 */
HWTEST_F(BmsEventHandlerTest, CombineBundleInfoAndUserInfo_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    std::map<std::string, std::vector<InnerBundleUserInfo>> innerBundleUserInfoMaps;
    DelayedSingleton<BundleMgrService>::GetInstance()->InitBundleDataMgr();
    std::map<std::string, std::vector<InnerBundleInfo>> installInfos;
    EXPECT_FALSE(handler->CombineBundleInfoAndUserInfo(installInfos, innerBundleUserInfoMaps));
}

/**
 * @tc.number: CombineBundleInfoAndUserInfo_0200
 * @tc.name: CombineBundleInfoAndUserInfo
 * @tc.desc: test CombineBundleInfoAndUserInfo with null bundleInfos
 */
HWTEST_F(BmsEventHandlerTest, CombineBundleInfoAndUserInfo_0200, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    DelayedSingleton<BundleMgrService>::GetInstance()->InitBundleDataMgr();
    std::map<std::string, std::vector<InnerBundleInfo>> installInfos;
    std::map<std::string, std::vector<InnerBundleUserInfo>> innerBundleUserInfoMaps;
    InnerBundleInfo innerBundleInfo;
    InnerBundleUserInfo innerBundleUserInfo;
    std::vector<InnerBundleInfo> info1 {innerBundleInfo};
    std::vector<InnerBundleUserInfo> info2 {innerBundleUserInfo};
    installInfos.emplace(BUNDLE_NAME, info1);
    innerBundleUserInfoMaps.emplace(BUNDLE_NAME, info2);
    bool res = handler->CombineBundleInfoAndUserInfo(installInfos, innerBundleUserInfoMaps);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: ProcessSystemBundleInstall_0100
 * @tc.name: ProcessSystemBundleInstall
 * @tc.desc: test ProcessSystemBundleInstall input bundleDir success
 */
HWTEST_F(BmsEventHandlerTest, ProcessSystemBundleInstall_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    std::string bundleDir = CALL_MOCK_BUNDLE_DIR_SUCCESS;
    int32_t userId = 100;
    Constants::AppType appType = Constants::AppType::SYSTEM_APP;
    handler->ProcessSystemBundleInstall(bundleDir, appType, userId);
    EXPECT_TRUE(bundleDir.compare(RETURN_MOCK_BUNDLE_DIR_SUCCESS) == 0);
}

/**
 * @tc.number: ProcessSystemBundleInstall_0200
 * @tc.name: ProcessSystemBundleInstall
 * @tc.desc: test ProcessSystemBundleInstall input bundleDir failed
 */
HWTEST_F(BmsEventHandlerTest, ProcessSystemBundleInstall_0200, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    std::string bundleDir = CALL_MOCK_BUNDLE_DIR_FAILED;
    int32_t userId = 100;
    Constants::AppType appType = Constants::AppType::SYSTEM_APP;
    handler->ProcessSystemBundleInstall(bundleDir, appType, userId);
    EXPECT_TRUE(bundleDir.compare(RETURN_MOCK_BUNDLE_DIR_FAILED) == 0);
}

/**
 * @tc.number: ProcessSystemBundleInstall_0300
 * @tc.name: ProcessSystemBundleInstall
 * @tc.desc: test ProcessSystemBundleInstall input preScanInfo success
 */
HWTEST_F(BmsEventHandlerTest, ProcessSystemBundleInstall_0300, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    PreScanInfo preScanInfo;
    preScanInfo.bundleDir = CALL_MOCK_BUNDLE_DIR_SUCCESS;
    int32_t userId = 100;
    Constants::AppType appType = Constants::AppType::SYSTEM_APP;
    handler->ProcessSystemBundleInstall(preScanInfo, appType, userId);
    EXPECT_TRUE(preScanInfo.bundleDir.compare(RETURN_MOCK_BUNDLE_DIR_SUCCESS) == 0);
}

/**
 * @tc.number: ProcessSystemBundleInstall_0400
 * @tc.name: ProcessSystemBundleInstall
 * @tc.desc: test ProcessSystemBundleInstall input preScanInfo failed
 */
HWTEST_F(BmsEventHandlerTest, ProcessSystemBundleInstall_0400, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    PreScanInfo preScanInfo;
    preScanInfo.bundleDir = CALL_MOCK_BUNDLE_DIR_FAILED;
    int32_t userId = 100;
    Constants::AppType appType = Constants::AppType::SYSTEM_APP;
    handler->ProcessSystemBundleInstall(preScanInfo, appType, userId);
    EXPECT_TRUE(preScanInfo.bundleDir.compare(RETURN_MOCK_BUNDLE_DIR_FAILED) == 0);
}

/**
 * @tc.number: BundleBootStartEvent_0100
 * @tc.name: BundleBootStartEvent
 * @tc.desc: test BundleBootStartEvent running normally
 */
HWTEST_F(BmsEventHandlerTest, BundleBootStartEvent_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    handler->BundleBootStartEvent();
    EXPECT_NE(handler, nullptr);
}

/**
 * @tc.number: AddParseInfosToMap_0100
 * @tc.name: AddParseInfosToMap
 * @tc.desc: test AddParseInfosToMap with null hapParseInfoMap_
 */
HWTEST_F(BmsEventHandlerTest, AddParseInfosToMap_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    std::string bundleName = BUNDLE_NAME;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    handler->AddParseInfosToMap(bundleName, infos);
    EXPECT_EQ(handler->hapParseInfoMap_.size(), 1);
}

/**
 * @tc.number: AddParseInfosToMap_0200
 * @tc.name: AddParseInfosToMap
 * @tc.desc: test AddParseInfosToMap with hapParseInfoMap_ is not null
 */
HWTEST_F(BmsEventHandlerTest, AddParseInfosToMap_0200, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    std::string bundleName = BUNDLE_NAME_ONE;
    std::string testBundleName = TEST_BUNDLE_NAME;
    InnerBundleInfo innerBundleInfo;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    std::unordered_map<std::string, InnerBundleInfo> testInfos;
    infos.insert(make_pair(bundleName, innerBundleInfo));
    testInfos.insert(make_pair(testBundleName, innerBundleInfo));
    handler->hapParseInfoMap_.insert(make_pair(bundleName, infos));
    handler->AddParseInfosToMap(testBundleName, testInfos);
    EXPECT_EQ(handler->hapParseInfoMap_.size(), 2);
}

/**
 * @tc.number: AddParseInfosToMap_0300
 * @tc.name: AddParseInfosToMap
 * @tc.desc: test AddParseInfosToMap with hapParseInfoMap_ is not null
 */
HWTEST_F(BmsEventHandlerTest, AddParseInfosToMap_0300, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    std::string bundleName = BUNDLE_NAME_ONE;
    std::string testBundleName = TEST_BUNDLE_NAME;

    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = testBundleName;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos.insert(make_pair(testBundleName, innerBundleInfo));
    handler->hapParseInfoMap_.insert(make_pair(bundleName, infos));
    handler->AddParseInfosToMap(bundleName, infos);
    auto res = handler->hapParseInfoMap_.find(testBundleName);
    EXPECT_EQ(res, handler->hapParseInfoMap_.end());
    handler->ClearCache();
}

/**
 * @tc.number: ProcessRebootBundleUninstall_0100
 * @tc.name: ProcessRebootBundleUninstall
 * @tc.desc: test ProcessRebootBundleUninstall without InnerProcessRebootBundleInstall
 */
HWTEST_F(BmsEventHandlerTest, ProcessRebootBundleUninstall_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    DelayedSingleton<BundleMgrService>::GetInstance()->InitBundleDataMgr();
    handler->ProcessRebootBundleUninstall();
    EXPECT_TRUE(handler->hapParseInfoMap_.empty());
}

/**
 * @tc.number: ProcessRebootBundleUninstall_0200
 * @tc.name: ProcessRebootBundleUninstall
 * @tc.desc: test ProcessRebootBundleUninstall without InnerProcessRebootBundleInstall
 */
HWTEST_F(BmsEventHandlerTest, ProcessRebootBundleUninstall_0200, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    DelayedSingleton<BundleMgrService>::GetInstance()->InitBundleDataMgr();
    PreInstallBundleInfo preInstallBundleInfo;
    handler->loadExistData_.emplace(BUNDLE_NAME, preInstallBundleInfo);
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos.insert(make_pair(BUNDLE_NAME, innerBundleInfo));
    handler->hapParseInfoMap_.insert(make_pair(BUNDLE_NAME, infos));
    handler->ProcessRebootBundleUninstall();
    EXPECT_FALSE(handler->hapParseInfoMap_.empty());
    handler->DeletePreInfoInDb("", "", true);
    handler->ClearCache();
}

/**
 * @tc.number: InnerProcessUninstallModule_0100
 * @tc.name: InnerProcessUninstallModule
 * @tc.desc: test InnerProcessUninstallModule
 */
HWTEST_F(BmsEventHandlerTest, InnerProcessUninstallModule_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    BundleInfo bundleInfo;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    bool isDownGrade = false;
    bool ret = handler->InnerProcessUninstallModule(bundleInfo, infos, isDownGrade);
    EXPECT_FALSE(ret);

    bundleInfo.versionCode = 2;
    InnerBundleInfo innerBundleInfo;
    BundleInfo baseBundleInfo;
    baseBundleInfo.versionCode = 1;
    innerBundleInfo.SetBaseBundleInfo(baseBundleInfo);
    infos[TEST_BUNDLE_NAME] = innerBundleInfo;
    ret = handler->InnerProcessUninstallModule(bundleInfo, infos, isDownGrade);
    EXPECT_FALSE(ret);

    bundleInfo.versionCode = 1;
    ret = handler->InnerProcessUninstallModule(bundleInfo, infos, isDownGrade);
    EXPECT_FALSE(ret);

    HapModuleInfo hapModuleInfo;
    hapModuleInfo.hapPath = "/data/app/el1/bundle/public/xxxxx";
    bundleInfo.hapModuleInfos.emplace_back(hapModuleInfo);
    ret = handler->InnerProcessUninstallModule(bundleInfo, infos, isDownGrade);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InnerProcessUninstallModule_0200
 * @tc.name: InnerProcessUninstallModule
 * @tc.desc: test InnerProcessUninstallModule
 */
HWTEST_F(BmsEventHandlerTest, InnerProcessUninstallModule_0200, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    BundleInfo bundleInfo;
    bundleInfo.versionCode = 1;
    HapModuleInfo hapModuleInfo;
    hapModuleInfo.hapPath = "/system/app/xxxx";
    bundleInfo.hapModuleInfos.emplace_back(hapModuleInfo);
    bundleInfo.hapModuleNames.emplace_back(MODULE_NAME);
    bundleInfo.hapModuleNames.emplace_back(MODULE_NAME_TWO);

    std::unordered_map<std::string, InnerBundleInfo> infos;
    InnerBundleInfo innerBundleInfo;
    BundleInfo baseBundleInfo;
    baseBundleInfo.versionCode = 1;
    innerBundleInfo.SetBaseBundleInfo(baseBundleInfo);
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.name = MODULE_NAME;
    innerModuleInfo.modulePackage = MODULE_NAME;
    innerModuleInfo.moduleName = MODULE_NAME;
    innerBundleInfo.InsertInnerModuleInfo(MODULE_NAME, innerModuleInfo);
    infos[TEST_BUNDLE_NAME] = innerBundleInfo;

    bool isDownGrade = false;
    bool ret = handler->InnerProcessUninstallModule(bundleInfo, infos, isDownGrade);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: ProcessOTAInstallSystemSharedBundle_0100
 * @tc.name: ProcessOTAInstallSystemSharedBundle
 * @tc.desc: test ProcessOTAInstallSystemSharedBundle with empty filePath
 */
HWTEST_F(BmsEventHandlerTest, ProcessOTAInstallSystemSharedBundle_0100, Function | SmallTest | Level0)
{
    std::vector<std::string> filePath;
    Constants::AppType appType = Constants::AppType::THIRD_PARTY_APP;
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    DelayedSingleton<BundleMgrService>::GetInstance()->InitBundleDataMgr();
    EXPECT_FALSE(handler->OTAInstallSystemSharedBundle(filePath, appType, true));
}

/**
 * @tc.number: ProcessOTAInstallSystemSharedBundle_0200
 * @tc.name: ProcessOTAInstallSystemSharedBundle
 * @tc.desc: test ProcessOTAInstallSystemSharedBundle with a valid filePath
 */
HWTEST_F(BmsEventHandlerTest, ProcessOTAInstallSystemSharedBundle_0200, Function | SmallTest | Level0)
{
    std::vector<std::string> filePath;
    filePath.push_back(UNEXIST_SHARED_LIBRARY);
    Constants::AppType appType = Constants::AppType::THIRD_PARTY_APP;
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    DelayedSingleton<BundleMgrService>::GetInstance()->InitBundleDataMgr();
    EXPECT_FALSE(handler->OTAInstallSystemSharedBundle(filePath, appType, true));
}

/**
 * @tc.number: UserUnlockedEventSubscriber_0100
 * @tc.name: UserUnlockedEventSubscriber
 * @tc.desc: test CreateBundleDataDir with a empty bundleName
 */
HWTEST_F(BmsEventHandlerTest, UserUnlockedEventSubscriber_0100, Function | SmallTest | Level0)
{
    BundleInfo bundleInfo;
    bool res = CreateBundleDataDir(bundleInfo, Constants::ALL_USERID);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: UpdateModuleByHash_0100
 * @tc.name: UpdateModuleByHash
 * @tc.desc: test UpdateModuleByHash
 */
HWTEST_F(BmsEventHandlerTest, UpdateModuleByHash_0100, Function | SmallTest | Level0)
{
    BundleInfo oldBundleInfo;
    HapModuleInfo oldModuleInfo;
    oldModuleInfo.package = MODULE_NAME;
    oldBundleInfo.hapModuleInfos.emplace_back(oldModuleInfo);
    InnerBundleInfo newInnerBundleInfo;
    InnerModuleInfo newInnerModuleInfo;
    newInnerModuleInfo.buildHash = BUILD_HASH;
    std::map<std::string, InnerModuleInfo> innerModuleMaps;
    innerModuleMaps.emplace(MODULE_NAME, newInnerModuleInfo);
    newInnerBundleInfo.AddInnerModuleInfo(innerModuleMaps);

    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    auto res = handler->UpdateModuleByHash(oldBundleInfo, newInnerBundleInfo);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: UpdateModuleByHash_0200
 * @tc.name: UpdateModuleByHash
 * @tc.desc: test UpdateModuleByHash
 */
HWTEST_F(BmsEventHandlerTest, UpdateModuleByHash_0200, Function | SmallTest | Level0)
{
    BundleInfo oldBundleInfo;
    HapModuleInfo oldModuleInfo;
    oldModuleInfo.package = MODULE_NAME;
    oldModuleInfo.buildHash = BUILD_HASH;
    oldBundleInfo.hapModuleInfos.emplace_back(oldModuleInfo);
    InnerBundleInfo newInnerBundleInfo;
    InnerModuleInfo newInnerModuleInfo;
    newInnerModuleInfo.buildHash = BUILD_HASH;
    std::map<std::string, InnerModuleInfo> innerModuleMaps;
    innerModuleMaps.emplace(MODULE_NAME, newInnerModuleInfo);
    newInnerBundleInfo.AddInnerModuleInfo(innerModuleMaps);

    std::string moduleHash;
    auto ret = newInnerBundleInfo.GetModuleBuildHash(MODULE_NAME_TWO, moduleHash);
    EXPECT_FALSE(ret);

    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    auto res = handler->UpdateModuleByHash(oldBundleInfo, newInnerBundleInfo);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: UpdateModuleByHash_0300
 * @tc.name: UpdateModuleByHash
 * @tc.desc: test UpdateModuleByHash
 */
HWTEST_F(BmsEventHandlerTest, UpdateModuleByHash_0300, Function | SmallTest | Level0)
{
    BundleInfo oldBundleInfo;
    HapModuleInfo oldModuleInfo;
    oldModuleInfo.package = MODULE_NAME;
    oldModuleInfo.buildHash = BUILD_HASH;
    oldBundleInfo.hapModuleInfos.emplace_back(oldModuleInfo);

    InnerModuleInfo newInnerModuleInfo;
    std::map<std::string, InnerModuleInfo> innerModuleMaps;
    innerModuleMaps.emplace(MODULE_NAME_TWO, newInnerModuleInfo);
    InnerBundleInfo newInnerBundleInfo;
    newInnerBundleInfo.AddInnerModuleInfo(innerModuleMaps);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    auto res = handler->UpdateModuleByHash(oldBundleInfo, newInnerBundleInfo);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: InnerProcessRebootTest_0100
 * @tc.name: InnerProcessRebootSharedBundleInstall
 * @tc.desc: test InnerProcessRebootSharedBundleInstall
 */
HWTEST_F(BmsEventHandlerTest, InnerProcessRebootTest_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    std::list<std::string> scanPathList {BUNDLE_PATH};
    auto appType = Constants::AppType::SYSTEM_APP;
    handler->InnerProcessRebootSharedBundleInstall(scanPathList, appType);
    EXPECT_FALSE(scanPathList.empty());
}

/**
 * @tc.number: InnerProcessRebootTest_0200
 * @tc.name: InnerProcessRebootSharedBundleInstall
 * @tc.desc: test InnerProcessRebootSharedBundleInstall
 */
HWTEST_F(BmsEventHandlerTest, InnerProcessRebootTest_0200, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    std::list<std::string> scanPathList {BUNDLE_PATH};
    auto appType = Constants::AppType::SYSTEM_APP;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<BundleDataMgr>();
    handler->InnerProcessRebootSharedBundleInstall(scanPathList, appType);
    bool removable = handler->IsPreInstallRemovable(BUNDLE_PATH);
    EXPECT_TRUE(removable);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = dataMgr;
}

/**
 * @tc.number: IsNeedToUpdateSharedAppByHash_0100
 * @tc.name: IsNeedToUpdateSharedAppByHash
 * @tc.desc: test IsNeedToUpdateSharedAppByHash
 */
HWTEST_F(BmsEventHandlerTest, IsNeedToUpdateSharedAppByHash_0100, Function | SmallTest | Level0)
{
    InnerBundleInfo oldInnerBundleInfo;
    InnerModuleInfo oldInnerModuleInfo;
    oldInnerBundleInfo.InsertInnerSharedModuleInfo(MODULE_NAME, oldInnerModuleInfo);

    InnerBundleInfo newInnerBundleInfo;
    InnerModuleInfo newInnerModuleInfo;
    newInnerModuleInfo.buildHash = BUILD_HASH;
    newInnerBundleInfo.InsertInnerSharedModuleInfo(MODULE_NAME, newInnerModuleInfo);

    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    auto res = handler->IsNeedToUpdateSharedAppByHash(oldInnerBundleInfo, newInnerBundleInfo);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: IsNeedToUpdateSharedAppByHash_0200
 * @tc.name: IsNeedToUpdateSharedAppByHash
 * @tc.desc: test IsNeedToUpdateSharedAppByHash
 */
HWTEST_F(BmsEventHandlerTest, IsNeedToUpdateSharedAppByHash_0200, Function | SmallTest | Level0)
{
    InnerBundleInfo oldInnerBundleInfo;
    InnerModuleInfo oldInnerModuleInfo;
    oldInnerModuleInfo.buildHash = BUILD_HASH;
    oldInnerBundleInfo.InsertInnerSharedModuleInfo(MODULE_NAME, oldInnerModuleInfo);

    InnerBundleInfo newInnerBundleInfo;
    InnerModuleInfo newInnerModuleInfo;
    newInnerModuleInfo.buildHash = BUILD_HASH;
    newInnerBundleInfo.InsertInnerSharedModuleInfo(MODULE_NAME, newInnerModuleInfo);

    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    auto res = handler->IsNeedToUpdateSharedAppByHash(oldInnerBundleInfo, newInnerBundleInfo);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: IsNeedToUpdateSharedAppByHash_0300
 * @tc.name: IsNeedToUpdateSharedAppByHash
 * @tc.desc: test IsNeedToUpdateSharedAppByHash
 */
HWTEST_F(BmsEventHandlerTest, IsNeedToUpdateSharedAppByHash_0300, Function | SmallTest | Level0)
{
    InnerBundleInfo oldInnerBundleInfo;

    InnerBundleInfo newInnerBundleInfo;
    InnerModuleInfo newInnerModuleInfo;
    newInnerBundleInfo.InsertInnerSharedModuleInfo(MODULE_NAME, newInnerModuleInfo);

    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    auto res = handler->IsNeedToUpdateSharedAppByHash(oldInnerBundleInfo, newInnerBundleInfo);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: ReInstallAllInstallDirApps_0100
 * @tc.name: ReInstallAllInstallDirApps
 * @tc.desc: test ReInstallAllInstallDirApps
 */
HWTEST_F(BmsEventHandlerTest, ReInstallAllInstallDirApps_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    handler->InnerProcessBootPreBundleProFileInstall(Constants::ALL_USERID);
    handler->UpdateAppDataSelinuxLabel("", "", false, false);
    DelayedSingleton<BundleMgrService>::GetInstance()->InitBundleInstaller();
    auto res = handler->ReInstallAllInstallDirApps();
    EXPECT_EQ(res, ResultCode::REINSTALL_OK);
}

/**
 * @tc.number: GetBundleDirFromScan_0100
 * @tc.name: GetBundleDirFromScan
 * @tc.desc: test GetBundleDirFromScan
 */
HWTEST_F(BmsEventHandlerTest, GetBundleDirFromScan_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    std::list<std::string> bundleDirs;
    handler->GetBundleDirFromScan(bundleDirs);
    #ifdef USE_BUNDLE_EXTENSION
    auto iter = std::find(bundleDirs.begin(), bundleDirs.end(), SYSTEM_RESOURCES_CAMERA_PATH);
    #else
    auto iter = std::find(bundleDirs.begin(), bundleDirs.end(), SYSTEM_RESOURCES_APP_PATH);
    #endif
    EXPECT_NE(iter, bundleDirs.end());
}

/**
 * @tc.number: HasModuleSavedInPreInstalledDbTest_0100
 * @tc.name: HasModuleSavedInPreInstalledDb
 * @tc.desc: test HasModuleSavedInPreInstalledDb
 */
HWTEST_F(BmsEventHandlerTest, HasModuleSavedInPreInstalledDbTest_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    PreInstallBundleInfo info;
    handler->loadExistData_[BUNDLE_NAME] = info;
    bool ret = handler->HasModuleSavedInPreInstalledDb(BUNDLE_NAME_ONE, BUNDLE_PATH);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number: HasModuleSavedInPreInstalledDbTest_0200
 * @tc.name: HasModuleSavedInPreInstalledDb
 * @tc.desc: test HasModuleSavedInPreInstalledDb
 */
HWTEST_F(BmsEventHandlerTest, HasModuleSavedInPreInstalledDbTest_0200, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    PreInstallBundleInfo info;
    std::vector<std::string> bundlePaths = {BUNDLE_PATH};
    info.bundlePaths_ = bundlePaths;
    handler->loadExistData_[BUNDLE_NAME] = info;
    bool ret = handler->HasModuleSavedInPreInstalledDb(BUNDLE_NAME, BUNDLE_PATH);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number: CombineBundleInfoAndUserInfo_0300
 * @tc.name: CombineBundleInfoAndUserInfo
 * @tc.desc: test userInfoMaps not find bundleName
 * @tc.require: issueI7HXM5
 */
HWTEST_F(BmsEventHandlerTest, CombineBundleInfoAndUserInfo_0300, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    DelayedSingleton<BundleMgrService>::GetInstance()->InitBundleDataMgr();
    std::map<std::string, std::vector<InnerBundleInfo>> installInfos;
    std::map<std::string, std::vector<InnerBundleUserInfo>> innerBundleUserInfoMaps;
    InnerBundleInfo innerBundleInfo;
    InnerBundleUserInfo innerBundleUserInfo;
    std::vector<InnerBundleInfo> info1 {innerBundleInfo};
    std::vector<InnerBundleUserInfo> info2 {innerBundleUserInfo};
    installInfos.emplace(BUNDLE_NAME, info1);
    innerBundleUserInfoMaps.emplace(TEST_BUNDLE_NAME, info2);
    bool res = handler->CombineBundleInfoAndUserInfo(installInfos, innerBundleUserInfoMaps);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: ProcessSystemSharedBundleInstall_0100
 * @tc.name: ProcessSystemSharedBundleInstall
 * @tc.desc: test ProcessSystemSharedBundleInstall failed
 * @tc.require: issueI7HXM5
 */
HWTEST_F(BmsEventHandlerTest, ProcessSystemSharedBundleInstall_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    std::string bundleDir = CALL_MOCK_BUNDLE_DIR_FAILED;
    Constants::AppType appType = Constants::AppType::SYSTEM_APP;
    handler->ProcessSystemSharedBundleInstall(bundleDir, appType);
    auto res = bundleDir.compare(CALL_MOCK_BUNDLE_DIR_FAILED) == 0;
    EXPECT_TRUE(res);
}

/**
 * @tc.number: HasModuleSavedInPreInstalledDb_0100
 * @tc.name: HasModuleSavedInPreInstalledDb
 * @tc.desc: test HasModuleSavedInPreInstalledDb failed
 * @tc.require: issueI7HXM5
 */
HWTEST_F(BmsEventHandlerTest, HasModuleSavedInPreInstalledDb_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    auto ret = handler->HasModuleSavedInPreInstalledDb(BUNDLE_TEST_NAME, BUNDLE_TEST_PATH);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetPreInstallCapability_0300
 * @tc.name: GetPreInstallCapability
 * @tc.desc: test GetPreInstallCapability.
 * @tc.require: issueI7HXM5
 */
HWTEST_F(BmsEventHandlerTest, GetPreInstallCapability_0300, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    PreBundleConfigInfo preBundleConfigInfo;
    preBundleConfigInfo.bundleName = BUNDLE_NAME;
    EXPECT_TRUE(handler->LoadPreInstallProFile());
    EXPECT_FALSE(handler->GetPreInstallCapability(preBundleConfigInfo));
}

/**
 * @tc.number: MatchSignature_0101
 * @tc.name: MatchSignature
 * @tc.desc: test MatchSignature
 * @tc.require: issueI7HXM5
 */
HWTEST_F(BmsEventHandlerTest, MatchSignature_0101, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    PreBundleConfigInfo preBundleConfigInfo;
    preBundleConfigInfo.bundleName = BUNDLE_NAME;
    bool ret = handler->MatchSignature(preBundleConfigInfo, "");
    EXPECT_FALSE(ret);

    preBundleConfigInfo.appSignature.emplace_back("signature_1");
    ret = handler->MatchSignature(preBundleConfigInfo, "");
    EXPECT_FALSE(ret);

    preBundleConfigInfo.appSignature.emplace_back("signature_2");
    ret = handler->MatchSignature(preBundleConfigInfo, "signature_2");
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: MatchSignature_0102
 * @tc.name: MatchOldSignatures
 * @tc.desc: test MatchOldSignatures
 * @tc.require: issueI7HXM5
 */
HWTEST_F(BmsEventHandlerTest, MatchSignature_0102, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    PreBundleConfigInfo preBundleConfigInfo;
    preBundleConfigInfo.bundleName = BUNDLE_NAME;
    std::vector<std::string> oldSignatures;
    bool ret = handler->MatchOldSignatures(preBundleConfigInfo, oldSignatures);
    EXPECT_FALSE(ret);

    preBundleConfigInfo.appSignature.emplace_back("signature_1");
    ret = handler->MatchOldSignatures(preBundleConfigInfo, oldSignatures);
    EXPECT_FALSE(ret);

    preBundleConfigInfo.appSignature.emplace_back("signature_2");
    oldSignatures.emplace_back("signature_2");
    oldSignatures.emplace_back("signature_3");
    ret = handler->MatchOldSignatures(preBundleConfigInfo, oldSignatures);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: CheckExtensionTypeInConfig_0100
 * @tc.name: CheckExtensionTypeInConfig
 * @tc.desc: test CheckExtensionTypeInConfig
 */
HWTEST_F(BmsEventHandlerTest, CheckExtensionTypeInConfig_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    std::string typeName;
    auto ret = handler->CheckExtensionTypeInConfig(typeName);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: CheckExtensionTypeInConfig_0200
 * @tc.name: CheckExtensionTypeInConfig
 * @tc.desc: test CheckExtensionTypeInConfig
 */
HWTEST_F(BmsEventHandlerTest, CheckExtensionTypeInConfig_0200, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    std::string typeName;
    handler->LoadPreInstallProFile();
    auto ret = handler->CheckExtensionTypeInConfig(typeName);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: CheckExtensionTypeInConfig_0300
 * @tc.name: CheckExtensionTypeInConfig
 * @tc.desc: test CheckExtensionTypeInConfig
 */
HWTEST_F(BmsEventHandlerTest, CheckExtensionTypeInConfig_0300, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    handler->LoadPreInstallProFile();
    handler->ParsePreBundleProFile(BUNDLE_PATH);
    std::string typeName = BUNDLE_TEST_NAME;
    auto ret = handler->CheckExtensionTypeInConfig(typeName);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: ScanAndAnalyzeUserDatas_0100
 * @tc.name: ScanAndAnalyzeUserDatas
 * @tc.desc: test ScanAndAnalyzeUserDatas
 */
HWTEST_F(BmsEventHandlerTest, ScanAndAnalyzeUserDatas_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    std::map<std::string, std::vector<InnerBundleUserInfo>> userMaps;
    auto ret = handler->ScanAndAnalyzeUserDatas(userMaps);
    EXPECT_EQ(ret, ScanResultCode::SCAN_NO_DATA);
}

/**
 * @tc.number: AddTaskParallel_0100
 * @tc.name: AddTaskParallel
 * @tc.desc: test AddTaskParallel
 */
HWTEST_F(BmsEventHandlerTest, AddTaskParallel_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    int32_t taskPriority = 1;
    int32_t userId = 1;
    std::vector<PreScanInfo> tasks;
    PreScanInfo preScanInfo;
    tasks.push_back(preScanInfo);
    handler->AddTaskParallel(taskPriority, tasks, userId);
    EXPECT_FALSE(tasks.empty());
}

/**
 * @tc.number: ProcessCheckAppDataDir_0100
 * @tc.name: ProcessCheckAppDataDir
 * @tc.desc: test ProcessCheckAppDataDir
 */
HWTEST_F(BmsEventHandlerTest, ProcessCheckAppDataDir_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    std::map<std::string, InnerBundleUserInfo> innerBundleUserInfos;
    InnerBundleUserInfo info;
    int32_t userId = 1;
    info.bundleUserInfo.userId = userId;
    innerBundleUserInfos["_100"] = info;
    innerBundleInfo.innerBundleUserInfos_ = innerBundleUserInfos;
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, innerBundleInfo);
    handler->ProcessCheckAppDataDir();
    EXPECT_FALSE(dataMgr->bundleInfos_.empty());
    dataMgr->bundleInfos_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: OTAInstallSystemHsp_0100
 * @tc.name: OTAInstallSystemHsp
 * @tc.desc: test OTAInstallSystemHsp
 */
HWTEST_F(BmsEventHandlerTest, OTAInstallSystemHsp_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    std::vector<std::string> filePaths;
    filePaths.push_back(BUNDLE_PATH);
    auto ret = handler->OTAInstallSystemHsp(filePaths);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
}

/**
 * @tc.number: IsNeedToUpdateSharedHspByHash_0100
 * @tc.name: IsNeedToUpdateSharedHspByHash
 * @tc.desc: test IsNeedToUpdateSharedHspByHash
 */
HWTEST_F(BmsEventHandlerTest, IsNeedToUpdateSharedHspByHash_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    bool ret = handler->IsNeedToUpdateSharedHspByHash(oldInfo, newInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsNeedToUpdateSharedHspByHash_0200
 * @tc.name: IsNeedToUpdateSharedHspByHash
 * @tc.desc: test IsNeedToUpdateSharedHspByHash
 */
HWTEST_F(BmsEventHandlerTest, IsNeedToUpdateSharedHspByHash_0200, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = BUNDLE_NAME;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.buildHash = "buildHashTest";
    newInfo.innerModuleInfos_.emplace(BUNDLE_NAME, innerModuleInfo);
    oldInfo.innerModuleInfos_.emplace(BUNDLE_NAME, innerModuleInfo);
    bool ret = handler->IsNeedToUpdateSharedHspByHash(oldInfo, newInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsNeedToUpdateSharedHspByHash_0300
 * @tc.name: IsNeedToUpdateSharedHspByHash
 * @tc.desc: test IsNeedToUpdateSharedHspByHash
 */
HWTEST_F(BmsEventHandlerTest, IsNeedToUpdateSharedHspByHash_0300, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    InnerBundleInfo oldInfo;
    InnerBundleInfo newInfo;
    newInfo.currentPackage_ = BUNDLE_NAME;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.buildHash = "buildHashTest";
    InnerModuleInfo innerModuleInfo2;
    innerModuleInfo2.buildHash = "buildHashTest2";
    newInfo.innerModuleInfos_.emplace(BUNDLE_NAME, innerModuleInfo);
    oldInfo.innerModuleInfos_.emplace(BUNDLE_NAME, innerModuleInfo2);
    bool ret = handler->IsNeedToUpdateSharedHspByHash(oldInfo, newInfo);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: DeletePreInfoInDb_0100
 * @tc.name: DeletePreInfoInDb
 * @tc.desc: test DeletePreInfoInDb
 */
HWTEST_F(BmsEventHandlerTest, DeletePreInfoInDb_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    handler->DeletePreInfoInDb(BUNDLE_NAME, BUNDLE_PATH, false);
    EXPECT_NE(dataMgr->preInstallDataStorage_, nullptr);
}

/**
 * @tc.number: UpdateRemovable_0100
 * @tc.name: UpdateRemovable
 * @tc.desc: test UpdateRemovable
 */
HWTEST_F(BmsEventHandlerTest, UpdateRemovable_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    handler->UpdateRemovable(BUNDLE_NAME, false);
    EXPECT_TRUE(dataMgr->bundleInfos_.empty());
}

/**
 * @tc.number: UpdateAllPrivilegeCapability_0100
 * @tc.name: UpdateAllPrivilegeCapability
 * @tc.desc: test UpdateAllPrivilegeCapability
 */
HWTEST_F(BmsEventHandlerTest, UpdateAllPrivilegeCapability_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    handler->UpdateAllPrivilegeCapability();
    EXPECT_TRUE(dataMgr->bundleInfos_.empty());
}

/**
 * @tc.number: UpdatePrivilegeCapability_0100
 * @tc.name: UpdatePrivilegeCapability
 * @tc.desc: test UpdatePrivilegeCapability
 */
HWTEST_F(BmsEventHandlerTest, UpdatePrivilegeCapability_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    PreBundleConfigInfo preBundleConfigInfo;
    handler->UpdatePrivilegeCapability(preBundleConfigInfo);
    EXPECT_TRUE(dataMgr->bundleInfos_.empty());
}

/**
 * @tc.number: FetchInnerBundleInfo_0100
 * @tc.name: FetchInnerBundleInfo
 * @tc.desc: test FetchInnerBundleInfo
 */
HWTEST_F(BmsEventHandlerTest, FetchInnerBundleInfo_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo innerBundleInfo;
    std::map<std::string, InnerBundleUserInfo> innerBundleUserInfos;
    InnerBundleUserInfo info;
    int32_t userId = 1;
    info.bundleUserInfo.userId = userId;
    innerBundleUserInfos["_100"] = info;
    innerBundleInfo.innerBundleUserInfos_ = innerBundleUserInfos;
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, innerBundleInfo);
    InnerBundleInfo innerBundleInfo2;
    bool ret = handler->FetchInnerBundleInfo(BUNDLE_NAME, innerBundleInfo2);
    EXPECT_TRUE(ret);
    dataMgr->bundleInfos_.erase(BUNDLE_NAME);
}

/**
 * @tc.number: IsQuickfixPatchApp_0100
 * @tc.name: IsQuickfixPatchApp
 * @tc.desc: test IsQuickfixPatchApp
 */
HWTEST_F(BmsEventHandlerTest, IsQuickfixPatchApp_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    BundleInfo bundleInfo;
    Metadata metadata;
    metadata.name = "ohos.app.quickfix";
    HapModuleInfo hapModuleInfo;
    hapModuleInfo.metadata.push_back(metadata);
    bundleInfo.hapModuleInfos.push_back(hapModuleInfo);
    bool ret = handler->IsQuickfixPatchApp(bundleInfo.name, bundleInfo.versionCode);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsQuickfixPatchApp_0200
 * @tc.name: IsQuickfixPatchApp
 * @tc.desc: test IsQuickfixPatchApp
 */
HWTEST_F(BmsEventHandlerTest, IsQuickfixPatchApp_0200, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    BundleInfo bundleInfo;
    bool ret = handler->IsQuickfixPatchApp(bundleInfo.name, bundleInfo.versionCode);
    EXPECT_FALSE(ret);
    HapModuleInfo hapModuleInfo;
    bundleInfo.hapModuleInfos.push_back(hapModuleInfo);
    ret = handler->IsQuickfixPatchApp(bundleInfo.name, bundleInfo.versionCode);
    EXPECT_FALSE(ret);
    bundleInfo.hapModuleInfos.clear();
    Metadata metadata;
    metadata.name = "test";
    hapModuleInfo.metadata.push_back(metadata);
    bundleInfo.hapModuleInfos.push_back(hapModuleInfo);
    ret = handler->IsQuickfixPatchApp(bundleInfo.name, bundleInfo.versionCode);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: InnerProcessUninstallForExistPreBundle_0100
 * @tc.name: InnerProcessUninstallForExistPreBundle
 * @tc.desc: test InnerProcessUninstallForExistPreBundle
 */
HWTEST_F(BmsEventHandlerTest, InnerProcessUninstallForExistPreBundle_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    EXPECT_NE(handler, nullptr);
    if (handler) {
        BundleInfo bundleInfo;
        bool ret = handler->InnerProcessUninstallForExistPreBundle(bundleInfo);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: InnerProcessUninstallForExistPreBundle_0200
 * @tc.name: InnerProcessUninstallForExistPreBundle
 * @tc.desc: test InnerProcessUninstallForExistPreBundle
 */
HWTEST_F(BmsEventHandlerTest, InnerProcessUninstallForExistPreBundle_0200, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    EXPECT_NE(handler, nullptr);
    if (handler) {
        HapModuleInfo moduleInfo_1;
        moduleInfo_1.hapPath = "/data/app/el1/bundle/public/xxx.hap";
        BundleInfo bundleInfo;
        bundleInfo.hapModuleInfos.emplace_back(moduleInfo_1);
        bool ret = handler->InnerProcessUninstallForExistPreBundle(bundleInfo);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: InnerProcessUninstallForExistPreBundle_0300
 * @tc.name: InnerProcessUninstallForExistPreBundle
 * @tc.desc: test InnerProcessUninstallForExistPreBundle
 */
HWTEST_F(BmsEventHandlerTest, InnerProcessUninstallForExistPreBundle_0300, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    EXPECT_NE(handler, nullptr);
    if (handler) {
        HapModuleInfo moduleInfo_1;
        moduleInfo_1.hapPath = "/system/app/xxx.hap";
        BundleInfo bundleInfo;
        bundleInfo.hapModuleInfos.emplace_back(moduleInfo_1);
        bool ret = handler->InnerProcessUninstallForExistPreBundle(bundleInfo);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: InnerProcessUninstallForExistPreBundle_0400
 * @tc.name: InnerProcessUninstallForExistPreBundle
 * @tc.desc: test InnerProcessUninstallForExistPreBundle
 */
HWTEST_F(BmsEventHandlerTest, InnerProcessUninstallForExistPreBundle_0400, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    EXPECT_NE(handler, nullptr);
    if (handler) {
        HapModuleInfo moduleInfo_1;
        moduleInfo_1.hapPath = "/data/app/el1/bundle/public/xxx.hap";
        HapModuleInfo moduleInfo_2;
        moduleInfo_2.hapPath = "/system/app/xxx.hap";

        BundleInfo bundleInfo;
        bundleInfo.hapModuleInfos.emplace_back(moduleInfo_1);
        bundleInfo.hapModuleInfos.emplace_back(moduleInfo_2);
        bool ret = handler->InnerProcessUninstallForExistPreBundle(bundleInfo);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: InnerProcessUninstallForExistPreBundle_0500
 * @tc.name: InnerProcessUninstallForExistPreBundle
 * @tc.desc: test InnerProcessUninstallForExistPreBundle
 */
HWTEST_F(BmsEventHandlerTest, InnerProcessUninstallForExistPreBundle_0500, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    EXPECT_NE(handler, nullptr);
    if (handler) {
        HapModuleInfo moduleInfo_1;
        moduleInfo_1.hapPath = "/data/app/el1/bundle/public/xxx.hap";
        BundleInfo bundleInfo;
        bundleInfo.isPreInstallApp = true;
        bundleInfo.hapModuleInfos.emplace_back(moduleInfo_1);
        bool ret = handler->InnerProcessUninstallForExistPreBundle(bundleInfo);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: IsHapPathExist_0010
 * @tc.name: IsHapPathExist
 * @tc.desc: test IsHapPathExist
 */
HWTEST_F(BmsEventHandlerTest, IsHapPathExist_0010, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    EXPECT_NE(handler, nullptr);
    if (handler) {
        BundleInfo bundleInfo;
        bool ret = handler->IsHapPathExist(bundleInfo);
        EXPECT_FALSE(ret);
        HapModuleInfo moduleInfo_1;
        moduleInfo_1.hapPath = "/data/app/el1/bundle/public/xxx.hap";
        bundleInfo.hapModuleInfos.emplace_back(moduleInfo_1);
        ret = handler->IsHapPathExist(bundleInfo);
        EXPECT_FALSE(ret);
        bundleInfo.hapModuleInfos.clear();
        moduleInfo_1.hapPath = "/system/app/xxx.hap";
        bundleInfo.hapModuleInfos.emplace_back(moduleInfo_1);
        ret = handler->IsHapPathExist(bundleInfo);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: IsHspPathExist_0010
 * @tc.name: IsHspPathExist
 * @tc.desc: test IsHspPathExist
 */
HWTEST_F(BmsEventHandlerTest, IsHspPathExist_0010, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    EXPECT_NE(handler, nullptr);
    if (handler) {
        InnerBundleInfo bundleInfo;
        bool ret = handler->IsHspPathExist(bundleInfo);
        EXPECT_FALSE(ret);
        InnerModuleInfo moduleInfo_1;
        moduleInfo_1.hapPath = "/data/app/el1/bundle/public/xxx.hsp";
        bundleInfo.innerModuleInfos_["test"] = moduleInfo_1;
        ret = handler->IsHspPathExist(bundleInfo);
        EXPECT_FALSE(ret);
        bundleInfo.innerModuleInfos_.clear();
        moduleInfo_1.hapPath = "/system/app/xxx.hap";
        bundleInfo.innerModuleInfos_["test"] = moduleInfo_1;
        ret = handler->IsHspPathExist(bundleInfo);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: GetValueFromJson_0100
 * @tc.name: GetValueFromJson
 * @tc.desc: test GetValueFromJson
 */
HWTEST_F(BmsEventHandlerTest, GetValueFromJson_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    nlohmann::json jsonObject = R"(
    {
        "list": [
            {
                "key": "value"
            },
            {
                "key2": "value"
            }
        ]
    }
    )"_json;
    bool ret = handler->GetValueFromJson(jsonObject);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: UpdatePreinstallDBForNotUpdatedBundle_0100
 * @tc.name: UpdatePreinstallDBForNotUpdatedBundle
 * @tc.desc: test UpdatePreinstallDBForNotUpdatedBundle
 */
HWTEST_F(BmsEventHandlerTest, UpdatePreinstallDBForNotUpdatedBundle_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    std::unordered_map<std::string, InnerBundleInfo> innerBundleInfos;
    InnerBundleInfo innerBundleInfo;
    handler->UpdatePreinstallDBForNotUpdatedBundle(BUNDLE_NAME, innerBundleInfos);
    EXPECT_NE(innerBundleInfo.baseBundleInfo_, nullptr);
    innerBundleInfos.insert({ BUNDLE_NAME, innerBundleInfo });
    handler->UpdatePreinstallDBForNotUpdatedBundle(BUNDLE_NAME, innerBundleInfos);
    EXPECT_NE(innerBundleInfo.baseBundleInfo_, nullptr);
}

/**
 * @tc.number: InnerMultiProcessBundleInstall_0100
 * @tc.name: InnerMultiProcessBundleInstall
 * @tc.desc: test InnerMultiProcessBundleInstall
 */
HWTEST_F(BmsEventHandlerTest, InnerMultiProcessBundleInstall_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    EXPECT_NE(handler, nullptr);
    if (handler) {
        std::unordered_map<std::string, std::pair<std::string, bool>> needInstallMap;
        bool ret = handler->InnerMultiProcessBundleInstall(needInstallMap, Constants::AppType::SYSTEM_APP);
        EXPECT_TRUE(ret);
        needInstallMap["testName"] = std::make_pair("notExist", true);
        ret = handler->InnerMultiProcessBundleInstall(needInstallMap, Constants::AppType::SYSTEM_APP);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: InnerCheckSingletonBundleUserInfo_0100
 * @tc.name: InnerCheckSingletonBundleUserInfo
 * @tc.desc: test InnerCheckSingletonBundleUserInfo
 */
HWTEST_F(BmsEventHandlerTest, InnerCheckSingletonBundleUserInfo_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    EXPECT_NE(handler, nullptr);
    if (handler) {
        InnerBundleInfo innerBundleInfo;
        innerBundleInfo.baseApplicationInfo_->bundleName = "InnerCheckSingletonBundleUserInfo";
        bool ret = handler->InnerCheckSingletonBundleUserInfo(innerBundleInfo);
        EXPECT_TRUE(ret);
        InnerBundleUserInfo userInfo;
        userInfo.bundleUserInfo.userId = 100;
        innerBundleInfo.innerBundleUserInfos_["_100"] = userInfo;

        userInfo.bundleUserInfo.userId = 101;
        innerBundleInfo.innerBundleUserInfos_["_101"] = userInfo;

        ret = handler->InnerCheckSingletonBundleUserInfo(innerBundleInfo);
        EXPECT_TRUE(ret);

        userInfo.bundleUserInfo.userId = 0;
        innerBundleInfo.innerBundleUserInfos_["_0"] = userInfo;
        ret = handler->InnerCheckSingletonBundleUserInfo(innerBundleInfo);
        EXPECT_FALSE(ret);

        innerBundleInfo.SetSingleton(true);
        ret = handler->InnerCheckSingletonBundleUserInfo(innerBundleInfo);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: GetBundleNameByPreInstallPath_0100
 * @tc.name: GetBundleNameByPreInstallPath
 * @tc.desc: test GetBundleNameByPreInstallPath
 */
HWTEST_F(BmsEventHandlerTest, GetBundleNameByPreInstallPath_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    EXPECT_NE(handler, nullptr);
    if (handler) {
        std::string path = "";
        std::string bundleName = handler->GetBundleNameByPreInstallPath(path);
        EXPECT_TRUE(bundleName.empty());

        path = "/";
        bundleName = handler->GetBundleNameByPreInstallPath(path);
        EXPECT_TRUE(bundleName.empty());

        path = "aaa/bbb";
        bundleName = handler->GetBundleNameByPreInstallPath(path);
        EXPECT_FALSE(bundleName.empty());
    }
}

/**
 * @tc.number: HandleInstallModuleUpdateSystemHsp_0100
 * @tc.name: HandleInstallModuleUpdateSystemHsp
 * @tc.desc: test HandleInstallModuleUpdateSystemHsp
 */
HWTEST_F(BmsEventHandlerTest, HandleInstallModuleUpdateSystemHsp_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    EXPECT_NE(handler, nullptr);
    if (handler) {
        std::vector<std::string> appDirList;
        bool ret = handler->HandleInstallModuleUpdateSystemHsp(appDirList);
        EXPECT_TRUE(ret);

        appDirList.emplace_back("/system/not/exist");
        ret = handler->HandleInstallModuleUpdateSystemHsp(appDirList);
        EXPECT_FALSE(ret);
    }
}

/**
 * @tc.number: CheckIsModuleUpdate_0100
 * @tc.name: CheckIsModuleUpdate
 * @tc.desc: test CheckIsModuleUpdate
 */
HWTEST_F(BmsEventHandlerTest, CheckIsModuleUpdate_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    EXPECT_NE(handler, nullptr);
    if (handler) {
        std::string path;
        bool ret = handler->CheckIsModuleUpdate(path);
        EXPECT_FALSE(ret);

        path = "module_update";
        ret = handler->CheckIsModuleUpdate(path);
        EXPECT_TRUE(ret);

        path = "/module_update";
        ret = handler->CheckIsModuleUpdate(path);
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: CheckIsModuleUpdate_0100
 * @tc.name: CheckIsModuleUpdate
 * @tc.desc: test CheckIsModuleUpdate
 */
HWTEST_F(BmsEventHandlerTest, CheckIsModuleUpdate_0200, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    std::string str;
    auto ret = handler->CheckIsModuleUpdate(str);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: ProcessSystemHspInstall_0100
 * @tc.name: ProcessSystemHspInstall
 * @tc.desc: test ProcessSystemHspInstall
 */
HWTEST_F(BmsEventHandlerTest, ProcessSystemHspInstall_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    std::string systemHspDir;
    auto ret = handler->ProcessSystemHspInstall(systemHspDir);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetModuleUpdatePathList_0100
 * @tc.name: GetModuleUpdatePathList
 * @tc.desc: test GetModuleUpdatePathList
 */
HWTEST_F(BmsEventHandlerTest, GetModuleUpdatePathList_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    std::map<std::string, std::vector<std::string>> moduleUpdateAppServiceMap;
    std::map<std::string, std::vector<std::string>> moduleUpdateNotAppServiceMap;
    auto ret = handler->GetModuleUpdatePathList(moduleUpdateAppServiceMap, moduleUpdateNotAppServiceMap);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: HandleInstallHmp_0100
 * @tc.name: HandleInstallHmp
 * @tc.desc: test HandleInstallHmp
 */
HWTEST_F(BmsEventHandlerTest, HandleInstallHmp_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    std::map<std::string, std::vector<std::string>> moduleUpdateAppServiceMap;
    std::map<std::string, std::vector<std::string>> moduleUpdateNotAppServiceMap;
    auto ret = handler->HandleInstallHmp(moduleUpdateAppServiceMap, moduleUpdateNotAppServiceMap);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: HandleInstallModuleUpdateNormalApp_0100
 * @tc.name: HandleInstallModuleUpdateNormalApp
 * @tc.desc: test HandleInstallModuleUpdateNormalApp
 */
HWTEST_F(BmsEventHandlerTest, HandleInstallModuleUpdateNormalApp_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    std::vector<std::string> appDirList;
    auto ret = handler->HandleInstallModuleUpdateNormalApp(appDirList);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: CheckAppIsUpdatedByUser_0100
 * @tc.name: CheckAppIsUpdatedByUser
 * @tc.desc: test CheckAppIsUpdatedByUser
 */
HWTEST_F(BmsEventHandlerTest, CheckAppIsUpdatedByUser_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    std::string appDir;
    auto ret = handler->CheckAppIsUpdatedByUser(appDir);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetRemovableInfo_0100
 * @tc.name: GetRemovableInfo
 * @tc.desc: test GetRemovableInfo
 */
HWTEST_F(BmsEventHandlerTest, GetRemovableInfo_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    std::string bundleDir;
    auto ret = handler->GetRemovableInfo(bundleDir);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: FilterModuleUpdate_0100
 * @tc.name: FilterModuleUpdate
 * @tc.desc: test FilterModuleUpdate
 */
HWTEST_F(BmsEventHandlerTest, FilterModuleUpdate_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    std::vector<std::string> preInstallDirs;
    preInstallDirs.emplace_back(MODULE_UPDATE_PATH);
    std::map<std::string, std::vector<std::string>> moduleUpdatePathMap;
    handler->FilterModuleUpdate(preInstallDirs, moduleUpdatePathMap, false);
    EXPECT_FALSE(moduleUpdatePathMap.empty());
}

/**
 * @tc.number: SaveHmpBundlePathInfo_0100
 * @tc.name: SaveHmpBundlePathInfo
 * @tc.desc: test SaveHmpBundlePathInfo
 */
HWTEST_F(BmsEventHandlerTest, SaveHmpBundlePathInfo_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    std::string hmpName;
    std::string bundlePath;
    handler->SaveHmpBundlePathInfo(hmpName, BUNDLE_NAME, bundlePath, false);
    EXPECT_FALSE(handler->hmpBundlePathInfos_.empty());
}

/**
 * @tc.number: GetRevertHmpList_0100
 * @tc.name: GetRevertHmpList
 * @tc.desc: test GetRevertHmpList
 */
HWTEST_F(BmsEventHandlerTest, GetRevertHmpList_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    std::vector<std::string> revertHmpList;
    std::map<std::string, std::vector<std::string>> moduleUpdateAppServiceMap;
    std::map<std::string, std::vector<std::string>> moduleUpdateNotAppServiceMap;
    auto ret = handler->GetRevertHmpList(revertHmpList, moduleUpdateAppServiceMap, moduleUpdateNotAppServiceMap);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: GetHmpList_0100
 * @tc.name: GetHmpList
 * @tc.desc: test GetHmpList
 */
HWTEST_F(BmsEventHandlerTest, GetHmpList_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    std::vector<std::string> hmpList;
    std::map<std::string, std::vector<std::string>> moduleUpdateAppServiceMap;
    moduleUpdateAppServiceMap[BUNDLE_NAME] = hmpList;
    std::map<std::string, std::vector<std::string>> moduleUpdateNotAppServiceMap;
    handler->GetHmpList(hmpList, moduleUpdateAppServiceMap, moduleUpdateNotAppServiceMap);
    EXPECT_FALSE(hmpList.empty());
}

/**
 * @tc.number: DeletePreInstallExceptionAppService_0100
 * @tc.name: DeletePreInstallExceptionAppService
 * @tc.desc: test DeletePreInstallExceptionAppService
 */
HWTEST_F(BmsEventHandlerTest, DeletePreInstallExceptionAppService_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    auto preInstallExceptionMgr = std::make_shared<PreInstallExceptionMgr>();
    ASSERT_NE(preInstallExceptionMgr, nullptr);
    DelayedSingleton<BundleMgrService>::GetInstance()->preInstallExceptionMgr_ = preInstallExceptionMgr;
    auto bmsParam = std::make_shared<BmsParam>();
    ASSERT_NE(bmsParam, nullptr);
    DelayedSingleton<BundleMgrService>::GetInstance()->bmsParam_ = bmsParam;
    preInstallExceptionMgr->exceptionAppServicePaths_.insert(MODULE_UPDATE_PATH);
    handler->DeletePreInstallExceptionAppService(MODULE_UPDATE_PATH);
    EXPECT_TRUE(preInstallExceptionMgr->exceptionAppServicePaths_.find(MODULE_UPDATE_PATH) ==
                preInstallExceptionMgr->exceptionAppServicePaths_.end());
}

/**
 * @tc.number: HandlePreInstallAppServicePathsException_0100
 * @tc.name: HandlePreInstallAppServicePathsException
 * @tc.desc: test HandlePreInstallAppServicePathsException
 */
HWTEST_F(BmsEventHandlerTest, HandlePreInstallAppServicePathsException_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    auto preInstallExceptionMgr = std::make_shared<PreInstallExceptionMgr>();
    ASSERT_NE(preInstallExceptionMgr, nullptr);
    DelayedSingleton<BundleMgrService>::GetInstance()->preInstallExceptionMgr_ = preInstallExceptionMgr;
    auto bmsParam = std::make_shared<BmsParam>();
    ASSERT_NE(bmsParam, nullptr);
    DelayedSingleton<BundleMgrService>::GetInstance()->bmsParam_ = bmsParam;
    preInstallExceptionMgr->exceptionPaths_.insert(MODULE_UPDATE_PATH);
    std::set<std::string> exceptionAppServicePaths;
    exceptionAppServicePaths.emplace(MODULE_UPDATE_PATH);
    handler->HandlePreInstallAppServicePathsException(preInstallExceptionMgr, exceptionAppServicePaths);
    EXPECT_TRUE(preInstallExceptionMgr->exceptionPaths_.find(MODULE_UPDATE_PATH) ==
                preInstallExceptionMgr->exceptionPaths_.end());
}

/**
 * @tc.number: HandlePreInstallAppPathsException_0100
 * @tc.name: HandlePreInstallAppPathsException
 * @tc.desc: test HandlePreInstallAppPathsException
 */
HWTEST_F(BmsEventHandlerTest, HandlePreInstallAppPathsException_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    auto preInstallExceptionMgr = std::make_shared<PreInstallExceptionMgr>();
    ASSERT_NE(preInstallExceptionMgr, nullptr);
    DelayedSingleton<BundleMgrService>::GetInstance()->preInstallExceptionMgr_ = preInstallExceptionMgr;
    auto bmsParam = std::make_shared<BmsParam>();
    ASSERT_NE(bmsParam, nullptr);
    DelayedSingleton<BundleMgrService>::GetInstance()->bmsParam_ = bmsParam;
    preInstallExceptionMgr->exceptionPaths_.insert(MODULE_UPDATE_PATH);
    std::set<std::string> exceptionPaths;
    exceptionPaths.emplace(MODULE_UPDATE_PATH);
    handler->HandlePreInstallAppPathsException(preInstallExceptionMgr, exceptionPaths);
    EXPECT_TRUE(preInstallExceptionMgr->exceptionPaths_.find(MODULE_UPDATE_PATH) ==
                preInstallExceptionMgr->exceptionPaths_.end());
}

/**
 * @tc.number: HandlePreInstallAppServiceBundleNamesException_0100
 * @tc.name: HandlePreInstallAppServiceBundleNamesException
 * @tc.desc: test HandlePreInstallAppServiceBundleNamesException
 */
HWTEST_F(BmsEventHandlerTest, HandlePreInstallAppServiceBundleNamesException_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    PreInstallBundleInfo info;
    handler->loadExistData_.emplace(MODULE_UPDATE_PATH, info);
    auto preInstallExceptionMgr = std::make_shared<PreInstallExceptionMgr>();
    ASSERT_NE(preInstallExceptionMgr, nullptr);
    DelayedSingleton<BundleMgrService>::GetInstance()->preInstallExceptionMgr_ = preInstallExceptionMgr;
    auto bmsParam = std::make_shared<BmsParam>();
    ASSERT_NE(bmsParam, nullptr);
    DelayedSingleton<BundleMgrService>::GetInstance()->bmsParam_ = bmsParam;
    preInstallExceptionMgr->exceptionBundleNames_.insert(MODULE_UPDATE_PATH);
    std::set<std::string> exceptionAppServiceBundleNames;
    exceptionAppServiceBundleNames.emplace(MODULE_UPDATE_PATH);
    handler->HandlePreInstallAppServiceBundleNamesException(preInstallExceptionMgr, exceptionAppServiceBundleNames);
    EXPECT_TRUE(preInstallExceptionMgr->exceptionBundleNames_.find(MODULE_UPDATE_PATH) ==
                preInstallExceptionMgr->exceptionBundleNames_.end());
}

/**
 * @tc.number: HandlePreInstallBundleNamesException_0100
 * @tc.name: HandlePreInstallBundleNamesException
 * @tc.desc: test HandlePreInstallBundleNamesException
 */
HWTEST_F(BmsEventHandlerTest, HandlePreInstallBundleNamesException_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    PreInstallBundleInfo info;
    handler->loadExistData_.emplace(MODULE_UPDATE_PATH, info);
    auto preInstallExceptionMgr = std::make_shared<PreInstallExceptionMgr>();
    ASSERT_NE(preInstallExceptionMgr, nullptr);
    DelayedSingleton<BundleMgrService>::GetInstance()->preInstallExceptionMgr_ = preInstallExceptionMgr;
    auto bmsParam = std::make_shared<BmsParam>();
    ASSERT_NE(bmsParam, nullptr);
    DelayedSingleton<BundleMgrService>::GetInstance()->bmsParam_ = bmsParam;
    preInstallExceptionMgr->exceptionBundleNames_.insert(MODULE_UPDATE_PATH);
    std::set<std::string> exceptionBundleNames;
    exceptionBundleNames.emplace(MODULE_UPDATE_PATH);
    handler->HandlePreInstallBundleNamesException(preInstallExceptionMgr, exceptionBundleNames);
    EXPECT_TRUE(preInstallExceptionMgr->exceptionBundleNames_.find(MODULE_UPDATE_PATH) ==
                preInstallExceptionMgr->exceptionBundleNames_.end());
}

/**
 * @tc.number: ConvertApplicationFlagToInstallSource_0100
 * @tc.name: ConvertApplicationFlagToInstallSource
 * @tc.desc: test ConvertApplicationFlagToInstallSource
 */
HWTEST_F(BmsEventHandlerTest, ConvertApplicationFlagToInstallSource_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    std::string installSource = handler->ConvertApplicationFlagToInstallSource(
        static_cast<int32_t>(ApplicationInfoFlag::FLAG_BOOT_INSTALLED));
    EXPECT_EQ(installSource, "pre-installed");
}

/**
 * @tc.number: ConvertApplicationFlagToInstallSource_0200
 * @tc.name: ConvertApplicationFlagToInstallSource
 * @tc.desc: test ConvertApplicationFlagToInstallSource
 */
HWTEST_F(BmsEventHandlerTest, ConvertApplicationFlagToInstallSource_0200, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    std::string installSource = handler->ConvertApplicationFlagToInstallSource(
        static_cast<int32_t>(ApplicationInfoFlag::FLAG_OTA_INSTALLED));
    EXPECT_EQ(installSource, "ota");
}

/**
 * @tc.number: ConvertApplicationFlagToInstallSource_0300
 * @tc.name: ConvertApplicationFlagToInstallSource
 * @tc.desc: test ConvertApplicationFlagToInstallSource
 */
HWTEST_F(BmsEventHandlerTest, ConvertApplicationFlagToInstallSource_0300, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    std::string installSource = handler->ConvertApplicationFlagToInstallSource(
        static_cast<int32_t>(ApplicationInfoFlag::FLAG_RECOVER_INSTALLED));
    EXPECT_EQ(installSource, "recovery");
}
} // OHOS