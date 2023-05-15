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
}
class BmsEventHandlerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    bool CreateBundleDataDir(const BundleInfo &bundleInfo, int32_t userId);
};

void BmsEventHandlerTest::SetUpTestCase()
{}

void BmsEventHandlerTest::TearDownTestCase()
{}

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
    subscriberPtr->UpdateAppDataDirSelinuxLabel(userId);
    return subscriberPtr->CreateBundleDataDir(bundleInfo, userId);
}

/**
 * @tc.number: BeforeBmsStart_0100
 * @tc.name: BeforeBmsStart
 * @tc.desc: test BeforeBmsStart running normally
 */
HWTEST_F(BmsEventHandlerTest, BeforeBmsStart_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
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
    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
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
    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
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
    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
    handler->needNotifyBundleScanStatus_ = true;
    handler->hasLoadAllPreInstallBundleInfosFromDb_ = true;
    handler->AfterBmsStart();
    EXPECT_FALSE(handler->hasLoadAllPreInstallBundleInfosFromDb_);
}

/**
 * @tc.number: GetPreInstallDirFromLoadProFile_0100
 * @tc.name: GetPreInstallDirFromLoadProFile
 * @tc.desc: test GetPreInstallDirFromLoadProFile success
 */
HWTEST_F(BmsEventHandlerTest, GetPreInstallDirFromLoadProFile_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
    std::vector<std::string> bundleDirs;
    handler->LoadPreInstallProFile();
    handler->GetPreInstallDirFromLoadProFile(bundleDirs);
    EXPECT_NE(bundleDirs.size(), 0);
}

/**
 * @tc.number: GetPreInstallCapability_0100
 * @tc.name: GetPreInstallCapability
 * @tc.desc: test GetPreInstallCapability with null bundleName
 */
HWTEST_F(BmsEventHandlerTest, GetPreInstallCapability_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
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
    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
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
    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
    DelayedSingleton<BundleMgrService>::GetInstance()->InitBundleDataMgr();
    InnerBundleInfo info;
    handler->SaveInstallInfoToCache(info);
    EXPECT_EQ(info.GetAppCodePath(), Constants::BUNDLE_CODE_DIR + Constants::PATH_SEPARATOR);
}

/**
 * @tc.number: CombineBundleInfoAndUserInfo_0100
 * @tc.name: CombineBundleInfoAndUserInfo
 * @tc.desc: test CombineBundleInfoAndUserInfo with null bundleInfos
 */
HWTEST_F(BmsEventHandlerTest, CombineBundleInfoAndUserInfo_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
    std::map<std::string, std::vector<InnerBundleUserInfo>> innerBundleUserInfoMaps;
    DelayedSingleton<BundleMgrService>::GetInstance()->InitBundleDataMgr();
    std::map<std::string, std::vector<InnerBundleInfo>> installInfos;
    EXPECT_FALSE(handler->CombineBundleInfoAndUserInfo(installInfos, innerBundleUserInfoMaps));
}

/**
 * @tc.number: ProcessSystemBundleInstall_0100
 * @tc.name: ProcessSystemBundleInstall
 * @tc.desc: test ProcessSystemBundleInstall input bundleDir success
 */
HWTEST_F(BmsEventHandlerTest, ProcessSystemBundleInstall_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
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
    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
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
    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
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
    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
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
    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
    handler->BundleBootStartEvent();
    EXPECT_NE(handler, nullptr);
    EXPECT_NE(runner, nullptr);
}

/**
 * @tc.number: AddParseInfosToMap_0100
 * @tc.name: AddParseInfosToMap
 * @tc.desc: test AddParseInfosToMap with null hapParseInfoMap_
 */
HWTEST_F(BmsEventHandlerTest, AddParseInfosToMap_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
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
    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
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
 * @tc.number: ProcessRebootBundleUninstall_0100
 * @tc.name: ProcessRebootBundleUninstall
 * @tc.desc: test ProcessRebootBundleUninstall without InnerProcessRebootBundleInstall
 */
HWTEST_F(BmsEventHandlerTest, ProcessRebootBundleUninstall_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
    DelayedSingleton<BundleMgrService>::GetInstance()->InitBundleDataMgr();
    handler->ProcessRebootBundleUninstall();
    EXPECT_TRUE(handler->hapParseInfoMap_.empty());
}

/**
 * @tc.number: ProcessOTAInstallSystemSharedBundle_0100
 * @tc.name: ProcessOTAInstallSystemSharedBundle
 * @tc.desc: test ProcessOTAInstallSystemSharedBundle with empty filePath
 */
HWTEST_F(BmsEventHandlerTest, ProcessOTAInstallSystemSharedBundle_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::vector<std::string> filePath;
    Constants::AppType appType = Constants::AppType::THIRD_PARTY_APP;
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
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
    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::vector<std::string> filePath;
    filePath.push_back(UNEXIST_SHARED_LIBRARY);
    Constants::AppType appType = Constants::AppType::THIRD_PARTY_APP;
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
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

    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
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

    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
    auto res = handler->UpdateModuleByHash(oldBundleInfo, newInnerBundleInfo);
    EXPECT_FALSE(res);
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

    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
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

    std::shared_ptr<EventRunner> runner = EventRunner::Create(Constants::BMS_SERVICE_NAME);
    EXPECT_NE(nullptr, runner);
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>(runner);
    auto res = handler->IsNeedToUpdateSharedAppByHash(oldInnerBundleInfo, newInnerBundleInfo);
    EXPECT_FALSE(res);

    newInnerBundleInfo.InsertInnerSharedModuleInfo(MODULE_NAME_TWO, newInnerModuleInfo);
    auto result = handler->IsNeedToUpdateSharedAppByHash(oldInnerBundleInfo, newInnerBundleInfo);
    EXPECT_TRUE(result);
}