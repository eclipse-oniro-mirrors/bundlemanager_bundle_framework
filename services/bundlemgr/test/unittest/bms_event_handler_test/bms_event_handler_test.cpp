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
#include <filesystem>
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
#include "el5_filekey_callback.h"
#include "installd_client.h"
#include "installd_service.h"
#include "patch_data_mgr.h"
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
    const std::string TEST_SHADER_CACHE_NAME_ONE = "bundleName03";
    const std::string TEST_SHADER_CACHE_NAME_TWO = "bundleName04";
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
    constexpr const char* VERSION_CODE = "versionCode";
    constexpr const char* APP_PATCH_TYPE = "appPatchType";
    constexpr const char* BUNDLE_RDB_TABLE_NAME = "installed_bundle";
    const int32_t TEST_UID = 20020098;
    const std::string UNINSTALL_PREINSTALL_BUNDLE_NAME = "com.ohos.telephonydataability";
    const std::string BUNDLE_NAME_FOR_TEST_U1ENABLE = "com.example.u1Enable_test";
    const int32_t TEST_U100 = 100;
    const int32_t TEST_U1 = 1;
}
class BmsEventHandlerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    bool CreateBundleDataDir(const BundleInfo &bundleInfo, int32_t userId);
    bool CheckShaderCachePathExist(const std::string &bundleName,
        const int32_t appIndex, const int32_t &userId) const;

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

bool BmsEventHandlerTest::CheckShaderCachePathExist(const std::string &bundleName,
    const int32_t appIndex, const int32_t &userId) const
{
    bool isExist = false;
    std::string cloneBundleName = bundleName;
    if (appIndex != 0) {
        cloneBundleName = BundleCloneCommonHelper::GetCloneDataDir(bundleName, appIndex);
    }
    std::string newShaderCachePath = std::string(ServiceConstants::NEW_SHADER_CACHE_PATH);
    newShaderCachePath = newShaderCachePath.replace(newShaderCachePath.find("%"), 1, std::to_string(userId));
    newShaderCachePath = newShaderCachePath + cloneBundleName;
    if (access(newShaderCachePath.c_str(), F_OK) == 0) {
        isExist = true;
    } else {
        LOG_E(BMS_TAG_INSTALLD, "%{public}s can not access, errno: %{public}d",
            newShaderCachePath.c_str(), errno);
    }
    return isExist;
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
 * @tc.number: FilterVersionSpecialCustomApps_0100
 * @tc.name: test FilterVersionSpecialCustomApps
 * @tc.desc: 1.call FilterVersionSpecialCustomApps, expect installList not empty
 */
HWTEST_F(BmsEventHandlerTest, FilterVersionSpecialCustomApps_0100, Function | SmallTest | Level0)
{
    std::set<PreScanInfo> installList;
    installList.insert(PreScanInfo());
    BMSEventHandler::FilterVersionSpecialCustomApps(installList);
    EXPECT_FALSE(installList.empty());
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
    #ifdef USE_EXTENSION_DATA
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_FAILED_NO_BUNDLE_SIGNATURE);
    #else
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
    #endif
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

/**
 * @tc.number: InnerPatchInfo_FromJson_0001
 * @tc.name: test InnerPatchInfo_FromJson
 * @tc.desc: test InnerPatchInfo_FromJson
 */
HWTEST_F(BmsEventHandlerTest, InnerPatchInfo_FromJson_0001, Function | SmallTest | Level0)
{
    InnerPatchInfo innerPatchInfo;

    std::string emptyJson = "";
    EXPECT_FALSE(innerPatchInfo.FromJson(emptyJson));

    std::string notJson = R"({"versionCode": "123", "appPatchType":})";
    EXPECT_FALSE(innerPatchInfo.FromJson(notJson));

    std::string missingFieldsJson = R"({"versionCode": 123})";
    EXPECT_FALSE(innerPatchInfo.FromJson(missingFieldsJson));

    std::string wrongKeyJson = R"({"versionCode1": "abc", "appPatchType": "xyz"})";
    EXPECT_FALSE(innerPatchInfo.FromJson(wrongKeyJson));

    std::string invalidJson = R"({"versionCode": "abc", "appPatchType": "xyz"})";
    EXPECT_FALSE(innerPatchInfo.FromJson(invalidJson));

    std::string validJson = R"({"versionCode": 123, "appPatchType": 1})";
    EXPECT_TRUE(innerPatchInfo.FromJson(validJson));
}

/**
 * @tc.number: InnerPatchInfo_ToJson_0001
 * @tc.name: test InnerPatchInfo_ToJson
 * @tc.desc: test InnerPatchInfo_ToJson
 */
HWTEST_F(BmsEventHandlerTest, InnerPatchInfo_ToJson_0001, Function | SmallTest | Level0)
{
    PatchInfo patchInfo;
    patchInfo.versionCode = 123;
    patchInfo.appPatchType = AppPatchType::INTERNAL;
    InnerPatchInfo innerPatchInfo;
    innerPatchInfo.SetPatchInfo(patchInfo);
    EXPECT_EQ(innerPatchInfo.GetVersionCode(), 123);
    EXPECT_EQ(innerPatchInfo.GetAppPatchType(), AppPatchType::INTERNAL);

    nlohmann::json jsonObj;
    innerPatchInfo.ToJson(jsonObj);
    EXPECT_TRUE(jsonObj.contains(VERSION_CODE));
    EXPECT_TRUE(jsonObj.contains(APP_PATCH_TYPE));
    EXPECT_EQ(jsonObj[VERSION_CODE], 123);
    EXPECT_EQ(jsonObj[APP_PATCH_TYPE], static_cast<int>(AppPatchType::INTERNAL));
}

/**
 * @tc.number: InnerPatchInfo_ToString_0001
 * @tc.name: test InnerPatchInfo_ToString
 * @tc.desc: test InnerPatchInfo_ToString
 */
HWTEST_F(BmsEventHandlerTest, InnerPatchInfo_ToString_0001, Function | SmallTest | Level0)
{
    PatchInfo patchInfo;
    patchInfo.versionCode = 123;
    patchInfo.appPatchType = AppPatchType::INTERNAL;
    InnerPatchInfo innerPatchInfo;
    innerPatchInfo.SetPatchInfo(patchInfo);

    std::string jsonString = innerPatchInfo.ToString();
    nlohmann::json jsonObj = nlohmann::json::parse(jsonString);

    EXPECT_TRUE(jsonObj.contains(VERSION_CODE));
    EXPECT_TRUE(jsonObj.contains(APP_PATCH_TYPE));
    EXPECT_EQ(jsonObj[VERSION_CODE], 123);
    EXPECT_EQ(jsonObj[APP_PATCH_TYPE], static_cast<int>(AppPatchType::INTERNAL));
}

/**
 * @tc.number: AddInnerPatchInfo_0001
 * @tc.name: test AddInnerPatchInfo
 * @tc.desc: test AddInnerPatchInfo
 */
HWTEST_F(BmsEventHandlerTest, AddInnerPatchInfo_0001, Function | SmallTest | Level0)
{
    InnerPatchInfo innerPatchInfo;
    EXPECT_FALSE(PatchDataMgr::GetInstance().AddInnerPatchInfo("", innerPatchInfo));
    PatchDataMgr::GetInstance().patchDataStorage_->rdbDataManager_ = nullptr;
    EXPECT_FALSE(PatchDataMgr::GetInstance().AddInnerPatchInfo("bundleName", innerPatchInfo));
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = BUNDLE_RDB_TABLE_NAME;
    PatchDataMgr::GetInstance().patchDataStorage_->rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);

    PatchInfo patchInfo;
    patchInfo.versionCode = 123;
    patchInfo.appPatchType = AppPatchType::INTERNAL;
    innerPatchInfo.SetPatchInfo(patchInfo);
    EXPECT_TRUE(PatchDataMgr::GetInstance().AddInnerPatchInfo("bundleName", innerPatchInfo));

    EXPECT_TRUE(PatchDataMgr::GetInstance().DeleteInnerPatchInfo("bundleName"));
}

/**
 * @tc.number: GetInnerPatchInfo_0001
 * @tc.name: test GetInnerPatchInfo
 * @tc.desc: test GetInnerPatchInfo
 */
HWTEST_F(BmsEventHandlerTest, GetInnerPatchInfo_0001, Function | SmallTest | Level0)
{
    InnerPatchInfo innerPatchInfo;
    EXPECT_FALSE(PatchDataMgr::GetInstance().GetInnerPatchInfo("", innerPatchInfo));
    EXPECT_FALSE(PatchDataMgr::GetInstance().GetInnerPatchInfo("bundleName", innerPatchInfo));

    PatchInfo patchInfo;
    patchInfo.versionCode = 123;
    patchInfo.appPatchType = AppPatchType::INTERNAL;
    innerPatchInfo.SetPatchInfo(patchInfo);
    EXPECT_TRUE(PatchDataMgr::GetInstance().AddInnerPatchInfo("bundleName", innerPatchInfo));
    EXPECT_TRUE(PatchDataMgr::GetInstance().GetInnerPatchInfo("bundleName", innerPatchInfo));

    EXPECT_TRUE(PatchDataMgr::GetInstance().DeleteInnerPatchInfo("bundleName"));
}

/**
 * @tc.number: DeleteInnerPatchInfo_0001
 * @tc.name: test DeleteInnerPatchInfo
 * @tc.desc: test DeleteInnerPatchInfo
 */
HWTEST_F(BmsEventHandlerTest, DeleteInnerPatchInfo_0001, Function | SmallTest | Level0)
{
    EXPECT_FALSE(PatchDataMgr::GetInstance().DeleteInnerPatchInfo(""));
    PatchDataMgr::GetInstance().patchDataStorage_->rdbDataManager_ = nullptr;
    EXPECT_FALSE(PatchDataMgr::GetInstance().DeleteInnerPatchInfo("bundleName"));
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = BUNDLE_RDB_TABLE_NAME;
    PatchDataMgr::GetInstance().patchDataStorage_->rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);

    InnerPatchInfo innerPatchInfo;
    PatchInfo patchInfo;
    patchInfo.versionCode = 123;
    patchInfo.appPatchType = AppPatchType::INTERNAL;
    innerPatchInfo.SetPatchInfo(patchInfo);
    EXPECT_TRUE(PatchDataMgr::GetInstance().AddInnerPatchInfo("bundleName", innerPatchInfo));
    EXPECT_TRUE(PatchDataMgr::GetInstance().DeleteInnerPatchInfo("bundleName"));
}

/**
 * @tc.number: ProcessPatchInfo_0001
 * @tc.name: test ProcessPatchInfo
 * @tc.desc: test ProcessPatchInfo
 */
HWTEST_F(BmsEventHandlerTest, ProcessPatchInfo_0001, Function | SmallTest | Level0)
{
    InnerPatchInfo innerPatchInfo;
    std::vector<std::string> installSources;

    PatchDataMgr::GetInstance().ProcessPatchInfo("", installSources, 0, AppPatchType::INTERNAL, false);
    EXPECT_FALSE(PatchDataMgr::GetInstance().GetInnerPatchInfo("bundleName", innerPatchInfo));

    installSources.emplace_back("test");
    PatchDataMgr::GetInstance().ProcessPatchInfo("bundleName", installSources, 2, AppPatchType::INTERNAL, true);
    EXPECT_TRUE(PatchDataMgr::GetInstance().GetInnerPatchInfo("bundleName", innerPatchInfo));

    PatchDataMgr::GetInstance().ProcessPatchInfo("test", installSources, 1, AppPatchType::INTERNAL, false);
    EXPECT_FALSE(PatchDataMgr::GetInstance().GetInnerPatchInfo("test", innerPatchInfo));

    PatchDataMgr::GetInstance().ProcessPatchInfo("bundleName", installSources, 1, AppPatchType::INTERNAL, false);
    EXPECT_TRUE(PatchDataMgr::GetInstance().GetInnerPatchInfo("bundleName", innerPatchInfo));

    PatchDataMgr::GetInstance().ProcessPatchInfo("bundleName", installSources, 3, AppPatchType::INTERNAL, false);
    EXPECT_FALSE(PatchDataMgr::GetInstance().GetInnerPatchInfo("bundleName", innerPatchInfo));

    EXPECT_TRUE(PatchDataMgr::GetInstance().DeleteInnerPatchInfo("bundleName"));
}

/**
 * @tc.number: GetStoragePatchInfo_0001
 * @tc.name: test GetStoragePatchInfo
 * @tc.desc: test GetStoragePatchInfo
 */
HWTEST_F(BmsEventHandlerTest, GetStoragePatchInfo_0001, Function | SmallTest | Level0)
{
    std::shared_ptr<PatchDataStorageRdb> patchDataStorage_ = std::make_shared<PatchDataStorageRdb>();
    InnerPatchInfo innerPatchInfo;
    EXPECT_FALSE(patchDataStorage_->GetStoragePatchInfo("", innerPatchInfo));
    EXPECT_FALSE(patchDataStorage_->GetStoragePatchInfo("bundleName", innerPatchInfo));

    EXPECT_TRUE(patchDataStorage_->rdbDataManager_->InsertData("bundleName", "123"));
    EXPECT_FALSE(patchDataStorage_->GetStoragePatchInfo("bundleName", innerPatchInfo));
    EXPECT_TRUE(patchDataStorage_->DeleteStoragePatchInfo("bundleName"));

    EXPECT_TRUE(patchDataStorage_->SaveStoragePatchInfo("bundleName", innerPatchInfo));
    EXPECT_TRUE(patchDataStorage_->GetStoragePatchInfo("bundleName", innerPatchInfo));
    EXPECT_TRUE(patchDataStorage_->DeleteStoragePatchInfo("bundleName"));
}

/**
 * @tc.number: SaveStoragePatchInfo_0001
 * @tc.name: test SaveStoragePatchInfo
 * @tc.desc: test SaveStoragePatchInfo
 */
HWTEST_F(BmsEventHandlerTest, SaveStoragePatchInfo_0001, Function | SmallTest | Level0)
{
    std::shared_ptr<PatchDataStorageRdb> patchDataStorage_ = std::make_shared<PatchDataStorageRdb>();
    InnerPatchInfo innerPatchInfo;
    EXPECT_FALSE(patchDataStorage_->SaveStoragePatchInfo("", innerPatchInfo));

    EXPECT_TRUE(patchDataStorage_->SaveStoragePatchInfo("bundleName", innerPatchInfo));
    EXPECT_TRUE(patchDataStorage_->DeleteStoragePatchInfo("bundleName"));
}

/**
 * @tc.number: DeleteStoragePatchInfo_0001
 * @tc.name: test DeleteStoragePatchInfo
 * @tc.desc: test DeleteStoragePatchInfo
 */
HWTEST_F(BmsEventHandlerTest, DeleteStoragePatchInfo_0001, Function | SmallTest | Level0)
{
    std::shared_ptr<PatchDataStorageRdb> patchDataStorage_ = std::make_shared<PatchDataStorageRdb>();
    InnerPatchInfo innerPatchInfo;
    EXPECT_FALSE(patchDataStorage_->DeleteStoragePatchInfo(""));

    EXPECT_TRUE(patchDataStorage_->SaveStoragePatchInfo("bundleName", innerPatchInfo));
    EXPECT_TRUE(patchDataStorage_->DeleteStoragePatchInfo("bundleName"));
}

/**
 * @tc.number: PatchDataStorageRdb_Nullptr_0001
 * @tc.name: test PatchDataStorageRdb_Nullptr
 * @tc.desc: test PatchDataStorageRdb_Nullptr
 */
HWTEST_F(BmsEventHandlerTest, PatchDataStorageRdb_Nullptr_0001, Function | SmallTest | Level0)
{
    std::shared_ptr<PatchDataStorageRdb> patchDataStorage_ = std::make_shared<PatchDataStorageRdb>();
    patchDataStorage_->rdbDataManager_ = nullptr;
    InnerPatchInfo innerPatchInfo;
    EXPECT_FALSE(patchDataStorage_->GetStoragePatchInfo("bundleName", innerPatchInfo));
    EXPECT_FALSE(patchDataStorage_->SaveStoragePatchInfo("bundleName", innerPatchInfo));
    EXPECT_FALSE(patchDataStorage_->DeleteStoragePatchInfo("bundleName"));
}

/**
 * @tc.number: PatchSharedHspInstall_0001
 * @tc.name: test PatchSharedHspInstall
 * @tc.desc: test PatchSharedHspInstall
 */
HWTEST_F(BmsEventHandlerTest, PatchSharedHspInstall_0001, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    std::string path = "test";
    handler->PatchSharedHspInstall(path);
    EXPECT_EQ(path, "test");
    path = "/system/app/shared_bundles";
    handler->PatchSharedHspInstall(path);
    EXPECT_EQ(path, "/system/app/shared_bundles");
}

/**
 * @tc.number: OnRegenerateAppKey_0001
 * @tc.name: test OnRegenerateAppKey
 * @tc.desc: test OnRegenerateAppKey
 */
HWTEST_F(BmsEventHandlerTest, OnRegenerateAppKey_0001, Function | SmallTest | Level0)
{
    El5FilekeyCallback callback;
    std::vector<Security::AccessToken::AppKeyInfo> infos;
    EXPECT_EQ(callback.OnRegenerateAppKey(infos), ERR_INVALID_DATA);
    EXPECT_EQ(infos.size(), 0);

    Security::AccessToken::AppKeyInfo infoApp;
    infoApp.type = Security::AccessToken::AppKeyType::APP;
    Security::AccessToken::AppKeyInfo infoGroup;
    infoGroup.type = Security::AccessToken::AppKeyType::GROUPID;
    infos.emplace_back(infoApp);
    infos.emplace_back(infoGroup);
    EXPECT_EQ(callback.OnRegenerateAppKey(infos), ERR_OK);
    EXPECT_EQ(infos.size(), 2);
}

/**
 * @tc.number: ProcessAppEl5Dir_0001
 * @tc.name: test ProcessAppEl5Dir
 * @tc.desc: test ProcessAppEl5Dir
 */
HWTEST_F(BmsEventHandlerTest, ProcessAppEl5Dir_0001, Function | SmallTest | Level0)
{
    InnerBundleCloneInfo cloneInfo;
    cloneInfo.appIndex = 1;
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = 100;
    userInfo.cloneInfos.insert(std::make_pair(std::to_string(1), cloneInfo));
    InnerBundleInfo bundleInfo;
    bundleInfo.AddInnerBundleUserInfo(userInfo);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    dataMgr->bundleInfos_.emplace("com.test.test", bundleInfo);

    El5FilekeyCallback callback;
    Security::AccessToken::AppKeyInfo info;
    info.bundleName = "+clone-test";
    callback.ProcessAppEl5Dir(info);
    info.bundleName = "com.test.test";
    callback.ProcessAppEl5Dir(info);
    info.bundleName = "+clone-1+com.test.test";
    callback.ProcessAppEl5Dir(info);
    info.bundleName = "+clone-2+com.test.test";
    callback.ProcessAppEl5Dir(info);

    InnerBundleInfo fetchedBundleInfo;
    EXPECT_TRUE(dataMgr->FetchInnerBundleInfo("com.test.test", fetchedBundleInfo));
    InnerBundleUserInfo fetchedUserInfo;
    EXPECT_TRUE(fetchedBundleInfo.GetInnerBundleUserInfo(100, fetchedUserInfo));
    EXPECT_EQ(fetchedUserInfo.cloneInfos["1"].keyId, "");
}

/**
 * @tc.number: ProcessGroupEl5Dir_0001
 * @tc.name: test ProcessGroupEl5Dir
 * @tc.desc: test ProcessGroupEl5Dir
 */
HWTEST_F(BmsEventHandlerTest, ProcessGroupEl5Dir_0001, Function | SmallTest | Level0)
{
    El5FilekeyCallback callback;
    Security::AccessToken::AppKeyInfo info;
    info.type = Security::AccessToken::AppKeyType::APP;
    callback.ProcessGroupEl5Dir(info);
    EXPECT_EQ(info.type, Security::AccessToken::AppKeyType::APP);

    info.type = Security::AccessToken::AppKeyType::GROUPID;
    info.uid = 1;
    info.groupID = "123";
    callback.ProcessGroupEl5Dir(info);
    EXPECT_EQ(info.type, Security::AccessToken::AppKeyType::GROUPID);
}

/**
 * @tc.number: CheckEl5Dir_0001
 * @tc.name: test CheckEl5Dir
 * @tc.desc: test CheckEl5Dir
 */
HWTEST_F(BmsEventHandlerTest, CheckEl5Dir_0001, Function | SmallTest | Level0)
{
    El5FilekeyCallback callback;
    Security::AccessToken::AppKeyInfo info;
    info.userId = -1;
    InnerBundleInfo bundleInfo;
    callback.CheckEl5Dir(info, bundleInfo, "com.test.test");
    EXPECT_EQ(info.userId, -1);

    info.userId = 100;
    callback.CheckEl5Dir(info, bundleInfo, "com.test.test");
    EXPECT_EQ(info.userId, 100);
}

/**
 * @tc.number: BundleCloneEl1ShaderCacheLocal_0100
 * @tc.name: CheckBundleCloneEl1ShaderCacheLocal
 * @tc.desc: test CheckBundleCloneEl1ShaderCacheLocal and CleanBundleCloneEl1ShaderCacheLocal
 */
HWTEST_F(BmsEventHandlerTest, BundleCloneEl1ShaderCacheLocal_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    DelayedSingleton<BundleMgrService>::GetInstance()->InitBundleDataMgr();
    // test first time mkdir with invalid uid
    setuid(Constants::FOUNDATION_UID);
    handler->CheckBundleCloneEl1ShaderCacheLocal(TEST_SHADER_CACHE_NAME_ONE,
        1, Constants::DEFAULT_USERID, Constants::INVALID_UID);
    bool isExist = CheckShaderCachePathExist(TEST_SHADER_CACHE_NAME_ONE, 1, Constants::START_USERID);
    EXPECT_FALSE(isExist) << "test1: mkdir shader cache succeed: " << TEST_SHADER_CACHE_NAME_ONE;
    setuid(Constants::ROOT_UID);
}

/**
 * @tc.number: BundleCloneEl1ShaderCacheLocal_0200
 * @tc.name: CheckBundleCloneEl1ShaderCacheLocal
 * @tc.desc: test CheckBundleCloneEl1ShaderCacheLocal and CleanBundleCloneEl1ShaderCacheLocal
 */
HWTEST_F(BmsEventHandlerTest, BundleCloneEl1ShaderCacheLocal_0200, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    DelayedSingleton<BundleMgrService>::GetInstance()->InitBundleDataMgr();
    // test first time mkdir with no permission uid
    setuid(Constants::ROOT_UID);
    handler->CheckBundleCloneEl1ShaderCacheLocal(TEST_SHADER_CACHE_NAME_ONE,
        1, Constants::START_USERID, TEST_UID);
    bool isExist = CheckShaderCachePathExist(TEST_SHADER_CACHE_NAME_ONE, 1, Constants::START_USERID);
    EXPECT_FALSE(isExist) << "test2: mkdir shader cache succeed: " << TEST_SHADER_CACHE_NAME_ONE;
}

/**
 * @tc.number: BundleCloneEl1ShaderCacheLocal_0300
 * @tc.name: CheckBundleCloneEl1ShaderCacheLocal
 * @tc.desc: test CheckBundleCloneEl1ShaderCacheLocal and CleanBundleCloneEl1ShaderCacheLocal
 */
HWTEST_F(BmsEventHandlerTest, BundleCloneEl1ShaderCacheLocal_0300, Function | SmallTest | Level0)
{
    std::string el1ShaderCachePath = std::string(ServiceConstants::NEW_SHADER_CACHE_PATH);
    el1ShaderCachePath = el1ShaderCachePath.replace(el1ShaderCachePath.find("%"), 1,
        std::to_string(Constants::START_USERID));
    ASSERT_NE(AppExecFwk::InstalldClient::GetInstance(), nullptr);
    setuid(Constants::FOUNDATION_UID);
    ErrCode ret = AppExecFwk::InstalldClient::GetInstance()->CreateBundleDir(el1ShaderCachePath);
    EXPECT_EQ(ret, ERR_OK);

    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    DelayedSingleton<BundleMgrService>::GetInstance()->InitBundleDataMgr();
    // test first time mkdir shadercache
    setuid(Constants::FOUNDATION_UID);
    handler->CheckBundleCloneEl1ShaderCacheLocal(UNINSTALL_PREINSTALL_BUNDLE_NAME,
        0, Constants::START_USERID, TEST_UID);
    bool isExist = CheckShaderCachePathExist(UNINSTALL_PREINSTALL_BUNDLE_NAME, 0, Constants::START_USERID);
    EXPECT_TRUE(isExist) << "the shader cache path does not exist: " << UNINSTALL_PREINSTALL_BUNDLE_NAME;
    // test shader cache already exist and mkdir second time
    handler->CheckBundleCloneEl1ShaderCacheLocal(UNINSTALL_PREINSTALL_BUNDLE_NAME,
        0, Constants::START_USERID, TEST_UID);
    isExist = CheckShaderCachePathExist(UNINSTALL_PREINSTALL_BUNDLE_NAME, 0, Constants::START_USERID);
    EXPECT_TRUE(isExist) << "the shader cache path second time mkdir failed: " << UNINSTALL_PREINSTALL_BUNDLE_NAME;
    setuid(Constants::ROOT_UID);
}

/**
 * @tc.number: BundleCloneEl1ShaderCacheLocal_0400
 * @tc.name: CheckBundleCloneEl1ShaderCacheLocal
 * @tc.desc: test CheckBundleCloneEl1ShaderCacheLocal and CleanBundleCloneEl1ShaderCacheLocal
 */
HWTEST_F(BmsEventHandlerTest, BundleCloneEl1ShaderCacheLocal_0400, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    DelayedSingleton<BundleMgrService>::GetInstance()->InitBundleDataMgr();
    // test CleanBundleCloneEl1ShaderCacheLocal
    setuid(Constants::ROOT_UID);
    handler->CleanBundleCloneEl1ShaderCacheLocal(UNINSTALL_PREINSTALL_BUNDLE_NAME, 0, Constants::START_USERID);
    bool isExist = CheckShaderCachePathExist(UNINSTALL_PREINSTALL_BUNDLE_NAME, 0, Constants::START_USERID);
    EXPECT_TRUE(isExist) << "the shader cache path was deleted: " << UNINSTALL_PREINSTALL_BUNDLE_NAME;

    setuid(Constants::FOUNDATION_UID);
    handler->CleanBundleCloneEl1ShaderCacheLocal(UNINSTALL_PREINSTALL_BUNDLE_NAME, 0, Constants::START_USERID);
    isExist = CheckShaderCachePathExist(UNINSTALL_PREINSTALL_BUNDLE_NAME, 0, Constants::START_USERID);
    EXPECT_TRUE(isExist) << "the shader cache path was deleted: " << UNINSTALL_PREINSTALL_BUNDLE_NAME;

    // test for invalid app index
    handler->CleanBundleCloneEl1ShaderCacheLocal(UNINSTALL_PREINSTALL_BUNDLE_NAME, 1, Constants::START_USERID);
    isExist = CheckShaderCachePathExist(UNINSTALL_PREINSTALL_BUNDLE_NAME, 1, Constants::START_USERID);
    EXPECT_FALSE(isExist) << "the shader cache path was deleted: " << UNINSTALL_PREINSTALL_BUNDLE_NAME;
    setuid(Constants::ROOT_UID);
}

/**
 * @tc.number: BundleEl1ShaderCacheLocal_0100
 * @tc.name: CheckAllBundleEl1ShaderCacheLocal and CleanAllBundleEl1ShaderCacheLocal
 * @tc.desc: test CheckAllBundleEl1ShaderCacheLocal and CleanAllBundleEl1ShaderCacheLocal
 */
HWTEST_F(BmsEventHandlerTest, BundleEl1ShaderCacheLocal_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(Constants::START_USERID);

    InnerBundleInfo innerBundleInfo;
    // set application
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    // set innerBundleUserInfo
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = BUNDLE_NAME;
    innerBundleUserInfo.bundleUserInfo.enabled = true;
    innerBundleUserInfo.bundleUserInfo.userId = Constants::START_USERID;
    innerBundleUserInfo.uid = TEST_UID;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);

    // set cloneinfo
    InnerBundleCloneInfo cloneInfo;
    cloneInfo.userId = Constants::START_USERID;
    cloneInfo.uid = 1001;
    cloneInfo.appIndex = 1;
    cloneInfo.accessTokenId = 20000;
    ErrCode r1 = innerBundleInfo.AddCloneBundle(cloneInfo);
    EXPECT_EQ(r1, ERR_OK);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, innerBundleInfo);

    // mkdir /data/app/el1/100/shader_cache
    std::string el1ShaderCachePath = std::string(ServiceConstants::NEW_SHADER_CACHE_PATH);
    el1ShaderCachePath = el1ShaderCachePath.replace(el1ShaderCachePath.find("%"), 1,
        std::to_string(Constants::START_USERID));
    setuid(Constants::FOUNDATION_UID);
    ASSERT_NE(AppExecFwk::InstalldClient::GetInstance(), nullptr);
    ErrCode ret = AppExecFwk::InstalldClient::GetInstance()->CreateBundleDir(el1ShaderCachePath);
    EXPECT_EQ(ret, ERR_OK);

    setuid(Constants::FOUNDATION_UID);
    // test CheckAllBundleEl1ShaderCacheLocal succeed
    handler->CheckAllBundleEl1ShaderCacheLocal();
    bool isExist = CheckShaderCachePathExist(BUNDLE_NAME, 0, Constants::START_USERID);
    EXPECT_TRUE(isExist) << "the shader cache path not exist: " << BUNDLE_NAME;

    // test CleanAllBundleEl1ShaderCacheLocal succeed
    handler->CleanAllBundleEl1ShaderCacheLocal();
    isExist = CheckShaderCachePathExist(BUNDLE_NAME, 0, Constants::START_USERID);
    EXPECT_FALSE(isExist) << "the shader cache path not exist: " << BUNDLE_NAME;

    // test when shader cache path no exist
    ErrCode removeRet = AppExecFwk::InstalldClient::GetInstance()->RemoveDir(el1ShaderCachePath);
    EXPECT_EQ(removeRet, ERR_OK);
    handler->CheckAllBundleEl1ShaderCacheLocal();
    isExist = CheckShaderCachePathExist(UNINSTALL_PREINSTALL_BUNDLE_NAME, 0, Constants::START_USERID);
    EXPECT_FALSE(isExist) << "the shader cache path exist: " << UNINSTALL_PREINSTALL_BUNDLE_NAME;

    handler->CleanAllBundleEl1ShaderCacheLocal();
    isExist = CheckShaderCachePathExist(UNINSTALL_PREINSTALL_BUNDLE_NAME, 0, Constants::START_USERID);
    EXPECT_FALSE(isExist) << "the shader cache path not exist: " << UNINSTALL_PREINSTALL_BUNDLE_NAME;
    setuid(Constants::ROOT_UID);
}

/**
 * @tc.number: SaveBmsSystemTimeForShortcut_0100
 * @tc.name: SaveBmsSystemTimeForShortcut
 * @tc.desc: test SaveBmsSystemTimeForShortcut
 */
HWTEST_F(BmsEventHandlerTest, SaveBmsSystemTimeForShortcut_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    EXPECT_NE(handler, nullptr);
    if (handler) {
        DelayedSingleton<BundleMgrService>::GetInstance()->bmsParam_ = nullptr;
        bool ret = handler->SaveBmsSystemTimeForShortcut();
        EXPECT_FALSE(ret);
        auto bmsParam = std::make_shared<BmsParam>();
        EXPECT_NE(bmsParam, nullptr);
        if (bmsParam) {
            ret = bmsParam->DeleteBmsParam(ServiceConstants::BMS_SYSTEM_TIME_FOR_SHORTCUT);
            EXPECT_TRUE(ret);
            DelayedSingleton<BundleMgrService>::GetInstance()->bmsParam_ = std::make_shared<BmsParam>();
            ret = handler->SaveBmsSystemTimeForShortcut();
            EXPECT_TRUE(ret);
        }
        ret = handler->SaveBmsSystemTimeForShortcut();
        EXPECT_TRUE(ret);
    }
}

/**
 * @tc.number: InnerProcessAllDynamicIconInfoWhenOta_0100
 * @tc.name: InnerProcessAllDynamicIconInfoWhenOta
 * @tc.desc: test InnerProcessAllDynamicIconInfoWhenOta
 */
HWTEST_F(BmsEventHandlerTest, InnerProcessAllDynamicIconInfoWhenOta_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);

    handler->InnerProcessAllDynamicIconInfoWhenOta();
    bool checkDynamicIcon = false;
    handler->CheckOtaFlag(OTAFlag::PROCESS_DYNAMIC_CION, checkDynamicIcon);
    EXPECT_TRUE(checkDynamicIcon);

    handler->InnerProcessAllDynamicIconInfoWhenOta();
    handler->CheckOtaFlag(OTAFlag::PROCESS_DYNAMIC_CION, checkDynamicIcon);
    EXPECT_TRUE(checkDynamicIcon);
}

/**
 * @tc.number: InnerBundleInfo_0100
 * @tc.name: UpdateRemovable
 * @tc.desc: test UpdateRemovable
 */
HWTEST_F(BmsEventHandlerTest, InnerBundleInfo_0100, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.UpdateRemovable(false, true);
    EXPECT_TRUE(innerBundleInfo.IsRemovable());
}

/**
 * @tc.number: InnerBundleInfo_0100
 * @tc.name: UpdateRemovable
 * @tc.desc: test UpdateRemovable
 */
HWTEST_F(BmsEventHandlerTest, InnerBundleInfo_0200, Function | SmallTest | Level0)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.UpdateRemovable(true, true);
    EXPECT_TRUE(innerBundleInfo.IsRemovable());
}

/**
 * @tc.number: InnerProcessCheckAppLogDir_0100
 * @tc.name: InnerProcessCheckAppLogDir
 * @tc.desc: test InnerProcessCheckAppLogDir
 */
HWTEST_F(BmsEventHandlerTest, InnerProcessCheckAppLogDir_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(Constants::DEFAULT_USERID);
    dataMgr->AddUserId(Constants::U1);
    dataMgr->bundleInfos_.clear();
    // test bundleInfos_ only has bundleinfo in 0 and 100
    InnerBundleInfo innerBundleInfo;
    InnerBundleUserInfo innerBundleUserInfo0;
    innerBundleUserInfo0.bundleUserInfo.userId = 0;
    innerBundleUserInfo0.bundleName = BUNDLE_NAME_FOR_TEST_U1ENABLE;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo0);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME_FOR_TEST_U1ENABLE, innerBundleInfo);
 
    handler->InnerProcessCheckAppLogDir();
    std::string parentDir1 = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + ServiceConstants::BUNDLE_EL[1] +
        ServiceConstants::PATH_SEPARATOR + std::to_string(1) + ServiceConstants::LOG;
    std::string bundleLogDir1 = parentDir1 + BUNDLE_NAME_FOR_TEST_U1ENABLE;
    bool isExist = false;
    (void)InstalldClient::GetInstance()->IsExistDir(bundleLogDir1, isExist);
    EXPECT_FALSE(isExist);
    dataMgr->bundleInfos_.clear();
    EXPECT_TRUE(dataMgr->bundleInfos_.empty());
    // add innerBundleUserInfo for u1
    InnerBundleUserInfo innerBundleUserInfo1;
    innerBundleUserInfo1.bundleUserInfo.userId = TEST_U1;
    innerBundleUserInfo1.bundleName = BUNDLE_NAME_FOR_TEST_U1ENABLE;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo1);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME_FOR_TEST_U1ENABLE, innerBundleInfo);
    handler->InnerProcessCheckAppLogDir();
    (void)InstalldClient::GetInstance()->IsExistDir(bundleLogDir1, isExist);
    EXPECT_FALSE(isExist);
    (void)InstalldClient::GetInstance()->RemoveDir(bundleLogDir1);
    dataMgr->bundleInfos_.clear();
}

/**
 * @tc.number: CreateAppInstallDir_0100
 * @tc.name: CreateAppInstallDir
 * @tc.desc: test CreateAppInstallDir
 */
HWTEST_F(BmsEventHandlerTest, CreateAppInstallDir_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    ASSERT_NE(handler, nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->AddUserId(Constants::U1);
    dataMgr->AddUserId(Constants::START_USERID);
    handler->CreateAppInstallDir();
    std::string path = std::string(ServiceConstants::HAP_COPY_PATH) +
        ServiceConstants::GALLERY_DOWNLOAD_PATH + std::to_string(Constants::U1);
    EXPECT_EQ(BundleUtil::IsExistDir(path), false);
    std::string appClonePath = path + ServiceConstants::GALLERY_CLONE_PATH;
    EXPECT_EQ(BundleUtil::IsExistDir(appClonePath), false);
}

/**
 * @tc.number: ProcessRebootBundleUninstall_0300
 * @tc.name: ProcessRebootBundleUninstall
 * @tc.desc: test ProcessRebootBundleUninstall
 */
HWTEST_F(BmsEventHandlerTest, ProcessRebootBundleUninstall_0300, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    DelayedSingleton<BundleMgrService>::GetInstance()->InitBundleDataMgr();
    PreInstallBundleInfo preInstallBundleInfo;
    handler->loadExistData_.emplace(BUNDLE_NAME, preInstallBundleInfo);
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, innerBundleInfo);

    handler->ProcessRebootBundleUninstall();
    std::string path = std::string(ServiceConstants::BUNDLE_MANAGER_SERVICE_PATH) +
        ServiceConstants::UNINSTALLED_PRELOAD_PATH + ServiceConstants::UNINSTALLED_PRELOAD_FILE;
    bool isExist = false;
    if (std::filesystem::exists(path)) {
        isExist = true;
    }
    EXPECT_FALSE(isExist);
}

/**
 * @tc.number: SaveUninstalledPreloadAppToFile_0100
 * @tc.name: SaveUninstalledPreloadAppToFile
 * @tc.desc: test SaveUninstalledPreloadAppToFile
 */
HWTEST_F(BmsEventHandlerTest, SaveUninstalledPreloadAppToFile_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    DelayedSingleton<BundleMgrService>::GetInstance()->InitBundleDataMgr();
    handler->RemoveUninstalledPreloadFile();
    std::vector<std::string> preloadBundleNames;
    handler->SaveUninstalledPreloadAppToFile(preloadBundleNames);
    bool isExist = false;
    std::string path = std::string(ServiceConstants::BUNDLE_MANAGER_SERVICE_PATH) +
        ServiceConstants::UNINSTALLED_PRELOAD_PATH + ServiceConstants::UNINSTALLED_PRELOAD_FILE;
    if (std::filesystem::exists(path)) {
        isExist = true;
    }
    EXPECT_FALSE(isExist);

    preloadBundleNames.emplace_back(BUNDLE_NAME);
    handler->SaveUninstalledPreloadAppToFile(preloadBundleNames);
    if (std::filesystem::exists(path)) {
        isExist = true;
    }
    EXPECT_TRUE(isExist);
    handler->RemoveUninstalledPreloadFile();
}

/**
 * @tc.number: SavePreloadAppUninstallInfo_0100
 * @tc.name: SavePreloadAppUninstallInfo
 * @tc.desc: test SavePreloadAppUninstallInfo
 */
HWTEST_F(BmsEventHandlerTest, SavePreloadAppUninstallInfo_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    std::vector<std::string> preloadBundleNames;
    dataMgr->bundleInfos_.clear();
    handler->SavePreloadAppUninstallInfo(BUNDLE_NAME, preloadBundleNames);
    EXPECT_FALSE(preloadBundleNames.empty());

    InnerBundleInfo innerBundleInfo;
    preloadBundleNames.clear();
    dataMgr->bundleInfos_.emplace(BUNDLE_NAME, innerBundleInfo);

    handler->SavePreloadAppUninstallInfo(BUNDLE_NAME, preloadBundleNames);
    EXPECT_TRUE(preloadBundleNames.empty());
}

/**
 * @tc.number: ProcessUpdatePermissions_0100
 * @tc.name: ProcessUpdatePermissions
 * @tc.desc: test ProcessUpdatePermissions
 */
HWTEST_F(BmsEventHandlerTest, ProcessUpdatePermissions_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    EXPECT_NE(handler, nullptr);
    if (handler) {
        DelayedSingleton<BundleMgrService>::GetInstance()->bmsParam_ = nullptr;
        handler->ProcessUpdatePermissions();
        auto bmsParam = std::make_shared<BmsParam>();
        EXPECT_NE(bmsParam, nullptr);
        if (bmsParam) {
            DelayedSingleton<BundleMgrService>::GetInstance()->bmsParam_ = std::make_shared<BmsParam>();
            handler->ProcessUpdatePermissions();
            DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = std::make_shared<BundleDataMgr>();
            handler->ProcessUpdatePermissions();
        }
    }
}

/**
 * @tc.number: IsPermissionsUpdated_0100
 * @tc.name: IsPermissionsUpdated
 * @tc.desc: test IsPermissionsUpdated
 */
HWTEST_F(BmsEventHandlerTest, IsPermissionsUpdated_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    EXPECT_NE(handler, nullptr);
    if (handler) {
        DelayedSingleton<BundleMgrService>::GetInstance()->bmsParam_ = nullptr;
        bool ret = handler->IsPermissionsUpdated();
        EXPECT_FALSE(ret);
        auto bmsParam = std::make_shared<BmsParam>();
        EXPECT_NE(bmsParam, nullptr);
        if (bmsParam) {
            ret = handler->IsPermissionsUpdated();
            EXPECT_FALSE(ret);
            DelayedSingleton<BundleMgrService>::GetInstance()->bmsParam_ = std::make_shared<BmsParam>();
            ret = handler->IsPermissionsUpdated();
            EXPECT_TRUE(ret);
            ret = bmsParam->DeleteBmsParam(ServiceConstants::UPDATE_PERMISSIONS_FLAG);
            EXPECT_TRUE(ret);
            ret = handler->IsPermissionsUpdated();
            EXPECT_FALSE(ret);
            ret = bmsParam->SaveBmsParam(ServiceConstants::UPDATE_PERMISSIONS_FLAG,
                ServiceConstants::UPDATE_PERMISSIONS_FLAG_UPDATED);
            EXPECT_TRUE(ret);
        }
    }
}

/**
 * @tc.number: SaveUpdatePermissionsFlag_0100
 * @tc.name: SaveUpdatePermissionsFlag
 * @tc.desc: test SaveUpdatePermissionsFlag
 */
HWTEST_F(BmsEventHandlerTest, SaveUpdatePermissionsFlag_0100, Function | SmallTest | Level0)
{
    std::shared_ptr<BMSEventHandler> handler = std::make_shared<BMSEventHandler>();
    EXPECT_NE(handler, nullptr);
    if (handler) {
        DelayedSingleton<BundleMgrService>::GetInstance()->bmsParam_ = nullptr;
        bool ret = handler->SaveUpdatePermissionsFlag();
        EXPECT_FALSE(ret);
        auto bmsParam = std::make_shared<BmsParam>();
        EXPECT_NE(bmsParam, nullptr);
        if (bmsParam) {
            std::string value;
            ret = bmsParam->GetBmsParam(ServiceConstants::UPDATE_PERMISSIONS_FLAG, value);
            EXPECT_TRUE(ret);
            DelayedSingleton<BundleMgrService>::GetInstance()->bmsParam_ = std::make_shared<BmsParam>();
            ret = handler->SaveUpdatePermissionsFlag();
            EXPECT_TRUE(ret);
            ret = bmsParam->GetBmsParam(ServiceConstants::UPDATE_PERMISSIONS_FLAG, value);
            EXPECT_TRUE(ret);
        }
    }
}
} // OHOS
