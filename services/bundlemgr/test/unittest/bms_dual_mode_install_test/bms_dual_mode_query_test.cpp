/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

// Dual-mode appIndex=0/10000 query-side unit tests, split from bms_dual_mode_install_test.cpp.
// Same white-box approach: drive private members directly. Mode is driven through the
// test-injection system parameters (persist.bms.test_dual_mode switches DualModeHelper to the
// persist.bms.* test keys); DualModeHelper reads these directly each call (no cache).
#define private public
#define protected public
#include <gtest/gtest.h>
#include <string>
#include <unordered_map>
#include <vector>

#include "appexecfwk_errors.h"
#include "application_info.h"
#include "bundle_constants.h"
#include "bundle_dir.h"
#include "bundle_info.h"
#include "base_bundle_installer.h"
#include "bundle_data_mgr.h"
#include "bundle_data_storage_rdb.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_service_constants.h"
#include "dual_mode_helper.h"
#include "extend_resource/extend_resource_manager_host_impl.h"
#include "inner_bundle_info.h"
#include "install_param.h"
#include "message_parcel.h"
#include "nlohmann/json.hpp"
#include "parameters.h"
#include "shortcut_info.h"
#include "bundle_resource/bundle_resource_manager.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.example.test";
const std::string PREFIXED_NAME = "+clone-10000+" + BUNDLE_NAME;
const std::string CLONE_APP_NAME = "+clone-1+" + BUNDLE_NAME;  // regular clone (appIndex 1..5), not dual-mode
const int32_t TEST_USERID = 100;
constexpr const char *TEST_DUAL_MODE_PARAM = "persist.bms.test_dual_mode";
constexpr const char *TEST_ISPCMODE_PARAM = "persist.bms.ispcmode";
constexpr const char *TEST_MAINMODE_PARAM = "persist.bms.mainmode";
}  // namespace

class BmsDualModeQueryTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp();
    void TearDown() {}
};

// Reset the mode params so cases do not affect each other. Both params set to invalid (-1) so
// IsDualModeDevice() returns false unless a case explicitly sets a valid mode.
void BmsDualModeQueryTest::SetUp()
{
    OHOS::system::SetParameter(TEST_DUAL_MODE_PARAM, "true");
    OHOS::system::SetParameter(TEST_ISPCMODE_PARAM,
        std::to_string(ServiceConstants::DUAL_MODE_VALUE_INVALID));
    OHOS::system::SetParameter(TEST_MAINMODE_PARAM,
        std::to_string(ServiceConstants::DUAL_MODE_VALUE_INVALID));
}

// Drive DualModeHelper mode judgment via the test-injection system parameters.
// ispcmode: 0=tablet, 1=2in1 (current mode); mainmode: 0=main tablet, 1=main 2in1; -1=invalid.
// DualModeHelper reads these directly each call (no cache, no refresh needed).
static void SetDualModeCache(int ispcmode, int mainmode)
{
    OHOS::system::SetParameter(TEST_DUAL_MODE_PARAM, "true");
    OHOS::system::SetParameter(TEST_ISPCMODE_PARAM, std::to_string(ispcmode));
    OHOS::system::SetParameter(TEST_MAINMODE_PARAM, std::to_string(mainmode));
}

static void EnableSecondaryMode()
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_2IN1, ServiceConstants::DUAL_MODE_VALUE_TABLET);
}

// Primary mode: ispcmode == mainmode (both tablet), so IsSecondaryMode() == false.
static void EnablePrimaryMode()
{
    SetDualModeCache(ServiceConstants::DUAL_MODE_VALUE_TABLET, ServiceConstants::DUAL_MODE_VALUE_TABLET);
}

// Build a fresh BundleDataMgr, register userId and install it into the global BundleMgrService.
static std::shared_ptr<BundleDataMgr> InstallTestDataMgr(int32_t userId)
{
    auto service = DelayedSingleton<BundleMgrService>::GetInstance();
    auto dataMgr = std::make_shared<BundleDataMgr>();
    dataMgr->multiUserIdsSet_.insert(userId);
    service->dataMgr_ = dataMgr;
    return dataMgr;
}

// ====================== InnerBundleInfo::GetApplicationEnabledV9 dual-mode ======================

static InnerBundleUserInfo MakeUserInfo(const std::string &name, int32_t userId, bool enabled)
{
    InnerBundleUserInfo userInfo;
    userInfo.bundleName = name;
    userInfo.bundleUserInfo.userId = userId;
    userInfo.bundleUserInfo.enabled = enabled;
    return userInfo;
}

HWTEST_F(BmsDualModeQueryTest, GetApplicationEnabledV9_DualModeClone_0100, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    info.SetDualModeCloneApp(true);
    info.SetAppIndex(ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    auto userInfo = MakeUserInfo(BUNDLE_NAME, TEST_USERID, true);
    std::string key = BUNDLE_NAME + "_" + std::to_string(TEST_USERID);
    info.innerBundleUserInfos_.try_emplace(key, userInfo);
    bool isEnabled = false;
    auto ret = info.GetApplicationEnabledV9(TEST_USERID, isEnabled, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(isEnabled);
}

HWTEST_F(BmsDualModeQueryTest, GetApplicationEnabledV9_DualModeCloneAppIndex0_0200, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    info.SetDualModeCloneApp(true);
    info.SetAppIndex(ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    auto userInfo = MakeUserInfo(BUNDLE_NAME, TEST_USERID, false);
    std::string key = BUNDLE_NAME + "_" + std::to_string(TEST_USERID);
    info.innerBundleUserInfos_.try_emplace(key, userInfo);
    bool isEnabled = true;
    auto ret = info.GetApplicationEnabledV9(TEST_USERID, isEnabled, 0);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isEnabled);
}

HWTEST_F(BmsDualModeQueryTest, GetApplicationEnabledV9_NonCloneReject10000_0300, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    info.SetDualModeCloneApp(false);
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    auto userInfo = MakeUserInfo(BUNDLE_NAME, TEST_USERID, true);
    std::string key = BUNDLE_NAME + "_" + std::to_string(TEST_USERID);
    info.innerBundleUserInfos_.try_emplace(key, userInfo);
    bool isEnabled = false;
    auto ret = info.GetApplicationEnabledV9(TEST_USERID, isEnabled, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    EXPECT_EQ(ret, ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE);
}

// ====================== InnerBundleInfo::GetApplicationInfoAdaptBundleClone dual-mode ======================

HWTEST_F(BmsDualModeQueryTest, GetApplicationInfoAdaptBundleClone_DualModeClone_0100, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    info.SetDualModeCloneApp(true);
    info.SetAppIndex(ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    auto userInfo = MakeUserInfo(BUNDLE_NAME, TEST_USERID, true);
    ApplicationInfo appInfo;
    EXPECT_TRUE(info.GetApplicationInfoAdaptBundleClone(userInfo,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, appInfo));
    EXPECT_EQ(appInfo.appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, GetApplicationInfoAdaptBundleClone_DualModeCloneAppIndex0_0200,
    Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    info.SetDualModeCloneApp(true);
    info.SetAppIndex(ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    auto userInfo = MakeUserInfo(BUNDLE_NAME, TEST_USERID, true);
    ApplicationInfo appInfo;
    EXPECT_TRUE(info.GetApplicationInfoAdaptBundleClone(userInfo, 0, appInfo));
    EXPECT_EQ(appInfo.appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, GetApplicationInfoAdaptBundleClone_NonCloneReject10000_0300,
    Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    info.SetDualModeCloneApp(false);
    auto userInfo = MakeUserInfo(BUNDLE_NAME, TEST_USERID, true);
    ApplicationInfo appInfo;
    EXPECT_FALSE(info.GetApplicationInfoAdaptBundleClone(userInfo,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, appInfo));
}

// ====================== InnerBundleInfo::GetBundleInfoAdaptBundleClone dual-mode ======================

HWTEST_F(BmsDualModeQueryTest, GetBundleInfoAdaptBundleClone_NonCloneReject10000_0100,
    Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    info.SetDualModeCloneApp(false);
    auto userInfo = MakeUserInfo(BUNDLE_NAME, TEST_USERID, true);
    BundleInfo bundleInfo;
    EXPECT_FALSE(info.GetBundleInfoAdaptBundleClone(userInfo,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, bundleInfo));
}

// ====================== InnerBundleInfo::GetUid dual-mode ======================

HWTEST_F(BmsDualModeQueryTest, GetUid_DualModeClone_0100, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    info.SetDualModeCloneApp(true);
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    InnerBundleUserInfo userInfo = MakeUserInfo(BUNDLE_NAME, TEST_USERID, true);
    userInfo.uid = 200000;
    std::string key = BUNDLE_NAME + "_" + std::to_string(TEST_USERID);
    info.innerBundleUserInfos_.try_emplace(key, userInfo);
    EXPECT_EQ(info.GetUid(TEST_USERID, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX), 200000);
}

HWTEST_F(BmsDualModeQueryTest, GetUid_DualModeCloneAppIndex0_0200, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    info.SetDualModeCloneApp(true);
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    InnerBundleUserInfo userInfo = MakeUserInfo(BUNDLE_NAME, TEST_USERID, true);
    userInfo.uid = 200000;
    std::string key = BUNDLE_NAME + "_" + std::to_string(TEST_USERID);
    info.innerBundleUserInfos_.try_emplace(key, userInfo);
    EXPECT_EQ(info.GetUid(TEST_USERID, 0), 200000);
}

HWTEST_F(BmsDualModeQueryTest, GetUid_NonCloneAppIndex10000_0300, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    info.SetDualModeCloneApp(false);
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    InnerBundleUserInfo userInfo = MakeUserInfo(BUNDLE_NAME, TEST_USERID, true);
    userInfo.uid = 200000;
    std::string key = BUNDLE_NAME + "_" + std::to_string(TEST_USERID);
    info.innerBundleUserInfos_.try_emplace(key, userInfo);
    EXPECT_EQ(info.GetUid(TEST_USERID, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX), Constants::INVALID_UID);
}

// ====================== BundleDataMgr::GetBundleNameAndIndex dual-mode ======================

HWTEST_F(BmsDualModeQueryTest, GetBundleNameAndIndex_DualModeCloneKey_0100, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    int32_t bundleId = 10001;
    dataMgr->bundleIdMap_.emplace(bundleId, PREFIXED_NAME);
    std::string bundleName;
    int32_t appIndex = 0;
    auto ret = dataMgr->GetBundleNameAndIndex(bundleId, bundleName, appIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(bundleName, BUNDLE_NAME);
    EXPECT_EQ(appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

// ====================== BundleDataMgr::CheckBundleExist dual-mode ======================

HWTEST_F(BmsDualModeQueryTest, CheckBundleExist_DualModeClone_0100, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    InnerBundleInfo info;
    info.SetDualModeCloneApp(true);
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    auto userInfo = MakeUserInfo(BUNDLE_NAME, TEST_USERID, true);
    std::string key = BUNDLE_NAME + "_" + std::to_string(TEST_USERID);
    info.innerBundleUserInfos_.try_emplace(key, userInfo);
    dataMgr->bundleInfos_[BUNDLE_NAME] = info;
    auto ret = dataMgr->CheckBundleExist(BUNDLE_NAME, TEST_USERID,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    EXPECT_EQ(ret, ERR_OK);
}

HWTEST_F(BmsDualModeQueryTest, CheckBundleExist_NonCloneAppIndex10000_0200, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    InnerBundleInfo info;
    info.SetDualModeCloneApp(false);
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    auto userInfo = MakeUserInfo(BUNDLE_NAME, TEST_USERID, true);
    std::string key = BUNDLE_NAME + "_" + std::to_string(TEST_USERID);
    info.innerBundleUserInfos_.try_emplace(key, userInfo);
    dataMgr->bundleInfos_[BUNDLE_NAME] = info;
    auto ret = dataMgr->CheckBundleExist(BUNDLE_NAME, TEST_USERID,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_APPINDEX_NOT_EXIST);
}

// ====================== BundleDataMgr::IsBundleInstalled dual-mode ======================

HWTEST_F(BmsDualModeQueryTest, IsBundleInstalled_DualModeClone_0100, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    InnerBundleInfo info;
    info.SetDualModeCloneApp(true);
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    auto userInfo = MakeUserInfo(BUNDLE_NAME, TEST_USERID, true);
    std::string key = BUNDLE_NAME + "_" + std::to_string(TEST_USERID);
    info.innerBundleUserInfos_.try_emplace(key, userInfo);
    dataMgr->bundleInfos_[BUNDLE_NAME] = info;
    bool isInstalled = false;
    auto ret = dataMgr->IsBundleInstalled(BUNDLE_NAME, TEST_USERID,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, isInstalled);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(isInstalled);
}

HWTEST_F(BmsDualModeQueryTest, IsBundleInstalled_NonCloneAppIndex10000_0200, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    InnerBundleInfo info;
    info.SetDualModeCloneApp(false);
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    auto userInfo = MakeUserInfo(BUNDLE_NAME, TEST_USERID, true);
    std::string key = BUNDLE_NAME + "_" + std::to_string(TEST_USERID);
    info.innerBundleUserInfos_.try_emplace(key, userInfo);
    dataMgr->bundleInfos_[BUNDLE_NAME] = info;
    bool isInstalled = true;
    auto ret = dataMgr->IsBundleInstalled(BUNDLE_NAME, TEST_USERID,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, isInstalled);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isInstalled);
}

// ====================== BundleDataMgr::GetDirByBundleNameAndAppIndex dual-mode ======================

HWTEST_F(BmsDualModeQueryTest, GetDirByBundleNameAndAppIndex_InvalidAppIndex_0100,
    Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    std::string dataDir;
    auto ret = dataMgr->GetDirByBundleNameAndAppIndex(BUNDLE_NAME, 9999, dataDir);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_GET_DIR_INVALID_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, GetDirByBundleNameAndAppIndex_NonCloneAppIndex10000_0200,
    Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    info.SetDualModeCloneApp(false);
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    dataMgr->bundleInfos_[BUNDLE_NAME] = info;
    std::string dataDir;
    auto ret = dataMgr->GetDirByBundleNameAndAppIndex(BUNDLE_NAME,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, dataDir);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_GET_DIR_INVALID_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, GetDirByBundleNameAndAppIndex_DualModeCloneAppIndex10000_0300,
    Function | SmallTest | Level0)
{
    EnableSecondaryMode();
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    info.SetDualModeCloneApp(true);
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    dataMgr->bundleInfos_[BUNDLE_NAME] = info;
    std::string dataDir;
    auto ret = dataMgr->GetDirByBundleNameAndAppIndex(BUNDLE_NAME,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, dataDir);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(dataDir, PREFIXED_NAME);
}

HWTEST_F(BmsDualModeQueryTest, GetDirByBundleNameAndAppIndex_DualModeCloneAppIndex0_0400,
    Function | SmallTest | Level0)
{
    EnableSecondaryMode();
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    info.SetDualModeCloneApp(true);
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    dataMgr->bundleInfos_[BUNDLE_NAME] = info;
    std::string dataDir;
    auto ret = dataMgr->GetDirByBundleNameAndAppIndex(BUNDLE_NAME, 0, dataDir);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(dataDir, PREFIXED_NAME);
}

HWTEST_F(BmsDualModeQueryTest, GetDirByBundleNameAndAppIndex_NormalAppAppIndex0_0500,
    Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    info.SetDualModeCloneApp(false);
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    dataMgr->bundleInfos_[BUNDLE_NAME] = info;
    std::string dataDir;
    auto ret = dataMgr->GetDirByBundleNameAndAppIndex(BUNDLE_NAME, 0, dataDir);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(dataDir, BUNDLE_NAME);
}

HWTEST_F(BmsDualModeQueryTest, HostImplGetDirByBundleNameAndAppIndex_NonCloneAppIndex10000_0600,
    Function | SmallTest | Level0)
{
    EnableSecondaryMode();
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    info.SetDualModeCloneApp(false);
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    dataMgr->bundleInfos_[BUNDLE_NAME] = info;
    auto service = DelayedSingleton<BundleMgrService>::GetInstance();
    service->RegisterDataMgr(dataMgr);
    auto hostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::string dataDir;
    auto ret = hostImpl->GetDirByBundleNameAndAppIndex(BUNDLE_NAME,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, dataDir);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_GET_DIR_INVALID_APP_INDEX);
    service->RegisterDataMgr(nullptr);
}

HWTEST_F(BmsDualModeQueryTest, HostImplGetDirByBundleNameAndAppIndex_DualModeCloneAppIndex10000_0700,
    Function | SmallTest | Level0)
{
    EnableSecondaryMode();
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo info;
    info.SetDualModeCloneApp(true);
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    dataMgr->bundleInfos_[BUNDLE_NAME] = info;
    auto service = DelayedSingleton<BundleMgrService>::GetInstance();
    service->RegisterDataMgr(dataMgr);
    auto hostImpl = std::make_shared<BundleMgrHostImpl>();
    ASSERT_NE(hostImpl, nullptr);
    std::string dataDir;
    auto ret = hostImpl->GetDirByBundleNameAndAppIndex(BUNDLE_NAME,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, dataDir);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(dataDir, PREFIXED_NAME);
    service->RegisterDataMgr(nullptr);
}

// ====================== BundleDataMgr::GetShortcutInfoByAppIndex dual-mode ======================

HWTEST_F(BmsDualModeQueryTest, GetShortcutInfoByAppIndex_DualModeClone_0100, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    std::vector<ShortcutInfo> shortcutInfos;
    auto ret = dataMgr->GetShortcutInfoByAppIndex(BUNDLE_NAME,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, shortcutInfos);
    EXPECT_NE(ret, ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE);
}

// ====================== BundleDataMgr::GetShortcutInfoByAbility dual-mode ======================

HWTEST_F(BmsDualModeQueryTest, GetShortcutInfoByAbility_DualModeClone_0100, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    std::vector<ShortcutInfo> shortcutInfos;
    auto ret = dataMgr->GetShortcutInfoByAbility(BUNDLE_NAME, "module1", "ability1", TEST_USERID,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, shortcutInfos);
    EXPECT_NE(ret, ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE);
}

// ====================== InnerBundleInfo::IsAbilityEnabledV9 dual-mode ======================

static AbilityInfo MakeAbilityInfo(const std::string &bundleName, const std::string &abilityName)
{
    AbilityInfo abilityInfo;
    abilityInfo.bundleName = bundleName;
    abilityInfo.name = abilityName;
    abilityInfo.moduleName = "entry";
    return abilityInfo;
}

HWTEST_F(BmsDualModeQueryTest, IsAbilityEnabledV9_DualModeClone_0100, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    info.SetDualModeCloneApp(true);
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    auto userInfo = MakeUserInfo(BUNDLE_NAME, TEST_USERID, true);
    std::string key = BUNDLE_NAME + "_" + std::to_string(TEST_USERID);
    info.innerBundleUserInfos_.try_emplace(key, userInfo);
    bool isEnable = false;
    auto ret = info.IsAbilityEnabledV9(MakeAbilityInfo(BUNDLE_NAME, "MainAbility"),
        TEST_USERID, isEnable, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(isEnable);
}

HWTEST_F(BmsDualModeQueryTest, IsAbilityEnabledV9_DualModeCloneAppIndex0_0200, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    info.SetDualModeCloneApp(true);
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    auto userInfo = MakeUserInfo(BUNDLE_NAME, TEST_USERID, true);
    userInfo.bundleUserInfo.disabledAbilities.push_back("MainAbility");
    std::string key = BUNDLE_NAME + "_" + std::to_string(TEST_USERID);
    info.innerBundleUserInfos_.try_emplace(key, userInfo);
    bool isEnable10000 = true;
    bool isEnable0 = true;
    auto ret10000 = info.IsAbilityEnabledV9(MakeAbilityInfo(BUNDLE_NAME, "MainAbility"),
        TEST_USERID, isEnable10000, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    auto ret0 = info.IsAbilityEnabledV9(MakeAbilityInfo(BUNDLE_NAME, "MainAbility"),
        TEST_USERID, isEnable0, 0);
    EXPECT_EQ(ret10000, ERR_OK);
    EXPECT_EQ(ret0, ERR_OK);
    EXPECT_FALSE(isEnable10000);
    EXPECT_FALSE(isEnable0);
    EXPECT_EQ(isEnable10000, isEnable0);
}

HWTEST_F(BmsDualModeQueryTest, IsAbilityEnabledV9_NonCloneReject10000_0300, Function | SmallTest | Level0)
{
    InnerBundleInfo info;
    info.SetDualModeCloneApp(false);
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    auto userInfo = MakeUserInfo(BUNDLE_NAME, TEST_USERID, true);
    std::string key = BUNDLE_NAME + "_" + std::to_string(TEST_USERID);
    info.innerBundleUserInfos_.try_emplace(key, userInfo);
    bool isEnable = false;
    auto ret = info.IsAbilityEnabledV9(MakeAbilityInfo(BUNDLE_NAME, "MainAbility"),
        TEST_USERID, isEnable, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    EXPECT_EQ(ret, ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE);
}

// ====================== BundleDataMgr::IsAbilityEnabled dual-mode ======================

// InnerBundleInfo with one ability and one userInfo entry.
static InnerBundleInfo MakeAbilityEnabledInfo(bool isClone, const std::string &bundleName, int32_t userId)
{
    InnerBundleInfo info;
    info.SetDualModeCloneApp(isClone);
    info.baseApplicationInfo_->bundleName = bundleName;
    InnerAbilityInfo innerAbilityInfo;
    innerAbilityInfo.bundleName = bundleName;
    innerAbilityInfo.name = "MainAbility";
    innerAbilityInfo.moduleName = "entry";
    info.baseAbilityInfos_.emplace("entry_MainAbility", innerAbilityInfo);
    auto userInfo = MakeUserInfo(bundleName, userId, true);
    std::string key = bundleName + "_" + std::to_string(userId);
    info.innerBundleUserInfos_.try_emplace(key, userInfo);
    return info;
}

HWTEST_F(BmsDualModeQueryTest, DataMgrIsAbilityEnabled_DualModeClone10000_0100, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    // IsAbilityEnabled resolves the user from the calling uid (0 in unit tests).
    dataMgr->multiUserIdsSet_.insert(0);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeAbilityEnabledInfo(true, BUNDLE_NAME, 0);
    bool isEnable = true;
    auto ret = dataMgr->IsAbilityEnabled(MakeAbilityInfo(BUNDLE_NAME, "MainAbility"),
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, isEnable);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(isEnable);
}

HWTEST_F(BmsDualModeQueryTest, DataMgrIsAbilityEnabled_NonClone10000_0200, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeAbilityEnabledInfo(false, BUNDLE_NAME, TEST_USERID);
    bool isEnable = false;
    auto ret = dataMgr->IsAbilityEnabled(MakeAbilityInfo(BUNDLE_NAME, "MainAbility"),
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, isEnable);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_INVALID_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, DataMgrIsAbilityEnabled_OtherInvalidIndex_0300, Function | SmallTest | Level0)
{
    // regression: appIndex=6 is outside clone range and not 10000
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeAbilityEnabledInfo(false, BUNDLE_NAME, TEST_USERID);
    bool isEnable = false;
    auto ret = dataMgr->IsAbilityEnabled(MakeAbilityInfo(BUNDLE_NAME, "MainAbility"), 6, isEnable);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_INVALID_APP_INDEX);
}

// ====================== BundleDataMgr::SetAbilityEnabled dual-mode ======================

HWTEST_F(BmsDualModeQueryTest, DataMgrSetAbilityEnabled_DualModeClone10000_0100, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeAbilityEnabledInfo(true, BUNDLE_NAME, TEST_USERID);
    bool stateChanged = false;
    auto ret = dataMgr->SetAbilityEnabled(MakeAbilityInfo(BUNDLE_NAME, "MainAbility"),
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, false, TEST_USERID, stateChanged);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(stateChanged);
    const auto &userInfo = dataMgr->bundleInfos_[BUNDLE_NAME]
        .innerBundleUserInfos_.at(BUNDLE_NAME + "_" + std::to_string(TEST_USERID));
    EXPECT_FALSE(userInfo.bundleUserInfo.disabledAbilities.empty());
    EXPECT_TRUE(userInfo.cloneInfos.empty());
}

HWTEST_F(BmsDualModeQueryTest, DataMgrSetAbilityEnabled_DualModeCloneRepeat_0200, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeAbilityEnabledInfo(true, BUNDLE_NAME, TEST_USERID);
    bool stateChanged = false;
    auto ret = dataMgr->SetAbilityEnabled(MakeAbilityInfo(BUNDLE_NAME, "MainAbility"),
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, false, TEST_USERID, stateChanged);
    ASSERT_EQ(ret, ERR_OK);
    EXPECT_TRUE(stateChanged);
    stateChanged = true;
    ret = dataMgr->SetAbilityEnabled(MakeAbilityInfo(BUNDLE_NAME, "MainAbility"),
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, false, TEST_USERID, stateChanged);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(stateChanged);
}

HWTEST_F(BmsDualModeQueryTest, DataMgrSetAbilityEnabled_NonClone10000_0300, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeAbilityEnabledInfo(false, BUNDLE_NAME, TEST_USERID);
    bool stateChanged = false;
    auto ret = dataMgr->SetAbilityEnabled(MakeAbilityInfo(BUNDLE_NAME, "MainAbility"),
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, false, TEST_USERID, stateChanged);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_INVALID_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, DataMgrSetAbilityEnabled_DualModeCloneAppIndex0_0400, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeAbilityEnabledInfo(true, BUNDLE_NAME, TEST_USERID);
    bool stateChanged = false;
    auto ret = dataMgr->SetAbilityEnabled(MakeAbilityInfo(BUNDLE_NAME, "MainAbility"),
        0, false, TEST_USERID, stateChanged);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(stateChanged);
    const auto &userInfo = dataMgr->bundleInfos_[BUNDLE_NAME]
        .innerBundleUserInfos_.at(BUNDLE_NAME + "_" + std::to_string(TEST_USERID));
    EXPECT_FALSE(userInfo.bundleUserInfo.disabledAbilities.empty());
}

// ====================== BundleDataMgr::SetApplicationEnabled dual-mode ======================

HWTEST_F(BmsDualModeQueryTest, DataMgrSetApplicationEnabled_DualModeClone10000_0100, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeAbilityEnabledInfo(true, BUNDLE_NAME, TEST_USERID);
    bool stateChanged = false;
    auto ret = dataMgr->SetApplicationEnabled(BUNDLE_NAME,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, false, "caller", TEST_USERID, stateChanged);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(stateChanged);
    const auto &userInfo = dataMgr->bundleInfos_[BUNDLE_NAME]
        .innerBundleUserInfos_.at(BUNDLE_NAME + "_" + std::to_string(TEST_USERID));
    EXPECT_FALSE(userInfo.bundleUserInfo.enabled);
}

// ====================== BundleDataMgr::ApplyDualModeCloneBundleState ======================

HWTEST_F(BmsDualModeQueryTest, ApplyDualModeCloneBundleState_NotDualModeKey_0100, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeAbilityEnabledInfo(true, BUNDLE_NAME, TEST_USERID);
    std::map<int32_t, BundleUserInfo> states;
    BundleUserInfo state;
    state.userId = TEST_USERID;
    state.enabled = false;
    states[TEST_USERID] = state;
    dataMgr->ApplyDualModeCloneBundleState(CLONE_APP_NAME, states);
    const auto &userInfo = dataMgr->bundleInfos_[BUNDLE_NAME]
        .innerBundleUserInfos_.at(BUNDLE_NAME + "_" + std::to_string(TEST_USERID));
    EXPECT_TRUE(userInfo.bundleUserInfo.enabled);
}

HWTEST_F(BmsDualModeQueryTest, ApplyDualModeCloneBundleState_SecondaryMode_0200, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeAbilityEnabledInfo(true, BUNDLE_NAME, TEST_USERID);
    std::map<int32_t, BundleUserInfo> states;
    BundleUserInfo state;
    state.userId = TEST_USERID;
    state.enabled = false;
    state.disabledAbilities.push_back("MainAbility");
    states[TEST_USERID] = state;
    dataMgr->ApplyDualModeCloneBundleState(PREFIXED_NAME, states);
    const auto &userInfo = dataMgr->bundleInfos_[BUNDLE_NAME]
        .innerBundleUserInfos_.at(BUNDLE_NAME + "_" + std::to_string(TEST_USERID));
    EXPECT_FALSE(userInfo.bundleUserInfo.enabled);
    EXPECT_FALSE(userInfo.bundleUserInfo.disabledAbilities.empty());
}

HWTEST_F(BmsDualModeQueryTest, ApplyDualModeCloneBundleState_PrimaryModeIsolated_0300, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeAbilityEnabledInfo(false, BUNDLE_NAME, TEST_USERID);
    dataMgr->tempBundleInfos_[BUNDLE_NAME] = MakeAbilityEnabledInfo(true, BUNDLE_NAME, TEST_USERID);
    std::map<int32_t, BundleUserInfo> states;
    BundleUserInfo state;
    state.userId = TEST_USERID;
    state.enabled = false;
    state.disabledAbilities.push_back("MainAbility");
    states[TEST_USERID] = state;
    dataMgr->ApplyDualModeCloneBundleState(PREFIXED_NAME, states);
    const auto &primaryUserInfo = dataMgr->bundleInfos_[BUNDLE_NAME]
        .innerBundleUserInfos_.at(BUNDLE_NAME + "_" + std::to_string(TEST_USERID));
    EXPECT_TRUE(primaryUserInfo.bundleUserInfo.enabled);
    EXPECT_TRUE(primaryUserInfo.bundleUserInfo.disabledAbilities.empty());
    const auto &cloneUserInfo = dataMgr->tempBundleInfos_[BUNDLE_NAME]
        .innerBundleUserInfos_.at(BUNDLE_NAME + "_" + std::to_string(TEST_USERID));
    EXPECT_FALSE(cloneUserInfo.bundleUserInfo.enabled);
    EXPECT_FALSE(cloneUserInfo.bundleUserInfo.disabledAbilities.empty());
}

HWTEST_F(BmsDualModeQueryTest, ApplyDualModeCloneBundleState_NoCloneRecord_0400, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeAbilityEnabledInfo(false, BUNDLE_NAME, TEST_USERID);
    std::map<int32_t, BundleUserInfo> states;
    BundleUserInfo state;
    state.userId = TEST_USERID;
    state.enabled = false;
    state.disabledAbilities.push_back("MainAbility");
    states[TEST_USERID] = state;
    dataMgr->ApplyDualModeCloneBundleState(PREFIXED_NAME, states);
    const auto &primaryUserInfo = dataMgr->bundleInfos_[BUNDLE_NAME]
        .innerBundleUserInfos_.at(BUNDLE_NAME + "_" + std::to_string(TEST_USERID));
    EXPECT_TRUE(primaryUserInfo.bundleUserInfo.enabled);
    EXPECT_TRUE(primaryUserInfo.bundleUserInfo.disabledAbilities.empty());
}

// ====================== BundleDataMgr::ResetBundleStateData dual-mode ======================

HWTEST_F(BmsDualModeQueryTest, ResetBundleStateData_CoversTempBundleInfos_0100, Function | SmallTest | Level0)
{
    EnablePrimaryMode();
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo cloneInfo = MakeAbilityEnabledInfo(true, BUNDLE_NAME, TEST_USERID);
    cloneInfo.innerBundleUserInfos_.at(BUNDLE_NAME + "_" + std::to_string(TEST_USERID))
        .bundleUserInfo.enabled = false;
    dataMgr->tempBundleInfos_[BUNDLE_NAME] = cloneInfo;
    dataMgr->ResetBundleStateData();
    const auto &userInfo = dataMgr->tempBundleInfos_[BUNDLE_NAME]
        .innerBundleUserInfos_.at(BUNDLE_NAME + "_" + std::to_string(TEST_USERID));
    EXPECT_TRUE(userInfo.bundleUserInfo.enabled);
}

// ====================== BundleDataMgr::IsApplicationEnabled legacy error-code compat ======================

HWTEST_F(BmsDualModeQueryTest, DataMgrIsApplicationEnabled_LegacyCloneNotInstalled_0100, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeAbilityEnabledInfo(false, BUNDLE_NAME, TEST_USERID);
    bool isEnabled = false;
    auto ret = dataMgr->IsApplicationEnabled(BUNDLE_NAME, 3, isEnabled, TEST_USERID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_INVALID_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, DataMgrIsApplicationEnabled_LegacyCliSandboxRejected_0200, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeAbilityEnabledInfo(false, BUNDLE_NAME, TEST_USERID);
    bool isEnabled = false;
    auto ret = dataMgr->IsApplicationEnabled(BUNDLE_NAME, 2000, isEnabled, TEST_USERID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_INVALID_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, DataMgrIsApplicationEnabled_UserInfoMissing_NonZeroIndex_0300,
    Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    InnerBundleInfo info = MakeAbilityEnabledInfo(false, BUNDLE_NAME, TEST_USERID);
    info.innerBundleUserInfos_.clear();
    dataMgr->bundleInfos_[BUNDLE_NAME] = info;
    bool isEnabled = false;
    auto ret = dataMgr->IsApplicationEnabled(BUNDLE_NAME, 1, isEnabled, TEST_USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

HWTEST_F(BmsDualModeQueryTest, DataMgrIsApplicationEnabled_UserInfoMissing_Index0_0400,
    Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    InnerBundleInfo info = MakeAbilityEnabledInfo(false, BUNDLE_NAME, TEST_USERID);
    info.innerBundleUserInfos_.clear();
    dataMgr->bundleInfos_[BUNDLE_NAME] = info;
    bool isEnabled = false;
    auto ret = dataMgr->IsApplicationEnabled(BUNDLE_NAME, 0, isEnabled, TEST_USERID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

HWTEST_F(BmsDualModeQueryTest, DataMgrIsApplicationEnabled_NonClone10000_0500, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeAbilityEnabledInfo(false, BUNDLE_NAME, TEST_USERID);
    bool isEnabled = false;
    auto ret = dataMgr->IsApplicationEnabled(
        BUNDLE_NAME, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, isEnabled, TEST_USERID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SANDBOX_INSTALL_INVALID_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, DataMgrIsApplicationEnabled_DualModeClone10000_0600, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeAbilityEnabledInfo(true, BUNDLE_NAME, TEST_USERID);
    bool isEnabled = false;
    auto ret = dataMgr->IsApplicationEnabled(
        BUNDLE_NAME, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, isEnabled, TEST_USERID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(isEnabled);
}

HWTEST_F(BmsDualModeQueryTest, DataMgrIsApplicationEnabled_DualModeCloneIndex0_0700, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeAbilityEnabledInfo(true, BUNDLE_NAME, TEST_USERID);
    bool isEnabled = false;
    auto ret = dataMgr->IsApplicationEnabled(BUNDLE_NAME, 0, isEnabled, TEST_USERID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(isEnabled);
}

HWTEST_F(BmsDualModeQueryTest, DataMgrIsApplicationEnabled_LegacyCloneInstalled_0800, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    InnerBundleInfo info = MakeAbilityEnabledInfo(false, BUNDLE_NAME, TEST_USERID);
    InnerBundleCloneInfo cloneInfo;
    cloneInfo.appIndex = 1;
    cloneInfo.enabled = false;
    info.innerBundleUserInfos_.at(BUNDLE_NAME + "_" + std::to_string(TEST_USERID))
        .cloneInfos.emplace("1", cloneInfo);
    dataMgr->bundleInfos_[BUNDLE_NAME] = info;
    bool isEnabled = true;
    auto ret = dataMgr->IsApplicationEnabled(BUNDLE_NAME, 1, isEnabled, TEST_USERID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(isEnabled);
}

// ====================== BundleDataMgr::QueryCloneAbilityInfo dual-mode ======================

// InnerBundleInfo with one ability and one userInfo entry (uid set, optional disabledAbilities).
static InnerBundleInfo MakeQueryCloneInfo(bool isClone, int32_t userId, int32_t uid, bool disableAbility)
{
    InnerBundleInfo info;
    info.SetDualModeCloneApp(isClone);
    if (isClone) {
        info.SetAppIndex(ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    }
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    InnerAbilityInfo innerAbilityInfo;
    innerAbilityInfo.bundleName = BUNDLE_NAME;
    innerAbilityInfo.name = "MainAbility";
    innerAbilityInfo.moduleName = "entry";
    info.baseAbilityInfos_.emplace("entry_MainAbility", innerAbilityInfo);
    auto userInfo = MakeUserInfo(BUNDLE_NAME, userId, true);
    userInfo.uid = uid;
    if (disableAbility) {
        userInfo.bundleUserInfo.disabledAbilities.emplace_back("MainAbility");
    }
    std::string key = BUNDLE_NAME + "_" + std::to_string(userId);
    info.innerBundleUserInfos_.try_emplace(key, userInfo);
    return info;
}

static ElementName MakeQueryCloneElement()
{
    ElementName element;
    element.SetBundleName(BUNDLE_NAME);
    element.SetModuleName("entry");
    element.SetAbilityName("MainAbility");
    return element;
}

static Want MakeQueryCloneWant()
{
    Want want;
    want.SetElement(MakeQueryCloneElement());
    return want;
}

HWTEST_F(BmsDualModeQueryTest, QueryCloneAbilityInfo_DualModeClone10000_0100, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneInfo(true, TEST_USERID, 200000, false);
    AbilityInfo abilityInfo;
    auto ret = dataMgr->QueryCloneAbilityInfo(MakeQueryCloneElement(), 0, TEST_USERID,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, abilityInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(abilityInfo.uid, 200000);
    EXPECT_EQ(abilityInfo.appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, QueryCloneAbilityInfo_DualModeClone10000Disabled_0200,
    Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneInfo(true, TEST_USERID, 200000, true);
    AbilityInfo abilityInfo;
    auto ret = dataMgr->QueryCloneAbilityInfo(MakeQueryCloneElement(), 0, TEST_USERID,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, abilityInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_DISABLED);
}

HWTEST_F(BmsDualModeQueryTest, QueryCloneAbilityInfo_DualModeCloneIndex0_0300,
    Function | SmallTest | Level0)
{
    // regression: appIndex=0 path unchanged
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneInfo(true, TEST_USERID, 200000, false);
    AbilityInfo abilityInfo;
    auto ret = dataMgr->QueryCloneAbilityInfo(MakeQueryCloneElement(), 0, TEST_USERID, 0, abilityInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(abilityInfo.uid, 200000);
    // dual-mode: a clone record echoes DUAL_MODE_CLONE_APP_INDEX even when requested with 0
    EXPECT_EQ(abilityInfo.appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, QueryCloneAbilityInfo_NonClone10000_0400, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneInfo(false, TEST_USERID, 200000, false);
    AbilityInfo abilityInfo;
    auto ret = dataMgr->QueryCloneAbilityInfo(MakeQueryCloneElement(), 0, TEST_USERID,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, abilityInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE);
}

HWTEST_F(BmsDualModeQueryTest, QueryCloneAbilityInfo_DualModeClone10000WithApplication_0500,
    Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneInfo(true, TEST_USERID, 200000, false);
    AbilityInfo abilityInfo;
    int32_t flags = static_cast<int32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_APPLICATION);
    auto ret = dataMgr->QueryCloneAbilityInfo(MakeQueryCloneElement(), flags, TEST_USERID,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, abilityInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(abilityInfo.applicationInfo.appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    EXPECT_EQ(abilityInfo.uid, 200000);
}

HWTEST_F(BmsDualModeQueryTest, GetCloneBundleInfo_DualModeClone10000Abilities_0600,
    Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    InnerBundleInfo info = MakeQueryCloneInfo(true, TEST_USERID, 200000, false);
    InnerModuleInfo moduleInfo;
    moduleInfo.modulePackage = "entry";
    moduleInfo.moduleName = "entry";
    moduleInfo.name = "entry";
    info.innerModuleInfos_.emplace("entry", moduleInfo);
    dataMgr->bundleInfos_[BUNDLE_NAME] = info;
    BundleInfo bundleInfo;
    int32_t flags = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY);
    auto ret = dataMgr->GetCloneBundleInfo(BUNDLE_NAME, flags,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX, bundleInfo, TEST_USERID);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(bundleInfo.hapModuleInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(bundleInfo.hapModuleInfos[0].abilityInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(bundleInfo.hapModuleInfos[0].abilityInfos[0].name, "MainAbility");
    EXPECT_EQ(bundleInfo.hapModuleInfos[0].abilityInfos[0].appIndex,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

// ====================== BundleDataMgr::ExplicitQueryExtensionInfoV9 dual-mode ======================

// InnerBundleInfo with one extension and one userInfo entry (uid set).
static InnerBundleInfo MakeQueryCloneExtensionInfo(bool isClone, int32_t userId, int32_t uid)
{
    InnerBundleInfo info;
    info.SetDualModeCloneApp(isClone);
    if (isClone) {
        info.SetAppIndex(ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    }
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    InnerExtensionInfo innerExtensionInfo;
    innerExtensionInfo.bundleName = BUNDLE_NAME;
    innerExtensionInfo.name = "MainExtension";
    innerExtensionInfo.moduleName = "entry";
    info.baseExtensionInfos_.emplace("entry_MainExtension", innerExtensionInfo);
    auto userInfo = MakeUserInfo(BUNDLE_NAME, userId, true);
    userInfo.uid = uid;
    std::string key = BUNDLE_NAME + "_" + std::to_string(userId);
    info.innerBundleUserInfos_.try_emplace(key, userInfo);
    return info;
}

static Want MakeQueryCloneExtensionWant()
{
    ElementName element;
    element.SetBundleName(BUNDLE_NAME);
    element.SetModuleName("entry");
    element.SetAbilityName("MainExtension");
    Want want;
    want.SetElement(element);
    return want;
}

HWTEST_F(BmsDualModeQueryTest, ExplicitQueryExtensionInfoV9_DualModeClone10000_0100,
    Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneExtensionInfo(true, TEST_USERID, 200000);
    ExtensionAbilityInfo extensionInfo;
    auto ret = dataMgr->ExplicitQueryExtensionInfoV9(MakeQueryCloneExtensionWant(), 0, TEST_USERID,
        extensionInfo, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(extensionInfo.uid, 200000);
    EXPECT_EQ(extensionInfo.appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, ExplicitQueryExtensionInfoV9_NonClone10000_0200,
    Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneExtensionInfo(false, TEST_USERID, 200000);
    ExtensionAbilityInfo extensionInfo;
    auto ret = dataMgr->ExplicitQueryExtensionInfoV9(MakeQueryCloneExtensionWant(), 0, TEST_USERID,
        extensionInfo, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    EXPECT_EQ(ret, ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE);
}

HWTEST_F(BmsDualModeQueryTest, ExplicitQueryExtensionInfoV9_DualModeCloneIndex0_0300,
    Function | SmallTest | Level0)
{
    // regression: appIndex=0 path unchanged
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneExtensionInfo(true, TEST_USERID, 200000);
    ExtensionAbilityInfo extensionInfo;
    auto ret = dataMgr->ExplicitQueryExtensionInfoV9(MakeQueryCloneExtensionWant(), 0, TEST_USERID,
        extensionInfo, 0);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(extensionInfo.uid, 200000);
    // dual-mode: a clone record echoes DUAL_MODE_CLONE_APP_INDEX even when requested with 0
    EXPECT_EQ(extensionInfo.appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, ExplicitQueryExtensionInfoV9_DualModeClone10000WithApplication_0400,
    Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneExtensionInfo(true, TEST_USERID, 200000);
    ExtensionAbilityInfo extensionInfo;
    int32_t flags = static_cast<int32_t>(
        GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION);
    auto ret = dataMgr->ExplicitQueryExtensionInfoV9(MakeQueryCloneExtensionWant(), flags, TEST_USERID,
        extensionInfo, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(extensionInfo.applicationInfo.appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    EXPECT_EQ(extensionInfo.uid, 200000);
}

// ====================== BundleResourceManager::GetDualModeQueryName dual-mode ======================

HWTEST_F(BmsDualModeQueryTest, GetDualModeQueryName_DualModeClone10000_0100, Function | SmallTest | Level0)
{
    auto dataMgr = InstallTestDataMgr(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneInfo(true, TEST_USERID, 200000, false);
    auto manager = std::make_shared<BundleResourceManager>();
    ASSERT_NE(manager, nullptr);
    std::string queryName;
    int32_t queryAppIndex = ServiceConstants::DUAL_MODE_CLONE_APP_INDEX;
    EXPECT_TRUE(manager->GetDualModeQueryName(BUNDLE_NAME, queryAppIndex, queryName));
    EXPECT_EQ(queryName, DualModeHelper::GetDualModeBundleName(BUNDLE_NAME));
    EXPECT_EQ(queryAppIndex, 0);
}

HWTEST_F(BmsDualModeQueryTest, GetDualModeQueryName_DualModeCloneIndex0_0200, Function | SmallTest | Level0)
{
    auto dataMgr = InstallTestDataMgr(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneInfo(true, TEST_USERID, 200000, false);
    auto manager = std::make_shared<BundleResourceManager>();
    ASSERT_NE(manager, nullptr);
    std::string queryName;
    int32_t queryAppIndex = 0;
    EXPECT_TRUE(manager->GetDualModeQueryName(BUNDLE_NAME, queryAppIndex, queryName));
    EXPECT_EQ(queryName, DualModeHelper::GetDualModeBundleName(BUNDLE_NAME));
    EXPECT_EQ(queryAppIndex, 0);
}

HWTEST_F(BmsDualModeQueryTest, GetDualModeQueryName_NonClone_0300, Function | SmallTest | Level0)
{
    auto dataMgr = InstallTestDataMgr(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneInfo(false, TEST_USERID, 200000, false);
    auto manager = std::make_shared<BundleResourceManager>();
    ASSERT_NE(manager, nullptr);
    std::string queryName;
    int32_t queryAppIndex = ServiceConstants::DUAL_MODE_CLONE_APP_INDEX;
    EXPECT_FALSE(manager->GetDualModeQueryName(BUNDLE_NAME, queryAppIndex, queryName));
    EXPECT_EQ(queryName, BUNDLE_NAME);
    EXPECT_EQ(queryAppIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, GetDualModeQueryName_BundleNotExist_0400, Function | SmallTest | Level0)
{
    auto dataMgr = InstallTestDataMgr(TEST_USERID);
    (void)dataMgr;
    auto manager = std::make_shared<BundleResourceManager>();
    ASSERT_NE(manager, nullptr);
    std::string queryName;
    int32_t queryAppIndex = 0;
    EXPECT_FALSE(manager->GetDualModeQueryName(BUNDLE_NAME, queryAppIndex, queryName));
    EXPECT_EQ(queryName, BUNDLE_NAME);
    EXPECT_EQ(queryAppIndex, 0);
}

// ====================== BundleDataMgr::GetBundleNameAndIndexByName dual-mode ======================

HWTEST_F(BmsDualModeQueryTest, GetBundleNameAndIndexByName_DualModeCloneKey_0100, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    std::string bundleName;
    int32_t appIndex = -1;
    dataMgr->GetBundleNameAndIndexByName(PREFIXED_NAME, bundleName, appIndex);
    EXPECT_EQ(bundleName, BUNDLE_NAME);
    EXPECT_EQ(appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, GetBundleNameAndIndexByName_RegularCloneKey_0200, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    // regular clone key format: "{index}clone_{bundleName}", must keep the legacy parse result
    std::string bundleName;
    int32_t appIndex = -1;
    dataMgr->GetBundleNameAndIndexByName("1clone_" + BUNDLE_NAME, bundleName, appIndex);
    EXPECT_EQ(bundleName, BUNDLE_NAME);
    EXPECT_EQ(appIndex, 1);
}

HWTEST_F(BmsDualModeQueryTest, GetBundleNameAndIndexByName_PlainName_0300, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    std::string bundleName;
    int32_t appIndex = -1;
    dataMgr->GetBundleNameAndIndexByName(BUNDLE_NAME, bundleName, appIndex);
    EXPECT_EQ(bundleName, BUNDLE_NAME);
    EXPECT_EQ(appIndex, 0);
}

// ====================== BundleDataMgr::GetInnerBundleInfoAndIndexByUid dual-mode ======================

HWTEST_F(BmsDualModeQueryTest, GetInnerBundleInfoAndIndexByUid_DualModeCloneUid_0100,
    Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    const int32_t bundleId = 99;
    const int32_t cloneUid = TEST_USERID * Constants::BASE_USER_RANGE + bundleId;
    dataMgr->bundleIdMap_.emplace(bundleId, PREFIXED_NAME);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneInfo(true, TEST_USERID, cloneUid, false);
    InnerBundleInfo resultInfo;
    int32_t appIndex = 0;
    EXPECT_EQ(dataMgr->GetInnerBundleInfoAndIndexByUid(cloneUid, resultInfo, appIndex), ERR_OK);
    EXPECT_EQ(appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    EXPECT_EQ(resultInfo.GetBundleName(), BUNDLE_NAME);
}

HWTEST_F(BmsDualModeQueryTest, GetInnerBundleInfoAndIndexByUid_NonCloneRecordRejectsCloneUid_0200,
    Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    const int32_t bundleId = 99;
    const int32_t cloneUid = TEST_USERID * Constants::BASE_USER_RANGE + bundleId;
    dataMgr->bundleIdMap_.emplace(bundleId, PREFIXED_NAME);
    // main-mode (non-clone) record holds the uid itself, but appIndex 10000 must be rejected
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneInfo(false, TEST_USERID, cloneUid, false);
    InnerBundleInfo resultInfo;
    int32_t appIndex = 0;
    EXPECT_EQ(dataMgr->GetInnerBundleInfoAndIndexByUid(cloneUid, resultInfo, appIndex),
        ERR_BUNDLE_MANAGER_INVALID_UID);
}

// ====================== BundleDataMgr::GetAllBundleDirs dual-mode ======================

HWTEST_F(BmsDualModeQueryTest, GetAllBundleDirs_DualModeCloneRecord_0100, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneInfo(true, TEST_USERID, 200000, false);
    std::vector<BundleDir> bundleDirs;
    EXPECT_EQ(dataMgr->GetAllBundleDirs(TEST_USERID, bundleDirs), ERR_OK);
    ASSERT_EQ(bundleDirs.size(), 1u);
    EXPECT_EQ(bundleDirs[0].bundleName, BUNDLE_NAME);
    EXPECT_EQ(bundleDirs[0].appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    EXPECT_EQ(bundleDirs[0].dir, PREFIXED_NAME);
}

HWTEST_F(BmsDualModeQueryTest, GetAllBundleDirs_NonCloneRecordKeepsMainIndex_0200,
    Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneInfo(false, TEST_USERID, 200000, false);
    std::vector<BundleDir> bundleDirs;
    EXPECT_EQ(dataMgr->GetAllBundleDirs(TEST_USERID, bundleDirs), ERR_OK);
    ASSERT_EQ(bundleDirs.size(), 1u);
    EXPECT_EQ(bundleDirs[0].bundleName, BUNDLE_NAME);
    EXPECT_EQ(bundleDirs[0].appIndex, 0);
    EXPECT_EQ(bundleDirs[0].dir, BUNDLE_NAME);
}

// ====================== InnerBundleInfo curDynamicIconModule dual-mode ======================

static InnerBundleInfo MakeDynamicIconCloneInfo(bool isClone)
{
    InnerBundleInfo info;
    info.SetDualModeCloneApp(isClone);
    if (isClone) {
        info.SetAppIndex(ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    }
    info.baseApplicationInfo_->bundleName = BUNDLE_NAME;
    auto userInfo = MakeUserInfo(BUNDLE_NAME, TEST_USERID, true);
    std::string key = BUNDLE_NAME + "_" + std::to_string(TEST_USERID);
    info.innerBundleUserInfos_.try_emplace(key, userInfo);
    return info;
}

HWTEST_F(BmsDualModeQueryTest, CurDynamicIconModule_DualModeClone10000Roundtrip_0100,
    Function | SmallTest | Level0)
{
    auto info = MakeDynamicIconCloneInfo(true);
    EXPECT_TRUE(info.SetCurDynamicIconModule("dyn_module", TEST_USERID,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX));
    EXPECT_EQ(info.GetCurDynamicIconModule(TEST_USERID, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX),
        "dyn_module");
    // appIndex 0 addresses the same base slot on the clone record
    EXPECT_EQ(info.GetCurDynamicIconModule(TEST_USERID, 0), "dyn_module");
    EXPECT_TRUE(info.SetCurDynamicIconModule("dyn_module_zero", TEST_USERID, 0));
    EXPECT_EQ(info.GetCurDynamicIconModule(TEST_USERID, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX),
        "dyn_module_zero");
}

HWTEST_F(BmsDualModeQueryTest, CurDynamicIconModule_NonCloneReject10000_0200,
    Function | SmallTest | Level0)
{
    auto info = MakeDynamicIconCloneInfo(false);
    EXPECT_FALSE(info.SetCurDynamicIconModule("dyn_module", TEST_USERID,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX));
    EXPECT_TRUE(info.GetCurDynamicIconModule(TEST_USERID,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX).empty());
}

// ====================== ExtendResourceManagerHostImpl::CheckParamInvalid dual-mode ======================

HWTEST_F(BmsDualModeQueryTest, CheckParamInvalid_DualModeClone10000_0100, Function | SmallTest | Level0)
{
    auto dataMgr = InstallTestDataMgr(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeDynamicIconCloneInfo(true);
    ExtendResourceManagerHostImpl impl;
    InnerBundleInfo info = dataMgr->bundleInfos_[BUNDLE_NAME];
    EXPECT_EQ(impl.CheckParamInvalid(info, TEST_USERID, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX),
        ERR_OK);
    DelayedSingleton<BundleMgrService>::GetInstance()->RegisterDataMgr(nullptr);
}

HWTEST_F(BmsDualModeQueryTest, CheckParamInvalid_NonCloneReject10000_0200, Function | SmallTest | Level0)
{
    auto dataMgr = InstallTestDataMgr(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeDynamicIconCloneInfo(false);
    ExtendResourceManagerHostImpl impl;
    InnerBundleInfo info = dataMgr->bundleInfos_[BUNDLE_NAME];
    EXPECT_EQ(impl.CheckParamInvalid(info, TEST_USERID, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX),
        ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE);
    DelayedSingleton<BundleMgrService>::GetInstance()->RegisterDataMgr(nullptr);
}

// ====================== BundleDataMgr::GetShortcutInfosByInnerBundleInfo dual-mode ======================

HWTEST_F(BmsDualModeQueryTest, GetShortcutInfosByInnerBundleInfo_DualModeClone_0100,
    Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    auto info = MakeQueryCloneInfo(true, TEST_USERID, 200000, false);
    // old version branch (default isNewVersion_ = false)
    ShortcutInfo shortcut;
    shortcut.bundleName = BUNDLE_NAME;
    shortcut.id = "id_test";
    shortcut.sourceType = 1;
    info.shortcutInfos_.emplace("id_test", shortcut);
    std::vector<ShortcutInfo> shortcutInfos;
    EXPECT_TRUE(dataMgr->GetShortcutInfosByInnerBundleInfo(info, shortcutInfos));
    ASSERT_EQ(shortcutInfos.size(), 1u);
    EXPECT_EQ(shortcutInfos[0].appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, GetShortcutInfosByInnerBundleInfo_NonCloneKeepsIndex0_0200,
    Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    auto info = MakeQueryCloneInfo(false, TEST_USERID, 200000, false);
    ShortcutInfo shortcut;
    shortcut.bundleName = BUNDLE_NAME;
    shortcut.id = "id_test";
    shortcut.sourceType = 1;
    info.shortcutInfos_.emplace("id_test", shortcut);
    std::vector<ShortcutInfo> shortcutInfos;
    EXPECT_TRUE(dataMgr->GetShortcutInfosByInnerBundleInfo(info, shortcutInfos));
    ASSERT_EQ(shortcutInfos.size(), 1u);
    EXPECT_EQ(shortcutInfos[0].appIndex, 0);
}

HWTEST_F(BmsDualModeQueryTest, GetShortcutInfoByAbility_DualModeCloneIndex0Echoes10000_0100,
    Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    auto info = MakeQueryCloneInfo(true, TEST_USERID, 200000, false);
    // old version branch: static shortcut from the base shortcutInfos_ map
    ShortcutInfo shortcut;
    shortcut.bundleName = BUNDLE_NAME;
    shortcut.moduleName = "entry";
    shortcut.hostAbility = "MainAbility";
    shortcut.id = "id_test";
    shortcut.sourceType = 1;
    info.shortcutInfos_.emplace("id_test", shortcut);
    dataMgr->bundleInfos_[BUNDLE_NAME] = info;
    std::vector<ShortcutInfo> shortcutInfos;
    EXPECT_EQ(dataMgr->GetShortcutInfoByAbility(BUNDLE_NAME, "entry", "MainAbility",
        TEST_USERID, 0, shortcutInfos), ERR_OK);
    ASSERT_EQ(shortcutInfos.size(), 1u);
    EXPECT_EQ(shortcutInfos[0].appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

// ====================== InnerBundleInfo::GetMainAbilityInfo dual-mode ======================

static void AddEntryModule(InnerBundleInfo &info)
{
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "entry";
    moduleInfo.isEntry = true;
    moduleInfo.entryAbilityKey = "entry_MainAbility";
    info.innerModuleInfos_.emplace("entry", moduleInfo);
}

HWTEST_F(BmsDualModeQueryTest, GetMainAbilityInfo_DualModeClone_0100, Function | SmallTest | Level0)
{
    auto info = MakeQueryCloneInfo(true, TEST_USERID, 200000, false);
    AddEntryModule(info);
    AbilityInfo abilityInfo;
    info.GetMainAbilityInfo(abilityInfo);
    EXPECT_EQ(abilityInfo.name, "MainAbility");
    EXPECT_EQ(abilityInfo.appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, GetMainAbilityInfo_NonCloneKeepsIndex0_0200, Function | SmallTest | Level0)
{
    auto info = MakeQueryCloneInfo(false, TEST_USERID, 200000, false);
    AddEntryModule(info);
    AbilityInfo abilityInfo;
    info.GetMainAbilityInfo(abilityInfo);
    EXPECT_EQ(abilityInfo.name, "MainAbility");
    EXPECT_EQ(abilityInfo.appIndex, 0);
}

// ====================== BundleDataMgr::QueryAbilityInfo / QueryAbilityInfos dual-mode ======================

static constexpr const char* IMPLICIT_ACTION = "action.test.dual";

// Clone info whose abilities carry a skill matching the implicit want action.
static InnerBundleInfo MakeQueryCloneInfoWithSkills(bool isClone, int32_t userId, int32_t uid)
{
    auto info = MakeQueryCloneInfo(isClone, userId, uid, false);
    for (auto &item : info.baseAbilityInfos_) {
        Skill skill;
        skill.actions.emplace_back(IMPLICIT_ACTION);
        item.second.skills.emplace_back(skill);
    }
    return info;
}

static Want MakeImplicitWant()
{
    Want want;
    want.SetAction(IMPLICIT_ACTION);
    return want;
}

HWTEST_F(BmsDualModeQueryTest, QueryAbilityInfo_ExplicitIndex0Echoes10000_0100, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneInfo(true, TEST_USERID, 200000, false);
    AbilityInfo abilityInfo;
    EXPECT_TRUE(dataMgr->QueryAbilityInfo(MakeQueryCloneWant(), 0, TEST_USERID, abilityInfo));
    EXPECT_EQ(abilityInfo.uid, 200000);
    EXPECT_EQ(abilityInfo.appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, QueryAbilityInfosV9_ExplicitIndex0Echoes10000_0200, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneInfo(true, TEST_USERID, 200000, false);
    std::vector<AbilityInfo> abilityInfos;
    EXPECT_EQ(dataMgr->QueryAbilityInfosV9(MakeQueryCloneWant(), 0, TEST_USERID, abilityInfos), ERR_OK);
    ASSERT_EQ(abilityInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(abilityInfos[0].appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, QueryAbilityInfos_ImplicitEchoes10000_0300, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneInfoWithSkills(true, TEST_USERID, 200000);
    std::vector<AbilityInfo> abilityInfos;
    EXPECT_TRUE(dataMgr->QueryAbilityInfos(MakeImplicitWant(), 0, TEST_USERID, abilityInfos));
    ASSERT_EQ(abilityInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(abilityInfos[0].appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, QueryAbilityInfosV9_ImplicitEchoes10000_0400, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneInfoWithSkills(true, TEST_USERID, 200000);
    std::vector<AbilityInfo> abilityInfos;
    EXPECT_EQ(dataMgr->QueryAbilityInfosV9(MakeImplicitWant(), 0, TEST_USERID, abilityInfos), ERR_OK);
    ASSERT_EQ(abilityInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(abilityInfos[0].appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, QueryAbilityInfo_NonCloneKeepsIndex0_0500, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneInfo(false, TEST_USERID, 200000, false);
    AbilityInfo abilityInfo;
    EXPECT_TRUE(dataMgr->QueryAbilityInfo(MakeQueryCloneWant(), 0, TEST_USERID, abilityInfo));
    EXPECT_EQ(abilityInfo.appIndex, 0);
}

HWTEST_F(BmsDualModeQueryTest, QueryAbilityInfoByContinueType_Echoes10000_0600, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    auto info = MakeQueryCloneInfo(true, TEST_USERID, 200000, false);
    info.baseAbilityInfos_.begin()->second.continueType.emplace_back("continue.test");
    dataMgr->bundleInfos_[BUNDLE_NAME] = info;
    AbilityInfo abilityInfo;
    EXPECT_EQ(dataMgr->QueryAbilityInfoByContinueType(
        BUNDLE_NAME, "continue.test", abilityInfo, TEST_USERID), ERR_OK);
    EXPECT_EQ(abilityInfo.uid, 200000);
    EXPECT_EQ(abilityInfo.appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, QueryAbilityInfoByUri_Echoes10000_0700, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    auto info = MakeQueryCloneInfo(true, TEST_USERID, 200000, false);
    info.baseAbilityInfos_.begin()->second.uri = "dataability://testuri";
    dataMgr->bundleInfos_[BUNDLE_NAME] = info;
    AbilityInfo abilityInfo;
    EXPECT_TRUE(dataMgr->QueryAbilityInfoByUri(
        "dataability://" + BUNDLE_NAME + "/testuri", TEST_USERID, abilityInfo));
    EXPECT_EQ(abilityInfo.appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

// ====================== BundleDataMgr::QueryExtensionAbilityInfos dual-mode ======================

static InnerBundleInfo MakeQueryCloneExtensionInfoWithSkills(bool isClone, int32_t userId, int32_t uid)
{
    auto info = MakeQueryCloneExtensionInfo(isClone, userId, uid);
    for (auto &item : info.baseExtensionInfos_) {
        Skill skill;
        skill.actions.emplace_back(IMPLICIT_ACTION);
        item.second.skills.emplace_back(skill);
    }
    return info;
}

HWTEST_F(BmsDualModeQueryTest, QueryExtensionAbilityInfos_ExplicitIndex0Echoes10000_0100,
    Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneExtensionInfo(true, TEST_USERID, 200000);
    std::vector<ExtensionAbilityInfo> extensionInfos;
    EXPECT_TRUE(dataMgr->QueryExtensionAbilityInfos(
        MakeQueryCloneExtensionWant(), 0, TEST_USERID, extensionInfos));
    ASSERT_EQ(extensionInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(extensionInfos[0].appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, QueryExtensionAbilityInfosV9_ExplicitIndex0Echoes10000_0200,
    Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneExtensionInfo(true, TEST_USERID, 200000);
    std::vector<ExtensionAbilityInfo> extensionInfos;
    EXPECT_EQ(dataMgr->QueryExtensionAbilityInfosV9(
        MakeQueryCloneExtensionWant(), 0, TEST_USERID, extensionInfos), ERR_OK);
    ASSERT_EQ(extensionInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(extensionInfos[0].appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, QueryExtensionAbilityInfos_ImplicitEchoes10000_0300,
    Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneExtensionInfoWithSkills(true, TEST_USERID, 200000);
    std::vector<ExtensionAbilityInfo> extensionInfos;
    EXPECT_TRUE(dataMgr->QueryExtensionAbilityInfos(
        MakeImplicitWant(), 0, TEST_USERID, extensionInfos));
    ASSERT_EQ(extensionInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(extensionInfos[0].appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, QueryExtensionAbilityInfosV9_ImplicitEchoes10000_0400,
    Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    dataMgr->bundleInfos_[BUNDLE_NAME] = MakeQueryCloneExtensionInfoWithSkills(true, TEST_USERID, 200000);
    std::vector<ExtensionAbilityInfo> extensionInfos;
    EXPECT_EQ(dataMgr->QueryExtensionAbilityInfosV9(
        MakeImplicitWant(), 0, TEST_USERID, extensionInfos), ERR_OK);
    ASSERT_EQ(extensionInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(extensionInfos[0].appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, QueryExtensionAbilityInfosByType_Echoes10000_0500, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    auto info = MakeQueryCloneExtensionInfo(true, TEST_USERID, 200000);
    info.baseExtensionInfos_.begin()->second.type = ExtensionAbilityType::FORM;
    dataMgr->bundleInfos_[BUNDLE_NAME] = info;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    EXPECT_TRUE(dataMgr->QueryExtensionAbilityInfos(
        ExtensionAbilityType::FORM, TEST_USERID, extensionInfos));
    ASSERT_EQ(extensionInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(extensionInfos[0].appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, QueryExtensionAbilityInfosByType_NonCloneKeepsIndex0_0600,
    Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->multiUserIdsSet_.insert(TEST_USERID);
    auto info = MakeQueryCloneExtensionInfo(false, TEST_USERID, 200000);
    info.baseExtensionInfos_.begin()->second.type = ExtensionAbilityType::FORM;
    dataMgr->bundleInfos_[BUNDLE_NAME] = info;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    EXPECT_TRUE(dataMgr->QueryExtensionAbilityInfos(
        ExtensionAbilityType::FORM, TEST_USERID, extensionInfos));
    ASSERT_EQ(extensionInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(extensionInfos[0].appIndex, 0);
}

// ====================== InnerBundleInfo::GetBundleInfoV9 / GetBundleInfo nested dual-mode ======================

// Module info matching the V9 nested-array path (modulePackage keyed, moduleName matched by field).
static void AddQueryCloneModule(InnerBundleInfo &info)
{
    InnerModuleInfo moduleInfo;
    moduleInfo.modulePackage = "entry";
    moduleInfo.moduleName = "entry";
    moduleInfo.name = "entry";
    info.innerModuleInfos_.emplace("entry", moduleInfo);
}

HWTEST_F(BmsDualModeQueryTest, GetBundleInfoV9_NestedAbilitiesIndex0Echoes10000_0100,
    Function | SmallTest | Level0)
{
    auto info = MakeQueryCloneInfo(true, TEST_USERID, 200000, false);
    AddQueryCloneModule(info);
    InnerExtensionInfo innerExtensionInfo;
    innerExtensionInfo.bundleName = BUNDLE_NAME;
    innerExtensionInfo.name = "MainExtension";
    innerExtensionInfo.moduleName = "entry";
    info.baseExtensionInfos_.emplace(BUNDLE_NAME + ".entry.MainExtension", innerExtensionInfo);
    BundleInfo bundleInfo;
    int32_t flags = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY);
    EXPECT_EQ(info.GetBundleInfoV9(flags, bundleInfo, TEST_USERID, 0), ERR_OK);
    ASSERT_EQ(bundleInfo.hapModuleInfos.size(), static_cast<size_t>(1));
    ASSERT_EQ(bundleInfo.hapModuleInfos[0].abilityInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(bundleInfo.hapModuleInfos[0].abilityInfos[0].appIndex,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    ASSERT_EQ(bundleInfo.hapModuleInfos[0].extensionInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(bundleInfo.hapModuleInfos[0].extensionInfos[0].appIndex,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    // top-level applicationInfo stays consistent with the nested arrays
    EXPECT_EQ(bundleInfo.applicationInfo.appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, GetBundleInfoV9_NonCloneNestedKeepsIndex0_0200,
    Function | SmallTest | Level0)
{
    auto info = MakeQueryCloneInfo(false, TEST_USERID, 200000, false);
    AddQueryCloneModule(info);
    BundleInfo bundleInfo;
    int32_t flags = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY);
    EXPECT_EQ(info.GetBundleInfoV9(flags, bundleInfo, TEST_USERID, 0), ERR_OK);
    ASSERT_EQ(bundleInfo.hapModuleInfos.size(), static_cast<size_t>(1));
    ASSERT_EQ(bundleInfo.hapModuleInfos[0].abilityInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(bundleInfo.hapModuleInfos[0].abilityInfos[0].appIndex, 0);
}

HWTEST_F(BmsDualModeQueryTest, GetBundleInfo_OldPathNestedEchoes10000_0300,
    Function | SmallTest | Level0)
{
    // old BundleFlag path: ability/extension keys must use the dotted format
    // "{bundleName}.{moduleName}.{name}" for FindHapModuleInfo key matching
    auto info = MakeQueryCloneInfo(true, TEST_USERID, 200000, false);
    info.baseAbilityInfos_.begin()->second.skills.clear();
    AddQueryCloneModule(info);
    InnerExtensionInfo innerExtensionInfo;
    innerExtensionInfo.bundleName = BUNDLE_NAME;
    innerExtensionInfo.name = "MainExtension";
    innerExtensionInfo.moduleName = "entry";
    innerExtensionInfo.enabled = true;
    info.baseExtensionInfos_.clear();
    info.baseExtensionInfos_.emplace(BUNDLE_NAME + ".entry.MainExtension", innerExtensionInfo);
    // rebuild the ability key in dotted format
    auto innerAbility = info.baseAbilityInfos_.begin()->second;
    info.baseAbilityInfos_.clear();
    info.baseAbilityInfos_.emplace(BUNDLE_NAME + ".entry.MainAbility", innerAbility);
    BundleInfo bundleInfo;
    int32_t flags = GET_BUNDLE_WITH_ABILITIES | GET_BUNDLE_WITH_EXTENSION_INFO;
    EXPECT_TRUE(info.GetBundleInfo(flags, bundleInfo, TEST_USERID, 0));
    ASSERT_EQ(bundleInfo.abilityInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(bundleInfo.abilityInfos[0].appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    ASSERT_EQ(bundleInfo.extensionInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(bundleInfo.extensionInfos[0].appIndex, ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    // old path also fills hapModuleInfos via FindHapModuleInfo
    ASSERT_EQ(bundleInfo.hapModuleInfos.size(), static_cast<size_t>(1));
    ASSERT_EQ(bundleInfo.hapModuleInfos[0].abilityInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(bundleInfo.hapModuleInfos[0].abilityInfos[0].appIndex,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
    ASSERT_EQ(bundleInfo.hapModuleInfos[0].extensionInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(bundleInfo.hapModuleInfos[0].extensionInfos[0].appIndex,
        ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
}

HWTEST_F(BmsDualModeQueryTest, GetBundleInfo_OldPathNonCloneNestedKeepsIndex0_0400,
    Function | SmallTest | Level0)
{
    auto info = MakeQueryCloneInfo(false, TEST_USERID, 200000, false);
    AddQueryCloneModule(info);
    auto innerAbility = info.baseAbilityInfos_.begin()->second;
    info.baseAbilityInfos_.clear();
    info.baseAbilityInfos_.emplace(BUNDLE_NAME + ".entry.MainAbility", innerAbility);
    BundleInfo bundleInfo;
    int32_t flags = GET_BUNDLE_WITH_ABILITIES;
    EXPECT_TRUE(info.GetBundleInfo(flags, bundleInfo, TEST_USERID, 0));
    ASSERT_EQ(bundleInfo.abilityInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(bundleInfo.abilityInfos[0].appIndex, 0);
    ASSERT_EQ(bundleInfo.hapModuleInfos.size(), static_cast<size_t>(1));
    ASSERT_EQ(bundleInfo.hapModuleInfos[0].abilityInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(bundleInfo.hapModuleInfos[0].abilityInfos[0].appIndex, 0);
}
} // OHOS
