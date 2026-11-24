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

#define private public

#include <gtest/gtest.h>

#include "app_provision_info.h"
#include "ability_info.h"
#include "application_info.h"
#include "bundle_constants.h"
#include "bundle_info.h"
#include "bundle_mgr_host_impl.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_service_constants.h"
#include "default_app_host_impl.h"
#include "extension_ability_info.h"
#include "inner_bundle_info.h"
#include "module_info.h"
#include "plugin/plugin_bundle_info.h"
#include "shortcut_info.h"
#include "want.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

// Extern declarations for mock setter functions (defined in mock/src/bundle_permission_mgr.cpp)
void SetVerifyCallingPermissionForTest(bool value);
void SetSystemAppForTest(bool value);
void SetNativeTokenTypeForTest(bool value);
void SetPermissionResultForTest(const std::string &permissionName, bool granted);
void ResetTestValues();

namespace OHOS {
namespace AppExecFwk {

namespace {
const std::string TEST_BUNDLE_NAME = "com.example.provisiontest";
constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t OTHER_USER_ID = 200;
}

class BmsBundleMgrHostImplProvisionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    std::shared_ptr<BundleMgrHostImpl> bundleMgrHostImpl_ = std::make_unique<BundleMgrHostImpl>();
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleMgrHostImplProvisionTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

void BmsBundleMgrHostImplProvisionTest::SetUpTestCase()
{
    bundleMgrService_->InitBundleInstaller();
    bundleMgrService_->InitBundleDataMgr();
    bundleMgrService_->GetDataMgr()->AddUserId(TEST_USER_ID);
}

void BmsBundleMgrHostImplProvisionTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleMgrHostImplProvisionTest::SetUp()
{
    ResetTestValues();
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
}

void BmsBundleMgrHostImplProvisionTest::TearDown()
{
    ResetTestValues();
}

/**
 * @tc.number: GetAppProvisionInfoInDevice_HostImpl_0001
 * @tc.name: test GetAppProvisionInfoInDevice CheckAcrossUserPermission failed
 * @tc.desc: 1. system app with permission, but across user permission denied
 *           2. returns ERR_BUNDLE_MANAGER_PERMISSION_DENIED
 */
HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetAppProvisionInfoInDevice_HostImpl_0001,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED, true);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);

    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = bundleMgrHostImpl_->GetAppProvisionInfoInDevice(
        TEST_BUNDLE_NAME, OTHER_USER_ID, appProvisionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: GetAppProvisionInfoInDevice_HostImpl_0002
 * @tc.name: test GetAppProvisionInfoInDevice with dataMgr nullptr
 * @tc.desc: 1. system app with permission, across user permission passed
 *           2. dataMgr is nullptr, returns ERR_APPEXECFWK_NULL_PTR
 */
HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetAppProvisionInfoInDevice_HostImpl_0002,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(true);

    // set dataMgr to nullptr to simulate service not ready
    auto originalDataMgr = bundleMgrService_->GetDataMgr();
    bundleMgrService_->dataMgr_ = nullptr;

    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = bundleMgrHostImpl_->GetAppProvisionInfoInDevice(
        TEST_BUNDLE_NAME, Constants::UNSPECIFIED_USERID, appProvisionInfos);
    ASSERT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);

    // Restore dataMgr
    bundleMgrService_->dataMgr_ = originalDataMgr;
}

/**
 * @tc.number: GetAllAppProvisionInfoInDevice_HostImpl_0001
 * @tc.name: test GetAllAppProvisionInfoInDevice CheckAcrossUserPermission failed
 * @tc.desc: 1. system app with permission, but across user permission denied
 *           2. returns ERR_BUNDLE_MANAGER_PERMISSION_DENIED
 */
HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetAllAppProvisionInfoInDevice_HostImpl_0001,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED, true);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);

    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = bundleMgrHostImpl_->GetAllAppProvisionInfoInDevice(OTHER_USER_ID, appProvisionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: GetAllAppProvisionInfoInDevice_HostImpl_0002
 * @tc.name: test GetAllAppProvisionInfoInDevice with dataMgr nullptr
 * @tc.desc: 1. system app with permission, native token (across user check bypassed)
 *           2. dataMgr is nullptr, returns ERR_APPEXECFWK_NULL_PTR
 */
HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetAllAppProvisionInfoInDevice_HostImpl_0002,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(true);
    SetPermissionResultForTest(Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST, true);

    // set dataMgr to nullptr to simulate service not ready
    auto originalDataMgr = bundleMgrService_->GetDataMgr();
    bundleMgrService_->dataMgr_ = nullptr;

    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = bundleMgrHostImpl_->GetAllAppProvisionInfoInDevice(OTHER_USER_ID, appProvisionInfos);
    ASSERT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);

    // Restore dataMgr
    bundleMgrService_->dataMgr_ = originalDataMgr;
}

/**
 * @tc.number: SetAdditionalInfoByIndex_HostImpl_0001
 * @tc.name: test SetAdditionalInfoByIndex non-system app
 * @tc.desc: 1. non-system app calling
 *           2. returns ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED
 */
HWTEST_F(BmsBundleMgrHostImplProvisionTest, SetAdditionalInfoByIndex_HostImpl_0001,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(false);

    std::string additionalInfo = "additionalInfo";
    ErrCode ret = bundleMgrHostImpl_->SetAdditionalInfoByIndex(
        TEST_BUNDLE_NAME, additionalInfo, Constants::DEFAULT_APP_INDEX);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: SetAdditionalInfoByIndex_HostImpl_0002
 * @tc.name: test SetAdditionalInfoByIndex permission denied
 * @tc.desc: 1. system app but without GET_BUNDLE_INFO_PRIVILEGED permission
 *           2. returns ERR_BUNDLE_MANAGER_PERMISSION_DENIED
 */
HWTEST_F(BmsBundleMgrHostImplProvisionTest, SetAdditionalInfoByIndex_HostImpl_0002,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(false);

    std::string additionalInfo = "additionalInfo";
    ErrCode ret = bundleMgrHostImpl_->SetAdditionalInfoByIndex(
        TEST_BUNDLE_NAME, additionalInfo, Constants::DEFAULT_APP_INDEX);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: GetAppProvisionInfoInDevice_HostImpl_0003
 * @tc.name: test GetAppProvisionInfoInDevice non-system app
 * @tc.desc: 1. non-system app calling
 *           2. return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED
 */
HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetAppProvisionInfoInDevice_HostImpl_0003,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(false);

    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = bundleMgrHostImpl_->GetAppProvisionInfoInDevice(
        TEST_BUNDLE_NAME, Constants::UNSPECIFIED_USERID, appProvisionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: GetAppProvisionInfoInDevice_HostImpl_0004
 * @tc.name: test GetAppProvisionInfoInDevice permission denied
 * @tc.desc: 1. system app but without GET_BUNDLE_INFO_PRIVILEGED permission
 *           2. returns ERR_BUNDLE_MANAGER_PERMISSION_DENIED
 */
HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetAppProvisionInfoInDevice_HostImpl_0004,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(false);

    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = bundleMgrHostImpl_->GetAppProvisionInfoInDevice(
        TEST_BUNDLE_NAME, Constants::UNSPECIFIED_USERID, appProvisionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: GetAllAppProvisionInfoInDevice_HostImpl_0003
 * @tc.name: test GetAllAppProvisionInfoInDevice non-system app
 * @tc.desc: 1. non-system app calling
 *           2. return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED
 */
HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetAllAppProvisionInfoInDevice_HostImpl_0003,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(false);

    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = bundleMgrHostImpl_->GetAllAppProvisionInfoInDevice(OTHER_USER_ID, appProvisionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: GetAllAppProvisionInfoInDevice_HostImpl_0004
 * @tc.name: test GetAllAppProvisionInfoInDevice permission denied
 * @tc.desc: 1. system app but without GET_INSTALL_BUNDLE_LIST permission
 *           2. returns ERR_BUNDLE_MANAGER_PERMISSION_DENIED
 */
HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetAllAppProvisionInfoInDevice_HostImpl_0004,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(false);

    std::vector<AppProvisionInfo> appProvisionInfos;
    ErrCode ret = bundleMgrHostImpl_->GetAllAppProvisionInfoInDevice(OTHER_USER_ID, appProvisionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: SetAdditionalInfoByIndex_HostImpl_0003
 * @tc.name: test SetAdditionalInfoByIndex invalid appIndex
 * @tc.desc: 1. system app with permission
 *           2. appIndex is neither DEFAULT_APP_INDEX nor DUAL_MODE_CLONE_APP_INDEX
 *           3. returns ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE
 */
HWTEST_F(BmsBundleMgrHostImplProvisionTest, SetAdditionalInfoByIndex_HostImpl_0003,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetPermissionResultForTest(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED, true);

    std::string additionalInfo = "additionalInfo";
    ErrCode ret = bundleMgrHostImpl_->SetAdditionalInfoByIndex(
        TEST_BUNDLE_NAME, additionalInfo, 999);
    EXPECT_EQ(ret, ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE);
}

/**
 * @tc.number: SetAdditionalInfoByIndex_HostImpl_0004
 * @tc.name: test SetAdditionalInfoByIndex not app gallery call
 * @tc.desc: 1. system app with permission, valid appIndex
 *           2. calling bundle is not app gallery
 *           3. returns ERR_BUNDLE_MANAGER_NOT_APP_GALLERY_CALL
 */
HWTEST_F(BmsBundleMgrHostImplProvisionTest, SetAdditionalInfoByIndex_HostImpl_0004,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetPermissionResultForTest(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED, true);
    SetNativeTokenTypeForTest(true);

    std::string additionalInfo = "additionalInfo";
    ErrCode ret = bundleMgrHostImpl_->SetAdditionalInfoByIndex(
        TEST_BUNDLE_NAME, additionalInfo, Constants::DEFAULT_APP_INDEX);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_NOT_APP_GALLERY_CALL);
}

// === Cross-user permission denial tests for CheckAcrossUserPermission gates ===
// Common setup: system app + calling permission granted + non-native token +
// INTERACT_ACROSS_LOCAL_ACCOUNTS denied + target OTHER_USER_ID, expect
// ERR_BUNDLE_MANAGER_PERMISSION_DENIED before reaching the data layer.

HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetApplicationInfoV9_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    ApplicationInfo appInfo;
    ErrCode ret = bundleMgrHostImpl_->GetApplicationInfoV9(TEST_BUNDLE_NAME, 0, OTHER_USER_ID, appInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetApplicationInfosV9_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    std::vector<ApplicationInfo> appInfos;
    ErrCode ret = bundleMgrHostImpl_->GetApplicationInfosV9(0, OTHER_USER_ID, appInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetBundleInfosV9_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    std::vector<BundleInfo> bundleInfos;
    ErrCode ret = bundleMgrHostImpl_->GetBundleInfosV9(0, bundleInfos, OTHER_USER_ID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, QueryAbilityInfosV9_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    AAFwk::Want want;
    std::vector<AbilityInfo> abilityInfos;
    ErrCode ret = bundleMgrHostImpl_->QueryAbilityInfosV9(want, 0, OTHER_USER_ID, abilityInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, BatchQueryAbilityInfos_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    std::vector<AAFwk::Want> wants;
    wants.emplace_back();
    std::vector<AbilityInfo> abilityInfos;
    ErrCode ret = bundleMgrHostImpl_->BatchQueryAbilityInfos(wants, 0, OTHER_USER_ID, abilityInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, QueryLauncherAbilityInfos_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    AAFwk::Want want;
    std::vector<AbilityInfo> abilityInfos;
    ErrCode ret = bundleMgrHostImpl_->QueryLauncherAbilityInfos(want, OTHER_USER_ID, abilityInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetShortcutInfoV9_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    std::vector<ShortcutInfo> shortcutInfos;
    ErrCode ret = bundleMgrHostImpl_->GetShortcutInfoV9(TEST_BUNDLE_NAME, shortcutInfos, OTHER_USER_ID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, QueryExtensionAbilityInfosV9ByWant_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    AAFwk::Want want;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    ErrCode ret = bundleMgrHostImpl_->QueryExtensionAbilityInfosV9(want, 0, OTHER_USER_ID, extensionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, QueryExtensionAbilityInfosV9ByWantAndType_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    AAFwk::Want want;
    ExtensionAbilityType extType = static_cast<ExtensionAbilityType>(0);
    std::vector<ExtensionAbilityInfo> extensionInfos;
    ErrCode ret = bundleMgrHostImpl_->QueryExtensionAbilityInfosV9(want, extType, 0, OTHER_USER_ID, extensionInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetAppProvisionInfo_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    AppProvisionInfo appProvisionInfo;
    ErrCode ret = bundleMgrHostImpl_->GetAppProvisionInfo(TEST_BUNDLE_NAME, OTHER_USER_ID, appProvisionInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetProvisionMetadata_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    std::vector<Metadata> provisionMetadatas;
    ErrCode ret = bundleMgrHostImpl_->GetProvisionMetadata(TEST_BUNDLE_NAME, OTHER_USER_ID, provisionMetadatas);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetJsonProfile_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    std::string profile;
    ErrCode ret = bundleMgrHostImpl_->GetJsonProfile(
        static_cast<ProfileType>(0), TEST_BUNDLE_NAME, "", profile, OTHER_USER_ID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetAllJsonProfile_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    std::vector<JsonProfileInfo> profileInfos;
    ErrCode ret = bundleMgrHostImpl_->GetAllJsonProfile(static_cast<ProfileType>(0), OTHER_USER_ID, profileInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetAllPluginInfo_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    std::vector<PluginBundleInfo> pluginBundleInfos;
    ErrCode ret = bundleMgrHostImpl_->GetAllPluginInfo(TEST_BUNDLE_NAME, OTHER_USER_ID, pluginBundleInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, AddDesktopShortcutInfo_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    ShortcutInfo shortcutInfo;
    ErrCode ret = bundleMgrHostImpl_->AddDesktopShortcutInfo(shortcutInfo, OTHER_USER_ID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, DeleteDesktopShortcutInfo_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    ShortcutInfo shortcutInfo;
    ErrCode ret = bundleMgrHostImpl_->DeleteDesktopShortcutInfo(shortcutInfo, OTHER_USER_ID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetAllDesktopShortcutInfo_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    std::vector<ShortcutInfo> shortcutInfos;
    ErrCode ret = bundleMgrHostImpl_->GetAllDesktopShortcutInfo(OTHER_USER_ID, shortcutInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, RecoverBackupBundleData_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    ErrCode ret = bundleMgrHostImpl_->RecoverBackupBundleData(TEST_BUNDLE_NAME, OTHER_USER_ID, 0);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, RemoveBackupBundleData_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    ErrCode ret = bundleMgrHostImpl_->RemoveBackupBundleData(TEST_BUNDLE_NAME, OTHER_USER_ID, 0);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

// === Cross-user allowed path: native token bypasses the gate ===

HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetApplicationInfoV9_NativeTokenBypass_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(true);
    ApplicationInfo appInfo;
    ErrCode ret = bundleMgrHostImpl_->GetApplicationInfoV9(TEST_BUNDLE_NAME, 0, OTHER_USER_ID, appInfo);
    EXPECT_NE(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetAllDesktopShortcutInfo_NativeTokenBypass_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(true);
    std::vector<ShortcutInfo> shortcutInfos;
    ErrCode ret = bundleMgrHostImpl_->GetAllDesktopShortcutInfo(OTHER_USER_ID, shortcutInfos);
    EXPECT_NE(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

// === DefaultAppHostImpl cross-user permission denial tests ===
// VerifyAcrossUserPermission mock returns g_verifyPermission; setting it false
// makes the host-layer gate deny before delegating to DefaultAppMgr.

HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetDefaultApplication_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetVerifyCallingPermissionForTest(false);
    auto defaultAppHost = std::make_shared<DefaultAppHostImpl>();
    BundleInfo bundleInfo;
    ErrCode ret = defaultAppHost->GetDefaultApplication(OTHER_USER_ID, "browser", bundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, SetDefaultApplication_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetVerifyCallingPermissionForTest(false);
    auto defaultAppHost = std::make_shared<DefaultAppHostImpl>();
    AAFwk::Want want;
    ErrCode ret = defaultAppHost->SetDefaultApplication(OTHER_USER_ID, "browser", want);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, ResetDefaultApplication_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetVerifyCallingPermissionForTest(false);
    auto defaultAppHost = std::make_shared<DefaultAppHostImpl>();
    ErrCode ret = defaultAppHost->ResetDefaultApplication(OTHER_USER_ID, "browser");
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

// === DEFAULT_USERID bypass tests ===
// VerifyExemptedCrossUserPermission returns true for userId == 0 before
// delegating to the mock, so the gate must NOT deny even with permissions off.

HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetApplicationInfoV9_DefaultUserBypass_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    ApplicationInfo appInfo;
    ErrCode ret = bundleMgrHostImpl_->GetApplicationInfoV9(
        TEST_BUNDLE_NAME, 0, Constants::DEFAULT_USERID, appInfo);
    EXPECT_NE(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetDefaultApplication_DefaultUserBypass_0100,
    Function | SmallTest | Level1)
{
    SetVerifyCallingPermissionForTest(false);
    auto defaultAppHost = std::make_shared<DefaultAppHostImpl>();
    BundleInfo bundleInfo;
    ErrCode ret = defaultAppHost->GetDefaultApplication(
        Constants::DEFAULT_USERID, "browser", bundleInfo);
    EXPECT_NE(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

// === Pre-existing CheckAcrossUserPermission denial tests ===

HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetLaunchWantForBundle_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(false);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    AAFwk::Want want;
    ErrCode ret = bundleMgrHostImpl_->GetLaunchWantForBundle(
        TEST_BUNDLE_NAME, want, OTHER_USER_ID, true);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetShortcutInfoByAbility_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    std::vector<ShortcutInfo> shortcutInfos;
    ErrCode ret = bundleMgrHostImpl_->GetShortcutInfoByAbility(
        TEST_BUNDLE_NAME, "", "", OTHER_USER_ID, Constants::DEFAULT_APP_INDEX, shortcutInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, UpdateDesktopShortcutInfo_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    ShortcutInfo shortcutInfo;
    ErrCode ret = bundleMgrHostImpl_->UpdateDesktopShortcutInfo(shortcutInfo, OTHER_USER_ID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, IsApplicationDisableForbidden_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    bool forbidden = false;
    ErrCode ret = bundleMgrHostImpl_->IsApplicationDisableForbidden(
        TEST_BUNDLE_NAME, OTHER_USER_ID, Constants::DEFAULT_APP_INDEX, forbidden);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

HWTEST_F(BmsBundleMgrHostImplProvisionTest, GetAllBundleInfoInstances_AcrossUserDenied_0100,
    Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);
    std::vector<BundleInfo> bundleInfos;
    ErrCode ret = bundleMgrHostImpl_->GetAllBundleInfoInstances(
        TEST_BUNDLE_NAME, 0, bundleInfos, OTHER_USER_ID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}
}
}
