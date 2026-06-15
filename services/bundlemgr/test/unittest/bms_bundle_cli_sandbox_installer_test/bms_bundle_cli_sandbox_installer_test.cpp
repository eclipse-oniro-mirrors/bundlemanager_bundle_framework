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

#include "bundle_cli_sandbox_installer.h"

#include "appexecfwk_errors.h"
#include "bundle_constants.h"
#include "bundle_data_storage_rdb.h"
#include "bundle_mgr_service.h"
#include "inner_bundle_user_info.h"
#include "inner_cli_sandbox_info.h"
#include "scope_guard.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::DelayedSingleton;

namespace {
const std::string BUNDLE_NAME = "com.ohos.clisandboxtest";
const std::string CREATOR_BUNDLE_NAME = "com.ohos.caller";
const std::string ENV_CALLER_BUNDLE_NAME = "com.ohos.envcaller";
const std::string OTHER_CALLER = "com.ohos.othercaller";
const std::int32_t USER_ID = 100;
const std::int32_t VALID_APP_INDEX = 2000;
const std::int32_t INVALID_APP_INDEX_LOW = 1999;
const std::int32_t INVALID_APP_INDEX_HIGH = 3001;
const std::int32_t TEST_UID = 200100;
const std::uint32_t TEST_ACCESS_TOKEN_ID = 12345u;
} // namespace

namespace OHOS {
extern int32_t g_testVerifyPermission;
class BmsBundleCliSandboxInstallerTest : public testing::Test {
public:
    BmsBundleCliSandboxInstallerTest() {}
    ~BmsBundleCliSandboxInstallerTest() {}
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override;
    void TearDown() override;

    void SetBundleDataMgr();
    void UnsetBundleDataMgr();
    void SetUserIdToDataMgr(int32_t userId);
    void SetBundleInfoWithSandbox(const std::string &bundleName, int32_t userId,
        int32_t appIndex, const std::vector<std::string> &callerNames);
    void DeleteBundle(const std::string &bundleName);

    std::shared_ptr<BundleCliSandboxInstaller> installer_ = nullptr;
};

void BmsBundleCliSandboxInstallerTest::SetUp()
{
    installer_ = std::make_shared<BundleCliSandboxInstaller>();
    g_testVerifyPermission = 0;
}

void BmsBundleCliSandboxInstallerTest::TearDown()
{
    if (installer_) {
        installer_->ResetInstallProperties();
    }
}

void BmsBundleCliSandboxInstallerTest::SetBundleDataMgr()
{
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ =
        std::make_shared<AppExecFwk::BundleDataMgr>();
    EXPECT_TRUE(DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ != nullptr);
}

void BmsBundleCliSandboxInstallerTest::UnsetBundleDataMgr()
{
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
}

void BmsBundleCliSandboxInstallerTest::SetUserIdToDataMgr(int32_t userId)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    dataMgr->AddUserId(userId);
}

void BmsBundleCliSandboxInstallerTest::SetBundleInfoWithSandbox(const std::string &bundleName,
    int32_t userId, int32_t appIndex, const std::vector<std::string> &callerNames)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }

    InnerBundleUserInfo userInfo;
    userInfo.bundleName = bundleName;
    userInfo.bundleUserInfo.userId = userId;

    InnerCliSandboxInfo sandboxInfo;
    sandboxInfo.userId = userId;
    sandboxInfo.appIndex = appIndex;
    sandboxInfo.uid = TEST_UID;
    sandboxInfo.accessTokenId = TEST_ACCESS_TOKEN_ID;
    sandboxInfo.callerBundleNames = callerNames;
    userInfo.sandboxInfos[InnerBundleUserInfo::AppIndexToKey(appIndex)] = sandboxInfo;

    InnerBundleInfo innerBundleInfo;
    ApplicationInfo appInfo;
    appInfo.bundleName = bundleName;
    innerBundleInfo.SetBaseApplicationInfo(appInfo);
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);

    dataMgr->bundleInfos_[bundleName] = innerBundleInfo;
}

void BmsBundleCliSandboxInstallerTest::DeleteBundle(const std::string &bundleName)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    dataMgr->bundleInfos_.erase(bundleName);
}

/**
 * @tc.number: BmsBundleCliSandboxInstallerTest_0100
 * @tc.name: ProcessDestroyCliSandbox
 * @tc.desc: Test ProcessDestroyCliSandbox with empty bundle name
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, BmsBundleCliSandboxInstallerTest_0100, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    // bundleName (3rd parameter) is empty
    EXPECT_EQ(installer_->ProcessDestroyCliSandbox("", "", "", USER_ID, VALID_APP_INDEX, true),
        ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INVALID_BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleCliSandboxInstallerTest_0200
 * @tc.name: ProcessDestroyCliSandbox
 * @tc.desc: Test ProcessDestroyCliSandbox with appIndex below and above valid range
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, BmsBundleCliSandboxInstallerTest_0200, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    // appIndex < CLI_SANDBOX_APP_INDEX_MIN(2000)
    EXPECT_EQ(installer_->ProcessDestroyCliSandbox("", "", BUNDLE_NAME, USER_ID, INVALID_APP_INDEX_LOW, true),
        ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INVALID_APP_INDEX);
    // appIndex > CLI_SANDBOX_APP_INDEX_MAX(3000)
    EXPECT_EQ(installer_->ProcessDestroyCliSandbox("", "", BUNDLE_NAME, USER_ID, INVALID_APP_INDEX_HIGH, true),
        ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INVALID_APP_INDEX);
}

/**
 * @tc.number: BmsBundleCliSandboxInstallerTest_0300
 * @tc.name: ProcessDestroyCliSandbox
 * @tc.desc: Test ProcessDestroyCliSandbox when dataMgr is null
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, BmsBundleCliSandboxInstallerTest_0300, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    auto savedDataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_;
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = nullptr;
    installer_->dataMgr_ = nullptr;
    auto res = installer_->ProcessDestroyCliSandbox("", "", BUNDLE_NAME, USER_ID, VALID_APP_INDEX, true);
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = savedDataMgr;
    EXPECT_EQ(res, ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsBundleCliSandboxInstallerTest_0400
 * @tc.name: ProcessDestroyCliSandbox
 * @tc.desc: Test ProcessDestroyCliSandbox when userId does not exist
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, BmsBundleCliSandboxInstallerTest_0400, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    SetBundleDataMgr();
    ScopeGuard guard([this] { UnsetBundleDataMgr(); });
    installer_->dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(installer_->dataMgr_, nullptr);
    // multiUserIdsSet_ is empty, userId not found
    EXPECT_EQ(installer_->ProcessDestroyCliSandbox("", "", BUNDLE_NAME, USER_ID, VALID_APP_INDEX, true),
        ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_USER_NOT_EXIST);
}

/**
 * @tc.number: BmsBundleCliSandboxInstallerTest_0500
 * @tc.name: ProcessDestroyCliSandbox
 * @tc.desc: Test ProcessDestroyCliSandbox when bundle is not installed
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, BmsBundleCliSandboxInstallerTest_0500, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    SetBundleDataMgr();
    ScopeGuard guard([this] { UnsetBundleDataMgr(); });
    SetUserIdToDataMgr(USER_ID);
    installer_->dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(installer_->dataMgr_, nullptr);
    // bundleInfos_ does not contain BUNDLE_NAME
    EXPECT_EQ(installer_->ProcessDestroyCliSandbox("", "", BUNDLE_NAME, USER_ID, VALID_APP_INDEX, true),
        ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_APP_NOT_EXISTED);
}

/**
 * @tc.number: BmsBundleCliSandboxInstallerTest_0600
 * @tc.name: ProcessDestroyCliSandbox
 * @tc.desc: Test ProcessDestroyCliSandbox when bundle is not installed for the specified user
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, BmsBundleCliSandboxInstallerTest_0600, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    SetBundleDataMgr();
    ScopeGuard guard([this] { UnsetBundleDataMgr(); });
    SetUserIdToDataMgr(USER_ID);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    // Bundle exists but has no user info for USER_ID
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo appInfo;
    appInfo.bundleName = BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(appInfo);
    dataMgr->bundleInfos_[BUNDLE_NAME] = innerBundleInfo;
    installer_->dataMgr_ = dataMgr;
    EXPECT_EQ(installer_->ProcessDestroyCliSandbox("", "", BUNDLE_NAME, USER_ID, VALID_APP_INDEX, true),
        ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_NOT_INSTALLED_AT_SPECIFIED_USERID);
}

/**
 * @tc.number: BmsBundleCliSandboxInstallerTest_0700
 * @tc.name: ProcessDestroyCliSandbox
 * @tc.desc: Test ProcessDestroyCliSandbox when sandbox appIndex is not found
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, BmsBundleCliSandboxInstallerTest_0700, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    SetBundleDataMgr();
    ScopeGuard guard([this] { UnsetBundleDataMgr(); });
    SetUserIdToDataMgr(USER_ID);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    // User info exists but no sandbox for this appIndex
    InnerBundleUserInfo userInfo;
    userInfo.bundleName = BUNDLE_NAME;
    userInfo.bundleUserInfo.userId = USER_ID;
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo appInfo;
    appInfo.bundleName = BUNDLE_NAME;
    innerBundleInfo.SetBaseApplicationInfo(appInfo);
    innerBundleInfo.AddInnerBundleUserInfo(userInfo);
    dataMgr->bundleInfos_[BUNDLE_NAME] = innerBundleInfo;
    installer_->dataMgr_ = dataMgr;
    EXPECT_EQ(installer_->ProcessDestroyCliSandbox("", "", BUNDLE_NAME, USER_ID, VALID_APP_INDEX, true),
        ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_APP_INDEX_NOT_FOUND);
}

/**
 * @tc.number: BmsBundleCliSandboxInstallerTest_0800
 * @tc.name: ProcessDestroyCliSandbox
 * @tc.desc: Test ProcessDestroyCliSandbox caller check - GetActualCreatorBundleName returns empty
 *           when envCallerBundleName is empty and skipCallerCheck is false
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, BmsBundleCliSandboxInstallerTest_0800, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    SetBundleDataMgr();
    ScopeGuard guard([this] { UnsetBundleDataMgr(); });
    SetUserIdToDataMgr(USER_ID);
    SetBundleInfoWithSandbox(BUNDLE_NAME, USER_ID, VALID_APP_INDEX, {CREATOR_BUNDLE_NAME});
    installer_->dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(installer_->dataMgr_, nullptr);
    // envCallerBundleName is empty => GetActualCreatorBundleName returns ""
    EXPECT_EQ(installer_->ProcessDestroyCliSandbox(
        CREATOR_BUNDLE_NAME, "", BUNDLE_NAME, USER_ID, VALID_APP_INDEX, false),
        ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INVALID_CREATOR_BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleCliSandboxInstallerTest_0900
 * @tc.name: ProcessDestroyCliSandbox
 * @tc.desc: Test ProcessDestroyCliSandbox caller check - caller not in callerBundleNames
 *           Permission is not granted, so actualCaller is envCallerBundleName which is not in the list
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, BmsBundleCliSandboxInstallerTest_0900, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    SetBundleDataMgr();
    ScopeGuard guard([this] { UnsetBundleDataMgr(); });
    SetUserIdToDataMgr(USER_ID);
    SetBundleInfoWithSandbox(BUNDLE_NAME, USER_ID, VALID_APP_INDEX, {CREATOR_BUNDLE_NAME});
    installer_->dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(installer_->dataMgr_, nullptr);
    // Permission not granted => actualCaller = envCallerBundleName = OTHER_CALLER
    // OTHER_CALLER is not in callerBundleNames => invalid caller
    g_testVerifyPermission = -1;
    EXPECT_EQ(installer_->ProcessDestroyCliSandbox(
        CREATOR_BUNDLE_NAME, OTHER_CALLER, BUNDLE_NAME, USER_ID, VALID_APP_INDEX, false),
        ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INVALID_CREATOR_BUNDLE_NAME);
    g_testVerifyPermission = 0;
}

/**
 * @tc.number: BmsBundleCliSandboxInstallerTest_1000
 * @tc.name: ProcessDestroyCliSandbox
 * @tc.desc: Test ProcessDestroyCliSandbox - caller check passes but caller is not in the list
 *           Permission granted => actualCaller = inputCallerBundleName
 *           inputCallerBundleName is not in callerBundleNames => invalid caller
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, BmsBundleCliSandboxInstallerTest_1000, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    SetBundleDataMgr();
    ScopeGuard guard([this] { UnsetBundleDataMgr(); });
    SetUserIdToDataMgr(USER_ID);
    SetBundleInfoWithSandbox(BUNDLE_NAME, USER_ID, VALID_APP_INDEX, {CREATOR_BUNDLE_NAME});
    installer_->dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(installer_->dataMgr_, nullptr);
    // Permission granted (g_testVerifyPermission=0) => actualCaller = inputCallerBundleName = OTHER_CALLER
    // OTHER_CALLER is not in callerBundleNames => invalid caller
    g_testVerifyPermission = 0;
    EXPECT_EQ(installer_->ProcessDestroyCliSandbox(
        OTHER_CALLER, ENV_CALLER_BUNDLE_NAME, BUNDLE_NAME, USER_ID, VALID_APP_INDEX, false),
        ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INVALID_CREATOR_BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleCliSandboxInstallerTest_1100
 * @tc.name: ProcessDestroyCliSandbox
 * @tc.desc: Test ProcessDestroyCliSandbox - RemoveCliSandboxBundle fails due to null dataStorage_
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, BmsBundleCliSandboxInstallerTest_1100, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    SetBundleDataMgr();
    ScopeGuard guard([this] { UnsetBundleDataMgr(); });
    SetUserIdToDataMgr(USER_ID);
    SetBundleInfoWithSandbox(BUNDLE_NAME, USER_ID, VALID_APP_INDEX, {CREATOR_BUNDLE_NAME});
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    installer_->dataMgr_ = dataMgr;

    // Explicitly set dataStorage_ to nullptr to trigger RemoveCliSandboxBundle failure
    dataMgr->dataStorage_ = nullptr;

    EXPECT_EQ(installer_->ProcessDestroyCliSandbox(
        "", "", BUNDLE_NAME, USER_ID, VALID_APP_INDEX, true),
        ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsBundleCliSandboxInstallerTest_1200
 * @tc.name: ProcessDestroyCliSandbox
 * @tc.desc: Test ProcessDestroyCliSandbox - validation passes and member variables are set correctly
 *           even though RemoveCliSandboxBundle fails due to null dataStorage_.
 *           Verify uid_ and accessTokenId_ are populated from sandbox info.
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, BmsBundleCliSandboxInstallerTest_1200, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    SetBundleDataMgr();
    ScopeGuard guard([this] { UnsetBundleDataMgr(); });
    SetUserIdToDataMgr(USER_ID);
    SetBundleInfoWithSandbox(BUNDLE_NAME, USER_ID, VALID_APP_INDEX, {CREATOR_BUNDLE_NAME});
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    installer_->dataMgr_ = dataMgr;

    // Set dataStorage_ to nullptr to trigger RemoveCliSandboxBundle failure
    dataMgr->dataStorage_ = nullptr;

    // All validations pass, but RemoveCliSandboxBundle fails due to null storage
    auto res = installer_->ProcessDestroyCliSandbox(
        "", "", BUNDLE_NAME, USER_ID, VALID_APP_INDEX, true);
    // uid_ and accessTokenId_ should be set from sandbox info before RemoveCliSandboxBundle
    EXPECT_EQ(installer_->uid_, TEST_UID);
    EXPECT_EQ(installer_->accessTokenId_, TEST_ACCESS_TOKEN_ID);
    EXPECT_EQ(res, ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsBundleCliSandboxInstallerTest_1300
 * @tc.name: ProcessDestroyCliSandbox
 * @tc.desc: Test ProcessDestroyCliSandbox with caller check passing - permission granted
 *           and inputCallerBundleName is in callerBundleNames, but RemoveCliSandboxBundle fails
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, BmsBundleCliSandboxInstallerTest_1300, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    SetBundleDataMgr();
    ScopeGuard guard([this] { UnsetBundleDataMgr(); });
    SetUserIdToDataMgr(USER_ID);
    SetBundleInfoWithSandbox(BUNDLE_NAME, USER_ID, VALID_APP_INDEX, {CREATOR_BUNDLE_NAME});
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    installer_->dataMgr_ = dataMgr;

    // Set dataStorage_ to nullptr to trigger RemoveCliSandboxBundle failure
    dataMgr->dataStorage_ = nullptr;

    // Permission granted => actualCaller = inputCallerBundleName = CREATOR_BUNDLE_NAME
    // CREATOR_BUNDLE_NAME is in callerBundleNames => caller check passes
    g_testVerifyPermission = 0;
    auto res = installer_->ProcessDestroyCliSandbox(
        CREATOR_BUNDLE_NAME, ENV_CALLER_BUNDLE_NAME, BUNDLE_NAME, USER_ID, VALID_APP_INDEX, false);
    EXPECT_EQ(installer_->uid_, TEST_UID);
    EXPECT_EQ(installer_->accessTokenId_, TEST_ACCESS_TOKEN_ID);
    // RemoveCliSandboxBundle fails due to null storage
    EXPECT_EQ(res, ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INTERNAL_ERROR);
}

/**
 * @tc.number: BmsBundleCliSandboxInstallerTest_1400
 * @tc.name: ProcessDestroyCliSandbox
 * @tc.desc: Test ProcessDestroyCliSandbox with caller check passing - permission not granted
 *           so actualCaller = envCallerBundleName which IS in callerBundleNames
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, BmsBundleCliSandboxInstallerTest_1400, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    SetBundleDataMgr();
    ScopeGuard guard([this] { UnsetBundleDataMgr(); });
    SetUserIdToDataMgr(USER_ID);
    SetBundleInfoWithSandbox(BUNDLE_NAME, USER_ID, VALID_APP_INDEX,
        {CREATOR_BUNDLE_NAME, ENV_CALLER_BUNDLE_NAME});
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    installer_->dataMgr_ = dataMgr;

    // Set dataStorage_ to nullptr to trigger RemoveCliSandboxBundle failure
    dataMgr->dataStorage_ = nullptr;

    // Permission not granted => actualCaller = envCallerBundleName = ENV_CALLER_BUNDLE_NAME
    // ENV_CALLER_BUNDLE_NAME is in callerBundleNames => caller check passes
    g_testVerifyPermission = -1;
    auto res = installer_->ProcessDestroyCliSandbox(
        CREATOR_BUNDLE_NAME, ENV_CALLER_BUNDLE_NAME, BUNDLE_NAME, USER_ID, VALID_APP_INDEX, false);
    EXPECT_EQ(installer_->uid_, TEST_UID);
    EXPECT_EQ(installer_->accessTokenId_, TEST_ACCESS_TOKEN_ID);
    EXPECT_EQ(res, ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INTERNAL_ERROR);
    g_testVerifyPermission = 0;
}

/**
 * @tc.number: BmsBundleCliSandboxInstallerTest_1500
 * @tc.name: DestroyCliSandboxApp
 * @tc.desc: Test DestroyCliSandboxApp propagates error from ProcessDestroyCliSandbox
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, BmsBundleCliSandboxInstallerTest_1500, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    // Empty bundle name should return INVALID_BUNDLE_NAME
    EXPECT_EQ(installer_->DestroyCliSandboxApp(
        CREATOR_BUNDLE_NAME, ENV_CALLER_BUNDLE_NAME, "", USER_ID, VALID_APP_INDEX, true),
        ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INVALID_BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleCliSandboxInstallerTest_1600
 * @tc.name: DestroyCliSandboxApp
 * @tc.desc: Test DestroyCliSandboxApp with invalid appIndex
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, BmsBundleCliSandboxInstallerTest_1600, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    EXPECT_EQ(installer_->DestroyCliSandboxApp(
        CREATOR_BUNDLE_NAME, ENV_CALLER_BUNDLE_NAME, BUNDLE_NAME, USER_ID, INVALID_APP_INDEX_LOW, true),
        ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INVALID_APP_INDEX);
    EXPECT_EQ(installer_->DestroyCliSandboxApp(
        CREATOR_BUNDLE_NAME, ENV_CALLER_BUNDLE_NAME, BUNDLE_NAME, USER_ID, INVALID_APP_INDEX_HIGH, true),
        ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INVALID_APP_INDEX);
}

/**
 * @tc.number: BmsBundleCliSandboxInstallerTest_1700
 * @tc.name: DestroyCliSandboxApp
 * @tc.desc: Test DestroyCliSandboxApp resets properties after execution
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, BmsBundleCliSandboxInstallerTest_1700, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    SetBundleDataMgr();
    ScopeGuard guard([this] { UnsetBundleDataMgr(); });
    SetUserIdToDataMgr(USER_ID);
    SetBundleInfoWithSandbox(BUNDLE_NAME, USER_ID, VALID_APP_INDEX, {CREATOR_BUNDLE_NAME});
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    installer_->dataMgr_ = dataMgr;

    // Call DestroyCliSandboxApp which sets uid_ etc. then calls ResetInstallProperties
    installer_->DestroyCliSandboxApp(
        "", "", BUNDLE_NAME, USER_ID, VALID_APP_INDEX, true);
    // ResetInstallProperties should have cleared these
    EXPECT_EQ(installer_->uid_, 0);
    EXPECT_EQ(installer_->accessTokenId_, 0u);
    EXPECT_EQ(installer_->appId_, "");
    EXPECT_EQ(installer_->appIdentifier_, "");
}

/**
 * @tc.number: BmsBundleCliSandboxInstallerTest_1800
 * @tc.name: GetActualCreatorBundleName
 * @tc.desc: Test GetActualCreatorBundleName with empty envCallerBundleName
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, BmsBundleCliSandboxInstallerTest_1800, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    auto result = installer_->GetActualCreatorBundleName(CREATOR_BUNDLE_NAME, "", USER_ID);
    EXPECT_EQ(result, "");
}

/**
 * @tc.number: BmsBundleCliSandboxInstallerTest_1900
 * @tc.name: GetActualCreatorBundleName
 * @tc.desc: Test GetActualCreatorBundleName with permission granted
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, BmsBundleCliSandboxInstallerTest_1900, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    // g_testVerifyPermission = 0 => PERMISSION_GRANTED
    g_testVerifyPermission = 0;
    auto result = installer_->GetActualCreatorBundleName(CREATOR_BUNDLE_NAME, ENV_CALLER_BUNDLE_NAME, USER_ID);
    EXPECT_EQ(result, CREATOR_BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleCliSandboxInstallerTest_2000
 * @tc.name: GetActualCreatorBundleName
 * @tc.desc: Test GetActualCreatorBundleName with permission not granted
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, BmsBundleCliSandboxInstallerTest_2000, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    // g_testVerifyPermission != 0 => permission not granted
    g_testVerifyPermission = -1;
    auto result = installer_->GetActualCreatorBundleName(CREATOR_BUNDLE_NAME, ENV_CALLER_BUNDLE_NAME, USER_ID);
    EXPECT_EQ(result, ENV_CALLER_BUNDLE_NAME);
    g_testVerifyPermission = 0;
}

/**
 * @tc.number: BmsBundleCliSandboxInstallerTest_2100
 * @tc.name: GetActualCreatorBundleName
 * @tc.desc: Test GetActualCreatorBundleName with permission granted returns inputCallerBundleName
 *           even when inputCallerBundleName differs from envCallerBundleName
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, BmsBundleCliSandboxInstallerTest_2100, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    g_testVerifyPermission = 0;
    auto result = installer_->GetActualCreatorBundleName(OTHER_CALLER, ENV_CALLER_BUNDLE_NAME, USER_ID);
    EXPECT_EQ(result, OTHER_CALLER);
}

/**
 * @tc.number: DestroyAllCliSandboxApps_0100
 * @tc.name: DestroyAllCliSandboxApps - Empty Bundle Name
 * @tc.desc: Test DestroyAllCliSandboxApps with empty bundle name
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, DestroyAllCliSandboxApps_0100, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    SetBundleDataMgr();
    auto result = installer_->DestroyAllCliSandboxApps("", USER_ID);
    EXPECT_EQ(result, ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INVALID_BUNDLE_NAME);
    UnsetBundleDataMgr();
}

/**
 * @tc.number: DestroyAllCliSandboxApps_0200
 * @tc.name: DestroyAllCliSandboxApps - Non-existent Bundle
 * @tc.desc: Test DestroyAllCliSandboxApps with non-existent bundle
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, DestroyAllCliSandboxApps_0200, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    SetBundleDataMgr();
    SetUserIdToDataMgr(USER_ID);
    auto result = installer_->DestroyAllCliSandboxApps("non.existent.bundle", USER_ID);
    EXPECT_EQ(result, ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_APP_NOT_EXISTED);
    UnsetBundleDataMgr();
}

/**
 * @tc.number: DestroyAllCliSandboxApps_0300
 * @tc.name: DestroyAllCliSandboxApps - Bundle Without CLI Sandbox
 * @tc.desc: Test DestroyAllCliSandboxApps with bundle that has no CLI sandbox apps
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, DestroyAllCliSandboxApps_0300, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    SetBundleDataMgr();
    SetUserIdToDataMgr(USER_ID);
    SetBundleInfoWithSandbox(BUNDLE_NAME, USER_ID, 0, {});
    auto result = installer_->DestroyAllCliSandboxApps(BUNDLE_NAME, USER_ID);
    EXPECT_EQ(result, ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INTERNAL_ERROR);
    DeleteBundle(BUNDLE_NAME);
    UnsetBundleDataMgr();
}

/**
 * @tc.number: DestroyAllCliSandboxApps_0400
 * @tc.name: DestroyAllCliSandboxApps - Bundle With CLI Sandbox
 * @tc.desc: Test DestroyAllCliSandboxApps with bundle that has CLI sandbox apps
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, DestroyAllCliSandboxApps_0400, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    SetBundleDataMgr();
    SetUserIdToDataMgr(USER_ID);
    std::vector<std::string> callers = {CREATOR_BUNDLE_NAME};
    SetBundleInfoWithSandbox(BUNDLE_NAME, USER_ID, VALID_APP_INDEX, callers);
    auto result = installer_->DestroyAllCliSandboxApps(BUNDLE_NAME, USER_ID);
    EXPECT_EQ(result, ERR_OK);
    DeleteBundle(BUNDLE_NAME);
    UnsetBundleDataMgr();
}

/**
 * @tc.number: DestroyAllCliSandboxApps_0500
 * @tc.name: DestroyAllCliSandboxApps - Multiple CLI Sandbox Apps
 * @tc.desc: Test DestroyAllCliSandboxApps with bundle that has multiple CLI sandbox apps
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, DestroyAllCliSandboxApps_0500, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    SetBundleDataMgr();
    SetUserIdToDataMgr(USER_ID);
    std::vector<std::string> callers1 = {CREATOR_BUNDLE_NAME};
    std::vector<std::string> callers2 = {ENV_CALLER_BUNDLE_NAME};
    SetBundleInfoWithSandbox(BUNDLE_NAME, USER_ID, VALID_APP_INDEX, callers1);
    SetBundleInfoWithSandbox(BUNDLE_NAME, USER_ID, VALID_APP_INDEX + 1, callers2);
    auto result = installer_->DestroyAllCliSandboxApps(BUNDLE_NAME, USER_ID);
    EXPECT_EQ(result, ERR_OK);
    DeleteBundle(BUNDLE_NAME);
    UnsetBundleDataMgr();
}

/**
 * @tc.number: DestroyAllCliSandboxApps_0600
 * @tc.name: DestroyAllCliSandboxApps - Invalid User ID
 * @tc.desc: Test DestroyAllCliSandboxApps with invalid user ID
 */
HWTEST_F(BmsBundleCliSandboxInstallerTest, DestroyAllCliSandboxApps_0600, TestSize.Level1)
{
    ASSERT_NE(installer_, nullptr);
    SetBundleDataMgr();
    auto result = installer_->DestroyAllCliSandboxApps(BUNDLE_NAME, 999);
    EXPECT_EQ(result, ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_USER_NOT_EXIST);
    UnsetBundleDataMgr();
}
} // namespace OHOS
