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

#include <algorithm>

#include <gtest/gtest.h>

#include "bundle_constants.h"
#include "bundle_info.h"
#include "bundle_mgr_service.h"
#include "dual_mode_helper.h"
#include "inner_bundle_info.h"
#include "parameters.h"
#include "scope_guard.h"
#include "user_unlocked_event_subscriber.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {

namespace {
const std::string TEST_BUNDLE_NAME = "com.example.dualmodetest";
// A bundle name that only lives on the other-mode side (tempBundleInfos_): its dir queries
// prove that the dedicated other-mode pass ran, not the current-mode passes.
const std::string TEST_TEMP_BUNDLE_NAME = TEST_BUNDLE_NAME + ".temp";
const std::string TEST_MODULE_NAME = "entry";
constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t INVALID_USER_ID = -1;
constexpr int32_t NOT_CREATED_USER_ID = 999;
constexpr uint32_t TEST_APP_INDEX = 10000;
// DualModeHelper test-injection params (same keys as the sibling suites): the dedicated
// other-mode rebuild pass is gated on IsDualModeDevice(), which is false in a clean test
// environment unless these params are set (DualModeHelper reads them fresh per call).
constexpr const char *TEST_DUAL_MODE_PARAM = "persist.bms.test_dual_mode";
constexpr const char *TEST_ISPCMODE_PARAM = "persist.bms.ispcmode";
constexpr const char *TEST_MAINMODE_PARAM = "persist.bms.mainmode";
// Same flags as the unlock rebuild passes (UpdateAppDataMgr::UpdateAppDataDirSelinuxLabel).
constexpr int32_t TEST_QUERY_FLAGS = static_cast<int32_t>(BundleFlag::GET_BUNDLE_WITH_EXTENSION_INFO) |
    static_cast<int32_t>(BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION_NO_DETAILED);
}

class BmsBundleDataMgrDualModeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;
    void AddInnerBundleInfo(const std::string &bundleName) const;
    void ClearBundleInfos() const;

protected:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleDataMgrDualModeTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

void BmsBundleDataMgrDualModeTest::SetUpTestCase()
{
    bundleMgrService_->InitFreeInstall();
    bundleMgrService_->InitBundleInstaller();
    bundleMgrService_->InitBundleDataMgr();
    bundleMgrService_->GetDataMgr()->AddUserId(TEST_USER_ID);
}

void BmsBundleDataMgrDualModeTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleDataMgrDualModeTest::SetUp()
{
    // Clear any existing bundle infos before each test
    ClearBundleInfos();
}

void BmsBundleDataMgrDualModeTest::TearDown()
{
    // Clean up after test: structural safety net so a failing assertion cannot leak
    // BmsParam flags (e.g. the otaFlag set by UpdateTempModeAppDataDirsDualMode_0300)
    // into later cases.
    auto bmsParam = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsParam != nullptr) {
        bmsParam->DeleteBmsParam("otaFlag");
    }
    ClearBundleInfos();
}

std::shared_ptr<BundleDataMgr> BmsBundleDataMgrDualModeTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

void BmsBundleDataMgrDualModeTest::ClearBundleInfos() const
{
    auto dataMgr = GetBundleDataMgr();
    if (dataMgr) {
        dataMgr->bundleInfos_.clear();
        dataMgr->tempBundleInfos_.clear();
    }
}

void BmsBundleDataMgrDualModeTest::AddInnerBundleInfo(const std::string &bundleName) const
{
    auto dataMgr = GetBundleDataMgr();
    EXPECT_NE(dataMgr, nullptr);

    InnerBundleInfo innerBundleInfo;

    // Set up ApplicationInfo with appIndex
    ApplicationInfo appInfo;
    appInfo.bundleName = bundleName;
    appInfo.appIndex = TEST_APP_INDEX;
    innerBundleInfo.SetAppIndex(TEST_APP_INDEX);
    innerBundleInfo.SetBaseApplicationInfo(appInfo);

    // Set up BundleInfo with deviceModeDistributionPolicy and appSandboxPolicy
    BundleInfo bundleInfo;
    bundleInfo.name = bundleName;
    bundleInfo.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNSPECIFIED;
    bundleInfo.appSandboxPolicy = AppSandboxPolicy::SHARED_SANDBOX;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);

    // Set up InnerBundleUserInfo
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = bundleName;
    innerBundleUserInfo.bundleUserInfo.enabled = true;
    innerBundleUserInfo.bundleUserInfo.userId = TEST_USER_ID;
    innerBundleUserInfo.uid = TEST_USER_ID;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);

    dataMgr->bundleInfos_.emplace(bundleName, innerBundleInfo);
}

/**
 * @tc.number: GetBundleInfoDualMode_0100
 * @tc.name: test GetDualModeBundleInfo with empty bundle name
 * @tc.desc: 1. Call GetDualModeBundleInfo with empty bundle name
 *           2. Function should return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, GetBundleInfoDualMode_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    DualModeBundleInfo dualModeBundleInfo;
    ErrCode ret = dataMgr->GetDualModeBundleInfo("", TEST_USER_ID, dualModeBundleInfo);

    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST) << "Empty bundle name should return BUNDLE_NOT_EXIST";
}

/**
 * @tc.number: GetBundleInfoDualMode_0200
 * @tc.name: test GetDualModeBundleInfo with invalid userId
 * @tc.desc: 1. Call GetDualModeBundleInfo with INVALID_USER_ID
 *           2. Function should return ERR_BUNDLE_MANAGER_INVALID_USER_ID
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, GetBundleInfoDualMode_0200, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    DualModeBundleInfo dualModeBundleInfo;
    ErrCode ret = dataMgr->GetDualModeBundleInfo(TEST_BUNDLE_NAME, INVALID_USER_ID, dualModeBundleInfo);

    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID) << "Invalid userId should return INVALID_USER_ID";
}

/**
 * @tc.number: GetBundleInfoDualMode_0300
 * @tc.name: test GetDualModeBundleInfo when bundleInfos is empty
 * @tc.desc: 1. Ensure bundleInfos_ is empty
 *           2. Call GetDualModeBundleInfo
 *           3. Function should return ERR_BUNDLE_MANAGER_INTERNAL_ERROR
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, GetBundleInfoDualMode_0300, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    // Ensure bundleInfos is empty
    ClearBundleInfos();

    DualModeBundleInfo dualModeBundleInfo;
    ErrCode ret = dataMgr->GetDualModeBundleInfo(TEST_BUNDLE_NAME, TEST_USER_ID, dualModeBundleInfo);

    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR) << "Empty bundleInfos should return INTERNAL_ERROR";
}

/**
 * @tc.number: GetBundleInfoDualMode_0400
 * @tc.name: test GetDualModeBundleInfo when bundle not found
 * @tc.desc: 1. Add some bundle info but not the requested one
 *           2. Call GetDualModeBundleInfo with non-existent bundle
 *           3. Function should return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, GetBundleInfoDualMode_0400, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    // Add a different bundle
    AddInnerBundleInfo("com.example.other");

    DualModeBundleInfo dualModeBundleInfo;
    ErrCode ret = dataMgr->GetDualModeBundleInfo(TEST_BUNDLE_NAME, TEST_USER_ID, dualModeBundleInfo);

    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST) << "Non-existent bundle should return BUNDLE_NOT_EXIST";
}

/**
 * @tc.number: GetBundleInfoDualMode_0500
 * @tc.name: test GetDualModeBundleInfo with valid bundle and userId
 * @tc.desc: 1. Add InnerBundleInfo for the test bundle
 *           2. Call GetDualModeBundleInfo with valid parameters
 *           3. Function should return ERR_OK and correct output values
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, GetBundleInfoDualMode_0500, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    // Add the test bundle
    AddInnerBundleInfo(TEST_BUNDLE_NAME);

    DualModeBundleInfo dualModeBundleInfo;
    ErrCode ret = dataMgr->GetDualModeBundleInfo(TEST_BUNDLE_NAME, TEST_USER_ID, dualModeBundleInfo);

    EXPECT_EQ(ret, ERR_OK) << "Valid bundle should return ERR_OK";
    EXPECT_EQ(dualModeBundleInfo.appIndex, TEST_APP_INDEX) << "appIndex should match";
    EXPECT_EQ(dualModeBundleInfo.deviceModeDistributionPolicy, DeviceModeDistributionPolicy::UNSPECIFIED) <<
        "deviceModeDistributionPolicy should match";
    EXPECT_EQ(dualModeBundleInfo.appSandboxPolicy, AppSandboxPolicy::SHARED_SANDBOX) << "appSandboxPolicy should match";
}

/**
 * @tc.number: GetBundleInfoDualMode_0600
 * @tc.name: test GetDualModeBundleInfo with ANY_USERID
 * @tc.desc: 1. Add InnerBundleInfo for the test bundle
 *           2. Call GetDualModeBundleInfo with ANY_USERID
 *           3. Function should return ERR_OK and use the first available userId
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, GetBundleInfoDualMode_0600, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    // Add the test bundle
    AddInnerBundleInfo(TEST_BUNDLE_NAME);

    DualModeBundleInfo dualModeBundleInfo;
    ErrCode ret = dataMgr->GetDualModeBundleInfo(TEST_BUNDLE_NAME, Constants::ANY_USERID, dualModeBundleInfo);

    EXPECT_EQ(ret, ERR_OK) << "ANY_USERID should return ERR_OK";
    EXPECT_EQ(dualModeBundleInfo.appIndex, TEST_APP_INDEX) << "appIndex should match";
}

// Build a fresh InnerBundleInfo whose dual-mode fields are still at the defaults, so a policy
// refresh is observable. Used to seed tempBundleInfos_ (AddInnerBundleInfo only writes bundleInfos_).
static InnerBundleInfo MakeDefaultPolicyInfo(const std::string &bundleName)
{
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo appInfo;
    appInfo.bundleName = bundleName;
    innerBundleInfo.SetBaseApplicationInfo(appInfo);
    BundleInfo bundleInfo;
    bundleInfo.name = bundleName;
    bundleInfo.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNSPECIFIED;
    bundleInfo.appSandboxPolicy = AppSandboxPolicy::SHARED_SANDBOX;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    return innerBundleInfo;
}

/**
 * @tc.number: UpdateBundleInfoPolicyDualMode_0100
 * @tc.name: test UpdateBundleInfoPolicy with empty bundle name
 * @tc.desc: 1. Call UpdateBundleInfoPolicy with an empty bundle name
 *           2. Function should return false
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, UpdateBundleInfoPolicyDualMode_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    EXPECT_FALSE(dataMgr->UpdateBundleInfoPolicy("",
        DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE, AppSandboxPolicy::ISOLATED_SANDBOX));
}

/**
 * @tc.number: UpdateBundleInfoPolicyDualMode_0200
 * @tc.name: test UpdateBundleInfoPolicy when bundle does not exist
 * @tc.desc: 1. Keep bundleInfos_ empty
 *           2. Call UpdateBundleInfoPolicy for a missing bundle
 *           3. Function should return false
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, UpdateBundleInfoPolicyDualMode_0200, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);

    EXPECT_FALSE(dataMgr->UpdateBundleInfoPolicy(TEST_BUNDLE_NAME,
        DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE, AppSandboxPolicy::ISOLATED_SANDBOX));
}

/**
 * @tc.number: UpdateBundleInfoPolicyDualMode_0300
 * @tc.name: test UpdateBundleInfoPolicy when only the current side exists
 * @tc.desc: 1. Add the bundle to bundleInfos_ only (no tempBundleInfos_ copy)
 *           2. Call UpdateBundleInfoPolicy
 *           3. Function should return false because the temp side is missing (single-side state
 *              fails the both-side sync contract), but the main-side fields must still be refreshed
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, UpdateBundleInfoPolicyDualMode_0300, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    AddInnerBundleInfo(TEST_BUNDLE_NAME);

    EXPECT_FALSE(dataMgr->UpdateBundleInfoPolicy(TEST_BUNDLE_NAME,
        DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE, AppSandboxPolicy::ISOLATED_SANDBOX));
    EXPECT_EQ(dataMgr->bundleInfos_[TEST_BUNDLE_NAME].GetDeviceModeDistributionPolicy(),
        DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);
    EXPECT_EQ(dataMgr->bundleInfos_[TEST_BUNDLE_NAME].GetAppSandboxPolicy(), AppSandboxPolicy::ISOLATED_SANDBOX);
}

/**
 * @tc.number: UpdateBundleInfoPolicyDualMode_0400
 * @tc.name: test UpdateBundleInfoPolicy with both sides present
 * @tc.desc: 1. Add the bundle to bundleInfos_ and tempBundleInfos_ (dual-mode both-side state)
 *           2. Call UpdateBundleInfoPolicy
 *           3. Function should return true and refresh policy/sandbox on BOTH sides
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, UpdateBundleInfoPolicyDualMode_0400, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    AddInnerBundleInfo(TEST_BUNDLE_NAME);
    dataMgr->tempBundleInfos_[TEST_BUNDLE_NAME] = MakeDefaultPolicyInfo(TEST_BUNDLE_NAME);

    EXPECT_TRUE(dataMgr->UpdateBundleInfoPolicy(TEST_BUNDLE_NAME,
        DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE, AppSandboxPolicy::ISOLATED_SANDBOX));
    EXPECT_EQ(dataMgr->bundleInfos_[TEST_BUNDLE_NAME].GetDeviceModeDistributionPolicy(),
        DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);
    EXPECT_EQ(dataMgr->bundleInfos_[TEST_BUNDLE_NAME].GetAppSandboxPolicy(), AppSandboxPolicy::ISOLATED_SANDBOX);
    EXPECT_EQ(dataMgr->tempBundleInfos_[TEST_BUNDLE_NAME].GetDeviceModeDistributionPolicy(),
        DeviceModeDistributionPolicy::UNIVERSAL_DIFFERENT_PACKAGE);
    EXPECT_EQ(dataMgr->tempBundleInfos_[TEST_BUNDLE_NAME].GetAppSandboxPolicy(), AppSandboxPolicy::ISOLATED_SANDBOX);

    dataMgr->tempBundleInfos_.clear();
}

// Seed a dual-mode variant record installed for the given user (used for both the
// current-mode side bundleInfos_ and the other-mode side tempBundleInfos_).
// isCloneVariant marks the dual-mode clone variant (prefixed dir name, appIndex 10000).
static InnerBundleInfo MakeVariantInfo(const std::string &bundleName, int32_t userId, bool isCloneVariant)
{
    InnerBundleInfo innerBundleInfo;
    ApplicationInfo appInfo;
    appInfo.bundleName = bundleName;
    innerBundleInfo.SetBaseApplicationInfo(appInfo);
    BundleInfo bundleInfo;
    bundleInfo.name = bundleName;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    if (isCloneVariant) {
        innerBundleInfo.SetDualModeCloneApp(true);
        innerBundleInfo.SetAppIndex(TEST_APP_INDEX);
    }
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = bundleName;
    innerBundleUserInfo.bundleUserInfo.enabled = true;
    innerBundleUserInfo.bundleUserInfo.userId = userId;
    innerBundleUserInfo.uid = TEST_USER_ID;
    innerBundleInfo.AddInnerBundleUserInfo(innerBundleUserInfo);
    return innerBundleInfo;
}

// Seed one enabled regular clone (appIndex 1) into the given user info of the record.
static void AddRegularClone(InnerBundleInfo &info, int32_t userId, int32_t cloneUid)
{
    InnerBundleUserInfo userInfo;
    ASSERT_TRUE(info.GetInnerBundleUserInfo(userId, userInfo));
    InnerBundleCloneInfo cloneInfo;
    cloneInfo.userId = userId;
    cloneInfo.appIndex = 1;
    cloneInfo.uid = cloneUid;
    userInfo.cloneInfos.emplace("1", cloneInfo);
    info.AddInnerBundleUserInfo(userInfo);
}

// Seed one CLI sandbox (appIndex 2000, the CLI sandbox index floor) into the given
// user info of the record.
static void AddCliSandbox(InnerBundleInfo &info, int32_t userId, int32_t sandboxUid)
{
    InnerBundleUserInfo userInfo;
    ASSERT_TRUE(info.GetInnerBundleUserInfo(userId, userInfo));
    InnerCliSandboxInfo sandboxInfo;
    sandboxInfo.userId = userId;
    sandboxInfo.appIndex = Constants::CLI_SANDBOX_APP_INDEX_MIN;
    sandboxInfo.uid = sandboxUid;
    userInfo.sandboxInfos.emplace("2000", sandboxInfo);
    info.AddInnerBundleUserInfo(userInfo);
}

// Mock installd_client helpers for the IsExistDir query captures.
void ResetIsExistDirPathsForTest();
std::vector<std::string> GetIsExistDirPathsForTest();

// Whether the driven flow queried the given dir path (pass-coverage assertion).
static bool QueriedDirPath(const std::vector<std::string> &paths, const std::string &path)
{
    return std::find(paths.begin(), paths.end(), path) != paths.end();
}

/**
 * @tc.number: GetTempBundleInfosDualMode_0100
 * @tc.name: test GetTempBundleInfos with no other-mode variants
 * @tc.desc: 1. Keep tempBundleInfos_ empty (non-dual-mode state)
 *           2. Call GetTempBundleInfos
 *           3. Should return false with an empty result (no rebuild needed)
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, GetTempBundleInfosDualMode_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->tempBundleInfos_.clear();

    std::vector<BundleInfo> tempBundleInfos;
    bool ret = dataMgr->GetTempBundleInfos(TEST_QUERY_FLAGS, tempBundleInfos, TEST_USER_ID);

    EXPECT_FALSE(ret);
    EXPECT_TRUE(tempBundleInfos.empty()) << "Empty tempBundleInfos_ should collect nothing";
}

/**
 * @tc.number: GetTempBundleInfosDualMode_0200
 * @tc.name: test GetTempBundleInfos with a dual-mode clone variant
 * @tc.desc: 1. Seed tempBundleInfos_ with the other-mode clone variant (appIndex 10000) for user 100
 *           2. Call GetTempBundleInfos
 *           3. Result should carry the variant with the original name and appIndex 10000
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, GetTempBundleInfosDualMode_0200, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->tempBundleInfos_[TEST_BUNDLE_NAME] = MakeVariantInfo(TEST_BUNDLE_NAME, TEST_USER_ID, true);

    std::vector<BundleInfo> tempBundleInfos;
    bool ret = dataMgr->GetTempBundleInfos(TEST_QUERY_FLAGS, tempBundleInfos, TEST_USER_ID);

    EXPECT_TRUE(ret);
    ASSERT_EQ(tempBundleInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(tempBundleInfos[0].name, TEST_BUNDLE_NAME) << "clone variant keeps the original name";
    EXPECT_EQ(tempBundleInfos[0].appIndex, TEST_APP_INDEX) << "clone variant carries DUAL_MODE_CLONE_APP_INDEX";

    dataMgr->tempBundleInfos_.clear();
}

/**
 * @tc.number: GetTempBundleInfosDualMode_0300
 * @tc.name: test GetTempBundleInfos filters variants not installed for the user
 * @tc.desc: 1. Seed tempBundleInfos_ with a variant installed only for another user
 *           2. Call GetTempBundleInfos for user 100
 *           3. Should return false with an empty result (variant not installed for the user)
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, GetTempBundleInfosDualMode_0300, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->tempBundleInfos_[TEST_BUNDLE_NAME] = MakeVariantInfo(TEST_BUNDLE_NAME, TEST_USER_ID + 1, false);

    std::vector<BundleInfo> tempBundleInfos;
    bool ret = dataMgr->GetTempBundleInfos(TEST_QUERY_FLAGS, tempBundleInfos, TEST_USER_ID);

    EXPECT_FALSE(ret);
    EXPECT_TRUE(tempBundleInfos.empty()) << "Variant of another user should be filtered out";

    dataMgr->tempBundleInfos_.clear();
}

/**
 * @tc.number: GetTempBundleInfosDualMode_0400
 * @tc.name: test GetTempBundleInfos expands the clones of an other-mode variant
 * @tc.desc: 1. Seed tempBundleInfos_ with a variant carrying one regular clone (appIndex 1)
 *           2. Call GetTempBundleInfos
 *           3. Result should carry both the variant and its clone, mirroring GetBundleInfos
 *              (clone apps of the other-mode variants stay symmetric with the current mode)
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, GetTempBundleInfosDualMode_0400, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo tempInfo = MakeVariantInfo(TEST_BUNDLE_NAME, TEST_USER_ID, false);
    AddRegularClone(tempInfo, TEST_USER_ID, TEST_USER_ID + 1);
    dataMgr->tempBundleInfos_[TEST_BUNDLE_NAME] = tempInfo;

    std::vector<BundleInfo> tempBundleInfos;
    bool ret = dataMgr->GetTempBundleInfos(TEST_QUERY_FLAGS, tempBundleInfos, TEST_USER_ID);

    EXPECT_TRUE(ret);
    ASSERT_EQ(tempBundleInfos.size(), static_cast<size_t>(2));
    bool hasMainVariant = false;
    bool hasClone = false;
    for (const auto &bundleInfo : tempBundleInfos) {
        if (bundleInfo.appIndex == 0) {
            hasMainVariant = (bundleInfo.name == TEST_BUNDLE_NAME);
        } else if (bundleInfo.appIndex == 1) {
            hasClone = (bundleInfo.name == TEST_BUNDLE_NAME);
        }
    }
    EXPECT_TRUE(hasMainVariant) << "main variant should be collected";
    EXPECT_TRUE(hasClone) << "clone of the other-mode variant should be expanded";

    dataMgr->tempBundleInfos_.clear();
}

/**
 * @tc.number: CreateAppGroupDirTempDualMode_0100
 * @tc.name: test CreateAppGroupDir targeting the other-mode variant record
 * @tc.desc: 1. Keep the bundle only in tempBundleInfos_ (single-mode hidden variant)
 *           2. Call CreateAppGroupDir with toTempBundle=true / false
 *           3. true should resolve the temp record, false should fail (no current-mode record)
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, CreateAppGroupDirTempDualMode_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.erase(TEST_BUNDLE_NAME);
    dataMgr->tempBundleInfos_[TEST_BUNDLE_NAME] = MakeVariantInfo(TEST_BUNDLE_NAME, TEST_USER_ID, false);

    EXPECT_TRUE(dataMgr->CreateAppGroupDir(TEST_BUNDLE_NAME, TEST_USER_ID, true)) <<
        "toTempBundle=true should resolve the temp record (empty group set still succeeds)";
    EXPECT_FALSE(dataMgr->CreateAppGroupDir(TEST_BUNDLE_NAME, TEST_USER_ID, false)) <<
        "toTempBundle=false should not find the hidden-only bundle in bundleInfos_";

    dataMgr->tempBundleInfos_.clear();
}

/**
 * @tc.number: UpdateTempModeAppDataDirsDualMode_0100
 * @tc.name: smoke test the unlock rebuild with both mode sides seeded
 * @tc.desc: 1. Seed the current-mode side (bundleInfos_), the same-name other-mode clone
 *              variant and a temp-only other-mode clone variant (tempBundleInfos_)
 *           2. Run the full unlock rebuild entry (UpdateAppDataDirSelinuxLabel), which also
 *              triggers the dedicated other-mode pass (UpdateTempModeAppDataDirs)
 *           3. The rebuild completes and consumes neither side's records (the mode switch
 *              still relies on both maps staying intact), and the dedicated other-mode pass
 *              actually queried the temp-only variant's dir (pass-coverage proof: the
 *              current-mode passes cannot query a temp-only name)
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, UpdateTempModeAppDataDirsDualMode_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    // Turn on the dual-mode device state for this case: the dedicated other-mode pass is
    // gated on IsDualModeDevice() (false in a clean environment), so without the injection
    // the pass would never run and the temp-only dir queries below could not happen.
    // The guard restores the switch when the case ends (persist.* outlive the binary).
    OHOS::system::SetParameter(TEST_DUAL_MODE_PARAM, "true");
    ScopeGuard dualModeGuard([&] {
        OHOS::system::SetParameter(TEST_DUAL_MODE_PARAM, "false");
    });
    OHOS::system::SetParameter(TEST_ISPCMODE_PARAM,
        std::to_string(ServiceConstants::DUAL_MODE_VALUE_TABLET));
    OHOS::system::SetParameter(TEST_MAINMODE_PARAM,
        std::to_string(ServiceConstants::DUAL_MODE_VALUE_TABLET));
    ASSERT_TRUE(DualModeHelper::IsDualModeDevice())
        << "dual-mode injection params must drive IsDualModeDevice to true";
    AddInnerBundleInfo(TEST_BUNDLE_NAME);
    dataMgr->tempBundleInfos_[TEST_BUNDLE_NAME] = MakeVariantInfo(TEST_BUNDLE_NAME, TEST_USER_ID, true);
    dataMgr->tempBundleInfos_[TEST_TEMP_BUNDLE_NAME] = MakeVariantInfo(TEST_TEMP_BUNDLE_NAME, TEST_USER_ID, true);

    ResetIsExistDirPathsForTest();
    UpdateAppDataMgr::UpdateAppDataDirSelinuxLabel(TEST_USER_ID);

    EXPECT_EQ(dataMgr->bundleInfos_.count(TEST_BUNDLE_NAME), static_cast<size_t>(1)) <<
        "current-mode record must stay in bundleInfos_";
    EXPECT_EQ(dataMgr->tempBundleInfos_.count(TEST_BUNDLE_NAME), static_cast<size_t>(1)) <<
        "other-mode record must stay in tempBundleInfos_";
    EXPECT_EQ(dataMgr->tempBundleInfos_[TEST_BUNDLE_NAME].GetAppIndex(), TEST_APP_INDEX) <<
        "other-mode record must keep the clone variant identity";
    EXPECT_TRUE(QueriedDirPath(GetIsExistDirPathsForTest(),
        "/data/app/el2/100/database/+clone-10000+" + TEST_TEMP_BUNDLE_NAME)) <<
        "the dedicated other-mode pass must query the temp-only variant's el2 database dir";
#ifdef CHECK_ELDIR_ENABLED
    EXPECT_TRUE(QueriedDirPath(GetIsExistDirPathsForTest(),
        "/data/app/el3/100/database/+clone-10000+" + TEST_TEMP_BUNDLE_NAME)) <<
        "the dedicated other-mode EL3 pass must query the temp-only variant's database dir";
    EXPECT_TRUE(QueriedDirPath(GetIsExistDirPathsForTest(),
        "/data/app/el4/100/database/+clone-10000+" + TEST_TEMP_BUNDLE_NAME)) <<
        "the dedicated other-mode EL4 pass must query the temp-only variant's database dir";
#endif

    dataMgr->tempBundleInfos_.clear();
}

/**
 * @tc.number: GetTempBundleInfosDualMode_0500
 * @tc.name: test GetTempBundleInfos filters shared/skill bundle records
 * @tc.desc: 1. Seed tempBundleInfos_ with a SHARED-typed and a SKILL-typed variant
 *           2. Call GetTempBundleInfos
 *           3. Should return false with an empty result (shared/skill carry no data dirs)
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, GetTempBundleInfosDualMode_0500, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo sharedInfo = MakeVariantInfo(TEST_BUNDLE_NAME, TEST_USER_ID, false);
    sharedInfo.SetApplicationBundleType(BundleType::SHARED);
    dataMgr->tempBundleInfos_[TEST_BUNDLE_NAME] = sharedInfo;
    InnerBundleInfo skillInfo = MakeVariantInfo(TEST_TEMP_BUNDLE_NAME, TEST_USER_ID, false);
    skillInfo.SetApplicationBundleType(BundleType::SKILL);
    dataMgr->tempBundleInfos_[TEST_TEMP_BUNDLE_NAME] = skillInfo;

    std::vector<BundleInfo> tempBundleInfos;
    bool ret = dataMgr->GetTempBundleInfos(TEST_QUERY_FLAGS, tempBundleInfos, TEST_USER_ID);

    EXPECT_FALSE(ret);
    EXPECT_TRUE(tempBundleInfos.empty()) << "SHARED/SKILL-typed variants should be filtered out";

    dataMgr->tempBundleInfos_.clear();
}

/**
 * @tc.number: GetTempBundleInfosDualMode_0600
 * @tc.name: test GetTempBundleInfos filters bundle-status-disabled variants
 * @tc.desc: 1. Seed tempBundleInfos_ with a bundle-status-disabled variant carrying a clone
 *           2. Call GetTempBundleInfos
 *           3. Should return false with an empty result — a disabled record is skipped
 *              entirely, its clone is NOT expanded (same rule as GetBundleInfos)
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, GetTempBundleInfosDualMode_0600, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo tempInfo = MakeVariantInfo(TEST_BUNDLE_NAME, TEST_USER_ID, false);
    AddRegularClone(tempInfo, TEST_USER_ID, TEST_USER_ID + 1);
    tempInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    dataMgr->tempBundleInfos_[TEST_BUNDLE_NAME] = tempInfo;

    std::vector<BundleInfo> tempBundleInfos;
    bool ret = dataMgr->GetTempBundleInfos(TEST_QUERY_FLAGS, tempBundleInfos, TEST_USER_ID);

    EXPECT_FALSE(ret);
    EXPECT_TRUE(tempBundleInfos.empty()) << "disabled variant must be skipped with no clone expansion";

    dataMgr->tempBundleInfos_.clear();
}

/**
 * @tc.number: GetTempBundleInfosDualMode_0700
 * @tc.name: test GetTempBundleInfos with a non-existent user
 * @tc.desc: 1. Seed tempBundleInfos_ with a variant installed for user 100
 *           2. Call GetTempBundleInfos for a user that does not exist
 *           3. Should return false with an empty result (GetUserId resolves to INVALID)
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, GetTempBundleInfosDualMode_0700, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->tempBundleInfos_[TEST_BUNDLE_NAME] = MakeVariantInfo(TEST_BUNDLE_NAME, TEST_USER_ID, false);

    std::vector<BundleInfo> tempBundleInfos;
    bool ret = dataMgr->GetTempBundleInfos(TEST_QUERY_FLAGS, tempBundleInfos, NOT_CREATED_USER_ID);

    EXPECT_FALSE(ret);
    EXPECT_TRUE(tempBundleInfos.empty()) << "non-existent user should collect nothing";

    dataMgr->tempBundleInfos_.clear();
}

/**
 * @tc.number: GetTempBundleInfosDualMode_0800
 * @tc.name: test GetTempBundleInfos with the default userId resolves the calling user
 * @tc.desc: 1. Seed tempBundleInfos_ with a variant installed for user 100
 *           2. Call GetTempBundleInfos once with the default userId (UNSPECIFIED_USERID)
 *              and once with the explicit calling-uid user
 *           3. The default-parameter path must behave the same as the explicit one
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, GetTempBundleInfosDualMode_0800, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->tempBundleInfos_[TEST_BUNDLE_NAME] = MakeVariantInfo(TEST_BUNDLE_NAME, TEST_USER_ID, false);

    std::vector<BundleInfo> defaultUserInfos;
    bool retDefault = dataMgr->GetTempBundleInfos(TEST_QUERY_FLAGS, defaultUserInfos);
    std::vector<BundleInfo> explicitUserInfos;
    bool retExplicit = dataMgr->GetTempBundleInfos(TEST_QUERY_FLAGS, explicitUserInfos,
        dataMgr->GetUserIdByCallingUid());

    EXPECT_EQ(retDefault, retExplicit) <<
        "the default userId path must match the explicit calling-uid user";
    EXPECT_EQ(defaultUserInfos.size(), explicitUserInfos.size()) <<
        "the default userId path must collect the same variants";

    dataMgr->tempBundleInfos_.clear();
}

/**
 * @tc.number: GetBundleInfosDualMode_0100
 * @tc.name: regression test GetBundleInfos collects the main app and its clone
 * @tc.desc: 1. Seed bundleInfos_ with a current-mode variant carrying a clone (appIndex 1)
 *           2. Call GetBundleInfos
 *           3. Both the main app and the clone should be collected (shared loop core keeps
 *              the pre-refactor behavior)
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, GetBundleInfosDualMode_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo innerInfo = MakeVariantInfo(TEST_BUNDLE_NAME, TEST_USER_ID, false);
    AddRegularClone(innerInfo, TEST_USER_ID, TEST_USER_ID + 1);
    dataMgr->bundleInfos_[TEST_BUNDLE_NAME] = innerInfo;

    std::vector<BundleInfo> bundleInfos;
    bool ret = dataMgr->GetBundleInfos(TEST_QUERY_FLAGS, bundleInfos, TEST_USER_ID);

    EXPECT_TRUE(ret);
    ASSERT_EQ(bundleInfos.size(), static_cast<size_t>(2));
    bool hasMain = false;
    bool hasClone = false;
    for (const auto &bundleInfo : bundleInfos) {
        hasMain = hasMain || (bundleInfo.appIndex == 0);
        hasClone = hasClone || (bundleInfo.appIndex == 1);
    }
    EXPECT_TRUE(hasMain) << "main app should be collected";
    EXPECT_TRUE(hasClone) << "clone should be expanded";

    dataMgr->bundleInfos_.erase(TEST_BUNDLE_NAME);
}

// Drive the private CreateBundleDataDir entry and return the first dir path it queried
// through the mock InstalldClient (the DATABASE dir check is the first IsExistDir —
// reading the first capture keeps working even once the mock service is wired and the
// later el2 BASE check succeeds). Uses the original 3-arg form (toTempBundle defaults
// to false = current mode).
static std::string QueryDataDirPath(int32_t appIndex)
{
    BundleInfo bundleInfo;
    bundleInfo.name = TEST_BUNDLE_NAME;
    bundleInfo.appIndex = appIndex;
    ResetIsExistDirPathsForTest();
    (void)UpdateAppDataMgr::CreateBundleDataDir(bundleInfo, TEST_USER_ID,
        ServiceConstants::BUNDLE_EL[1]);
    auto paths = GetIsExistDirPathsForTest();
    return paths.empty() ? std::string() : paths.front();
}

/**
 * @tc.number: GetDirBundleNameDualMode_0100
 * @tc.name: test the dual-mode clone variant resolves the prefixed dir name
 * @tc.desc: 1. Build a BundleInfo of the dual-mode clone variant (appIndex 10000)
 *           2. Drive CreateBundleDataDir for the el2 pass
 *           3. The queried dir path must use the +clone-10000+ prefixed name, resolved from
 *              the record's own appIndex
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, GetDirBundleNameDualMode_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.clear();
    dataMgr->tempBundleInfos_.clear();

    std::string path = QueryDataDirPath(static_cast<int32_t>(TEST_APP_INDEX));

    EXPECT_EQ(path, std::string("/data/app/el2/100/database/+clone-10000+") + TEST_BUNDLE_NAME) <<
        "dual-mode clone variant must use the prefixed dir name";
}

/**
 * @tc.number: GetDirBundleNameDualMode_0200
 * @tc.name: test a normal variant resolves the original dir name
 * @tc.desc: 1. Build a BundleInfo of a normal variant (appIndex 0)
 *           2. Drive CreateBundleDataDir for the el2 pass
 *           3. The queried dir path must use the original bundle name
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, GetDirBundleNameDualMode_0200, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.clear();
    dataMgr->tempBundleInfos_.clear();

    std::string path = QueryDataDirPath(0);

    EXPECT_EQ(path, "/data/app/el2/100/database/" + TEST_BUNDLE_NAME) <<
        "normal variant must use the original dir name";
}

/**
 * @tc.number: GetDirBundleNameDualMode_0300
 * @tc.name: test a regular clone keeps the original dir name
 * @tc.desc: 1. Build a BundleInfo of a regular clone (appIndex 3)
 *           2. Drive CreateBundleDataDir for the el2 pass
 *           3. The queried dir path must keep the original bundle name — the dual-mode
 *              prefix belongs to the dual-mode clone variant (appIndex 10000) only
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, GetDirBundleNameDualMode_0300, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_.clear();
    dataMgr->tempBundleInfos_.clear();

    std::string path = QueryDataDirPath(3);

    EXPECT_EQ(path, "/data/app/el2/100/database/" + TEST_BUNDLE_NAME) <<
        "regular clone must keep the original dir name";
}

/**
 * @tc.number: CheckU1EnableProcessDualMode_0100
 * @tc.name: test CheckU1EnableProcess reads the U1 flag of the same variant's record
 * @tc.desc: 1. Seed a U1-enabled variant on one side only (tempBundleInfos_ vs bundleInfos_)
 *           2. Call CheckU1EnableProcess for both map routings
 *           3. Each routing must read its own side's U1 flag, not the other variant's
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, CheckU1EnableProcessDualMode_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    BundleInfo bundleInfo;
    bundleInfo.name = TEST_BUNDLE_NAME;
    bundleInfo.singleton = false;

    // Only the other-mode (temp) side is U1 enabled.
    InnerBundleInfo u1Info = MakeVariantInfo(TEST_BUNDLE_NAME, TEST_USER_ID, false);
    u1Info.SetAllowedAcls({Constants::PERMISSION_U1_ENABLED});
    dataMgr->tempBundleInfos_[TEST_BUNDLE_NAME] = u1Info;
    EXPECT_TRUE(UpdateAppDataMgr::CheckU1EnableProcess(bundleInfo, true)) <<
        "toTempBundle=true must read the temp record's U1 flag";
    EXPECT_FALSE(UpdateAppDataMgr::CheckU1EnableProcess(bundleInfo, false)) <<
        "no current-mode record means no U1 flag";

    // Mirror: only the current-mode side is U1 enabled.
    dataMgr->tempBundleInfos_.clear();
    dataMgr->bundleInfos_[TEST_BUNDLE_NAME] = u1Info;
    EXPECT_TRUE(UpdateAppDataMgr::CheckU1EnableProcess(bundleInfo, false)) <<
        "toTempBundle=false must read the current record's U1 flag";
    EXPECT_FALSE(UpdateAppDataMgr::CheckU1EnableProcess(bundleInfo, true)) <<
        "no temp record means no U1 flag";

    dataMgr->bundleInfos_.erase(TEST_BUNDLE_NAME);
}

/**
 * @tc.number: UpdateTempModeAppDataDirsDualMode_0200
 * @tc.name: smoke test the unlock rebuild without other-mode variants
 * @tc.desc: 1. Seed only a current-mode record (tempBundleInfos_ empty, non-dual-mode state)
 *           2. Run the full unlock rebuild entry (UpdateAppDataDirSelinuxLabel)
 *           3. Completes with the dedicated other-mode pass as a no-op, and the
 *              current-mode record stays intact
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, UpdateTempModeAppDataDirsDualMode_0200, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    AddInnerBundleInfo(TEST_BUNDLE_NAME);
    dataMgr->tempBundleInfos_.clear();

    UpdateAppDataMgr::UpdateAppDataDirSelinuxLabel(TEST_USER_ID);

    EXPECT_EQ(dataMgr->bundleInfos_.count(TEST_BUNDLE_NAME), static_cast<size_t>(1)) <<
        "current-mode record must stay in bundleInfos_";
    EXPECT_TRUE(dataMgr->tempBundleInfos_.empty()) << "no other-mode record may appear";
}

/**
 * @tc.number: UpdateTempModeAppDataDirsDualMode_0300
 * @tc.name: test the unlock rebuild also rebuilds the other-mode variants' clone data dirs
 * @tc.desc: 1. Seed a temp-only variant carrying one regular clone (appIndex 1) and set the
 *              MIGRATE_UID_TO_ATM ota flag so the clone dir pass is not skipped
 *           2. Run the full unlock rebuild entry (UpdateAppDataDirSelinuxLabel)
 *           3. The dedicated other-mode clone pass must query the clone's data base dir —
 *              the current-mode clone pass only walks bundleInfos_ records, so only the
 *              other-mode routing can query a temp-only name's clone dir
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, UpdateTempModeAppDataDirsDualMode_0300, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    // Turn on the dual-mode device state: the dedicated other-mode clone pass is reached
    // through UpdateAppDataDirSelinuxLabel's IsDualModeDevice() gate (see 0100).
    OHOS::system::SetParameter(TEST_DUAL_MODE_PARAM, "true");
    ScopeGuard dualModeGuard([&] {
        OHOS::system::SetParameter(TEST_DUAL_MODE_PARAM, "false");
    });
    OHOS::system::SetParameter(TEST_ISPCMODE_PARAM,
        std::to_string(ServiceConstants::DUAL_MODE_VALUE_TABLET));
    OHOS::system::SetParameter(TEST_MAINMODE_PARAM,
        std::to_string(ServiceConstants::DUAL_MODE_VALUE_TABLET));
    ASSERT_TRUE(DualModeHelper::IsDualModeDevice())
        << "dual-mode injection params must drive IsDualModeDevice to true";
    // The unlock entry returns early when no current-mode record is collected, so keep one.
    AddInnerBundleInfo(TEST_BUNDLE_NAME);
    InnerBundleInfo tempInfo = MakeVariantInfo(TEST_TEMP_BUNDLE_NAME, TEST_USER_ID, false);
    AddRegularClone(tempInfo, TEST_USER_ID, TEST_USER_ID + 1);
    dataMgr->tempBundleInfos_[TEST_TEMP_BUNDLE_NAME] = tempInfo;
    DelayedSingleton<BundleMgrService>::GetInstance()->InitBmsParam();
    auto bmsParam = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    ASSERT_NE(bmsParam, nullptr);
    bmsParam->SaveBmsParam("otaFlag", std::to_string(static_cast<int32_t>(OTAFlag::MIGRATE_UID_TO_ATM)));

    ResetIsExistDirPathsForTest();
    UpdateAppDataMgr::UpdateAppDataDirSelinuxLabel(TEST_USER_ID);

    EXPECT_TRUE(QueriedDirPath(GetIsExistDirPathsForTest(),
        "/data/app/el2/100/base/+clone-1+" + TEST_TEMP_BUNDLE_NAME)) <<
        "the other-mode clone pass must query the temp variant's clone data base dir";

    bmsParam->DeleteBmsParam("otaFlag");
    dataMgr->tempBundleInfos_.clear();
}

/**
 * @tc.number: UpdateTempModeAppDataDirsDualMode_0400
 * @tc.name: test a stale taskNum cancels every pass of the other-mode rebuild
 * @tc.desc: 1. Seed both mode sides and run the full unlock rebuild entry once so the live
 *              task number has moved past 0 regardless of test execution order
 *           2. Drive UpdateTempModeAppDataDirs directly with a stale taskNum (0)
 *           3. Every pass must be cancelled before any dir query: no new IsExistDir and
 *              neither map's records are consumed
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, UpdateTempModeAppDataDirsDualMode_0400, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    AddInnerBundleInfo(TEST_BUNDLE_NAME);
    dataMgr->tempBundleInfos_[TEST_TEMP_BUNDLE_NAME] = MakeVariantInfo(TEST_TEMP_BUNDLE_NAME, TEST_USER_ID, true);
    UpdateAppDataMgr::UpdateAppDataDirSelinuxLabel(TEST_USER_ID);

    ResetIsExistDirPathsForTest();
    UpdateAppDataMgr::UpdateTempModeAppDataDirs(TEST_USER_ID, 0);

    EXPECT_TRUE(GetIsExistDirPathsForTest().empty()) <<
        "a stale taskNum must cancel every pass of the other-mode rebuild";
    EXPECT_EQ(dataMgr->tempBundleInfos_.count(TEST_TEMP_BUNDLE_NAME), static_cast<size_t>(1)) <<
        "the cancelled rebuild must not consume the other-mode record";
    EXPECT_EQ(dataMgr->bundleInfos_.count(TEST_BUNDLE_NAME), static_cast<size_t>(1)) <<
        "the cancelled rebuild must not consume the current-mode record";
}

/**
 * @tc.number: UpdateTempModeAppDataDirsDualMode_0500
 * @tc.name: test the other-mode rebuild entry with a null DataMgr
 * @tc.desc: 1. Null the service's DataMgr member (restored before the case ends)
 *           2. Drive UpdateTempModeAppDataDirs
 *           3. The nullptr guard must return early without any dir query or crash
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, UpdateTempModeAppDataDirsDualMode_0500, Function | SmallTest | Level1)
{
    auto bms = DelayedSingleton<BundleMgrService>::GetInstance();
    auto savedDataMgr = bms->dataMgr_;
    bms->dataMgr_ = nullptr;
    // Restore DataMgr even if the case body is later extended with failing assertions.
    ScopeGuard restoreDataMgrGuard([&bms, &savedDataMgr]() { bms->dataMgr_ = savedDataMgr; });
    ResetIsExistDirPathsForTest();
    UpdateAppDataMgr::UpdateTempModeAppDataDirs(TEST_USER_ID, 0);
    EXPECT_TRUE(GetIsExistDirPathsForTest().empty()) <<
        "the nullptr guard must return before any dir query";
}

// Mock installd_client helpers for the SetEncryptionPolicy call history.
void ResetSetEncryptionPolicyState();
int32_t GetSetEncryptionPolicyCallCount();
std::string GetLastSetEncryptionPolicyBundleName();
std::string GetFirstSetEncryptionPolicyBundleName();

/**
 * @tc.number: CreateEl5DirDualMode_0100
 * @tc.name: test CreateEl5Dir routes the record fetch and policy to the temp map
 * @tc.desc: 1. Seed a non-clone other-mode variant carrying one regular clone (appIndex 1)
 *              in tempBundleInfos_ only
 *           2. Drive CreateEl5Dir with toTempBundle=true
 *           3. The variant's own record must be resolved: the clone extra is expanded and
 *              the encryption policy is attempted for the variant and its clone
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, CreateEl5DirDualMode_0100, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo tempInfo = MakeVariantInfo(TEST_BUNDLE_NAME, TEST_USER_ID, false);
    AddRegularClone(tempInfo, TEST_USER_ID, TEST_USER_ID + 1);
    dataMgr->tempBundleInfos_[TEST_BUNDLE_NAME] = tempInfo;

    CreateDirParam createDirParam;
    createDirParam.bundleName = TEST_BUNDLE_NAME;
    createDirParam.userId = TEST_USER_ID;
    ResetSetEncryptionPolicyState();
    (void)UpdateAppDataMgr::CreateEl5Dir(createDirParam, true);

    EXPECT_EQ(GetSetEncryptionPolicyCallCount(), 2) <<
        "the temp record's own policy and its clone extra must both be attempted";
    EXPECT_EQ(GetLastSetEncryptionPolicyBundleName(), "+clone-1+" + TEST_BUNDLE_NAME) <<
        "the clone extra must carry the clone dir name";

    dataMgr->tempBundleInfos_.clear();
}

/**
 * @tc.number: CreateEl5DirDualMode_0200
 * @tc.name: test CreateEl5Dir resolves the dual-mode clone variant's record by the original name
 * @tc.desc: 1. Seed the dual-mode clone variant (appIndex 10000) carrying one regular clone
 *              (appIndex 1) and one CLI sandbox (appIndex 2000) in tempBundleInfos_ only
 *           2. Drive CreateEl5Dir with the prefixed (effective) name and toTempBundle=true
 *           3. The record must be resolved by the original name (both maps are keyed by the
 *              original bundle name, not the prefixed one): the clone and sandbox extras are
 *              both expanded, keeping the install-time dir layout (+clone-N+original name)
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, CreateEl5DirDualMode_0200, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleInfo tempInfo = MakeVariantInfo(TEST_BUNDLE_NAME, TEST_USER_ID, true);
    AddRegularClone(tempInfo, TEST_USER_ID, TEST_USER_ID + 1);
    AddCliSandbox(tempInfo, TEST_USER_ID, TEST_USER_ID + 2);
    dataMgr->tempBundleInfos_[TEST_BUNDLE_NAME] = tempInfo;

    CreateDirParam createDirParam;
    createDirParam.bundleName = "+clone-10000+" + TEST_BUNDLE_NAME;
    createDirParam.userId = TEST_USER_ID;
    ResetSetEncryptionPolicyState();
    (void)UpdateAppDataMgr::CreateEl5Dir(createDirParam, true);

    EXPECT_EQ(GetSetEncryptionPolicyCallCount(), 3) <<
        "the prefixed name must resolve the temp record and expand both extras";
    EXPECT_EQ(GetFirstSetEncryptionPolicyBundleName(), "+clone-10000+" + TEST_BUNDLE_NAME) <<
        "the main variant's own policy must use the prefixed (effective) name";
    EXPECT_EQ(GetLastSetEncryptionPolicyBundleName(),
        "+clone-" + std::to_string(Constants::CLI_SANDBOX_APP_INDEX_MIN) + "+" + TEST_BUNDLE_NAME) <<
        "the sandbox extra (appended last) must keep the install-time dir layout";

    dataMgr->tempBundleInfos_.clear();
}

/**
 * @tc.number: CreateEl5DirDualMode_0300
 * @tc.name: test CreateEl5Dir with toTempBundle=true only reads the temp map
 * @tc.desc: 1. Seed the variant record in bundleInfos_ only (current-mode side)
 *           2. Drive CreateEl5Dir with toTempBundle=true while tempBundleInfos_ stays empty
 *           3. No record is resolved on the temp side: no clone extra and no encryption
 *              policy attempt (the current-mode record must not be consumed)
 */
HWTEST_F(BmsBundleDataMgrDualModeTest, CreateEl5DirDualMode_0300, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    ASSERT_NE(dataMgr, nullptr);
    dataMgr->bundleInfos_[TEST_BUNDLE_NAME] = MakeVariantInfo(TEST_BUNDLE_NAME, TEST_USER_ID, false);

    CreateDirParam createDirParam;
    createDirParam.bundleName = TEST_BUNDLE_NAME;
    createDirParam.userId = TEST_USER_ID;
    ResetSetEncryptionPolicyState();
    (void)UpdateAppDataMgr::CreateEl5Dir(createDirParam, true);

    EXPECT_EQ(GetSetEncryptionPolicyCallCount(), 0) <<
        "toTempBundle=true must not resolve the current-mode record";

    dataMgr->bundleInfos_.erase(TEST_BUNDLE_NAME);
}
}
}
