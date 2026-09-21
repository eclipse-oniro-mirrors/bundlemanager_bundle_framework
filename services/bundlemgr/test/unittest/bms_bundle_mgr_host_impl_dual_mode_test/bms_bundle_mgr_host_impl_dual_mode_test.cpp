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

#include "bundle_constants.h"
#include "bundle_info.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_host_impl.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "inner_bundle_info.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

// Extern declarations for mock setter functions (defined in mock/src/bundle_permission_mgr.cpp)
void SetVerifyCallingPermissionForTest(bool value);
void SetSystemAppForTest(bool value);
void SetIsBundleSelfCallingForTest(bool value);
void SetNativeTokenTypeForTest(bool value);
void SetPermissionResultForTest(const std::string &permissionName, bool granted);
void ResetTestValues();

namespace OHOS {
namespace AppExecFwk {

namespace {
const std::string TEST_BUNDLE_NAME = "com.example.dualmodetest";
const std::string TEST_BUNDLE_NAME_EMPTY = "";
const std::string TEST_OTHER_BUNDLE_NAME = "com.example.other";
constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t INVALID_USER_ID = -1;
constexpr int32_t TEST_APP_INDEX = 10000;
}

class BmsBundleMgrHostImplDualModeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<BundleMgrHostImpl> GetBundleMgrHostImpl() const;

protected:
    // Inject a nullptr dataMgr into the service so the host impl hits the
    // dataMgr == nullptr branch.
    void ClearServiceDataMgr() const;
    // Inject a fresh dataMgr that knows TEST_USER_ID but has an empty bundleInfos_,
    // used to exercise the bundleInfos_.empty() branch of BundleDataMgr.
    void PrepareEmptyDataMgr() const;
    // Inject a fresh dataMgr that knows TEST_USER_ID and carries one bundle
    // populated with the given appIndex and dual-mode policy/sandbox defaults.
    void PrepareDataMgrWithBundle(const std::string &bundleName, int32_t appIndex) const;

    std::shared_ptr<BundleMgrHostImpl> bundleMgrHostImpl_;
};

void BmsBundleMgrHostImplDualModeTest::SetUpTestCase()
{
    // Reset test values before all tests
    ResetTestValues();
}

void BmsBundleMgrHostImplDualModeTest::TearDownTestCase()
{
    // Reset test values after all tests
    ResetTestValues();
}

void BmsBundleMgrHostImplDualModeTest::SetUp()
{
    bundleMgrHostImpl_ = std::make_shared<BundleMgrHostImpl>();
    // Reset mock values before each test
    ResetTestValues();
    // Set default values for successful path
    SetVerifyCallingPermissionForTest(true);
    SetSystemAppForTest(true);
    SetIsBundleSelfCallingForTest(true);
}

void BmsBundleMgrHostImplDualModeTest::TearDown()
{
    bundleMgrHostImpl_.reset();
    // Reset mock values after each test
    ResetTestValues();
}

std::shared_ptr<BundleMgrHostImpl> BmsBundleMgrHostImplDualModeTest::GetBundleMgrHostImpl() const
{
    return bundleMgrHostImpl_;
}

void BmsBundleMgrHostImplDualModeTest::ClearServiceDataMgr() const
{
    auto service = DelayedSingleton<BundleMgrService>::GetInstance();
    if (service != nullptr) {
        service->dataMgr_ = nullptr;
    }
}

void BmsBundleMgrHostImplDualModeTest::PrepareEmptyDataMgr() const
{
    auto service = DelayedSingleton<BundleMgrService>::GetInstance();
    ASSERT_NE(service, nullptr);
    auto dataMgr = std::make_shared<BundleDataMgr>();
    dataMgr->multiUserIdsSet_.insert(TEST_USER_ID);
    service->dataMgr_ = dataMgr;
}

void BmsBundleMgrHostImplDualModeTest::PrepareDataMgrWithBundle(
    const std::string &bundleName, int32_t appIndex) const
{
    auto service = DelayedSingleton<BundleMgrService>::GetInstance();
    ASSERT_NE(service, nullptr);
    auto dataMgr = std::make_shared<BundleDataMgr>();
    dataMgr->multiUserIdsSet_.insert(TEST_USER_ID);

    InnerBundleInfo info;
    info.SetAppIndex(appIndex);
    ApplicationInfo appInfo;
    appInfo.bundleName = bundleName;
    appInfo.appIndex = appIndex;
    info.SetBaseApplicationInfo(appInfo);
    BundleInfo bundleInfo;
    bundleInfo.name = bundleName;
    bundleInfo.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNSPECIFIED;
    bundleInfo.appSandboxPolicy = AppSandboxPolicy::SHARED_SANDBOX;
    info.SetBaseBundleInfo(bundleInfo);

    InnerBundleUserInfo userInfo;
    userInfo.bundleName = bundleName;
    userInfo.bundleUserInfo.userId = TEST_USER_ID;
    userInfo.bundleUserInfo.enabled = true;
    info.innerBundleUserInfos_.try_emplace(
        bundleName + Constants::FILE_UNDERLINE + std::to_string(TEST_USER_ID), userInfo);

    dataMgr->bundleInfos_[bundleName] = info;
    service->dataMgr_ = dataMgr;
}

/**
 * @tc.number: GetBundleInfoDualMode_0100
 * @tc.name: test GetDualModeBundleInfo denied for non-system app
 * @tc.desc: 1. IsSystemApp returns false
 *           2. Function should return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED before reaching dataMgr
 */
HWTEST_F(BmsBundleMgrHostImplDualModeTest, GetBundleInfoDualMode_0100, Function | SmallTest | Level1)
{
    SetSystemAppForTest(false);
    SetVerifyCallingPermissionForTest(true);
    SetIsBundleSelfCallingForTest(true);

    auto hostImpl = GetBundleMgrHostImpl();
    ASSERT_NE(hostImpl, nullptr);

    DualModeBundleInfo dualModeBundleInfo;
    ErrCode ret = hostImpl->GetDualModeBundleInfo(TEST_BUNDLE_NAME, TEST_USER_ID, dualModeBundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: GetBundleInfoDualMode_0200
 * @tc.name: test GetDualModeBundleInfo denied without privileged permission
 * @tc.desc: 1. IsSystemApp returns true but VerifyCallingPermissionForAll returns false
 *           2. Function should return ERR_BUNDLE_MANAGER_PERMISSION_DENIED
 */
HWTEST_F(BmsBundleMgrHostImplDualModeTest, GetBundleInfoDualMode_0200, Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(false);
    SetIsBundleSelfCallingForTest(true);

    auto hostImpl = GetBundleMgrHostImpl();
    ASSERT_NE(hostImpl, nullptr);

    DualModeBundleInfo dualModeBundleInfo;
    ErrCode ret = hostImpl->GetDualModeBundleInfo(TEST_BUNDLE_NAME, TEST_USER_ID, dualModeBundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: GetBundleInfoDualMode_0300
 * @tc.name: test GetDualModeBundleInfo denied when across-local-account permission is missing
 * @tc.desc: 1. IsSystemApp and privileged permission both pass
 *           2. Non-native token, requesting a different userId, and
 *              INTERACT_ACROSS_LOCAL_ACCOUNTS not granted
 *           3. CheckAcrossUserPermission returns false, function should return
 *              ERR_BUNDLE_MANAGER_PERMISSION_DENIED
 */
HWTEST_F(BmsBundleMgrHostImplDualModeTest, GetBundleInfoDualMode_0300, Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetIsBundleSelfCallingForTest(true);
    // Make the privileged permission still granted while denying the
    // across-local-account one: the privileged check falls back to
    // g_verifyPermission (true), the across-account check looks up the map.
    SetNativeTokenTypeForTest(false);
    SetPermissionResultForTest(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS, false);

    auto hostImpl = GetBundleMgrHostImpl();
    ASSERT_NE(hostImpl, nullptr);

    DualModeBundleInfo dualModeBundleInfo;
    ErrCode ret = hostImpl->GetDualModeBundleInfo(TEST_BUNDLE_NAME, TEST_USER_ID, dualModeBundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: GetBundleInfoDualMode_0400
 * @tc.name: test GetDualModeBundleInfo when dataMgr is nullptr
 * @tc.desc: 1. All permission checks pass
 *           2. BundleMgrService dataMgr is nullptr
 *           3. Function should return ERR_BUNDLE_MANAGER_INTERNAL_ERROR
 */
HWTEST_F(BmsBundleMgrHostImplDualModeTest, GetBundleInfoDualMode_0400, Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetIsBundleSelfCallingForTest(true);
    ClearServiceDataMgr();

    auto hostImpl = GetBundleMgrHostImpl();
    ASSERT_NE(hostImpl, nullptr);

    DualModeBundleInfo dualModeBundleInfo;
    ErrCode ret = hostImpl->GetDualModeBundleInfo(TEST_BUNDLE_NAME, TEST_USER_ID, dualModeBundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: GetBundleInfoDualMode_0500
 * @tc.name: test GetDualModeBundleInfo with empty bundle name
 * @tc.desc: 1. All permission checks pass and dataMgr is ready with a valid bundle
 *           2. Pass an empty bundle name
 *           3. dataMgr rejects empty name first, function should return
 *              ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST
 */
HWTEST_F(BmsBundleMgrHostImplDualModeTest, GetBundleInfoDualMode_0500, Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetIsBundleSelfCallingForTest(true);
    PrepareDataMgrWithBundle(TEST_BUNDLE_NAME, TEST_APP_INDEX);

    auto hostImpl = GetBundleMgrHostImpl();
    ASSERT_NE(hostImpl, nullptr);

    DualModeBundleInfo dualModeBundleInfo;
    ErrCode ret = hostImpl->GetDualModeBundleInfo(TEST_BUNDLE_NAME_EMPTY, TEST_USER_ID, dualModeBundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetBundleInfoDualMode_0600
 * @tc.name: test GetDualModeBundleInfo with invalid userId
 * @tc.desc: 1. All permission checks pass and dataMgr is ready with the bundle
 *           2. Pass INVALID_USER_ID; dataMgr resolves it to Constants::INVALID_USERID
 *           3. Function should return ERR_BUNDLE_MANAGER_INVALID_USER_ID
 */
HWTEST_F(BmsBundleMgrHostImplDualModeTest, GetBundleInfoDualMode_0600, Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetIsBundleSelfCallingForTest(true);
    PrepareDataMgrWithBundle(TEST_BUNDLE_NAME, TEST_APP_INDEX);

    auto hostImpl = GetBundleMgrHostImpl();
    ASSERT_NE(hostImpl, nullptr);

    DualModeBundleInfo dualModeBundleInfo;
    ErrCode ret = hostImpl->GetDualModeBundleInfo(TEST_BUNDLE_NAME, INVALID_USER_ID, dualModeBundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INVALID_USER_ID);
}

/**
 * @tc.number: GetBundleInfoDualMode_0700
 * @tc.name: test GetDualModeBundleInfo when bundleInfos_ is empty
 * @tc.desc: 1. All permission checks pass and dataMgr has the userId registered
 *           2. bundleInfos_ is empty so the bundle cannot be located
 *           3. Function should return ERR_BUNDLE_MANAGER_INTERNAL_ERROR
 */
HWTEST_F(BmsBundleMgrHostImplDualModeTest, GetBundleInfoDualMode_0700, Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetIsBundleSelfCallingForTest(true);
    PrepareEmptyDataMgr();

    auto hostImpl = GetBundleMgrHostImpl();
    ASSERT_NE(hostImpl, nullptr);

    DualModeBundleInfo dualModeBundleInfo;
    ErrCode ret = hostImpl->GetDualModeBundleInfo(TEST_BUNDLE_NAME, TEST_USER_ID, dualModeBundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: GetBundleInfoDualMode_0800
 * @tc.name: test GetDualModeBundleInfo when bundle is not installed
 * @tc.desc: 1. All permission checks pass and dataMgr has a different bundle only
 *           2. Requested bundle is not present in bundleInfos_
 *           3. Function should return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST
 */
HWTEST_F(BmsBundleMgrHostImplDualModeTest, GetBundleInfoDualMode_0800, Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetIsBundleSelfCallingForTest(true);
    PrepareDataMgrWithBundle(TEST_OTHER_BUNDLE_NAME, TEST_APP_INDEX);

    auto hostImpl = GetBundleMgrHostImpl();
    ASSERT_NE(hostImpl, nullptr);

    DualModeBundleInfo dualModeBundleInfo;
    ErrCode ret = hostImpl->GetDualModeBundleInfo(TEST_BUNDLE_NAME, TEST_USER_ID, dualModeBundleInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number: GetBundleInfoDualMode_0900
 * @tc.name: test GetDualModeBundleInfo success and output is filled
 * @tc.desc: 1. All permission checks pass and dataMgr has the requested bundle
 *           2. Call GetDualModeBundleInfo with valid parameters
 *           3. Function should return ERR_OK and fill dualModeBundleInfo with
 *              appIndex, deviceModeDistributionPolicy and appSandboxPolicy
 */
HWTEST_F(BmsBundleMgrHostImplDualModeTest, GetBundleInfoDualMode_0900, Function | SmallTest | Level1)
{
    SetSystemAppForTest(true);
    SetVerifyCallingPermissionForTest(true);
    SetIsBundleSelfCallingForTest(true);
    PrepareDataMgrWithBundle(TEST_BUNDLE_NAME, TEST_APP_INDEX);

    auto hostImpl = GetBundleMgrHostImpl();
    ASSERT_NE(hostImpl, nullptr);

    DualModeBundleInfo dualModeBundleInfo;
    dualModeBundleInfo.appIndex = 0;
    dualModeBundleInfo.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNSPECIFIED;
    dualModeBundleInfo.appSandboxPolicy = AppSandboxPolicy::SHARED_SANDBOX;

    ErrCode ret = hostImpl->GetDualModeBundleInfo(TEST_BUNDLE_NAME, TEST_USER_ID, dualModeBundleInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(dualModeBundleInfo.appIndex, TEST_APP_INDEX);
    EXPECT_EQ(dualModeBundleInfo.deviceModeDistributionPolicy, DeviceModeDistributionPolicy::UNSPECIFIED);
    EXPECT_EQ(dualModeBundleInfo.appSandboxPolicy, AppSandboxPolicy::SHARED_SANDBOX);
}

/**
 * @tc.number: GetAllBundleInfoInstances_0100
 * @tc.name: test GetAllBundleInfoInstances denied for non-system app
 * @tc.desc: 1. IsSystemApp returns false
 *           2. Function should return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED
 */
HWTEST_F(BmsBundleMgrHostImplDualModeTest, GetAllBundleInfoInstances_0100, Function | SmallTest | Level1)
{
    SetVerifyCallingPermissionForTest(true);
    SetSystemAppForTest(false);
    SetIsBundleSelfCallingForTest(true);

    auto hostImpl = GetBundleMgrHostImpl();
    ASSERT_NE(hostImpl, nullptr);

    std::vector<BundleInfo> bundleInfos;
    ErrCode ret = hostImpl->GetAllBundleInfoInstances(TEST_BUNDLE_NAME,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_OF_ALL_DEVICE_MODE), bundleInfos,
        TEST_USER_ID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED);
}

/**
 * @tc.number: GetAllBundleInfoInstances_0200
 * @tc.name: test GetAllBundleInfoInstances denied without privileged permission
 * @tc.desc: 1. IsSystemApp returns true, VerifyCallingPermissionForAll returns false
 *           2. Function should return ERR_BUNDLE_MANAGER_PERMISSION_DENIED
 */
HWTEST_F(BmsBundleMgrHostImplDualModeTest, GetAllBundleInfoInstances_0200, Function | SmallTest | Level1)
{
    SetVerifyCallingPermissionForTest(false);
    SetSystemAppForTest(true);
    SetIsBundleSelfCallingForTest(true);

    auto hostImpl = GetBundleMgrHostImpl();
    ASSERT_NE(hostImpl, nullptr);

    std::vector<BundleInfo> bundleInfos;
    ErrCode ret = hostImpl->GetAllBundleInfoInstances(TEST_BUNDLE_NAME,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_OF_ALL_DEVICE_MODE), bundleInfos,
        TEST_USER_ID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: GetAllBundleInfoInstances_0300
 * @tc.name: test GetAllBundleInfoInstances success with permission granted
 * @tc.desc: 1. All permission checks pass and a dataMgr with the bundle is installed
 *           2. Returns ERR_OK with the current-mode instance (no dual-mode
 *              parameter mock here, so the flag only returns the current one)
 */
HWTEST_F(BmsBundleMgrHostImplDualModeTest, GetAllBundleInfoInstances_0300, Function | SmallTest | Level1)
{
    SetVerifyCallingPermissionForTest(true);
    SetSystemAppForTest(true);
    SetIsBundleSelfCallingForTest(true);

    auto service = DelayedSingleton<BundleMgrService>::GetInstance();
    auto dataMgr = std::make_shared<BundleDataMgr>();
    dataMgr->multiUserIdsSet_.insert(TEST_USER_ID);
    InnerBundleInfo info;
    info.SetDualModeCloneApp(false);
    info.baseApplicationInfo_->bundleName = TEST_BUNDLE_NAME;
    info.baseBundleInfo_->name = TEST_BUNDLE_NAME;
    InnerBundleUserInfo userInfo;
    userInfo.bundleName = TEST_BUNDLE_NAME;
    userInfo.bundleUserInfo.userId = TEST_USER_ID;
    userInfo.bundleUserInfo.enabled = true;
    info.innerBundleUserInfos_.try_emplace(TEST_BUNDLE_NAME + "_" + std::to_string(TEST_USER_ID), userInfo);
    dataMgr->bundleInfos_[TEST_BUNDLE_NAME] = info;
    service->dataMgr_ = dataMgr;

    auto hostImpl = GetBundleMgrHostImpl();
    ASSERT_NE(hostImpl, nullptr);

    std::vector<BundleInfo> bundleInfos;
    ErrCode ret = hostImpl->GetAllBundleInfoInstances(TEST_BUNDLE_NAME,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_OF_ALL_DEVICE_MODE), bundleInfos,
        TEST_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(bundleInfos.size(), static_cast<size_t>(1));
    EXPECT_EQ(bundleInfos[0].name, TEST_BUNDLE_NAME);
}

/**
 * @tc.number: GetAllBundleInfoInstances_0400
 * @tc.name: test GetAllBundleInfoInstances with a bundle not found
 * @tc.desc: 1. All permission checks pass and a dataMgr without the bundle is installed
 *           2. Function should return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST
 */
HWTEST_F(BmsBundleMgrHostImplDualModeTest, GetAllBundleInfoInstances_0400, Function | SmallTest | Level1)
{
    SetVerifyCallingPermissionForTest(true);
    SetSystemAppForTest(true);
    SetIsBundleSelfCallingForTest(true);

    auto service = DelayedSingleton<BundleMgrService>::GetInstance();
    auto dataMgr = std::make_shared<BundleDataMgr>();
    dataMgr->multiUserIdsSet_.insert(TEST_USER_ID);
    service->dataMgr_ = dataMgr;

    auto hostImpl = GetBundleMgrHostImpl();
    ASSERT_NE(hostImpl, nullptr);

    std::vector<BundleInfo> bundleInfos;
    ErrCode ret = hostImpl->GetAllBundleInfoInstances(TEST_BUNDLE_NAME,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_OF_ALL_DEVICE_MODE), bundleInfos,
        TEST_USER_ID);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
}
}
}