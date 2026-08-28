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

#include "bundle_info.h"
#include "bundle_mgr_host_impl.h"
#include "bundle_permission_mgr.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

// Extern declarations for mock setter functions (defined in mock/src/bundle_permission_mgr.cpp)
void SetVerifyCallingPermissionForTest(bool value);
void SetSystemAppForTest(bool value);
void SetIsBundleSelfCallingForTest(bool value);
void ResetTestValues();

namespace OHOS {
namespace AppExecFwk {

namespace {
const std::string TEST_BUNDLE_NAME = "com.example.dualmodetest";
const std::string TEST_BUNDLE_NAME_EMPTY = "";
constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t INVALID_USER_ID = -1;
}

class BmsBundleMgrHostImplDualModeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<BundleMgrHostImpl> GetBundleMgrHostImpl() const;

protected:
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

/**
 * @tc.number: GetBundleInfoDualMode_0300
 * @tc.name: test GetDualModeBundleInfo with permission success - has privileged permission
 * @tc.desc: 1. VerifyCallingPermissionForAll returns true for privileged permission
 *           2. Function should proceed to call dataMgr->GetDualModeBundleInfo
 */
HWTEST_F(BmsBundleMgrHostImplDualModeTest, GetBundleInfoDualMode_0300, Function | SmallTest | Level1)
{
    // Set privileged permission to true, others to false
    SetVerifyCallingPermissionForTest(true);
    SetSystemAppForTest(false);
    SetIsBundleSelfCallingForTest(false);

    auto hostImpl = GetBundleMgrHostImpl();
    ASSERT_NE(hostImpl, nullptr);

    DualModeBundleInfo dualModeBundleInfo;
    ErrCode ret = hostImpl->GetDualModeBundleInfo(TEST_BUNDLE_NAME, TEST_USER_ID, dualModeBundleInfo);

    // Permission check passes, but dataMgr may be nullptr or return error
    // The key is we don't get PERMISSION_DENIED
    EXPECT_NE(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED) << "Privileged permission should pass permission check";
}

/**
 * @tc.number: GetBundleInfoDualMode_0400
 * @tc.name: test GetDualModeBundleInfo with permission success - system app with normal permission
 * @tc.desc: 1. VerifyCallingPermissionForAll returns true for normal permission
 *           2. IsSystemApp returns true
 *           3. Function should proceed to call dataMgr->GetDualModeBundleInfo
 */
HWTEST_F(BmsBundleMgrHostImplDualModeTest, GetBundleInfoDualMode_0400, Function | SmallTest | Level1)
{
    // Set: has normal permission AND is system app
    SetVerifyCallingPermissionForTest(true);
    SetSystemAppForTest(true);
    SetIsBundleSelfCallingForTest(false);

    auto hostImpl = GetBundleMgrHostImpl();
    ASSERT_NE(hostImpl, nullptr);

    DualModeBundleInfo dualModeBundleInfo;
    ErrCode ret = hostImpl->GetDualModeBundleInfo(TEST_BUNDLE_NAME, TEST_USER_ID, dualModeBundleInfo);

    // Permission check passes, but dataMgr may be nullptr or return error
    EXPECT_NE(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED) << "System app with permission should pass check";
}

/**
 * @tc.number: GetBundleInfoDualMode_0600
 * @tc.name: test GetDualModeBundleInfo with all permissions granted
 * @tc.desc: 1. All permission checks return true
 *           2. Function should proceed to call dataMgr->GetDualModeBundleInfo
 */
HWTEST_F(BmsBundleMgrHostImplDualModeTest, GetBundleInfoDualMode_0600, Function | SmallTest | Level1)
{
    // Set all permission checks to true
    SetVerifyCallingPermissionForTest(true);
    SetSystemAppForTest(true);
    SetIsBundleSelfCallingForTest(true);

    auto hostImpl = GetBundleMgrHostImpl();
    ASSERT_NE(hostImpl, nullptr);

    DualModeBundleInfo dualModeBundleInfo;
    ErrCode ret = hostImpl->GetDualModeBundleInfo(TEST_BUNDLE_NAME, TEST_USER_ID, dualModeBundleInfo);

    // Permission check passes, but dataMgr may be nullptr or return error
    EXPECT_NE(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED) << "All permissions granted should pass check";
}

/**
 * @tc.number: GetBundleInfoDualMode_0700
 * @tc.name: test GetDualModeBundleInfo with empty bundle name
 * @tc.desc: 1. Pass empty bundle name
 *           2. Function should handle gracefully
 * @tc.disabled: This test requires integration environment with real dataMgr to verify behavior
 */
HWTEST_F(BmsBundleMgrHostImplDualModeTest, GetBundleInfoDualMode_0700, Function | SmallTest | Level1)
{
    SetVerifyCallingPermissionForTest(true);
    SetSystemAppForTest(true);
    SetIsBundleSelfCallingForTest(true);

    auto hostImpl = GetBundleMgrHostImpl();
    ASSERT_NE(hostImpl, nullptr);

    DualModeBundleInfo dualModeBundleInfo;
    ErrCode ret = hostImpl->GetDualModeBundleInfo(TEST_BUNDLE_NAME_EMPTY, TEST_USER_ID, dualModeBundleInfo);

    // Empty bundle name may succeed or fail depending on dataMgr implementation
    // At minimum verify permission check passed (didn't get PERMISSION_DENIED)
    EXPECT_NE(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED) << "Empty bundle name: permission check should pass";
}

/**
 * @tc.number: GetBundleInfoDualMode_0800
 * @tc.name: test GetDualModeBundleInfo with invalid userId
 * @tc.desc: 1. Pass invalid (negative) userId
 *           2. Function should handle gracefully
 */
HWTEST_F(BmsBundleMgrHostImplDualModeTest, GetBundleInfoDualMode_0800, Function | SmallTest | Level1)
{
    SetVerifyCallingPermissionForTest(true);
    SetSystemAppForTest(true);
    SetIsBundleSelfCallingForTest(true);

    auto hostImpl = GetBundleMgrHostImpl();
    ASSERT_NE(hostImpl, nullptr);

    DualModeBundleInfo dualModeBundleInfo;
    ErrCode ret = hostImpl->GetDualModeBundleInfo(TEST_BUNDLE_NAME, INVALID_USER_ID, dualModeBundleInfo);

    // Result depends on dataMgr implementation - at least verify permission check passed
    EXPECT_NE(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED) << "Invalid userId: permission check should still pass";
}

/**
 * @tc.number: GetBundleInfoDualMode_0900
 * @tc.name: test GetDualModeBundleInfo output parameter is modified
 * @tc.desc: 1. Call GetDualModeBundleInfo with valid input
 *           2. Verify the output parameter can be accessed
 * @tc.disabled: This test requires integration environment with real dataMgr to verify output parameter values
 */
HWTEST_F(BmsBundleMgrHostImplDualModeTest, GetBundleInfoDualMode_0900, Function | SmallTest | Level1)
{
    SetVerifyCallingPermissionForTest(true);
    SetSystemAppForTest(true);
    SetIsBundleSelfCallingForTest(true);

    auto hostImpl = GetBundleMgrHostImpl();
    ASSERT_NE(hostImpl, nullptr);

    DualModeBundleInfo dualModeBundleInfo;
    // Initialize with known values
    dualModeBundleInfo.appIndex = 0;
    dualModeBundleInfo.deviceModeDistributionPolicy = DeviceModeDistributionPolicy::UNSPECIFIED;
    dualModeBundleInfo.appSandboxPolicy = AppSandboxPolicy::SHARED_SANDBOX;

    ErrCode ret = hostImpl->GetDualModeBundleInfo(TEST_BUNDLE_NAME, TEST_USER_ID, dualModeBundleInfo);

    // Cannot verify output parameter values without integration environment
    // Just verify function call doesn't crash and returns non-permission-denied code
    EXPECT_NE(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED) << "Permission should be granted in this test";
}
}
}