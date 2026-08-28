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
#include "bundle_mgr_service.h"
#include "inner_bundle_info.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {

namespace {
const std::string TEST_BUNDLE_NAME = "com.example.dualmodetest";
const std::string TEST_MODULE_NAME = "entry";
constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t INVALID_USER_ID = -1;
constexpr uint32_t TEST_APP_INDEX = 10000;
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
    // Clean up after test
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
}
}
