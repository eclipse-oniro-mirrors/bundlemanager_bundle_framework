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
#define protected public

#include <gtest/gtest.h>
#include <memory>
#include <vector>

#include "bms_update_selinux_mgr.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "bundle_option.h"
#include "idle_manager_rdb.h"
#include "mock_idle_manager_rdb.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const int32_t TEST_USER_ID = 100;
const int32_t TEST_USER_ID_2 = 101;
const int32_t TEST_APP_INDEX = 0;
const int32_t TEST_APP_INDEX_CLONE = 1;
const std::string TEST_BUNDLE_NAME = "com.example.test";
const std::string TEST_BUNDLE_NAME_2 = "com.example.test2";
const std::string TEST_STOP_REASON = "test_stop_reason";
const int32_t TEST_STOP_REASON_CODE = 1;
} // namespace

class BmsUpdateSelinuxMgrTest : public testing::Test {
public:
    BmsUpdateSelinuxMgrTest();
    ~BmsUpdateSelinuxMgrTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    void CreateFakeBundleOptionInfos(std::vector<BundleOptionInfo> &bundleOptionInfos);

private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
    std::shared_ptr<BmsUpdateSelinuxMgr> updateSelinuxMgr_;
};

std::shared_ptr<BundleMgrService> BmsUpdateSelinuxMgrTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsUpdateSelinuxMgrTest::BmsUpdateSelinuxMgrTest()
{}

BmsUpdateSelinuxMgrTest::~BmsUpdateSelinuxMgrTest()
{}

void BmsUpdateSelinuxMgrTest::SetUpTestCase()
{}

void BmsUpdateSelinuxMgrTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsUpdateSelinuxMgrTest::SetUp()
{
    // Reset test control state before each test
    SetGetAllBundleResultForTest(ERR_OK);
    SetAddBundlesResultForTest(ERR_OK);
    SetAddBundleResultForTest(ERR_OK);
    SetDeleteBundleResultForTest(ERR_OK);
    ClearBundlesForTest();

    updateSelinuxMgr_ = std::make_shared<BmsUpdateSelinuxMgr>();
}

void BmsUpdateSelinuxMgrTest::TearDown()
{
    updateSelinuxMgr_.reset();
}

void BmsUpdateSelinuxMgrTest::CreateFakeBundleOptionInfos(std::vector<BundleOptionInfo> &bundleOptionInfos)
{
    BundleOptionInfo bundleOptionInfo1;
    bundleOptionInfo1.bundleName = TEST_BUNDLE_NAME;
    bundleOptionInfo1.userId = TEST_USER_ID;
    bundleOptionInfo1.appIndex = TEST_APP_INDEX;
    bundleOptionInfos.push_back(bundleOptionInfo1);

    BundleOptionInfo bundleOptionInfo2;
    bundleOptionInfo2.bundleName = TEST_BUNDLE_NAME_2;
    bundleOptionInfo2.userId = TEST_USER_ID;
    bundleOptionInfo2.appIndex = TEST_APP_INDEX;
    bundleOptionInfos.push_back(bundleOptionInfo2);
}

/**
 * @tc.number: BmsUpdateSelinuxMgr_StopUpdateSelinuxLabel_001
 * @tc.name: test StopUpdateSelinuxLabel when already stopped
 * @tc.desc: 1.Test StopUpdateSelinuxLabel when needStop_ is already true
 */
HWTEST_F(BmsUpdateSelinuxMgrTest, BmsUpdateSelinuxMgr_StopUpdateSelinuxLabel_001, Function | SmallTest | Level1)
{
    updateSelinuxMgr_->needStop_.store(true);

    auto ret = updateSelinuxMgr_->StopUpdateSelinuxLabel(TEST_STOP_REASON_CODE, TEST_STOP_REASON);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsUpdateSelinuxMgr_AddBundles_001
 * @tc.name: test AddBundles with empty vector
 * @tc.desc: 1.Test AddBundles when bundleOptionInfos is empty
 */
HWTEST_F(BmsUpdateSelinuxMgrTest, BmsUpdateSelinuxMgr_AddBundles_001, Function | SmallTest | Level1)
{
    std::vector<BundleOptionInfo> emptyBundles;
    auto ret = updateSelinuxMgr_->AddBundles(emptyBundles);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: BmsUpdateSelinuxMgr_AddBundles_002
 * @tc.name: test AddBundles with success
 * @tc.desc: 1.Test AddBundles when rdb AddBundles succeeds
 */
HWTEST_F(BmsUpdateSelinuxMgrTest, BmsUpdateSelinuxMgr_AddBundles_002, Function | SmallTest | Level1)
{
    std::vector<BundleOptionInfo> bundleOptionInfos;
    CreateFakeBundleOptionInfos(bundleOptionInfos);

    SetAddBundlesResultForTest(ERR_OK);
    auto ret = updateSelinuxMgr_->AddBundles(bundleOptionInfos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsUpdateSelinuxMgr_AddBundles_003
 * @tc.name: test AddBundles with rdb failure
 * @tc.desc: 1.Test AddBundles when rdb AddBundles fails
 */
HWTEST_F(BmsUpdateSelinuxMgrTest, BmsUpdateSelinuxMgr_AddBundles_003, Function | SmallTest | Level1)
{
    std::vector<BundleOptionInfo> bundleOptionInfos;
    CreateFakeBundleOptionInfos(bundleOptionInfos);

    SetAddBundlesResultForTest(ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
    auto ret = updateSelinuxMgr_->AddBundles(bundleOptionInfos);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BmsUpdateSelinuxMgr_DeleteBundle_001
 * @tc.name: test DeleteBundle with empty bundleName
 * @tc.desc: 1.Test DeleteBundle when bundleName is empty
 */
HWTEST_F(BmsUpdateSelinuxMgrTest, BmsUpdateSelinuxMgr_DeleteBundle_001, Function | SmallTest | Level1)
{
    auto ret = updateSelinuxMgr_->DeleteBundle("", TEST_USER_ID, TEST_APP_INDEX);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: BmsUpdateSelinuxMgr_DeleteBundle_002
 * @tc.name: test DeleteBundle with success
 * @tc.desc: 1.Test DeleteBundle when rdb DeleteBundle succeeds
 */
HWTEST_F(BmsUpdateSelinuxMgrTest, BmsUpdateSelinuxMgr_DeleteBundle_002, Function | SmallTest | Level1)
{
    SetDeleteBundleResultForTest(ERR_OK);
    auto ret = updateSelinuxMgr_->DeleteBundle(TEST_BUNDLE_NAME, TEST_USER_ID, TEST_APP_INDEX);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsUpdateSelinuxMgr_DeleteBundle_003
 * @tc.name: test DeleteBundle with rdb failure
 * @tc.desc: 1.Test DeleteBundle when rdb DeleteBundle fails
 */
HWTEST_F(BmsUpdateSelinuxMgrTest, BmsUpdateSelinuxMgr_DeleteBundle_003, Function | SmallTest | Level1)
{
    SetDeleteBundleResultForTest(ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
    auto ret = updateSelinuxMgr_->DeleteBundle(TEST_BUNDLE_NAME, TEST_USER_ID, TEST_APP_INDEX);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BmsUpdateSelinuxMgr_DeleteBundleForUser_001
 * @tc.name: test DeleteBundleForUser with success
 * @tc.desc: 1.Test DeleteBundleForUser when rdb DeleteBundle succeeds
 */
HWTEST_F(BmsUpdateSelinuxMgrTest, BmsUpdateSelinuxMgr_DeleteBundleForUser_001, Function | SmallTest | Level1)
{
    SetDeleteBundleResultForTest(ERR_OK);
    auto ret = updateSelinuxMgr_->DeleteBundleForUser(TEST_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsUpdateSelinuxMgr_DeleteBundleForUser_002
 * @tc.name: test DeleteBundleForUser with rdb failure
 * @tc.desc: 1.Test DeleteBundleForUser when rdb DeleteBundle fails
 */
HWTEST_F(BmsUpdateSelinuxMgrTest, BmsUpdateSelinuxMgr_DeleteBundleForUser_002, Function | SmallTest | Level1)
{
    SetDeleteBundleResultForTest(ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
    auto ret = updateSelinuxMgr_->DeleteBundleForUser(TEST_USER_ID);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BmsUpdateSelinuxMgr_StartUpdateSelinuxLabel_001
 * @tc.name: test StartUpdateSelinuxLabel with empty bundles
 * @tc.desc: 1.Test StartUpdateSelinuxLabel when GetAllBundle returns empty
 */
HWTEST_F(BmsUpdateSelinuxMgrTest, BmsUpdateSelinuxMgr_StartUpdateSelinuxLabel_001, Function | SmallTest | Level1)
{
    ClearBundlesForTest();
    auto ret = updateSelinuxMgr_->StartUpdateSelinuxLabel(TEST_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsUpdateSelinuxMgr_StartUpdateSelinuxLabel_002
 * @tc.name: test StartUpdateSelinuxLabel with rdb error
 * @tc.desc: 1.Test StartUpdateSelinuxLabel when GetAllBundle fails
 */
HWTEST_F(BmsUpdateSelinuxMgrTest, BmsUpdateSelinuxMgr_StartUpdateSelinuxLabel_002, Function | SmallTest | Level1)
{
    SetGetAllBundleResultForTest(ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
    auto ret = updateSelinuxMgr_->StartUpdateSelinuxLabel(TEST_USER_ID);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BmsUpdateSelinuxMgr_StartUpdateSelinuxLabel_003
 * @tc.name: test StartUpdateSelinuxLabel with dataMgr null
 * @tc.desc: 1.Test StartUpdateSelinuxLabel when dataMgr is null
 */
HWTEST_F(BmsUpdateSelinuxMgrTest, BmsUpdateSelinuxMgr_StartUpdateSelinuxLabel_003, Function | SmallTest | Level1)
{
    // Prepare test data
    std::vector<BundleOptionInfo> bundles;
    CreateFakeBundleOptionInfos(bundles);
    SetBundlesForTest(bundles);

    // Mock BundleMgrService to return null dataMgr
    auto mockService = DelayedSingleton<BundleMgrService>::GetInstance();
    mockService->dataMgr_ = nullptr;

    auto ret = updateSelinuxMgr_->StartUpdateSelinuxLabel(TEST_USER_ID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_NULL_PTR);
}

/**
 * @tc.number: BmsUpdateSelinuxMgr_StartUpdateSelinuxLabel_004
 * @tc.name: test StartUpdateSelinuxLabel with empty dataMgr
 * @tc.desc: 1.Test StartUpdateSelinuxLabel when dataMgr has no bundle data
 */
HWTEST_F(BmsUpdateSelinuxMgrTest, BmsUpdateSelinuxMgr_StartUpdateSelinuxLabel_004, Function | SmallTest | Level1)
{
    // Prepare test data
    std::vector<BundleOptionInfo> bundles;
    CreateFakeBundleOptionInfos(bundles);
    SetBundlesForTest(bundles);

    // Create empty BundleDataMgr (no bundle data added)
    auto dataMgr = std::make_shared<BundleDataMgr>();
    auto mockService = DelayedSingleton<BundleMgrService>::GetInstance();
    mockService->dataMgr_ = dataMgr;

    auto ret = updateSelinuxMgr_->StartUpdateSelinuxLabel(TEST_USER_ID);
    // GetCreateDirParamByBundleOption will return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST
    // Code will continue to next bundle
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsUpdateSelinuxMgr_StartUpdateSelinuxLabel_005
 * @tc.name: test StartUpdateSelinuxLabel with needStop set
 * @tc.desc: 1.Test StartUpdateSelinuxLabel when needStop is set during loop
 */
HWTEST_F(BmsUpdateSelinuxMgrTest, BmsUpdateSelinuxMgr_StartUpdateSelinuxLabel_005, Function | SmallTest | Level1)
{
    // Prepare test data
    std::vector<BundleOptionInfo> bundles;
    CreateFakeBundleOptionInfos(bundles);
    SetBundlesForTest(bundles);

    // Create empty BundleDataMgr
    auto dataMgr = std::make_shared<BundleDataMgr>();
    auto mockService = DelayedSingleton<BundleMgrService>::GetInstance();
    mockService->dataMgr_ = dataMgr;

    // Set needStop flag to test early exit
    updateSelinuxMgr_->needStop_.store(true);

    auto ret = updateSelinuxMgr_->StartUpdateSelinuxLabel(TEST_USER_ID);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsUpdateSelinuxMgr_GetBundleDataPath_001
 * @tc.name: test GetBundleDataPath with default appIndex
 * @tc.desc: 1.Test GetBundleDataPath when appIndex is 0 and isContainsEl5Dir is false
 */
HWTEST_F(BmsUpdateSelinuxMgrTest, BmsUpdateSelinuxMgr_GetBundleDataPath_001, Function | SmallTest | Level1)
{
    auto paths = updateSelinuxMgr_->GetBundleDataPath(TEST_BUNDLE_NAME, TEST_USER_ID, TEST_APP_INDEX, false);

    // Expected paths for EL1-EL4 (11 paths)
    EXPECT_EQ(paths.size(), 11);
    EXPECT_NE(paths[0].find(TEST_BUNDLE_NAME), std::string::npos);
    EXPECT_NE(paths[0].find(std::to_string(TEST_USER_ID)), std::string::npos);
}

/**
 * @tc.number: BmsUpdateSelinuxMgr_GetBundleDataPath_002
 * @tc.name: test GetBundleDataPath with clone appIndex
 * @tc.desc: 1.Test GetBundleDataPath when appIndex is not 0
 */
HWTEST_F(BmsUpdateSelinuxMgrTest, BmsUpdateSelinuxMgr_GetBundleDataPath_002, Function | SmallTest | Level1)
{
    auto paths = updateSelinuxMgr_->GetBundleDataPath(TEST_BUNDLE_NAME, TEST_USER_ID, TEST_APP_INDEX_CLONE, false);

    // Expected paths for EL1-EL4 (11 paths)
    EXPECT_EQ(paths.size(), 11);
    EXPECT_NE(paths[0].find(std::to_string(TEST_USER_ID)), std::string::npos);
}

/**
 * @tc.number: BmsUpdateSelinuxMgr_GetBundleDataPath_003
 * @tc.name: test GetBundleDataPath with EL5 directory
 * @tc.desc: 1.Test GetBundleDataPath when isContainsEl5Dir is true
 */
HWTEST_F(BmsUpdateSelinuxMgrTest, BmsUpdateSelinuxMgr_GetBundleDataPath_003, Function | SmallTest | Level1)
{
    auto paths = updateSelinuxMgr_->GetBundleDataPath(TEST_BUNDLE_NAME, TEST_USER_ID, TEST_APP_INDEX, true);

    // Expected paths for EL1-EL4 (11 paths) + EL5 (2 paths)
    EXPECT_EQ(paths.size(), 13);
    EXPECT_NE(paths[0].find(TEST_BUNDLE_NAME), std::string::npos);
    EXPECT_NE(paths[0].find(std::to_string(TEST_USER_ID)), std::string::npos);
}

/**
 * @tc.number: BmsUpdateSelinuxMgr_GetBundleDataPath_004
 * @tc.name: test GetBundleDataPath with different userId
 * @tc.desc: 1.Test GetBundleDataPath with different userId values
 */
HWTEST_F(BmsUpdateSelinuxMgrTest, BmsUpdateSelinuxMgr_GetBundleDataPath_004, Function | SmallTest | Level1)
{
    auto paths1 = updateSelinuxMgr_->GetBundleDataPath(TEST_BUNDLE_NAME, TEST_USER_ID, TEST_APP_INDEX, false);
    auto paths2 = updateSelinuxMgr_->GetBundleDataPath(TEST_BUNDLE_NAME, TEST_USER_ID_2, TEST_APP_INDEX, false);

    EXPECT_EQ(paths1.size(), paths2.size());
    EXPECT_NE(paths1[0], paths2[0]);
}

/**
 * @tc.number: BmsUpdateSelinuxMgr_GetBundleDataPath_005
 * @tc.name: test GetBundleDataPath path format
 * @tc.desc: 1.Test GetBundleDataPath to verify correct path format
 */
HWTEST_F(BmsUpdateSelinuxMgrTest, BmsUpdateSelinuxMgr_GetBundleDataPath_005, Function | SmallTest | Level1)
{
    auto paths = updateSelinuxMgr_->GetBundleDataPath(TEST_BUNDLE_NAME, TEST_USER_ID, TEST_APP_INDEX, false);

    // Check that paths contain expected format
    bool hasEl1Path = false;
    bool hasEl2Path = false;
    bool hasEl3Path = false;
    bool hasEl4Path = false;

    for (const auto &path : paths) {
        if (path.find("/data/app/el1/") != std::string::npos) {
            hasEl1Path = true;
        }
        if (path.find("/data/app/el2/") != std::string::npos) {
            hasEl2Path = true;
        }
        if (path.find("/data/app/el3/") != std::string::npos) {
            hasEl3Path = true;
        }
        if (path.find("/data/app/el4/") != std::string::npos) {
            hasEl4Path = true;
        }
    }

    EXPECT_TRUE(hasEl1Path);
    EXPECT_TRUE(hasEl2Path);
    EXPECT_TRUE(hasEl3Path);
    EXPECT_TRUE(hasEl4Path);
}

/**
 * @tc.number: BmsUpdateSelinuxMgr_GetBundleDataPath_006
 * @tc.name: test GetBundleDataPath with EL5 paths
 * @tc.desc: 1.Test GetBundleDataPath to verify EL5 paths are included
 */
HWTEST_F(BmsUpdateSelinuxMgrTest, BmsUpdateSelinuxMgr_GetBundleDataPath_006, Function | SmallTest | Level1)
{
    auto paths = updateSelinuxMgr_->GetBundleDataPath(TEST_BUNDLE_NAME, TEST_USER_ID, TEST_APP_INDEX, true);

    // Check that paths contain EL5
    bool hasEl5Path = false;
    for (const auto &path : paths) {
        if (path.find("/data/app/el5/") != std::string::npos) {
            hasEl5Path = true;
            break;
        }
    }

    EXPECT_TRUE(hasEl5Path);
}

/**
 * @tc.number: BmsUpdateSelinuxMgr_GetBundleDataPath_007
 * @tc.name: test GetBundleDataPath with service paths
 * @tc.desc: 1.Test GetBundleDataPath to verify service paths are included
 */
HWTEST_F(BmsUpdateSelinuxMgrTest, BmsUpdateSelinuxMgr_GetBundleDataPath_007, Function | SmallTest | Level1)
{
    auto paths = updateSelinuxMgr_->GetBundleDataPath(TEST_BUNDLE_NAME, TEST_USER_ID, TEST_APP_INDEX, false);

    // Check that paths contain service directory
    bool hasServicePath = false;
    for (const auto &path : paths) {
        if (path.find("/data/service/") != std::string::npos) {
            hasServicePath = true;
            break;
        }
    }

    EXPECT_TRUE(hasServicePath);
}

} // namespace OHOS
