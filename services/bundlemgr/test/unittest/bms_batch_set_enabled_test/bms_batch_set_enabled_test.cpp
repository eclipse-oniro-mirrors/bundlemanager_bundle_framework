/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include "inner_bundle_clone_info.h"
#include "inner_bundle_user_info.h"
#include "inner_bundle_info.h"
#include "bundle_constants.h"
#include "bundle_file_util.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
namespace OHOS {
class BmsBatchSetEnabledTest : public testing::Test {
public:
    BmsBatchSetEnabledTest() {}
    ~BmsBatchSetEnabledTest() {}
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}

    static InnerBundleInfo CreateBundleWithClones(
        const std::string &bundleName, int32_t userId, const std::vector<int32_t> &appIndexes, bool defaultEnabled)
    {
        InnerBundleInfo info;
        ApplicationInfo appInfo;
        appInfo.bundleName = bundleName;
        info.SetBaseApplicationInfo(appInfo);
        InnerBundleUserInfo userInfo;
        userInfo.bundleUserInfo.userId = userId;
        info.AddInnerBundleUserInfo(userInfo);
        for (int32_t appIndex : appIndexes) {
            InnerBundleCloneInfo cloneInfo;
            cloneInfo.userId = userId;
            cloneInfo.appIndex = appIndex;
            cloneInfo.enabled = defaultEnabled;
            info.AddCloneBundle(cloneInfo);
        }
        return info;
    }
};

/**
 * @tc.number: BatchSetEnabled_InnerBundleInfo_0001
 * @tc.name: Test SetCloneApplicationEnabled basic enable/disable
 * @tc.desc: Verify enabling/disabling clone app via InnerBundleInfo works correctly
 */
HWTEST_F(BmsBatchSetEnabledTest, BatchSetEnabled_InnerBundleInfo_0001, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    auto info = CreateBundleWithClones("com.test.bundle1", userId, {1, 2}, true);

    auto ret = info.SetCloneApplicationEnabled(false, 2, "caller", userId);
    EXPECT_EQ(ret, ERR_OK);

    bool enabled = false;
    EXPECT_EQ(info.GetApplicationEnabledV9(userId, enabled, 1), ERR_OK);
    EXPECT_TRUE(enabled);

    EXPECT_EQ(info.GetApplicationEnabledV9(userId, enabled, 2), ERR_OK);
    EXPECT_FALSE(enabled);
}

/**
 * @tc.number: BatchSetEnabled_InnerBundleInfo_0002
 * @tc.name: Test SetCloneApplicationEnabled with non-existent appIndex
 * @tc.desc: Verify error returned when setting clone enabled for non-existent appIndex
 */
HWTEST_F(BmsBatchSetEnabledTest, BatchSetEnabled_InnerBundleInfo_0002, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    auto info = CreateBundleWithClones("com.test.bundle1", userId, {1}, true);

    auto ret = info.SetCloneApplicationEnabled(false, 3, "caller", userId);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BatchSetEnabled_InnerBundleInfo_0003
 * @tc.name: Test SetCloneApplicationEnabled with non-existent userId
 * @tc.desc: Verify error returned when setting clone enabled for non-existent userId
 */
HWTEST_F(BmsBatchSetEnabledTest, BatchSetEnabled_InnerBundleInfo_0003, Function | SmallTest | Level1)
{
    auto info = CreateBundleWithClones("com.test.bundle1", 100, {1}, true);
    auto ret = info.SetCloneApplicationEnabled(false, 1, "caller", 999);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BatchSetEnabled_CloneAppIndexes_0004
 * @tc.name: Test GetCloneBundleAppIndexes for filtering bundles
 * @tc.desc: Verify GetCloneBundleAppIndexes returns correct indexes for pre-check filtering
 */
HWTEST_F(BmsBatchSetEnabledTest, BatchSetEnabled_CloneAppIndexes_0004, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    auto info = CreateBundleWithClones("com.test.bundle1", userId, {1, 2}, true);

    auto cloneIndexes = info.GetCloneBundleAppIndexes();
    EXPECT_EQ(cloneIndexes.size(), 2u);
    EXPECT_NE(cloneIndexes.find(1), cloneIndexes.end());
    EXPECT_NE(cloneIndexes.find(2), cloneIndexes.end());
    EXPECT_EQ(cloneIndexes.find(3), cloneIndexes.end());
}

/**
 * @tc.number: BatchSetEnabled_Rollback_0005
 * @tc.name: Test rollback - disable then re-enable restores state
 * @tc.desc: Verify rollback restores the original enabled state
 */
HWTEST_F(BmsBatchSetEnabledTest, BatchSetEnabled_Rollback_0005, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    auto info = CreateBundleWithClones("com.test.bundle1", userId, {1, 2}, true);

    info.SetCloneApplicationEnabled(false, 2, "caller", userId);
    bool enabled = true;
    EXPECT_EQ(info.GetApplicationEnabledV9(userId, enabled, 2), ERR_OK);
    EXPECT_FALSE(enabled);

    // Rollback: re-enable
    info.SetCloneApplicationEnabled(true, 2, "rollback", userId);
    EXPECT_EQ(info.GetApplicationEnabledV9(userId, enabled, 2), ERR_OK);
    EXPECT_TRUE(enabled);
}

/**
 * @tc.number: BatchSetEnabled_NoClones_0006
 * @tc.name: Test bundle without clones
 * @tc.desc: Verify bundle without clones has empty cloneIndexes (skipped in batch loop)
 */
HWTEST_F(BmsBatchSetEnabledTest, BatchSetEnabled_NoClones_0006, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    InnerBundleInfo info;
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = userId;
    info.AddInnerBundleUserInfo(userInfo);

    auto cloneIndexes = info.GetCloneBundleAppIndexes();
    EXPECT_TRUE(cloneIndexes.empty());
}

/**
 * @tc.number: BatchSetEnabled_MultipleUsers_0007
 * @tc.name: clone enabled state is user-isolated
 * @tc.desc: Verify SetCloneApplicationEnabled on one userId does not affect another userId
 */
HWTEST_F(BmsBatchSetEnabledTest, BatchSetEnabled_MultipleUsers_0007, Function | SmallTest | Level1)
{
    int32_t userId1 = 100;
    int32_t userId2 = 200;
    auto info = CreateBundleWithClones("com.test.multi", userId1, {1}, true);

    InnerBundleUserInfo userInfo2;
    userInfo2.bundleUserInfo.userId = userId2;
    InnerBundleCloneInfo clone2;
    clone2.userId = userId2;
    clone2.appIndex = 1;
    clone2.enabled = true;
    userInfo2.cloneInfos["1"] = clone2;
    info.AddInnerBundleUserInfo(userInfo2);

    auto ret = info.SetCloneApplicationEnabled(false, 1, "caller", userId1);
    EXPECT_EQ(ret, ERR_OK);

    bool enabled = true;
    EXPECT_EQ(info.GetApplicationEnabledV9(userId1, enabled, 1), ERR_OK);
    EXPECT_FALSE(enabled);

    EXPECT_EQ(info.GetApplicationEnabledV9(userId2, enabled, 1), ERR_OK);
    EXPECT_TRUE(enabled);
}

/**
 * @tc.number: BatchSetEnabled_IdempotentEnable_0008
 * @tc.name: enabling an already-enabled clone is idempotent
 * @tc.desc: Verify that calling SetCloneApplicationEnabled(true) on already-enabled clone returns OK
 */
HWTEST_F(BmsBatchSetEnabledTest, BatchSetEnabled_IdempotentEnable_0008, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    auto info = CreateBundleWithClones("com.test.idempotent1", userId, {1}, true);

    auto ret = info.SetCloneApplicationEnabled(true, 1, "caller", userId);
    EXPECT_EQ(ret, ERR_OK);
    bool enabled = false;
    EXPECT_EQ(info.GetApplicationEnabledV9(userId, enabled, 1), ERR_OK);
    EXPECT_TRUE(enabled);
}

/**
 * @tc.number: BatchSetEnabled_AppIndexZeroNotInClone_0009
 * @tc.name: appIndex=0 is not a valid clone index
 * @tc.desc: Verify that appIndex=0 does not exist in cloneInfos and SetCloneApplicationEnabled
 *          rejects it. In the batch interface, appIndex=0 means "skip this operation", not
 *          "operate on the base app". The clone map keys start from 1, so 0 is never present.
 */
HWTEST_F(BmsBatchSetEnabledTest, BatchSetEnabled_AppIndexZeroNotInClone_0009, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    auto info = CreateBundleWithClones("com.test.zero", userId, {1, 2}, true);

    auto cloneIndexes = info.GetCloneBundleAppIndexes();
    EXPECT_EQ(cloneIndexes.find(0), cloneIndexes.end());

    auto ret = info.SetCloneApplicationEnabled(false, 0, "caller", userId);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BatchSetEnabled_LargeAppIndex_0010
 * @tc.name: AddCloneBundle rejects appIndex exceeding max clone count
 * @tc.desc: Verify that AddCloneBundle rejects appIndex > GetCloneMaxCount(), so the clone is
 *          never added to cloneInfos. SetCloneApplicationEnabled then also fails because the
 *          appIndex does not exist. The key assertion is that GetCloneBundleAppIndexes does not
 *          contain the out-of-range appIndex, confirming AddCloneBundle's range validation.
 */
HWTEST_F(BmsBatchSetEnabledTest, BatchSetEnabled_LargeAppIndex_0010, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    int32_t largeAppIndex = BundleFileUtil::GetCloneMaxCount() + 1;
    auto info = CreateBundleWithClones("com.test.large", userId, {largeAppIndex}, true);

    // Key assertion: AddCloneBundle rejected the out-of-range appIndex
    auto cloneIndexes = info.GetCloneBundleAppIndexes();
    EXPECT_EQ(cloneIndexes.find(largeAppIndex), cloneIndexes.end());

    auto ret = info.SetCloneApplicationEnabled(false, largeAppIndex, "caller", userId);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.number: BatchSetEnabled_ManyClones_0011
 * @tc.name: bundle with many clone apps up to max count
 * @tc.desc: Verify operations work with clone appIndexes within GetCloneMaxCount
 */
HWTEST_F(BmsBatchSetEnabledTest, BatchSetEnabled_ManyClones_0011, Function | SmallTest | Level1)
{
    int32_t userId = 100;
    int32_t maxCount = BundleFileUtil::GetCloneMaxCount();
    std::vector<int32_t> appIndexes;
    for (int32_t i = 1; i <= maxCount; ++i) {
        appIndexes.push_back(i);
    }
    auto info = CreateBundleWithClones("com.test.many", userId, appIndexes, true);

    auto cloneIndexes = info.GetCloneBundleAppIndexes();
    EXPECT_EQ(cloneIndexes.size(), static_cast<size_t>(maxCount));

    for (int32_t i = 1; i <= maxCount; ++i) {
        auto ret = info.SetCloneApplicationEnabled(false, i, "caller", userId);
        EXPECT_EQ(ret, ERR_OK);
    }

    for (int32_t i = 1; i <= maxCount; ++i) {
        bool enabled = true;
        EXPECT_EQ(info.GetApplicationEnabledV9(userId, enabled, i), ERR_OK);
        EXPECT_FALSE(enabled);
    }

    for (int32_t i = 1; i <= maxCount; ++i) {
        auto ret = info.SetCloneApplicationEnabled(true, i, "caller", userId);
        EXPECT_EQ(ret, ERR_OK);
    }

    for (int32_t i = 1; i <= maxCount; ++i) {
        bool enabled = false;
        EXPECT_EQ(info.GetApplicationEnabledV9(userId, enabled, i), ERR_OK);
        EXPECT_TRUE(enabled);
    }
}

} // namespace OHOS
