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

#include <gtest/gtest.h>

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

// Grant test access to BundleDataMgr internals (bundleInfos_ / tempBundleInfos_) to inject
// persisted token records; same pattern as bms_bundle_hsp_test / bms_dual_mode_install_test.
#define private public
#include "inner_bundle_info.h"
#include "bundle_data_mgr.h"
#undef private

#include "inner_bundle_user_info.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
constexpr int32_t TEST_USERID = 100;
constexpr int32_t TEST_USERID_SECOND = 101;
constexpr uint64_t TEST_TOKEN_IDEX = 0x53770001ULL;
constexpr uint64_t TEST_CLONE_TOKEN_IDEX = 0x53770002ULL;
constexpr uint64_t TEST_SANDBOX_TOKEN_IDEX = 0x53770003ULL;
constexpr int32_t TEST_CLONE_APP_INDEX = 2;
constexpr int32_t TEST_CLONE_APP_INDEX_SECOND = 3;
constexpr uint64_t TEST_CLONE_TOKEN_IDEX_SECOND = 0x53770004ULL;
constexpr int32_t TEST_SANDBOX_APP_INDEX = 2000;
const std::string TEST_BUNDLE = "com.test.snapshot";
}  // namespace

class BmsGetRestoreInfosTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}

protected:
    static InnerBundleInfo MakeBundleInfo()
    {
        InnerBundleInfo info;
        BundleInfo baseInfo;
        baseInfo.name = TEST_BUNDLE;
        info.SetBaseBundleInfo(baseInfo);
        return info;
    }

    static InnerBundleUserInfo MakeUserInfo(int32_t userId)
    {
        InnerBundleUserInfo userInfo;
        userInfo.bundleUserInfo.userId = userId;
        return userInfo;
    }
};

/**
 * @tc.number: BmsGetRestoreInfosTest_0100
 * @tc.name: test main app token entry is collected
 * @tc.desc: one bundle, one user with persisted accessTokenIdEx -> one entry with appIndex 0
 */
HWTEST_F(BmsGetRestoreInfosTest, BmsGetRestoreInfosTest_0100, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    InnerBundleInfo info = MakeBundleInfo();
    InnerBundleUserInfo userInfo = MakeUserInfo(TEST_USERID);
    userInfo.accessTokenIdEx = TEST_TOKEN_IDEX;
    info.AddInnerBundleUserInfo(userInfo);
    dataMgr->bundleInfos_[TEST_BUNDLE] = info;

    std::vector<AccessTokenRestoreInfo> restoreInfos;
    dataMgr->GetAccessTokenRestoreInfos(restoreInfos);

    ASSERT_EQ(1U, restoreInfos.size());
    EXPECT_EQ(TEST_BUNDLE, restoreInfos[0].bundleName);
    EXPECT_EQ(TEST_USERID, restoreInfos[0].userId);
    EXPECT_EQ(0, restoreInfos[0].appIndex);
    EXPECT_EQ(TEST_TOKEN_IDEX, restoreInfos[0].accessTokenIdEx);
}

/**
 * @tc.number: BmsGetRestoreInfosTest_0200
 * @tc.name: test entries without persisted token are skipped
 * @tc.desc: main and clone accessTokenIdEx are both 0 -> nothing collected
 */
HWTEST_F(BmsGetRestoreInfosTest, BmsGetRestoreInfosTest_0200, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    InnerBundleInfo info = MakeBundleInfo();
    InnerBundleUserInfo userInfo = MakeUserInfo(TEST_USERID);
    userInfo.accessTokenIdEx = 0;
    InnerBundleCloneInfo cloneInfo;
    cloneInfo.appIndex = TEST_CLONE_APP_INDEX;
    cloneInfo.accessTokenIdEx = 0;
    userInfo.cloneInfos[InnerBundleUserInfo::AppIndexToKey(TEST_CLONE_APP_INDEX)] = cloneInfo;
    info.AddInnerBundleUserInfo(userInfo);
    dataMgr->bundleInfos_[TEST_BUNDLE] = info;

    std::vector<AccessTokenRestoreInfo> restoreInfos;
    dataMgr->GetAccessTokenRestoreInfos(restoreInfos);

    EXPECT_TRUE(restoreInfos.empty());
}

/**
 * @tc.number: BmsGetRestoreInfosTest_0300
 * @tc.name: test clone app token entry is collected
 * @tc.desc: clone entry keeps its own appIndex and accessTokenIdEx
 */
HWTEST_F(BmsGetRestoreInfosTest, BmsGetRestoreInfosTest_0300, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    InnerBundleInfo info = MakeBundleInfo();
    InnerBundleUserInfo userInfo = MakeUserInfo(TEST_USERID);
    InnerBundleCloneInfo cloneInfo;
    cloneInfo.appIndex = TEST_CLONE_APP_INDEX;
    cloneInfo.accessTokenIdEx = TEST_CLONE_TOKEN_IDEX;
    userInfo.cloneInfos[InnerBundleUserInfo::AppIndexToKey(TEST_CLONE_APP_INDEX)] = cloneInfo;
    info.AddInnerBundleUserInfo(userInfo);
    dataMgr->bundleInfos_[TEST_BUNDLE] = info;

    std::vector<AccessTokenRestoreInfo> restoreInfos;
    dataMgr->GetAccessTokenRestoreInfos(restoreInfos);

    ASSERT_EQ(1U, restoreInfos.size());
    EXPECT_EQ(TEST_CLONE_APP_INDEX, restoreInfos[0].appIndex);
    EXPECT_EQ(TEST_CLONE_TOKEN_IDEX, restoreInfos[0].accessTokenIdEx);
    EXPECT_EQ(TEST_USERID, restoreInfos[0].userId);
}

/**
 * @tc.number: BmsGetRestoreInfosTest_0400
 * @tc.name: test cli sandbox token entry is collected
 * @tc.desc: sandbox entry keeps its own appIndex (2000 range) and accessTokenIdEx
 */
HWTEST_F(BmsGetRestoreInfosTest, BmsGetRestoreInfosTest_0400, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    InnerBundleInfo info = MakeBundleInfo();
    InnerBundleUserInfo userInfo = MakeUserInfo(TEST_USERID);
    InnerCliSandboxInfo sandboxInfo;
    sandboxInfo.appIndex = TEST_SANDBOX_APP_INDEX;
    sandboxInfo.accessTokenIdEx = TEST_SANDBOX_TOKEN_IDEX;
    userInfo.sandboxInfos[InnerBundleUserInfo::AppIndexToKey(TEST_SANDBOX_APP_INDEX)] = sandboxInfo;
    info.AddInnerBundleUserInfo(userInfo);
    dataMgr->bundleInfos_[TEST_BUNDLE] = info;

    std::vector<AccessTokenRestoreInfo> restoreInfos;
    dataMgr->GetAccessTokenRestoreInfos(restoreInfos);

    ASSERT_EQ(1U, restoreInfos.size());
    EXPECT_EQ(TEST_SANDBOX_APP_INDEX, restoreInfos[0].appIndex);
    EXPECT_EQ(TEST_SANDBOX_TOKEN_IDEX, restoreInfos[0].accessTokenIdEx);
}

/**
 * @tc.number: BmsGetRestoreInfosTest_0500
 * @tc.name: test multi-user entries are collected per user
 * @tc.desc: the same bundle installed for two users yields one main entry per user
 */
HWTEST_F(BmsGetRestoreInfosTest, BmsGetRestoreInfosTest_0500, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    InnerBundleInfo info = MakeBundleInfo();
    InnerBundleUserInfo first = MakeUserInfo(TEST_USERID);
    first.accessTokenIdEx = TEST_TOKEN_IDEX;
    InnerBundleUserInfo second = MakeUserInfo(TEST_USERID_SECOND);
    second.accessTokenIdEx = TEST_TOKEN_IDEX + 1;
    info.AddInnerBundleUserInfo(first);
    info.AddInnerBundleUserInfo(second);
    dataMgr->bundleInfos_[TEST_BUNDLE] = info;

    std::vector<AccessTokenRestoreInfo> restoreInfos;
    dataMgr->GetAccessTokenRestoreInfos(restoreInfos);

    ASSERT_EQ(2U, restoreInfos.size());
    std::set<int32_t> userIds;
    for (const auto &entry : restoreInfos) {
        EXPECT_EQ(TEST_BUNDLE, entry.bundleName);
        EXPECT_EQ(0, entry.appIndex);
        userIds.insert(entry.userId);
    }
    EXPECT_EQ(2U, userIds.size());
    EXPECT_TRUE(userIds.count(TEST_USERID) > 0);
    EXPECT_TRUE(userIds.count(TEST_USERID_SECOND) > 0);
}

/**
 * @tc.number: BmsGetRestoreInfosTest_0600
 * @tc.name: test temp (dual-mode) map is not part of the snapshot
 * @tc.desc: entries only in tempBundleInfos_ are not collected (feature not launched)
 */
HWTEST_F(BmsGetRestoreInfosTest, BmsGetRestoreInfosTest_0600, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    InnerBundleInfo info = MakeBundleInfo();
    InnerBundleUserInfo userInfo = MakeUserInfo(TEST_USERID);
    userInfo.accessTokenIdEx = TEST_TOKEN_IDEX;
    info.AddInnerBundleUserInfo(userInfo);
    dataMgr->tempBundleInfos_[TEST_BUNDLE] = info;

    std::vector<AccessTokenRestoreInfo> restoreInfos;
    dataMgr->GetAccessTokenRestoreInfos(restoreInfos);

    EXPECT_TRUE(restoreInfos.empty());
}

/**
 * @tc.number: BmsGetRestoreInfosTest_0700
 * @tc.name: test main, clone and sandbox entries of one bundle are all collected
 * @tc.desc: one user holding all three kinds of tokens -> three entries with appIndex {0, 2, 2000}
 */
HWTEST_F(BmsGetRestoreInfosTest, BmsGetRestoreInfosTest_0700, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    InnerBundleInfo info = MakeBundleInfo();
    InnerBundleUserInfo userInfo = MakeUserInfo(TEST_USERID);
    userInfo.accessTokenIdEx = TEST_TOKEN_IDEX;
    InnerBundleCloneInfo cloneInfo;
    cloneInfo.appIndex = TEST_CLONE_APP_INDEX;
    cloneInfo.accessTokenIdEx = TEST_CLONE_TOKEN_IDEX;
    userInfo.cloneInfos[InnerBundleUserInfo::AppIndexToKey(TEST_CLONE_APP_INDEX)] = cloneInfo;
    InnerCliSandboxInfo sandboxInfo;
    sandboxInfo.appIndex = TEST_SANDBOX_APP_INDEX;
    sandboxInfo.accessTokenIdEx = TEST_SANDBOX_TOKEN_IDEX;
    userInfo.sandboxInfos[InnerBundleUserInfo::AppIndexToKey(TEST_SANDBOX_APP_INDEX)] = sandboxInfo;
    info.AddInnerBundleUserInfo(userInfo);
    dataMgr->bundleInfos_[TEST_BUNDLE] = info;

    std::vector<AccessTokenRestoreInfo> restoreInfos;
    dataMgr->GetAccessTokenRestoreInfos(restoreInfos);

    ASSERT_EQ(3U, restoreInfos.size());
    std::map<int32_t, uint64_t> tokenByAppIndex;
    for (const auto &entry : restoreInfos) {
        EXPECT_EQ(TEST_BUNDLE, entry.bundleName);
        EXPECT_EQ(TEST_USERID, entry.userId);
        tokenByAppIndex[entry.appIndex] = entry.accessTokenIdEx;
    }
    EXPECT_EQ(3U, tokenByAppIndex.size());
    EXPECT_EQ(TEST_TOKEN_IDEX, tokenByAppIndex[0]);
    EXPECT_EQ(TEST_CLONE_TOKEN_IDEX, tokenByAppIndex[TEST_CLONE_APP_INDEX]);
    EXPECT_EQ(TEST_SANDBOX_TOKEN_IDEX, tokenByAppIndex[TEST_SANDBOX_APP_INDEX]);
}

/**
 * @tc.number: BmsGetRestoreInfosTest_0800
 * @tc.name: test multiple clones of one user are all collected
 * @tc.desc: one user with two clones (appIndex 2 and 3) -> two entries, each keeping its own
 *           appIndex and persisted token
 */
HWTEST_F(BmsGetRestoreInfosTest, BmsGetRestoreInfosTest_0800, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    InnerBundleInfo info = MakeBundleInfo();
    InnerBundleUserInfo userInfo = MakeUserInfo(TEST_USERID);
    InnerBundleCloneInfo firstClone;
    firstClone.appIndex = TEST_CLONE_APP_INDEX;
    firstClone.accessTokenIdEx = TEST_CLONE_TOKEN_IDEX;
    userInfo.cloneInfos[InnerBundleUserInfo::AppIndexToKey(TEST_CLONE_APP_INDEX)] = firstClone;
    InnerBundleCloneInfo secondClone;
    secondClone.appIndex = TEST_CLONE_APP_INDEX_SECOND;
    secondClone.accessTokenIdEx = TEST_CLONE_TOKEN_IDEX_SECOND;
    userInfo.cloneInfos[InnerBundleUserInfo::AppIndexToKey(TEST_CLONE_APP_INDEX_SECOND)] = secondClone;
    info.AddInnerBundleUserInfo(userInfo);
    dataMgr->bundleInfos_[TEST_BUNDLE] = info;

    std::vector<AccessTokenRestoreInfo> restoreInfos;
    dataMgr->GetAccessTokenRestoreInfos(restoreInfos);

    ASSERT_EQ(2U, restoreInfos.size());
    std::map<int32_t, uint64_t> tokenByAppIndex;
    for (const auto &entry : restoreInfos) {
        EXPECT_EQ(TEST_BUNDLE, entry.bundleName);
        EXPECT_EQ(TEST_USERID, entry.userId);
        tokenByAppIndex[entry.appIndex] = entry.accessTokenIdEx;
    }
    EXPECT_EQ(2U, tokenByAppIndex.size());
    EXPECT_EQ(TEST_CLONE_TOKEN_IDEX, tokenByAppIndex[TEST_CLONE_APP_INDEX]);
    EXPECT_EQ(TEST_CLONE_TOKEN_IDEX_SECOND, tokenByAppIndex[TEST_CLONE_APP_INDEX_SECOND]);
}

/**
 * @tc.number: BmsGetRestoreInfosTest_0900
 * @tc.name: test sandbox entry without persisted token is skipped while clone is kept
 * @tc.desc: a sandbox info with accessTokenIdEx 0 contributes nothing, a sibling clone with a
 *           token still does -> exactly one clone entry
 */
HWTEST_F(BmsGetRestoreInfosTest, BmsGetRestoreInfosTest_0900, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    InnerBundleInfo info = MakeBundleInfo();
    InnerBundleUserInfo userInfo = MakeUserInfo(TEST_USERID);
    InnerBundleCloneInfo cloneInfo;
    cloneInfo.appIndex = TEST_CLONE_APP_INDEX;
    cloneInfo.accessTokenIdEx = TEST_CLONE_TOKEN_IDEX;
    userInfo.cloneInfos[InnerBundleUserInfo::AppIndexToKey(TEST_CLONE_APP_INDEX)] = cloneInfo;
    InnerCliSandboxInfo sandboxInfo;
    sandboxInfo.appIndex = TEST_SANDBOX_APP_INDEX;
    sandboxInfo.accessTokenIdEx = 0;
    userInfo.sandboxInfos[InnerBundleUserInfo::AppIndexToKey(TEST_SANDBOX_APP_INDEX)] = sandboxInfo;
    info.AddInnerBundleUserInfo(userInfo);
    dataMgr->bundleInfos_[TEST_BUNDLE] = info;

    std::vector<AccessTokenRestoreInfo> restoreInfos;
    dataMgr->GetAccessTokenRestoreInfos(restoreInfos);

    ASSERT_EQ(1U, restoreInfos.size());
    EXPECT_EQ(TEST_CLONE_APP_INDEX, restoreInfos[0].appIndex);
    EXPECT_EQ(TEST_CLONE_TOKEN_IDEX, restoreInfos[0].accessTokenIdEx);
}

/**
 * @tc.number: BmsGetRestoreInfosTest_1000
 * @tc.name: test bundle without any user info is skipped
 * @tc.desc: a bundle entry that holds no innerBundleUserInfos_ contributes no restore entry
 */
HWTEST_F(BmsGetRestoreInfosTest, BmsGetRestoreInfosTest_1000, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    InnerBundleInfo info = MakeBundleInfo();
    dataMgr->bundleInfos_[TEST_BUNDLE] = info;

    std::vector<AccessTokenRestoreInfo> restoreInfos;
    dataMgr->GetAccessTokenRestoreInfos(restoreInfos);

    EXPECT_TRUE(restoreInfos.empty());
}
