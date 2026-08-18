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

#include <memory>
#include <string>

#include "access_token_error.h"
#include "appexecfwk_errors.h"

// Grant test access to BundleDataMgr internals (bundleInfos_) so persisted token records can be
// injected without touching storage; same pattern as bms_bundle_hsp_test / bms_dual_mode_install_test.
// bundle_access_token_recovery_mgr.h is expanded inside the block as well: its private static
// RestoreSingleApp is called directly by the fetch-failure case (a defensive branch the public
// ProcessRecovery path cannot reach, because snapshot and fetch read the same map).
#define private public
#include "inner_bundle_info.h"
#include "bundle_data_mgr.h"
#include "bundle_access_token_recovery_mgr.h"
#undef private

#include "accesstoken_kit.h"
#include "parameters.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security::AccessToken;

namespace {
constexpr const char *DB_ERROR_PARAM = "persist.accesstoken.permission.dberror";
constexpr int32_t TEST_USERID = 100;
constexpr uint64_t TEST_TOKEN_IDEX = 0x53770001ULL;
constexpr uint32_t TEST_TOKEN_ID = 0x53770001U;
constexpr uint64_t TEST_CLONE_TOKEN_IDEX = 0x53770002ULL;
constexpr uint32_t TEST_CLONE_TOKEN_ID = 0x53770002U;
constexpr int32_t TEST_CLONE_APP_INDEX = 2;
const std::string TEST_BUNDLE_A = "com.test.restore.a";
const std::string TEST_BUNDLE_B = "com.test.restore.b";
const std::string TEST_BUNDLE_C = "com.test.restore.c";
const std::string TEST_BUNDLE_MISSING = "com.test.restore.missing";
}  // namespace

class BmsProcessRecoveryTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        ClearInitHapTokenMockStateForTest();
        OHOS::system::RemoveParameter(DB_ERROR_PARAM);
    }
    void TearDown() override
    {
        ClearInitHapTokenMockStateForTest();
        OHOS::system::RemoveParameter(DB_ERROR_PARAM);
    }

protected:
    // Inject one bundle with a persisted main-app token (appIndex 0) into bundleInfos_.
    static void AddBundleWithMainToken(const std::shared_ptr<BundleDataMgr> &dataMgr,
        const std::string &bundleName, uint64_t tokenIdxEx)
    {
        InnerBundleUserInfo userInfo;
        userInfo.bundleUserInfo.userId = TEST_USERID;
        userInfo.accessTokenIdEx = tokenIdxEx;
        InnerBundleInfo info;
        BundleInfo baseInfo;
        baseInfo.name = bundleName;
        info.SetBaseBundleInfo(baseInfo);
        ApplicationInfo appInfo;
        appInfo.bundleName = bundleName;
        info.SetBaseApplicationInfo(appInfo);
        info.AddInnerBundleUserInfo(userInfo);
        dataMgr->bundleInfos_[bundleName] = info;
    }

    // Inject one bundle holding both a main-app token and a clone token (appIndex > 0).
    static void AddBundleWithMainAndCloneToken(const std::shared_ptr<BundleDataMgr> &dataMgr,
        const std::string &bundleName, uint64_t mainTokenIdxEx, int32_t cloneAppIndex,
        uint64_t cloneTokenIdxEx)
    {
        InnerBundleUserInfo userInfo;
        userInfo.bundleUserInfo.userId = TEST_USERID;
        userInfo.accessTokenIdEx = mainTokenIdxEx;
        InnerBundleCloneInfo cloneInfo;
        cloneInfo.appIndex = cloneAppIndex;
        cloneInfo.accessTokenIdEx = cloneTokenIdxEx;
        userInfo.cloneInfos[InnerBundleUserInfo::AppIndexToKey(cloneAppIndex)] = cloneInfo;
        InnerBundleInfo info;
        BundleInfo baseInfo;
        baseInfo.name = bundleName;
        info.SetBaseBundleInfo(baseInfo);
        ApplicationInfo appInfo;
        appInfo.bundleName = bundleName;
        info.SetBaseApplicationInfo(appInfo);
        info.AddInnerBundleUserInfo(userInfo);
        dataMgr->bundleInfos_[bundleName] = info;
    }
};

/**
 * @tc.number: BmsProcessRecoveryTest_0100
 * @tc.name: test no recovery when dberror parameter is not set
 * @tc.desc: 1.dberror is absent (mock returns the default false)
 *           2.InitHapToken and ResetDatabaseRecoveryStatus are never called
 */
HWTEST_F(BmsProcessRecoveryTest, BmsProcessRecoveryTest_0100, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    AddBundleWithMainToken(dataMgr, TEST_BUNDLE_A, TEST_TOKEN_IDEX);

    BundleAccessTokenRecoveryMgr::ProcessRecovery(dataMgr, "test");

    EXPECT_EQ(0U, GetInitHapTokenCallCountForTest());
    EXPECT_EQ(0, GetResetDatabaseRecoveryStatusCallCountForTest());
}

/**
 * @tc.number: BmsProcessRecoveryTest_0200
 * @tc.name: test recovery aborts without reset when data manager is null
 * @tc.desc: 1.dberror is true but dataMgr is null
 *           2.nothing restored and the marker is NOT cleared (next boot retries)
 */
HWTEST_F(BmsProcessRecoveryTest, BmsProcessRecoveryTest_0200, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(DB_ERROR_PARAM, "true");

    BundleAccessTokenRecoveryMgr::ProcessRecovery(nullptr, "test");

    EXPECT_EQ(0U, GetInitHapTokenCallCountForTest());
    EXPECT_EQ(0, GetResetDatabaseRecoveryStatusCallCountForTest());
}

/**
 * @tc.number: BmsProcessRecoveryTest_0300
 * @tc.name: test reset is still called when there is nothing to restore
 * @tc.desc: 1.dberror is true and the snapshot is empty
 *           2.ResetDatabaseRecoveryStatus is called exactly once after traversal
 */
HWTEST_F(BmsProcessRecoveryTest, BmsProcessRecoveryTest_0300, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(DB_ERROR_PARAM, "true");
    auto dataMgr = std::make_shared<BundleDataMgr>();

    BundleAccessTokenRecoveryMgr::ProcessRecovery(dataMgr, "test");

    EXPECT_EQ(0U, GetInitHapTokenCallCountForTest());
    EXPECT_EQ(1, GetResetDatabaseRecoveryStatusCallCountForTest());
}

/**
 * @tc.number: BmsProcessRecoveryTest_0400
 * @tc.name: test single app restored with persisted token id
 * @tc.desc: 1.dberror is true, one bundle with persisted accessTokenIdEx
 *           2.InitHapToken receives isRestore=true, tokenID (low 32 bits), userID and bundleName
 */
HWTEST_F(BmsProcessRecoveryTest, BmsProcessRecoveryTest_0400, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(DB_ERROR_PARAM, "true");
    auto dataMgr = std::make_shared<BundleDataMgr>();
    AddBundleWithMainToken(dataMgr, TEST_BUNDLE_A, TEST_TOKEN_IDEX);

    BundleAccessTokenRecoveryMgr::ProcessRecovery(dataMgr, "test");

    EXPECT_EQ(1U, GetInitHapTokenCallCountForTest());
    HapInfoParams captured = GetInitHapInfoParamsForTest(0);
    EXPECT_TRUE(captured.isRestore);
    EXPECT_EQ(TEST_TOKEN_ID, captured.tokenID);
    EXPECT_EQ(TEST_USERID, captured.userID);
    EXPECT_EQ(TEST_BUNDLE_A, captured.bundleName);
    EXPECT_EQ(0, captured.instIndex);
    EXPECT_EQ(1, GetResetDatabaseRecoveryStatusCallCountForTest());
}

/**
 * @tc.number: BmsProcessRecoveryTest_0500
 * @tc.name: test retry succeeds on the second attempt
 * @tc.desc: 1.first InitHapToken returns ERR_SERVICE_ABNORMAL, second succeeds (empty queue)
 *           2.InitHapToken is called exactly twice
 */
HWTEST_F(BmsProcessRecoveryTest, BmsProcessRecoveryTest_0500, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(DB_ERROR_PARAM, "true");
    auto dataMgr = std::make_shared<BundleDataMgr>();
    AddBundleWithMainToken(dataMgr, TEST_BUNDLE_A, TEST_TOKEN_IDEX);
    PushInitHapTokenResultForTest(AccessTokenError::ERR_SERVICE_ABNORMAL);

    BundleAccessTokenRecoveryMgr::ProcessRecovery(dataMgr, "test");

    EXPECT_EQ(2U, GetInitHapTokenCallCountForTest());
    EXPECT_EQ(1, GetResetDatabaseRecoveryStatusCallCountForTest());
}

/**
 * @tc.number: BmsProcessRecoveryTest_0600
 * @tc.name: test app gives up after four failed attempts
 * @tc.desc: 1.InitHapToken fails on every attempt
 *           2.exactly 4 attempts (1 initial + 3 retries per requirement), reset still called
 */
HWTEST_F(BmsProcessRecoveryTest, BmsProcessRecoveryTest_0600, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(DB_ERROR_PARAM, "true");
    auto dataMgr = std::make_shared<BundleDataMgr>();
    AddBundleWithMainToken(dataMgr, TEST_BUNDLE_A, TEST_TOKEN_IDEX);
    for (int32_t i = 0; i < 4; ++i) {
        PushInitHapTokenResultForTest(AccessTokenError::ERR_SERVICE_ABNORMAL);
    }

    BundleAccessTokenRecoveryMgr::ProcessRecovery(dataMgr, "test");

    EXPECT_EQ(4U, GetInitHapTokenCallCountForTest());
    EXPECT_EQ(1, GetResetDatabaseRecoveryStatusCallCountForTest());
}

/**
 * @tc.number: BmsProcessRecoveryTest_0700
 * @tc.name: test ERR_TOKENID_HAS_EXISTED is treated as success without retry
 * @tc.desc: 1.InitHapToken returns ERR_TOKENID_HAS_EXISTED
 *           2.no retry happens (exactly one call), reset is called
 */
HWTEST_F(BmsProcessRecoveryTest, BmsProcessRecoveryTest_0700, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(DB_ERROR_PARAM, "true");
    auto dataMgr = std::make_shared<BundleDataMgr>();
    AddBundleWithMainToken(dataMgr, TEST_BUNDLE_A, TEST_TOKEN_IDEX);
    PushInitHapTokenResultForTest(AccessTokenError::ERR_TOKENID_HAS_EXISTED);

    BundleAccessTokenRecoveryMgr::ProcessRecovery(dataMgr, "test");

    EXPECT_EQ(1U, GetInitHapTokenCallCountForTest());
    EXPECT_EQ(1, GetResetDatabaseRecoveryStatusCallCountForTest());
}

/**
 * @tc.number: BmsProcessRecoveryTest_0800
 * @tc.name: test retry loop stops as soon as ERR_TOKENID_HAS_EXISTED appears
 * @tc.desc: 1.result sequence is fail, fail, ERR_TOKENID_HAS_EXISTED
 *           2.exactly 3 attempts, no fourth call
 */
HWTEST_F(BmsProcessRecoveryTest, BmsProcessRecoveryTest_0800, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(DB_ERROR_PARAM, "true");
    auto dataMgr = std::make_shared<BundleDataMgr>();
    AddBundleWithMainToken(dataMgr, TEST_BUNDLE_A, TEST_TOKEN_IDEX);
    PushInitHapTokenResultForTest(AccessTokenError::ERR_SERVICE_ABNORMAL);
    PushInitHapTokenResultForTest(AccessTokenError::ERR_SERVICE_ABNORMAL);
    PushInitHapTokenResultForTest(AccessTokenError::ERR_TOKENID_HAS_EXISTED);

    BundleAccessTokenRecoveryMgr::ProcessRecovery(dataMgr, "test");

    EXPECT_EQ(3U, GetInitHapTokenCallCountForTest());
    EXPECT_EQ(1, GetResetDatabaseRecoveryStatusCallCountForTest());
}

/**
 * @tc.number: BmsProcessRecoveryTest_0900
 * @tc.name: test reset failure does not break the flow
 * @tc.desc: 1.ResetDatabaseRecoveryStatus returns an error
 *           2.restore still completed for the app and the flow returns normally
 */
HWTEST_F(BmsProcessRecoveryTest, BmsProcessRecoveryTest_0900, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(DB_ERROR_PARAM, "true");
    auto dataMgr = std::make_shared<BundleDataMgr>();
    AddBundleWithMainToken(dataMgr, TEST_BUNDLE_A, TEST_TOKEN_IDEX);
    SetResetDatabaseRecoveryStatusResultForTest(AccessTokenError::ERR_SERVICE_ABNORMAL);

    BundleAccessTokenRecoveryMgr::ProcessRecovery(dataMgr, "test");

    EXPECT_EQ(1U, GetInitHapTokenCallCountForTest());
    EXPECT_EQ(1, GetResetDatabaseRecoveryStatusCallCountForTest());
}

/**
 * @tc.number: BmsProcessRecoveryTest_1000
 * @tc.name: test mixed results across apps
 * @tc.desc: 1.three bundles processed in map order a/b/c; the mock result queue is consumed in
 *              that same order: a exhausts the four failures, b gets already-exist, c succeeds
 *           2.total InitHapToken calls = 4 + 1 + 1 = 6, reset called exactly once, and a failed
 *              app does not block the remaining apps
 */
HWTEST_F(BmsProcessRecoveryTest, BmsProcessRecoveryTest_1000, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(DB_ERROR_PARAM, "true");
    auto dataMgr = std::make_shared<BundleDataMgr>();
    AddBundleWithMainToken(dataMgr, TEST_BUNDLE_A, TEST_TOKEN_IDEX);
    AddBundleWithMainToken(dataMgr, TEST_BUNDLE_B, TEST_TOKEN_IDEX + 1);
    AddBundleWithMainToken(dataMgr, TEST_BUNDLE_C, TEST_TOKEN_IDEX + 2);
    for (int32_t i = 0; i < 4; ++i) {
        PushInitHapTokenResultForTest(AccessTokenError::ERR_SERVICE_ABNORMAL);  // consumed by bundle a
    }
    PushInitHapTokenResultForTest(AccessTokenError::ERR_TOKENID_HAS_EXISTED);   // consumed by bundle b
    // bundle c: queue drained, mock returns success

    BundleAccessTokenRecoveryMgr::ProcessRecovery(dataMgr, "test");

    EXPECT_EQ(6U, GetInitHapTokenCallCountForTest());
    EXPECT_EQ(1, GetResetDatabaseRecoveryStatusCallCountForTest());
    // Every restored entry must carry its own persisted token id (low 32 bits).
    HapInfoParams first = GetInitHapInfoParamsForTest(0);
    EXPECT_EQ(TEST_TOKEN_ID, first.tokenID);
    HapInfoParams second = GetInitHapInfoParamsForTest(4);
    EXPECT_EQ(TEST_TOKEN_ID + 1, second.tokenID);
    HapInfoParams last = GetInitHapInfoParamsForTest(5);
    EXPECT_EQ(TEST_TOKEN_ID + 2, last.tokenID);
}

/**
 * @tc.number: BmsProcessRecoveryTest_1100
 * @tc.name: test clone app is restored with its own appIndex and token
 * @tc.desc: 1.one bundle holding a main token and a clone token (appIndex 2)
 *           2.two InitHapToken calls in snapshot order: main first (instIndex 0, main token id),
 *              clone second (instIndex 2, clone token id); both carry isRestore=true
 */
HWTEST_F(BmsProcessRecoveryTest, BmsProcessRecoveryTest_1100, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(DB_ERROR_PARAM, "true");
    auto dataMgr = std::make_shared<BundleDataMgr>();
    AddBundleWithMainAndCloneToken(dataMgr, TEST_BUNDLE_A, TEST_TOKEN_IDEX,
        TEST_CLONE_APP_INDEX, TEST_CLONE_TOKEN_IDEX);

    BundleAccessTokenRecoveryMgr::ProcessRecovery(dataMgr, "test");

    EXPECT_EQ(2U, GetInitHapTokenCallCountForTest());
    HapInfoParams main = GetInitHapInfoParamsForTest(0);
    EXPECT_TRUE(main.isRestore);
    EXPECT_EQ(TEST_BUNDLE_A, main.bundleName);
    EXPECT_EQ(TEST_USERID, main.userID);
    EXPECT_EQ(0, main.instIndex);
    EXPECT_EQ(TEST_TOKEN_ID, main.tokenID);
    HapInfoParams clone = GetInitHapInfoParamsForTest(1);
    EXPECT_TRUE(clone.isRestore);
    EXPECT_EQ(TEST_BUNDLE_A, clone.bundleName);
    EXPECT_EQ(TEST_CLONE_APP_INDEX, clone.instIndex);
    EXPECT_EQ(TEST_CLONE_TOKEN_ID, clone.tokenID);
    EXPECT_EQ(1, GetResetDatabaseRecoveryStatusCallCountForTest());
}

/**
 * @tc.number: BmsProcessRecoveryTest_1200
 * @tc.name: test retry does not depend on the error code
 * @tc.desc: 1.first InitHapToken returns ERR_PERMISSION_DENIED (not ERR_SERVICE_ABNORMAL)
 *           2.the attempt is still retried and succeeds on the second call (exactly 2 calls),
 *              pinning the "retry regardless of the error code" contract
 */
HWTEST_F(BmsProcessRecoveryTest, BmsProcessRecoveryTest_1200, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(DB_ERROR_PARAM, "true");
    auto dataMgr = std::make_shared<BundleDataMgr>();
    AddBundleWithMainToken(dataMgr, TEST_BUNDLE_A, TEST_TOKEN_IDEX);
    PushInitHapTokenResultForTest(AccessTokenError::ERR_PERMISSION_DENIED);

    BundleAccessTokenRecoveryMgr::ProcessRecovery(dataMgr, "test");

    EXPECT_EQ(2U, GetInitHapTokenCallCountForTest());
    EXPECT_EQ(1, GetResetDatabaseRecoveryStatusCallCountForTest());
}

/**
 * @tc.number: BmsProcessRecoveryTest_1300
 * @tc.name: test second mount point is a no-op after a successful first one
 * @tc.desc: 1.recovery succeeds on mount 1 and ResetDatabaseRecoveryStatus clears the marker
 *              (the mock mirrors the access_token service contract: success sets dberror to 0)
 *           2.mount 2 short-circuits on NeedRecovery: no extra InitHapToken, no extra reset,
 *              which is the latch that makes the two startup mount points idempotent
 */
HWTEST_F(BmsProcessRecoveryTest, BmsProcessRecoveryTest_1300, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(DB_ERROR_PARAM, "true");
    auto dataMgr = std::make_shared<BundleDataMgr>();
    AddBundleWithMainToken(dataMgr, TEST_BUNDLE_A, TEST_TOKEN_IDEX);

    BundleAccessTokenRecoveryMgr::ProcessRecovery(dataMgr, "OnBmsStarting");

    EXPECT_EQ(1U, GetInitHapTokenCallCountForTest());
    EXPECT_EQ(1, GetResetDatabaseRecoveryStatusCallCountForTest());
    EXPECT_FALSE(OHOS::system::GetBoolParameter(DB_ERROR_PARAM, false));

    BundleAccessTokenRecoveryMgr::ProcessRecovery(dataMgr, "AfterBmsStart");

    EXPECT_EQ(1U, GetInitHapTokenCallCountForTest());
    EXPECT_EQ(1, GetResetDatabaseRecoveryStatusCallCountForTest());
}

/**
 * @tc.number: BmsProcessRecoveryTest_1400
 * @tc.name: test reset failure leaves the marker set so the next mount re-enters
 * @tc.desc: 1.mount 1 restores the app but ResetDatabaseRecoveryStatus fails, so dberror stays
 *              set (the access_token service only clears it on success)
 *           2.mount 2 runs the full pass again (one extra restore) and the now-successful reset
 *              clears the marker: the two mounts converge without breaking startup
 */
HWTEST_F(BmsProcessRecoveryTest, BmsProcessRecoveryTest_1400, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(DB_ERROR_PARAM, "true");
    auto dataMgr = std::make_shared<BundleDataMgr>();
    AddBundleWithMainToken(dataMgr, TEST_BUNDLE_A, TEST_TOKEN_IDEX);
    SetResetDatabaseRecoveryStatusResultForTest(AccessTokenError::ERR_SERVICE_ABNORMAL);

    BundleAccessTokenRecoveryMgr::ProcessRecovery(dataMgr, "OnBmsStarting");

    EXPECT_EQ(1U, GetInitHapTokenCallCountForTest());
    EXPECT_EQ(1, GetResetDatabaseRecoveryStatusCallCountForTest());
    EXPECT_TRUE(OHOS::system::GetBoolParameter(DB_ERROR_PARAM, false));

    SetResetDatabaseRecoveryStatusResultForTest(0);
    BundleAccessTokenRecoveryMgr::ProcessRecovery(dataMgr, "AfterBmsStart");

    EXPECT_EQ(2U, GetInitHapTokenCallCountForTest());
    EXPECT_EQ(2, GetResetDatabaseRecoveryStatusCallCountForTest());
    EXPECT_FALSE(OHOS::system::GetBoolParameter(DB_ERROR_PARAM, false));
}

/**
 * @tc.number: BmsProcessRecoveryTest_1500
 * @tc.name: test provision lookup failure degrades to empty capabilities but still restores
 * @tc.desc: 1.in this unit environment GetAppProvisionInfo cannot succeed (no registered user,
 *              no provision storage), so RestoreSingleApp passes an empty capability string
 *           2.the captured policy has an empty aclExtendedMap and the restore itself succeeds
 */
HWTEST_F(BmsProcessRecoveryTest, BmsProcessRecoveryTest_1500, Function | SmallTest | Level0)
{
    OHOS::system::SetParameter(DB_ERROR_PARAM, "true");
    auto dataMgr = std::make_shared<BundleDataMgr>();
    AddBundleWithMainToken(dataMgr, TEST_BUNDLE_A, TEST_TOKEN_IDEX);

    BundleAccessTokenRecoveryMgr::ProcessRecovery(dataMgr, "test");

    EXPECT_EQ(1U, GetInitHapTokenCallCountForTest());
    HapPolicyParams policy = GetInitHapPolicyParamsForTest(0);
    EXPECT_TRUE(policy.aclExtendedMap.empty());
    HapInfoParams captured = GetInitHapInfoParamsForTest(0);
    EXPECT_TRUE(captured.isRestore);
    EXPECT_EQ(1, GetResetDatabaseRecoveryStatusCallCountForTest());
}

/**
 * @tc.number: BmsProcessRecoveryTest_1600
 * @tc.name: test an entry whose bundle is gone at fetch time is not restored
 * @tc.desc: 1.calls RestoreSingleApp directly with a bundleName absent from bundleInfos_ (the
 *              defensive fetch-failure branch: snapshot and fetch read the same map, so the
 *              public single-threaded ProcessRecovery path cannot reach it)
 *           2.returns failure, alreadyExist stays false and InitHapToken is never reached
 */
HWTEST_F(BmsProcessRecoveryTest, BmsProcessRecoveryTest_1600, Function | SmallTest | Level0)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    AccessTokenRestoreInfo restoreInfo;
    restoreInfo.bundleName = TEST_BUNDLE_MISSING;
    restoreInfo.userId = TEST_USERID;
    restoreInfo.appIndex = 0;
    restoreInfo.accessTokenIdEx = TEST_TOKEN_IDEX;

    bool alreadyExist = false;
    int32_t ret = BundleAccessTokenRecoveryMgr::RestoreSingleApp(dataMgr, restoreInfo, alreadyExist);

    EXPECT_NE(ERR_OK, ret);
    EXPECT_FALSE(alreadyExist);
    EXPECT_EQ(0U, GetInitHapTokenCallCountForTest());
}
