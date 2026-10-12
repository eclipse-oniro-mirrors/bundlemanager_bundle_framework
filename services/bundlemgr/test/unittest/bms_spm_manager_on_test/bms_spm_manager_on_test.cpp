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

#include "access_token_error.h"
#include "appexecfwk_errors.h"
#include "bundle_install_checker.h"
#include "bundle_spm_manager.h"
#include "inner_bundle_info.h"
#include "parameters.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

// Counting stub accessors defined in test/mock/src/installd_client.cpp.
namespace OHOS {
namespace AppExecFwk {
void ResetClearSessionProvisionCacheCountForTest();
int32_t GetClearSessionProvisionCacheCountForTest();
extern int32_t g_clearSessionProvisionCacheRet;
} // namespace AppExecFwk

// SPM control variables and resetter defined in test/mock/src/accesstoken_kit.cpp.
namespace Security {
namespace AccessToken {
extern int32_t g_spmCheckHapSignInfoRet;
extern int32_t g_spmCheckHapSignInfoSessionId;
extern std::vector<TrustedBundleInfo> g_spmTrustedBundleInfos;
extern int32_t g_spmCheckHapPermissionInfoRet;
extern int32_t g_spmCheckHapPermissionInfoCallCount;
extern int32_t g_spmPrepareHapIdentityRet;
extern uint64_t g_spmPrepareIdentityTokenId;
extern int32_t g_spmPrepareIdentityUid;
extern int32_t g_spmUpdateHapPolicyRet;
extern int32_t g_spmFinishInstallRet;
extern int32_t g_spmFinishInstallCallCount;
extern bool g_spmFinishInstallLastPersistent;
void ResetSpmKitMockValuesForTest();
} // namespace AccessToken
} // namespace Security

// Legacy facade control variables defined in test/mock/src/bundle_permission_mgr.cpp.
void ResetSpmFacadeMockValues();
extern int32_t g_testVerifyPermission;
extern int32_t g_initHapTokenRet;
extern int32_t g_updateHapTokenRet;
extern bool g_updateHapTokenDataRefresh;
} // namespace OHOS

namespace {
const std::string BUNDLE_NAME = "com.ohos.spm.on.test";
const std::string PERMISSION_NAME = "ohos.permission.TEST_PERMISSION";
const std::string SPM_ENABLE_PARAM = "persist.bms.spm.enable";
constexpr int32_t TEST_USERID = 100;
constexpr int32_t TEST_SESSION_ID = 56789;
constexpr uint64_t TEST_IDENTITY_TOKENID = 101;
constexpr int32_t TEST_IDENTITY_UID = 102;
constexpr int32_t TEST_EXISTING_UID = 9999;
constexpr int32_t TEST_CLONE_UID = 1042;
constexpr int64_t TEST_INSTALL_TIME = 555;
} // namespace

namespace OHOS {

class BmsSpmManagerOnTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        // Must run before the first BundleSpmManager::IsEnabled() call in this
        // process: the switch is cached in a function-local static. This target
        // must NOT define GET_BOOL_PARAMETER_TRUE (it would flip unrelated params).
        OHOS::system::SetParameter(SPM_ENABLE_PARAM, "true");
    };
    static void TearDownTestCase() {};
    void SetUp() override
    {
        OHOS::ResetSpmFacadeMockValues();
        OHOS::Security::AccessToken::ResetSpmKitMockValuesForTest();
        OHOS::AppExecFwk::ResetClearSessionProvisionCacheCountForTest();
    };
    void TearDown() override {};
};

/**
 * @tc.number: BmsSpmManagerOnTest.IsEnabled_0001
 * @tc.name: IsEnabled under SPM ON
 * @tc.desc: The switch parameter set in SetUpTestCase makes IsEnabled return true
 *           for the whole process.
 */
HWTEST_F(BmsSpmManagerOnTest, IsEnabled_0001, Function | MediumTest | Level1)
{
    EXPECT_TRUE(BundleSpmManager::IsEnabled());
}

/**
 * @tc.number: BmsSpmManagerOnTest.CheckSignAndInitSession_ActiveSession_0001
 * @tc.name: CheckSignAndInitSession with an active session
 * @tc.desc: A successful CheckHapSignInfo allocates the session id. These tests
 *           construct active sessions with an empty hap list (no real hap files
 *           in unit tests); the count contract is pinned by the mismatch tests.
 */
HWTEST_F(BmsSpmManagerOnTest, CheckSignAndInitSession_ActiveSession_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;
    BundleInstallChecker checker;
    ErrCode errCode = ERR_OK;
    auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {}, false, checker, errCode, true, false);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_TRUE(session.IsActive());
    EXPECT_EQ(session.GetSessionId(), TEST_SESSION_ID);
    std::vector<Security::Verify::HapVerifyResult> results;
    EXPECT_FALSE(session.GetHapVerifyResults(results));
}

/**
 * @tc.number: BmsSpmManagerOnTest.CheckSignAndInitSession_Failure_0001
 * @tc.name: CheckSignAndInitSession failure passthrough
 * @tc.desc: A failed CheckHapSignInfo converts to the bundle signature error and
 *           returns an empty session.
 */
HWTEST_F(BmsSpmManagerOnTest, CheckSignAndInitSession_Failure_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoRet = -1;
    BundleInstallChecker checker;
    ErrCode errCode = ERR_OK;
    auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {}, false, checker, errCode, true, false);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE);
    EXPECT_FALSE(session.IsActive());
    EXPECT_EQ(session.GetSessionId(), 0);
}

/**
 * @tc.number: BmsSpmManagerOnTest.InitToken_DeferredSession_0001
 * @tc.name: InitToken on a deferred session goes through the AT session path
 * @tc.desc: Under SPM ON there is no deferred degradation anymore: a session id 0
 *           makes the AT side allocate the session; failures are passed through.
 */
HWTEST_F(BmsSpmManagerOnTest, InitToken_DeferredSession_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmPrepareHapIdentityRet = -2;
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    InnerBundleInfo info;
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    Security::AccessToken::HapInfoCheckResult checkResult;
    EXPECT_EQ(session.InitToken(info, TEST_USERID, 0, tokenIdEx, checkResult, "", nullptr, false), -2);
}

/**
 * @tc.number: BmsSpmManagerOnTest.InitToken_DeferredSession_0002
 * @tc.name: InitToken on a deferred session succeeds via the AT path
 * @tc.desc: Under SPM ON the deferred session takes the AT identity path; no
 *           FinishInstall is issued by InitToken itself.
 */
HWTEST_F(BmsSpmManagerOnTest, InitToken_DeferredSession_0002, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmPrepareIdentityTokenId = TEST_IDENTITY_TOKENID;
    OHOS::Security::AccessToken::g_spmPrepareIdentityUid = TEST_IDENTITY_UID;
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    Security::AccessToken::HapInfoCheckResult checkResult;
    EXPECT_EQ(session.InitToken(info, TEST_USERID, 0, tokenIdEx, checkResult, "", nullptr, false),
        ERR_OK);
    EXPECT_EQ(tokenIdEx.tokenIDEx, TEST_IDENTITY_TOKENID);
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 0);
}

/**
 * @tc.number: BmsSpmManagerOnTest.InitToken_ActiveSession_0001
 * @tc.name: InitToken with an active session
 * @tc.desc: PrepareHapIdentity provides the token id and the AT-allocated uid;
 *           the uid/gids of the user info are persisted (no local re-allocation
 *           drift — under SPM ON GenerateUidAndGid never allocates from the
 *           bundle-id counter, an INVALID uid reaching it fails fast).
 */
HWTEST_F(BmsSpmManagerOnTest, InitToken_ActiveSession_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;
    OHOS::Security::AccessToken::g_spmPrepareIdentityTokenId = TEST_IDENTITY_TOKENID;
    OHOS::Security::AccessToken::g_spmPrepareIdentityUid = TEST_IDENTITY_UID;
    BundleInstallChecker checker;
    ErrCode errCode = ERR_OK;
    auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {}, false, checker, errCode, true, false);
    ASSERT_EQ(errCode, ERR_OK);

    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    Security::AccessToken::HapInfoCheckResult checkResult;
    EXPECT_EQ(session.InitToken(info, TEST_USERID, 0, tokenIdEx, checkResult, "", nullptr, false),
        ERR_OK);
    EXPECT_EQ(tokenIdEx.tokenIDEx, TEST_IDENTITY_TOKENID);
    InnerBundleUserInfo userInfo;
    ASSERT_TRUE(info.GetInnerBundleUserInfo(TEST_USERID, userInfo));
    // fresh install: the AT allocated uid is persisted (no local re-allocation drift)
    EXPECT_EQ(userInfo.uid, TEST_IDENTITY_UID);
    ASSERT_EQ(userInfo.gids.size(), 1);
    EXPECT_EQ(userInfo.gids.front(), TEST_IDENTITY_UID);
}

/**
 * @tc.number: BmsSpmManagerOnTest.InitToken_ActiveSession_0002
 * @tc.name: InitToken preserves an existing user info
 * @tc.desc: An existing user info with a valid uid is never overwritten by the
 *           AT identity (keep-data re-install keeps uid/installTime/flags).
 */
HWTEST_F(BmsSpmManagerOnTest, InitToken_ActiveSession_0002, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;
    OHOS::Security::AccessToken::g_spmPrepareIdentityTokenId = TEST_IDENTITY_TOKENID;
    OHOS::Security::AccessToken::g_spmPrepareIdentityUid = TEST_IDENTITY_UID;
    BundleInstallChecker checker;
    ErrCode errCode = ERR_OK;
    auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {}, false, checker, errCode, true, false);
    ASSERT_EQ(errCode, ERR_OK);

    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    InnerBundleUserInfo existing;
    existing.bundleUserInfo.userId = TEST_USERID;
    existing.bundleName = BUNDLE_NAME;
    existing.uid = TEST_EXISTING_UID;
    existing.installTime = TEST_INSTALL_TIME;
    existing.isBundleFirstLaunched = true;
    info.AddInnerBundleUserInfo(existing);

    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    Security::AccessToken::HapInfoCheckResult checkResult;
    EXPECT_EQ(session.InitToken(info, TEST_USERID, 0, tokenIdEx, checkResult, "", nullptr, false),
        ERR_OK);
    InnerBundleUserInfo userInfo;
    ASSERT_TRUE(info.GetInnerBundleUserInfo(TEST_USERID, userInfo));
    EXPECT_EQ(userInfo.uid, TEST_EXISTING_UID);
    EXPECT_EQ(userInfo.installTime, TEST_INSTALL_TIME);
    EXPECT_TRUE(userInfo.isBundleFirstLaunched);
}

/**
 * @tc.number: BmsSpmManagerOnTest.InitToken_ActiveSession_0003
 * @tc.name: InitToken fills an unallocated uid with the AT identity uid
 * @tc.desc: An existing user info whose uid is still INVALID_UID is filled with
 *           the AT-allocated uid; the other fields are preserved (under SPM ON
 *           the local bundle-id counter never allocates the uid).
 */
HWTEST_F(BmsSpmManagerOnTest, InitToken_ActiveSession_0003, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;
    OHOS::Security::AccessToken::g_spmPrepareIdentityTokenId = TEST_IDENTITY_TOKENID;
    OHOS::Security::AccessToken::g_spmPrepareIdentityUid = TEST_IDENTITY_UID;
    BundleInstallChecker checker;
    ErrCode errCode = ERR_OK;
    auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {}, false, checker, errCode, true, false);
    ASSERT_EQ(errCode, ERR_OK);

    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    InnerBundleUserInfo existing;  // uid keeps the INVALID_UID default
    existing.bundleUserInfo.userId = TEST_USERID;
    existing.bundleName = BUNDLE_NAME;
    existing.installTime = TEST_INSTALL_TIME;
    info.AddInnerBundleUserInfo(existing);

    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    Security::AccessToken::HapInfoCheckResult checkResult;
    EXPECT_EQ(session.InitToken(info, TEST_USERID, 0, tokenIdEx, checkResult, "", nullptr, false),
        ERR_OK);
    InnerBundleUserInfo userInfo;
    ASSERT_TRUE(info.GetInnerBundleUserInfo(TEST_USERID, userInfo));
    // unallocated local uid: the AT allocated uid fills it, other fields preserved
    EXPECT_EQ(userInfo.uid, TEST_IDENTITY_UID);
    ASSERT_EQ(userInfo.gids.size(), 1);
    EXPECT_EQ(userInfo.gids.front(), TEST_IDENTITY_UID);
    EXPECT_EQ(userInfo.installTime, TEST_INSTALL_TIME);
}

/**
 * @tc.number: BmsSpmManagerOnTest.InitToken_ActiveSession_0004
 * @tc.name: InitToken failure passthrough
 * @tc.desc: A failed PrepareHapIdentity returns the raw AT error code.
 */
HWTEST_F(BmsSpmManagerOnTest, InitToken_ActiveSession_0004, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;
    OHOS::Security::AccessToken::g_spmPrepareHapIdentityRet = -3;
    BundleInstallChecker checker;
    ErrCode errCode = ERR_OK;
    auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {}, false, checker, errCode, true, false);
    ASSERT_EQ(errCode, ERR_OK);

    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    Security::AccessToken::HapInfoCheckResult checkResult;
    EXPECT_EQ(session.InitToken(info, TEST_USERID, 0, tokenIdEx, checkResult, "", nullptr, false),
        -3);
}

/**
 * @tc.number: BmsSpmManagerOnTest.UpdateToken_DeferredSession_0001
 * @tc.name: UpdateToken on a deferred session goes through UpdateHapPolicy
 * @tc.desc: Under SPM ON there is no deferred degradation anymore.
 */
HWTEST_F(BmsSpmManagerOnTest, UpdateToken_DeferredSession_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmUpdateHapPolicyRet = -3;
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    InnerBundleInfo info;
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIdExStruct.tokenID = 1;
    Security::AccessToken::HapInfoCheckResult checkResult;
    EXPECT_EQ(session.UpdateToken(tokenIdEx, info, TEST_USERID, checkResult, "", true, false), -3);
}

/**
 * @tc.number: BmsSpmManagerOnTest.UpdateToken_ActiveSession_0001
 * @tc.name: UpdateToken with an active session
 * @tc.desc: UpdateHapPolicy failure is passed through as the raw AT error code.
 */
HWTEST_F(BmsSpmManagerOnTest, UpdateToken_ActiveSession_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;
    OHOS::Security::AccessToken::g_spmUpdateHapPolicyRet = -6;
    BundleInstallChecker checker;
    ErrCode errCode = ERR_OK;
    auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {}, false, checker, errCode, true, false);
    ASSERT_EQ(errCode, ERR_OK);

    InnerBundleInfo info;
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIdExStruct.tokenID = 1;
    Security::AccessToken::HapInfoCheckResult checkResult;
    EXPECT_EQ(session.UpdateToken(tokenIdEx, info, TEST_USERID, checkResult, "", true, false), -6);
}

/**
 * @tc.number: BmsSpmManagerOnTest.CheckPermissionInfo_DeferredSession_0001
 * @tc.name: CheckPermissionInfo on a deferred session invokes the AT API
 * @tc.desc: Under SPM ON there is no deferred degradation anymore.
 */
HWTEST_F(BmsSpmManagerOnTest, CheckPermissionInfo_DeferredSession_0001, Function | MediumTest | Level1)
{
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    Security::AccessToken::HapInfoCheckResult checkResult;
    EXPECT_EQ(session.CheckPermissionInfo(Security::AccessToken::InstallTypeEnum::TYPE_INSTALL,
        checkResult), ERR_OK);
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmCheckHapPermissionInfoCallCount, 1);
}

/**
 * @tc.number: BmsSpmManagerOnTest.CheckPermissionInfo_ActiveSession_0001
 * @tc.name: CheckPermissionInfo with an active session
 * @tc.desc: The session pre-check result is passed through.
 */
HWTEST_F(BmsSpmManagerOnTest, CheckPermissionInfo_ActiveSession_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;
    OHOS::Security::AccessToken::g_spmCheckHapPermissionInfoRet = -7;
    BundleInstallChecker checker;
    ErrCode errCode = ERR_OK;
    auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {}, false, checker, errCode, true, false);
    ASSERT_EQ(errCode, ERR_OK);

    Security::AccessToken::HapInfoCheckResult checkResult;
    EXPECT_EQ(session.CheckPermissionInfo(Security::AccessToken::InstallTypeEnum::TYPE_REPLACE,
        checkResult), -7);
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmCheckHapPermissionInfoCallCount, 1);
}

/**
 * @tc.number: BmsSpmManagerOnTest.VerifyPermission_DeferredSession_0001
 * @tc.name: VerifyPermission on a deferred session queries the session policy
 * @tc.desc: Under SPM ON there is no deferred degradation anymore: a permission
 *           not in the (empty) session policy is denied.
 */
HWTEST_F(BmsSpmManagerOnTest, VerifyPermission_DeferredSession_0001, Function | MediumTest | Level1)
{
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    EXPECT_EQ(session.VerifyPermission(BUNDLE_NAME, PERMISSION_NAME, TEST_USERID), -1);
}

/**
 * @tc.number: BmsSpmManagerOnTest.Commit_DeferredSession_0001
 * @tc.name: Commit on a deferred session issues no FinishInstall
 * @tc.desc: Under SPM ON a session that never engaged the AT side (id 0) has
 *           nothing to finish: FinishHapInstall short-circuits on session id 0
 *           and no FinishInstall IPC is issued.
 */
HWTEST_F(BmsSpmManagerOnTest, Commit_DeferredSession_0001, Function | MediumTest | Level1)
{
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    EXPECT_EQ(session.Commit({}), ERR_OK);
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 0);
}

/**
 * @tc.number: BmsSpmManagerOnTest.Commit_Success_0001
 * @tc.name: Commit success
 * @tc.desc: A successful commit finishes the session persistently and clears the
 *           installd provision cache.
 */
HWTEST_F(BmsSpmManagerOnTest, Commit_Success_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;
    BundleInstallChecker checker;
    ErrCode errCode = ERR_OK;
    auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {}, false, checker, errCode, true, false);
    ASSERT_EQ(errCode, ERR_OK);

    EXPECT_EQ(session.Commit({}), ERR_OK);
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 1);
    EXPECT_TRUE(OHOS::Security::AccessToken::g_spmFinishInstallLastPersistent);
    EXPECT_EQ(OHOS::AppExecFwk::GetClearSessionProvisionCacheCountForTest(), 1);
}

/**
 * @tc.number: BmsSpmManagerOnTest.Commit_Failure_DestructorRollback_0001
 * @tc.name: A failed commit is rolled back by the destructor
 * @tc.desc: A failed commit fails the install, so the failure path must roll the
 *           session back: the destructor finishes it with isPersistent=false.
 */
HWTEST_F(BmsSpmManagerOnTest, Commit_Failure_DestructorRollback_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;
    OHOS::Security::AccessToken::g_spmFinishInstallRet = -5;
    {
        BundleInstallChecker checker;
        ErrCode errCode = ERR_OK;
        auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
            TEST_USERID, {}, false, checker, errCode, true, false);
        ASSERT_EQ(errCode, ERR_OK);

        EXPECT_EQ(session.Commit({}), -5);
        EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 1);
        // The session reached its end even on failure: the installd provision
        // cache is still dropped so nothing leaks in the privileged process.
        EXPECT_EQ(OHOS::AppExecFwk::GetClearSessionProvisionCacheCountForTest(), 1);
    }  // session destroyed here: un-committed, so the destructor rolls it back
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 2);
    EXPECT_FALSE(OHOS::Security::AccessToken::g_spmFinishInstallLastPersistent);
}

/**
 * @tc.number: BmsSpmManagerOnTest.Rollback_ExplicitAfterFailedCommit_0001
 * @tc.name: Explicit rollback still works after a failed commit
 * @tc.desc: An explicit Rollback() call (install failure path) finishes the
 *           session with isPersistent=false; the destructor adds no second call.
 */
HWTEST_F(BmsSpmManagerOnTest, Rollback_ExplicitAfterFailedCommit_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;
    OHOS::Security::AccessToken::g_spmFinishInstallRet = -5;
    {
        BundleInstallChecker checker;
        ErrCode errCode = ERR_OK;
        auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
            TEST_USERID, {}, false, checker, errCode, true, false);
        ASSERT_EQ(errCode, ERR_OK);

        EXPECT_EQ(session.Commit({}), -5);
        EXPECT_EQ(session.Rollback(), -5);
        EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 2);
        EXPECT_FALSE(OHOS::Security::AccessToken::g_spmFinishInstallLastPersistent);
    }  // session destroyed here
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 2);
}

/**
 * @tc.number: BmsSpmManagerOnTest.Destructor_Rollback_WithoutCommit_0001
 * @tc.name: Destructor rolls back an uncommitted session
 * @tc.desc: Without any commit attempt the destructor still finishes the session
 *           with isPersistent=false (classic RAII rollback).
 */
HWTEST_F(BmsSpmManagerOnTest, Destructor_Rollback_WithoutCommit_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;
    {
        BundleInstallChecker checker;
        ErrCode errCode = ERR_OK;
        auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
            TEST_USERID, {}, false, checker, errCode, true, false);
        ASSERT_EQ(errCode, ERR_OK);
        EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 0);
    }  // session destroyed here
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 1);
    EXPECT_FALSE(OHOS::Security::AccessToken::g_spmFinishInstallLastPersistent);
}

/**
 * @tc.number: BmsSpmManagerOnTest.MoveAssign_RollbackAfterFailedCommit_0001
 * @tc.name: Move assignment rolls back an un-committed session
 * @tc.desc: ResetInstallProperties swaps in a deferred session via move
 *           assignment; a failed (un-committed) session is rolled back by the
 *           assignment, keeping the AT side consistent with the failed install.
 */
HWTEST_F(BmsSpmManagerOnTest, MoveAssign_RollbackAfterFailedCommit_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;
    OHOS::Security::AccessToken::g_spmFinishInstallRet = -5;
    BundleInstallChecker checker;
    ErrCode errCode = ERR_OK;
    auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {}, false, checker, errCode, true, false);
    ASSERT_EQ(errCode, ERR_OK);

    EXPECT_EQ(session.Commit({}), -5);
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 1);
    session = BundleSpmManager::InstallSession::CreateDeferred();
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 2);
    EXPECT_FALSE(OHOS::Security::AccessToken::g_spmFinishInstallLastPersistent);
    EXPECT_FALSE(session.IsActive());
}

/**
 * @tc.number: BmsSpmManagerOnTest.Destructor_Rollback_WithoutCommit_0002
 * @tc.name: Move assignment still rolls back an uncommitted session
 * @tc.desc: Without a commit attempt, assigning a new session rolls the old one
 *           back (classic ResetInstallProperties behavior).
 */
HWTEST_F(BmsSpmManagerOnTest, Destructor_Rollback_WithoutCommit_0002, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;
    BundleInstallChecker checker;
    ErrCode errCode = ERR_OK;
    auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {}, false, checker, errCode, true, false);
    ASSERT_EQ(errCode, ERR_OK);

    session = BundleSpmManager::InstallSession::CreateDeferred();
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 1);
    EXPECT_FALSE(OHOS::Security::AccessToken::g_spmFinishInstallLastPersistent);
}

/**
 * @tc.number: BmsSpmManagerOnTest.Rollback_Success_StopsDestructorRollback_0001
 * @tc.name: A successful explicit rollback is not repeated by the destructor
 * @tc.desc: plugin/shared installers roll back explicitly on their success paths;
 *           after a successful rollback the destructor must not finish the same
 *           session a second time.
 */
HWTEST_F(BmsSpmManagerOnTest, Rollback_Success_StopsDestructorRollback_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;
    {
        BundleInstallChecker checker;
        ErrCode errCode = ERR_OK;
        auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
            TEST_USERID, {}, false, checker, errCode, true, false);
        ASSERT_EQ(errCode, ERR_OK);

        EXPECT_EQ(session.Rollback(), ERR_OK);
        EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 1);
        EXPECT_FALSE(OHOS::Security::AccessToken::g_spmFinishInstallLastPersistent);
        EXPECT_FALSE(session.IsActive());
    }  // session destroyed here
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 1);
}

/**
 * @tc.number: BmsSpmManagerOnTest.IsRecoverableSpmError_0001
 * @tc.name: IsRecoverableSpmError semantics under SPM ON
 * @tc.desc: Only the two AT recovery codes (uid missing / leftover identity) are
 *           recoverable; other codes keep the wrapped BMS error contract.
 */
HWTEST_F(BmsSpmManagerOnTest, IsRecoverableSpmError_0001, Function | MediumTest | Level1)
{
    EXPECT_TRUE(BundleSpmManager::IsRecoverableSpmError(
        Security::AccessToken::AccessTokenError::ERR_UID_NOT_EXIST));
    EXPECT_TRUE(BundleSpmManager::IsRecoverableSpmError(
        Security::AccessToken::AccessTokenError::ERR_BUNDLE_ALREADY_EXIST));
    EXPECT_FALSE(BundleSpmManager::IsRecoverableSpmError(0));
    EXPECT_FALSE(BundleSpmManager::IsRecoverableSpmError(-1));
}

/**
 * @tc.number: BmsSpmManagerOnTest.CheckSignAndInitSession_TrustedInfoParseFailure_0001
 * @tc.name: CheckSignAndInitSession fails on an unparsable provision
 * @tc.desc: An injected trusted bundle info whose provision raw cannot be parsed
 *           fails the session creation with the signature error.
 */
HWTEST_F(BmsSpmManagerOnTest, CheckSignAndInitSession_TrustedInfoParseFailure_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;
    Security::AccessToken::TrustedBundleInfo tbi;
    tbi.profileData.provisionRaw = "not-a-provision-json";
    tbi.profileData.profileBlock = {0x01, 0x02};
    tbi.profileData.profileBlockLength = 2;
    OHOS::Security::AccessToken::g_spmTrustedBundleInfos.push_back(tbi);
    BundleInstallChecker checker;
    ErrCode errCode = ERR_OK;
    auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {"/data/test/one.hap"}, false, checker, errCode, true, false);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE);
    EXPECT_FALSE(session.IsActive());
    // The AT session allocated by CheckHapSignInfo is rolled back, not leaked.
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 1);
    EXPECT_FALSE(OHOS::Security::AccessToken::g_spmFinishInstallLastPersistent);
}

/**
 * @tc.number: BmsSpmManagerOnTest.CheckSignAndInitSession_CountMismatch_0001
 * @tc.name: CheckSignAndInitSession fails when the trusted info count mismatches the hap count
 * @tc.desc: The AT side must return exactly one entry per hap; a short list fails
 *           closed instead of letting downstream path-indexed accesses read OOB.
 */
HWTEST_F(BmsSpmManagerOnTest, CheckSignAndInitSession_CountMismatch_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;
    Security::AccessToken::TrustedBundleInfo tbi;
    tbi.profileData.provisionRaw = "not-a-provision-json";
    OHOS::Security::AccessToken::g_spmTrustedBundleInfos.push_back(tbi);
    BundleInstallChecker checker;
    ErrCode errCode = ERR_OK;
    auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {"/data/test/one.hap", "/data/test/two.hap"}, false, checker, errCode, true,
        false);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE);
    EXPECT_FALSE(session.IsActive());
    // The AT session allocated by CheckHapSignInfo is rolled back, not leaked.
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 1);
    EXPECT_FALSE(OHOS::Security::AccessToken::g_spmFinishInstallLastPersistent);
}

/**
 * @tc.number: BmsSpmManagerOnTest.CheckSignAndInitSession_Failure_NoSessionLeak_0001
 * @tc.name: A failed CheckHapSignInfo leaves no AT session operation
 * @tc.desc: When the verification itself fails, no FinishInstall rollback is
 *           issued (the AT side owns the cleanup of its failed session).
 */
HWTEST_F(BmsSpmManagerOnTest, CheckSignAndInitSession_Failure_NoSessionLeak_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoRet = -1;
    BundleInstallChecker checker;
    ErrCode errCode = ERR_OK;
    auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {}, false, checker, errCode, true, false);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE);
    EXPECT_FALSE(session.IsActive());
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 0);
}

/**
 * @tc.number: BmsSpmManagerOnTest.CheckSignAndInitSession_ConvertResultCode_0001
 * @tc.name: CheckHapSignInfo result code conversion
 * @tc.desc: ERR_PARAM_INVALID maps to the BMS param error; ERR_BUNDLE_ALREADY_EXIST
 *           is passed through raw so the InstallBundle recovery chain can detect
 *           it; unknown codes fold into the signature verification failure.
 */
HWTEST_F(BmsSpmManagerOnTest, CheckSignAndInitSession_ConvertResultCode_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoRet =
        Security::AccessToken::AccessTokenError::ERR_PARAM_INVALID;
    BundleInstallChecker checker;
    ErrCode errCode = ERR_OK;
    auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {}, false, checker, errCode, true, false);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
    EXPECT_FALSE(session.IsActive());

    OHOS::Security::AccessToken::g_spmCheckHapSignInfoRet =
        Security::AccessToken::AccessTokenError::ERR_BUNDLE_ALREADY_EXIST;
    errCode = ERR_OK;
    session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {}, false, checker, errCode, true, false);
    EXPECT_EQ(errCode, Security::AccessToken::AccessTokenError::ERR_BUNDLE_ALREADY_EXIST);
    EXPECT_FALSE(session.IsActive());
}

/**
 * @tc.number: BmsSpmManagerOnTest.WrapRecoverableSpmErrorCode_0001
 * @tc.name: WrapRecoverableSpmErrorCode under SPM ON
 * @tc.desc: The two AT recovery codes are wrapped into the registered BMS install
 *           error; other codes pass through unchanged.
 */
HWTEST_F(BmsSpmManagerOnTest, WrapRecoverableSpmErrorCode_0001, Function | MediumTest | Level1)
{
    EXPECT_EQ(BundleSpmManager::WrapRecoverableSpmErrorCode(
        Security::AccessToken::AccessTokenError::ERR_UID_NOT_EXIST),
        ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED);
    EXPECT_EQ(BundleSpmManager::WrapRecoverableSpmErrorCode(
        Security::AccessToken::AccessTokenError::ERR_BUNDLE_ALREADY_EXIST),
        ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED);
    EXPECT_EQ(BundleSpmManager::WrapRecoverableSpmErrorCode(ERR_APPEXECFWK_INSTALL_PARAM_ERROR),
        ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
}

/**
 * @tc.number: BmsSpmManagerOnTest.FillProvisionProfileBlock_0001
 * @tc.name: The profile block vector is the length single source of truth
 * @tc.desc: An inconsistent claimed length from the AT side is clamped to the
 *           actual vector size and the content is deep-copied (out-of-bound
 *           read guard of the heap overflow fix).
 */
HWTEST_F(BmsSpmManagerOnTest, FillProvisionProfileBlock_0001, Function | MediumTest | Level1)
{
    Security::AccessToken::ProfileData profileData;
    profileData.profileBlock = {0x01, 0x02};
    profileData.profileBlockLength = 100;  // claimed length inconsistent with the block
    Security::Verify::ProvisionInfo provisionInfo;
    EXPECT_TRUE(BundleSpmManager::FillProvisionProfileBlock(profileData, provisionInfo));
    EXPECT_EQ(provisionInfo.profileBlockLength, 2);
    ASSERT_NE(provisionInfo.profileBlock, nullptr);
    EXPECT_EQ(provisionInfo.profileBlock.get()[0], 0x01);
    EXPECT_EQ(provisionInfo.profileBlock.get()[1], 0x02);

    Security::AccessToken::ProfileData emptyData;  // empty block: length clamps to 0
    Security::Verify::ProvisionInfo emptyInfo;
    EXPECT_TRUE(BundleSpmManager::FillProvisionProfileBlock(emptyData, emptyInfo));
    EXPECT_EQ(emptyInfo.profileBlockLength, 0);
}

/**
 * @tc.number: BmsSpmManagerOnTest.Commit_ClearCacheFailure_NonBlocking_0001
 * @tc.name: A failed provision cache clear does not break the commit
 * @tc.desc: The cache clear is best-effort: an installd IPC failure is only
 *           logged and never changes the commit result or the session state.
 */
HWTEST_F(BmsSpmManagerOnTest, Commit_ClearCacheFailure_NonBlocking_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;
    OHOS::AppExecFwk::g_clearSessionProvisionCacheRet = -9;
    BundleInstallChecker checker;
    ErrCode errCode = ERR_OK;
    auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {}, false, checker, errCode, true, false);
    ASSERT_EQ(errCode, ERR_OK);

    EXPECT_EQ(session.Commit({}), ERR_OK);
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 1);
    EXPECT_TRUE(OHOS::Security::AccessToken::g_spmFinishInstallLastPersistent);
    EXPECT_EQ(OHOS::AppExecFwk::GetClearSessionProvisionCacheCountForTest(), 1);
}

/**
 * @tc.number: BmsSpmManagerOnTest.InitToken_CloneInstall_0001
 * @tc.name: InitToken for a clone allocates the uid on the AT side
 * @tc.desc: A clone install (appIndex > 0) passes no desired uid: the AT side
 *           allocates a FRESH one (the token query filters by instIndex), the uid
 *           is returned via the out param, and the main app's user info in `info`
 *           is not touched (the caller owns the clone uid handling).
 */
HWTEST_F(BmsSpmManagerOnTest, InitToken_CloneInstall_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;
    OHOS::Security::AccessToken::g_spmPrepareIdentityTokenId = TEST_IDENTITY_TOKENID;
    OHOS::Security::AccessToken::g_spmPrepareIdentityUid = TEST_CLONE_UID;
    BundleInstallChecker checker;
    ErrCode errCode = ERR_OK;
    auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {}, false, checker, errCode, true, false);
    ASSERT_EQ(errCode, ERR_OK);

    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    info.SetAppIndex(1);  // clone
    InnerBundleUserInfo mainUser;
    mainUser.bundleUserInfo.userId = TEST_USERID;
    mainUser.bundleName = BUNDLE_NAME;
    mainUser.uid = TEST_EXISTING_UID;  // main app uid, must stay untouched
    info.AddInnerBundleUserInfo(mainUser);

    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    Security::AccessToken::HapInfoCheckResult checkResult;
    int32_t identityUid = 0;
    EXPECT_EQ(session.InitToken(info, TEST_USERID, 0, tokenIdEx, checkResult, "", nullptr, false,
        &identityUid), ERR_OK);
    EXPECT_EQ(tokenIdEx.tokenIDEx, TEST_IDENTITY_TOKENID);
    EXPECT_EQ(identityUid, TEST_CLONE_UID);
    // clone mode: the main user info keeps its uid and gains no extra gid
    InnerBundleUserInfo userInfo;
    ASSERT_TRUE(info.GetInnerBundleUserInfo(TEST_USERID, userInfo));
    EXPECT_EQ(userInfo.uid, TEST_EXISTING_UID);
    EXPECT_TRUE(userInfo.gids.empty());
}

/**
 * @tc.number: BmsSpmManagerOnTest.InitToken_ActiveSession_0005
 * @tc.name: The AT uid is authoritative when the desired local uid is not adopted
 * @tc.desc: An existing valid uid is passed as the desired identity, but the AT
 *           side reallocates a different one: under SPM ON the AT uid wins —
 *           userInfo adopts the AT uid, the stale local uid's gid is dropped
 *           (uid == gids[0]), and the installTime is preserved.
 */
HWTEST_F(BmsSpmManagerOnTest, InitToken_ActiveSession_0005, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;
    OHOS::Security::AccessToken::g_spmPrepareIdentityTokenId = TEST_IDENTITY_TOKENID;
    OHOS::Security::AccessToken::g_spmPrepareIdentityUid = TEST_IDENTITY_UID;  // != local 9999
    BundleInstallChecker checker;
    ErrCode errCode = ERR_OK;
    auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {}, false, checker, errCode, true, false);
    ASSERT_EQ(errCode, ERR_OK);

    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    InnerBundleUserInfo existing;
    existing.bundleUserInfo.userId = TEST_USERID;
    existing.bundleName = BUNDLE_NAME;
    existing.uid = TEST_EXISTING_UID;
    existing.installTime = TEST_INSTALL_TIME;
    existing.gids.emplace_back(TEST_EXISTING_UID);  // stale local gid to be dropped
    info.AddInnerBundleUserInfo(existing);

    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    Security::AccessToken::HapInfoCheckResult checkResult;
    EXPECT_EQ(session.InitToken(info, TEST_USERID, 0, tokenIdEx, checkResult, "", nullptr, false),
        ERR_OK);
    InnerBundleUserInfo userInfo;
    ASSERT_TRUE(info.GetInnerBundleUserInfo(TEST_USERID, userInfo));
    EXPECT_EQ(userInfo.uid, TEST_IDENTITY_UID);  // AT uid adopted
    ASSERT_EQ(userInfo.gids.size(), 1);
    EXPECT_EQ(userInfo.gids.front(), TEST_IDENTITY_UID);  // stale local gid dropped
    EXPECT_EQ(userInfo.installTime, TEST_INSTALL_TIME);
}

/**
 * @tc.number: BmsSpmManagerOnTest.DeleteToken_ZeroTokenId_0001
 * @tc.name: DeleteToken rejects zero tokenId under SPM ON
 * @tc.desc: A zero tokenId must never reach the AT side (DeleteIdentity(0, bn,
 *           NONE) deletes EVERY token of the bundle by name there). The facade
 *           rejects it with ERR_PARAM_INVALID.
 */
HWTEST_F(BmsSpmManagerOnTest, DeleteToken_ZeroTokenId_0001, Function | MediumTest | Level1)
{
    int32_t ret = BundleSpmManager::DeleteToken(0, BUNDLE_NAME,
        BundleSpmManager::TokenDeleteType::NONE);
    EXPECT_EQ(ret, Security::AccessToken::AccessTokenError::ERR_PARAM_INVALID);
}

/**
 * @tc.number: BmsSpmManagerOnTest.DeleteToken_ZeroTokenId_ReservedData_0001
 * @tc.name: DeleteToken rejects zero tokenId even for RESERVED types
 * @tc.desc: The zero-tokenId rejection applies to all TokenDeleteType values.
 */
HWTEST_F(BmsSpmManagerOnTest, DeleteToken_ZeroTokenId_ReservedData_0001, Function | MediumTest | Level1)
{
    int32_t ret = BundleSpmManager::DeleteToken(0, BUNDLE_NAME,
        BundleSpmManager::TokenDeleteType::RESERVED_DATA);
    EXPECT_EQ(ret, Security::AccessToken::AccessTokenError::ERR_PARAM_INVALID);
}

/**
 * @tc.number: BmsSpmManagerOnTest.DeleteToken_ValidTokenId_0001
 * @tc.name: DeleteToken with valid tokenId passes through to AT
 * @tc.desc: A non-zero tokenId reaches DeleteIdentity on the AT side (mock
 *           returns 0 = RET_SUCCESS).
 */
HWTEST_F(BmsSpmManagerOnTest, DeleteToken_ValidTokenId_0001, Function | MediumTest | Level1)
{
    int32_t ret = BundleSpmManager::DeleteToken(TEST_IDENTITY_TOKENID, BUNDLE_NAME,
        BundleSpmManager::TokenDeleteType::NONE);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsSpmManagerOnTest.InitToken_CacheUid_0001
 * @tc.name: InitToken caches the AT-allocated uid in uidIndexMap_
 * @tc.desc: When PrepareHapIdentity returns a non-zero uid, InitToken writes it
 *           to the BundleDataMgr's uidIndexMap_ so the ON reverse lookup can
 *           hit locally without an AT IPC.
 */
HWTEST_F(BmsSpmManagerOnTest, InitToken_CacheUid_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmPrepareIdentityTokenId = TEST_IDENTITY_TOKENID;
    OHOS::Security::AccessToken::g_spmPrepareIdentityUid = TEST_IDENTITY_UID;

    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);

    BundleSpmManager::InstallSession session;
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    Security::AccessToken::HapInfoCheckResult checkResult;
    int32_t identityUid = 0;
    int32_t ret = session.InitToken(info, TEST_USERID, 0, tokenIdEx, checkResult,
        "", nullptr, false, &identityUid);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(identityUid, TEST_IDENTITY_UID);
    EXPECT_EQ(tokenIdEx.tokenIdExStruct.tokenID, TEST_IDENTITY_TOKENID);

    // The uidIndexMap_ write goes through BundleMgrService::GetDataMgr(); in this
    // test target the service is not initialized, so the write is a no-op (null
    // dataMgr). The identityUid output param is the verifiable contract here.
}

/**
 * @tc.number: BmsSpmManagerOnTest.InitToken_CacheUid_0002
 * @tc.name: InitToken with a zero AT uid fails fast
 * @tc.desc: When PrepareHapIdentity returns uid<=0 (AT did not allocate), the
 *           call is treated as a failed SPM interface call: InitToken returns
 *           ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED and the
 *           identityUid output param is not written (the sentinel is kept —
 *           no partial handover on failure).
 */
HWTEST_F(BmsSpmManagerOnTest, InitToken_CacheUid_0002, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmPrepareIdentityTokenId = TEST_IDENTITY_TOKENID;
    OHOS::Security::AccessToken::g_spmPrepareIdentityUid = 0;  // AT did not allocate

    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);

    BundleSpmManager::InstallSession session;
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    Security::AccessToken::HapInfoCheckResult checkResult;
    int32_t identityUid = -1;  // sentinel
    int32_t ret = session.InitToken(info, TEST_USERID, 0, tokenIdEx, checkResult,
        "", nullptr, false, &identityUid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED);
    EXPECT_EQ(identityUid, -1);  // output param untouched on failure
}

/**
 * @tc.number: BmsSpmManagerOnTest.UpdateToken_UidOut_0001
 * @tc.name: UpdateToken returns success and the uidOut is consumed
 * @tc.desc: UpdateHapPolicy succeeds (mock ret=0); the uidOut handling (cache
 *           refresh + fs config) runs with the mock's default uidOut=0.
 */
HWTEST_F(BmsSpmManagerOnTest, UpdateToken_UidOut_0001, Function | MediumTest | Level1)
{
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = TEST_USERID;
    userInfo.bundleName = BUNDLE_NAME;
    userInfo.uid = TEST_IDENTITY_UID;
    info.AddInnerBundleUserInfo(userInfo);

    BundleSpmManager::InstallSession session;
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIdExStruct.tokenID = TEST_IDENTITY_TOKENID;
    Security::AccessToken::HapInfoCheckResult checkResult;
    int32_t ret = session.UpdateToken(tokenIdEx, info, TEST_USERID, checkResult, "", false, false);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: BmsSpmManagerOnTest.UpdateToken_Failure_0001
 * @tc.name: UpdateToken returns the AT error code on failure
 * @tc.desc: UpdateHapPolicy fails (mock ret != 0); the error propagates.
 */
HWTEST_F(BmsSpmManagerOnTest, UpdateToken_Failure_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmUpdateHapPolicyRet = -1;

    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);

    BundleSpmManager::InstallSession session;
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIdExStruct.tokenID = TEST_IDENTITY_TOKENID;
    Security::AccessToken::HapInfoCheckResult checkResult;
    int32_t ret = session.UpdateToken(tokenIdEx, info, TEST_USERID, checkResult, "", false, false);
    EXPECT_NE(ret, ERR_OK);

    OHOS::Security::AccessToken::g_spmUpdateHapPolicyRet = 0;
}

/**
 * @tc.number: BmsSpmManagerOnTest.CheckSignAndInitSession_SkipResign_0001
 * @tc.name: CheckSignAndInitSession with skipEnterpriseResign
 * @tc.desc: The skipEnterpriseResign flag is passed through to the OFF checker
 *           and consumed in the ON path (userId=-1 contract); the mock
 *           CheckHapSignInfo returns success.
 */
HWTEST_F(BmsSpmManagerOnTest, CheckSignAndInitSession_SkipResign_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;

    BundleInstallChecker checker;
    ErrCode errCode = ERR_OK;
    auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {"/data/test.hap"}, false, checker, errCode, true, true);
    EXPECT_EQ(errCode, ERR_OK);
    EXPECT_EQ(session.GetSessionId(), TEST_SESSION_ID);
}

} // namespace OHOS
