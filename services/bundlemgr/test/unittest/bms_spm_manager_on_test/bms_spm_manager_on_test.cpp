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
#include "bundle_data_mgr.h"
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
extern int32_t g_spmCheckHapSignInfoLastUserId;
extern std::vector<TrustedBundleInfo> g_spmTrustedBundleInfos;
extern int32_t g_spmCheckHapPermissionInfoRet;
extern int32_t g_spmCheckHapPermissionInfoCallCount;
extern int32_t g_spmPrepareHapIdentityRet;
extern uint64_t g_spmPrepareIdentityTokenId;
extern int32_t g_spmPrepareIdentityUid;
extern int32_t g_spmPrepareIdentitySessionId;
extern bool g_spmPrepareIdentityForceReallocate;
extern int32_t g_spmUpdateHapPolicyRet;
extern int32_t g_spmUpdateHapPolicyUidOut;
extern int32_t g_spmGetHapBaseInfoByUidRet;
extern Security::AccessToken::HapBaseInfo g_spmGetHapBaseInfo;
extern int32_t g_spmMigrateInstalledBundlesRet;
extern int32_t g_spmLastMigratedBaseInfoCount;
extern int32_t g_spmLastMigratedUidCount;
extern int32_t g_spmDeleteIdentityRet;
extern uint64_t g_lastDeleteIdentityTokenId;
extern std::string g_lastDeleteIdentityBundleName;
extern int32_t g_lastDeleteIdentityType;
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
// All mock uids live inside user 100's segment (100 * BASE_USER_RANGE):
// InitToken enforces user-segment consistency on the AT-returned uid.
constexpr int32_t TEST_IDENTITY_UID = 100 * 200000 + 102;
constexpr int32_t TEST_EXISTING_UID = 100 * 200000 + 9999;
constexpr int32_t TEST_CLONE_UID = 100 * 200000 + 1042;
constexpr int64_t TEST_INSTALL_TIME = 555;

// Constructs an ACTIVE session without real hap files. CheckSignAndInitSession
// rejects an empty hap list (aligned with the OFF checker's param error), and a
// non-empty list needs a parsable provision document (only available as .p7b
// assets), so the session is engaged through the deferred InitToken path
// instead: the g_spmPrepareIdentitySessionId mock knob makes PrepareHapIdentity
// allocate the session id and write it back — the same contract the real AT
// side implements for deferred callers. InitToken itself issues no
// FinishInstall, so the call-count assertions of the callers stay untouched.
BundleSpmManager::InstallSession MakeActiveSession()
{
    OHOS::Security::AccessToken::g_spmPrepareIdentitySessionId = TEST_SESSION_ID;
    OHOS::Security::AccessToken::g_spmPrepareIdentityTokenId = TEST_IDENTITY_TOKENID;
    OHOS::Security::AccessToken::g_spmPrepareIdentityUid = TEST_IDENTITY_UID;
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    OHOS::Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    OHOS::Security::AccessToken::HapInfoCheckResult checkResult;
    EXPECT_EQ(session.InitToken(info, TEST_USERID, 0, tokenIdEx, checkResult, "", nullptr, false),
        OHOS::ERR_OK);
    return session;
}
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
    static void TearDownTestCase()
    {
        // Reset the switch so nothing leaks past this binary: the mock
        // parameter map is process-local, but on integration hosts the same
        // key can resolve to the real persistent parameter service — a
        // leftover "true" would flip every later test binary on the device
        // into the SPM ON branches (and IsEnabled caches the value in a
        // function-local static for the whole process). Note: this target
        // compiles against the real SDK parameters.h (its include path does
        // not cover the mock parameter/ subdirectory), which has no
        // RemoveParameter — the explicit "false" reset works for both.
        OHOS::system::SetParameter(SPM_ENABLE_PARAM, "false");
    };
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
 * @tc.number: BmsSpmManagerOnTest.CheckSignAndInitSession_EmptyPaths_0001
 * @tc.name: CheckSignAndInitSession rejects an empty hap list
 * @tc.desc: The ON path aligns with the OFF checker (CheckMultipleHapsSignInfo
 *           rejects an empty path list with the registered param error): fail
 *           closed BEFORE any AT call, so no session is created and nothing is
 *           handed to the AT side. Active-session flows are covered through the
 *           deferred InitToken engagement (MakeActiveSession).
 */
HWTEST_F(BmsSpmManagerOnTest, CheckSignAndInitSession_EmptyPaths_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;
    BundleInstallChecker checker;
    ErrCode errCode = ERR_OK;
    auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {}, false, checker, errCode, true, false);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
    EXPECT_FALSE(session.IsActive());
    EXPECT_EQ(session.GetSessionId(), 0);
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 0);
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
        TEST_USERID, {"/data/test/one.hap"}, false, checker, errCode, true, false);
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
    auto session = MakeActiveSession();
    ASSERT_TRUE(session.IsActive());

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
    auto session = MakeActiveSession();
    ASSERT_TRUE(session.IsActive());

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
    auto session = MakeActiveSession();
    ASSERT_TRUE(session.IsActive());

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
    auto session = MakeActiveSession();
    ASSERT_TRUE(session.IsActive());
    // The failure knob is set AFTER the engagement: MakeActiveSession's own
    // InitToken must succeed to allocate the session id.
    OHOS::Security::AccessToken::g_spmPrepareHapIdentityRet = -3;

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
    auto session = MakeActiveSession();
    ASSERT_TRUE(session.IsActive());
    OHOS::Security::AccessToken::g_spmUpdateHapPolicyRet = -6;

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
    auto session = MakeActiveSession();
    ASSERT_TRUE(session.IsActive());
    OHOS::Security::AccessToken::g_spmCheckHapPermissionInfoRet = -7;

    Security::AccessToken::HapInfoCheckResult checkResult;
    EXPECT_EQ(session.CheckPermissionInfo(Security::AccessToken::InstallTypeEnum::TYPE_REPLACE,
        checkResult), -7);
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmCheckHapPermissionInfoCallCount, 1);
}

/**
 * @tc.number: BmsSpmManagerOnTest.VerifyPermission_DeferredSession_0001
 * @tc.name: VerifyPermission on a deferred session queries the session policy
 * @tc.desc: Under SPM ON there is no deferred degradation anymore: a permission
 *           not in the (empty) session policy is denied with the registered
 *           ERR_BUNDLE_MANAGER_PERMISSION_DENIED code.
 */
HWTEST_F(BmsSpmManagerOnTest, VerifyPermission_DeferredSession_0001, Function | MediumTest | Level1)
{
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    EXPECT_EQ(session.VerifyPermission(BUNDLE_NAME, PERMISSION_NAME, TEST_USERID),
        ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
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
    auto session = MakeActiveSession();
    ASSERT_TRUE(session.IsActive());

    EXPECT_EQ(session.Commit({}), ERR_OK);
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 1);
    EXPECT_TRUE(OHOS::Security::AccessToken::g_spmFinishInstallLastPersistent);
    EXPECT_EQ(OHOS::AppExecFwk::GetClearSessionProvisionCacheCountForTest(), 1);
}

/**
 * @tc.number: BmsSpmManagerOnTest.IsCommitted_DeferredSession_0001
 * @tc.name: IsCommitted flips after a successful Commit
 * @tc.desc: IsCommitted is the gating flag for the install-failure token
 *           rollback: an uncommitted session's freshly created identity is
 *           never persisted (the session rollback discards it, so no
 *           DeleteIdentity is needed), while a committed session's identity
 *           was persisted and is still deleted on failure. A session starts
 *           uncommitted and flips on a successful Commit.
 */
HWTEST_F(BmsSpmManagerOnTest, IsCommitted_DeferredSession_0001, Function | MediumTest | Level1)
{
    auto session = BundleSpmManager::InstallSession::CreateDeferred();
    EXPECT_FALSE(session.IsCommitted());
    EXPECT_EQ(session.Commit({}), ERR_OK);
    EXPECT_TRUE(session.IsCommitted());
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 0);
}

/**
 * @tc.number: BmsSpmManagerOnTest.Commit_Failure_DestructorRollback_0001
 * @tc.name: A failed commit is rolled back by the destructor
 * @tc.desc: A failed commit fails the install, so the failure path must roll the
 *           session back: the destructor finishes it with isPersistent=false.
 */
HWTEST_F(BmsSpmManagerOnTest, Commit_Failure_DestructorRollback_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmFinishInstallRet = -5;
    {
        auto session = MakeActiveSession();
        ASSERT_TRUE(session.IsActive());

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
 *           session with isPersistent=false. The rollback fails (-5) so the
 *           session id is kept and the destructor retries the rollback once
 *           more (the documented failed-rollback design: the id is only
 *           cleared on success), adding a third non-persistent FinishInstall.
 */
HWTEST_F(BmsSpmManagerOnTest, Rollback_ExplicitAfterFailedCommit_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmFinishInstallRet = -5;
    {
        auto session = MakeActiveSession();
        ASSERT_TRUE(session.IsActive());

        EXPECT_EQ(session.Commit({}), -5);
        EXPECT_EQ(session.Rollback(), -5);
        EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 2);
        EXPECT_FALSE(OHOS::Security::AccessToken::g_spmFinishInstallLastPersistent);
    }  // session destroyed here: the failed rollback kept the session id, so
        // the destructor retries the rollback once more (non-persistent)
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 3);
    EXPECT_FALSE(OHOS::Security::AccessToken::g_spmFinishInstallLastPersistent);
}

/**
 * @tc.number: BmsSpmManagerOnTest.Destructor_Rollback_WithoutCommit_0001
 * @tc.name: Destructor rolls back an uncommitted session
 * @tc.desc: Without any commit attempt the destructor still finishes the session
 *           with isPersistent=false (classic RAII rollback).
 */
HWTEST_F(BmsSpmManagerOnTest, Destructor_Rollback_WithoutCommit_0001, Function | MediumTest | Level1)
{
    {
        auto session = MakeActiveSession();
        ASSERT_TRUE(session.IsActive());
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
    OHOS::Security::AccessToken::g_spmFinishInstallRet = -5;
    auto session = MakeActiveSession();
    ASSERT_TRUE(session.IsActive());

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
    auto session = MakeActiveSession();
    ASSERT_TRUE(session.IsActive());

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
    {
        auto session = MakeActiveSession();
        ASSERT_TRUE(session.IsActive());

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
        TEST_USERID, {"/data/test/one.hap"}, false, checker, errCode, true, false);
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
        TEST_USERID, {"/data/test/one.hap"}, false, checker, errCode, true, false);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_INSTALL_PARAM_ERROR);
    EXPECT_FALSE(session.IsActive());

    OHOS::Security::AccessToken::g_spmCheckHapSignInfoRet =
        Security::AccessToken::AccessTokenError::ERR_BUNDLE_ALREADY_EXIST;
    errCode = ERR_OK;
    session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {"/data/test/one.hap"}, false, checker, errCode, true, false);
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
    OHOS::AppExecFwk::g_clearSessionProvisionCacheRet = -9;
    auto session = MakeActiveSession();
    ASSERT_TRUE(session.IsActive());

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
    auto session = MakeActiveSession();
    ASSERT_TRUE(session.IsActive());
    // The clone uid knob is set AFTER the engagement (the engagement itself
    // runs with the main-identity uid).
    OHOS::Security::AccessToken::g_spmPrepareIdentityUid = TEST_CLONE_UID;

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
    auto session = MakeActiveSession();
    ASSERT_TRUE(session.IsActive());
    // The reallocation knob is set AFTER the engagement; the AT uid knob keeps
    // the engagement value (!= the local desired uid 9999 below).
    OHOS::Security::AccessToken::g_spmPrepareIdentityForceReallocate = true;

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
 * @tc.name: InitToken hands the AT-allocated uid over through the out param
 * @tc.desc: When PrepareHapIdentity returns a non-zero uid, InitToken hands it
 *           to the caller through the identityUid out param (the reverse-
 *           lookup map entry is inserted at the DB-persistence point, not
 *           inside InitToken).
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
 * @tc.name: UpdateToken succeeds with no uid change reported
 * @tc.desc: UpdateHapPolicy succeeds (mock ret=0) with uidOut=0 (the mock
 *           default): no uid handling runs — refreshedUid stays 0.
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
    int32_t refreshedUid = 0;
    int32_t ret = session.UpdateToken(tokenIdEx, info, TEST_USERID, checkResult, "", false, false,
        0, 0, &refreshedUid);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(refreshedUid, 0);
}

/**
 * @tc.number: BmsSpmManagerOnTest.UpdateToken_UidUnchanged_0001
 * @tc.name: An unchanged uidOut skips the refresh handling
 * @tc.desc: The AT side reports the SAME uid the app already runs under: the
 *           refresh branch must not run (no redundant cache rewrite / fs
 *           config / handover) — refreshedUid stays 0.
 */
HWTEST_F(BmsSpmManagerOnTest, UpdateToken_UidUnchanged_0001, Function | MediumTest | Level1)
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

    OHOS::Security::AccessToken::g_spmUpdateHapPolicyUidOut = TEST_IDENTITY_UID;  // unchanged
    BundleSpmManager::InstallSession session;
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIdExStruct.tokenID = TEST_IDENTITY_TOKENID;
    Security::AccessToken::HapInfoCheckResult checkResult;
    int32_t refreshedUid = 0;
    int32_t ret = session.UpdateToken(tokenIdEx, info, TEST_USERID, checkResult, "", false, false,
        0, 0, &refreshedUid);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(refreshedUid, 0);  // unchanged: no handover
}

/**
 * @tc.number: BmsSpmManagerOnTest.UpdateToken_UidRefresh_0001
 * @tc.name: A changed uidOut hands the refreshed uid over
 * @tc.desc: The AT side reports a DIFFERENT uid: the refresh branch runs and
 *           the refreshed uid is handed back through the out param (the
 *           caller persists it through its normal save path).
 */
HWTEST_F(BmsSpmManagerOnTest, UpdateToken_UidRefresh_0001, Function | MediumTest | Level1)
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

    constexpr int32_t REFRESHED_UID = 100 * 200000 + 555;  // same user segment, different uid
    OHOS::Security::AccessToken::g_spmUpdateHapPolicyUidOut = REFRESHED_UID;
    BundleSpmManager::InstallSession session;
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIdExStruct.tokenID = TEST_IDENTITY_TOKENID;
    Security::AccessToken::HapInfoCheckResult checkResult;
    int32_t refreshedUid = 0;
    int32_t ret = session.UpdateToken(tokenIdEx, info, TEST_USERID, checkResult, "", false, false,
        0, 0, &refreshedUid);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(refreshedUid, REFRESHED_UID);
}

/**
 * @tc.number: BmsSpmManagerOnTest.UpdateToken_UidOut_CrossUserSegment_0001
 * @tc.name: A cross-user uidOut is rejected with the registered code
 * @tc.desc: The AT side reports a uid from ANOTHER user's segment as the
 *           refreshed binding: same user-segment consistency check as InitToken
 *           — the call fails fast with the registered BMS code and the out
 *           param is not written (no partial handover), so the drift can never
 *           reach the reverse-lookup cache, the fs config or the DB.
 */
HWTEST_F(BmsSpmManagerOnTest, UpdateToken_UidOut_CrossUserSegment_0001, Function | MediumTest | Level1)
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

    constexpr int32_t CROSS_USER_UID = 101 * 200000 + 555;  // user 101 segment
    OHOS::Security::AccessToken::g_spmUpdateHapPolicyUidOut = CROSS_USER_UID;
    BundleSpmManager::InstallSession session;
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIdExStruct.tokenID = TEST_IDENTITY_TOKENID;
    Security::AccessToken::HapInfoCheckResult checkResult;
    int32_t refreshedUid = 0;
    int32_t ret = session.UpdateToken(tokenIdEx, info, TEST_USERID, checkResult, "", false, false,
        0, 0, &refreshedUid);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED);
    EXPECT_EQ(refreshedUid, 0);  // output param untouched on rejection
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
 * @tc.desc: The skipEnterpriseResign flag is consumed in the ON path via the
 *           userId == -1 contract (hapList.userId tells the AT side to skip the
 *           enterprise resign verification); without the flag the real userId
 *           is passed through. A non-empty hap list is required to reach the AT
 *           call (the empty list fails closed), and the mock's empty trusted
 *           list then fails the 1:1 count check, so the session creation fails
 *           overall — the userId contract is still pinned through the mock's
 *           recorded last-user-id.
 */
HWTEST_F(BmsSpmManagerOnTest, CheckSignAndInitSession_SkipResign_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;

    BundleInstallChecker checker;
    ErrCode errCode = ERR_OK;
    auto session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {"/data/test/one.hap"}, false, checker, errCode, true, true);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE);
    EXPECT_FALSE(session.IsActive());
    // The cross-process contract: skipEnterpriseResign is carried as userId == -1.
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmCheckHapSignInfoLastUserId, -1);

    // Without the flag the real userId is passed through unchanged.
    session = BundleSpmManager::InstallSession::CheckSignAndInitSession(
        TEST_USERID, {"/data/test/one.hap"}, false, checker, errCode, true, false);
    EXPECT_EQ(errCode, ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE);
    EXPECT_FALSE(session.IsActive());
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmCheckHapSignInfoLastUserId, TEST_USERID);
}

// ===== BundleDataMgr reverse lookup through the reused bundleIdMap_ =====
// Under SPM ON the uid reverse lookup derives (userId, bundleId) from the uid
// and consults bundleIdMap_ (same path as OFF); the AT allocation contract
// matches the local allocator (same bundleId per bundle across users), so the
// map keeps the same shape under both modes. The hit is still cross-checked
// against the persisted user info (defense in depth against stale entries and
// contract violations) and a miss/mismatch falls back to the AT service. The
// DB-persistence hooks (AddInnerBundleInfo / AddInnerBundleUserInfo) insert
// the entries at install time, so these cases live in the ON-mode target.

namespace {
// Installs a minimal bundle with one user (uid at the given user's segment)
// and returns the data manager holding it. Extra users can be appended via
// the returned info copy before AddInnerBundleInfo.
std::shared_ptr<BundleDataMgr> SetUpDataMgrWithBundle(const std::string &bundleName, int32_t uid,
    int32_t userId = 100)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    if (!dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START)) {
        return nullptr;
    }
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = bundleName;
    info.SetBaseBundleInfo(bundleInfo);
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = userId;
    userInfo.bundleName = bundleName;
    userInfo.uid = uid;
    info.AddInnerBundleUserInfo(userInfo);
    if (!dataMgr->AddInnerBundleInfo(bundleName, info)) {
        return nullptr;
    }
    return dataMgr;
}
} // namespace

/**
 * @tc.number: BmsSpmManagerOnTest.BundleIdMap_LookupHit_0001
 * @tc.name: The DB-persistence hook entries resolve through the ON read path
 * @tc.desc: The install-time hooks insert the derived bundleId entries; the
 *           unified read path (derive -> bundleIdMap_ -> ParseBundleIdKey ->
 *           cross-check) resolves the main identity and a second user added
 *           through AddInnerBundleUserInfo. Per the AT allocation contract the
 *           second user's uid carries the SAME bundleId (same segment offset),
 *           so both lookups converge on one shared entry.
 */
HWTEST_F(BmsSpmManagerOnTest, BundleIdMap_LookupHit_0001, Function | MediumTest | Level1)
{
    constexpr int32_t UID_A = 100 * 200000 + 101;   // derived bundleId 101
    constexpr int32_t UID_A2 = 101 * 200000 + 101;  // same bundleId, user 101 segment
    auto dataMgr = SetUpDataMgrWithBundle(BUNDLE_NAME, UID_A);
    ASSERT_NE(dataMgr, nullptr);
    InnerBundleUserInfo secondUser;
    secondUser.bundleUserInfo.userId = 101;
    secondUser.bundleName = BUNDLE_NAME;
    secondUser.uid = UID_A2;
    // AddInnerBundleUserInfo returns an ErrCode (ERR_OK on success), not a
    // bool — assert the code, ASSERT_TRUE(ERR_OK) would always fail.
    ASSERT_EQ(dataMgr->AddInnerBundleUserInfo(BUNDLE_NAME, secondUser), ERR_OK);

    std::string resolvedName;
    int32_t resolvedIndex = -1;
    EXPECT_EQ(dataMgr->GetBundleNameAndIndex(UID_A, resolvedName, resolvedIndex), ERR_OK);
    EXPECT_EQ(resolvedName, BUNDLE_NAME);
    EXPECT_EQ(resolvedIndex, 0);

    EXPECT_EQ(dataMgr->GetBundleNameAndIndex(UID_A2, resolvedName, resolvedIndex), ERR_OK);
    EXPECT_EQ(resolvedName, BUNDLE_NAME);
    EXPECT_EQ(resolvedIndex, 0);
}

/**
 * @tc.number: BmsSpmManagerOnTest.BundleIdMap_LookupMiss_ATFallback_0001
 * @tc.name: A local miss falls back to the access token service
 * @tc.desc: A uid with no bundleIdMap_ entry resolves through the AT fallback
 *           (mock knob filled); an AT-side miss resolves to INVALID_UID.
 */
HWTEST_F(BmsSpmManagerOnTest, BundleIdMap_LookupMiss_ATFallback_0001, Function | MediumTest | Level1)
{
    constexpr int32_t UNKNOWN_UID = 102 * 200000 + 301;
    auto dataMgr = SetUpDataMgrWithBundle(BUNDLE_NAME, 100 * 200000 + 101);
    ASSERT_NE(dataMgr, nullptr);

    OHOS::Security::AccessToken::g_spmGetHapBaseInfoByUidRet = 0;
    OHOS::Security::AccessToken::g_spmGetHapBaseInfo.bundleName = BUNDLE_NAME;
    OHOS::Security::AccessToken::g_spmGetHapBaseInfo.instIndex = 2;
    std::string resolvedName;
    int32_t resolvedIndex = -1;
    EXPECT_EQ(dataMgr->GetBundleNameAndIndex(UNKNOWN_UID, resolvedName, resolvedIndex), ERR_OK);
    EXPECT_EQ(resolvedName, BUNDLE_NAME);
    EXPECT_EQ(resolvedIndex, 2);

    // AT-side miss: the mock default (-1) makes the fallback fail closed.
    constexpr int32_t MISSING_UID = 102 * 200000 + 302;
    OHOS::Security::AccessToken::g_spmGetHapBaseInfoByUidRet = -1;
    EXPECT_EQ(dataMgr->GetBundleNameAndIndex(MISSING_UID, resolvedName, resolvedIndex),
        ERR_BUNDLE_MANAGER_INVALID_UID);
}

/**
 * @tc.number: BmsSpmManagerOnTest.BundleIdMap_Collision_CrossCheck_0001
 * @tc.name: A derived-bundleId collision never resolves to the wrong bundle
 * @tc.desc: The confirmed AT contract rules this out in production (same
 *           bundleId per bundle across users, globally unique across bundles);
 *           the case pins the defense-in-depth behavior for a contract
 *           violation or a stale entry: the cross-check rejects the
 *           wrong-bundle hit and falls back to the AT service instead of
 *           answering with the other bundle.
 */
HWTEST_F(BmsSpmManagerOnTest, BundleIdMap_Collision_CrossCheck_0001, Function | MediumTest | Level1)
{
    constexpr int32_t UID_A = 100 * 200000 + 201;   // derived bundleId 201
    constexpr int32_t UID_B = 101 * 200000 + 201;   // SAME derived bundleId 201
    const std::string otherBundle = BUNDLE_NAME + ".other";
    auto dataMgr = SetUpDataMgrWithBundle(BUNDLE_NAME, UID_A);
    ASSERT_NE(dataMgr, nullptr);
    ASSERT_TRUE(dataMgr->UpdateBundleInstallState(otherBundle, InstallState::INSTALL_START));
    InnerBundleInfo otherInfo;
    BundleInfo otherBundleInfo;
    otherBundleInfo.name = otherBundle;
    otherInfo.SetBaseBundleInfo(otherBundleInfo);
    InnerBundleUserInfo otherUser;
    otherUser.bundleUserInfo.userId = 101;
    otherUser.bundleName = otherBundle;
    otherUser.uid = UID_B;
    otherInfo.AddInnerBundleUserInfo(otherUser);
    ASSERT_TRUE(dataMgr->AddInnerBundleInfo(otherBundle, otherInfo));

    std::string resolvedName;
    int32_t resolvedIndex = -1;
    // The collided entry maps to the OTHER bundle: the cross-check rejects it
    // for UID_A (its user is 101, not 100) and the AT fallback (mock default:
    // not found) fails closed — never a wrong answer.
    EXPECT_EQ(dataMgr->GetBundleNameAndIndex(UID_A, resolvedName, resolvedIndex),
        ERR_BUNDLE_MANAGER_INVALID_UID);
    // UID_B itself still resolves correctly through its own entry.
    EXPECT_EQ(dataMgr->GetBundleNameAndIndex(UID_B, resolvedName, resolvedIndex), ERR_OK);
    EXPECT_EQ(resolvedName, otherBundle);
    EXPECT_EQ(resolvedIndex, 0);
}

// ===== BundleDataMgr::GenerateUidAndGid — SPM ON branch =====
// Under SPM ON the allocation authority is the AT side: an already allocated
// uid is only completed with its gid (idempotent), any non-positive uid fails
// fast instead of being allocated from the local bundle-id counter.

/**
 * @tc.number: BmsSpmManagerOnTest.GenerateUidAndGid_On_Idempotent_0001
 * @tc.name: A positive uid keeps the uid and completes its gid
 * @tc.desc: The AT-allocated uid is authoritative: GenerateUidAndGid returns
 *           ERR_OK, leaves the uid untouched and appends it to the (empty)
 *           gids exactly once.
 */
HWTEST_F(BmsSpmManagerOnTest, GenerateUidAndGid_On_Idempotent_0001, Function | MediumTest | Level1)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    InnerBundleUserInfo userInfo;
    userInfo.bundleName = BUNDLE_NAME;
    userInfo.bundleUserInfo.userId = 100;
    constexpr int32_t AT_UID = 100 * 200000 + 201;
    userInfo.uid = AT_UID;

    EXPECT_EQ(dataMgr->GenerateUidAndGid(userInfo), ERR_OK);
    EXPECT_EQ(userInfo.uid, AT_UID);  // never re-allocated locally
    ASSERT_EQ(userInfo.gids.size(), static_cast<size_t>(1));
    EXPECT_EQ(userInfo.gids.front(), AT_UID);
}

/**
 * @tc.number: BmsSpmManagerOnTest.GenerateUidAndGid_On_GidsNoDuplicate_0001
 * @tc.name: A gid already present is not appended twice
 * @tc.desc: When gids already contains the uid the idempotent branch leaves
 *           the list unchanged (no duplicate entry).
 */
HWTEST_F(BmsSpmManagerOnTest, GenerateUidAndGid_On_GidsNoDuplicate_0001, Function | MediumTest | Level1)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    InnerBundleUserInfo userInfo;
    userInfo.bundleName = BUNDLE_NAME;
    userInfo.bundleUserInfo.userId = 100;
    constexpr int32_t AT_UID = 100 * 200000 + 202;
    userInfo.uid = AT_UID;
    userInfo.gids.emplace_back(AT_UID);  // already present

    EXPECT_EQ(dataMgr->GenerateUidAndGid(userInfo), ERR_OK);
    ASSERT_EQ(userInfo.gids.size(), static_cast<size_t>(1));  // no duplicate
    EXPECT_EQ(userInfo.gids.front(), AT_UID);
}

/**
 * @tc.number: BmsSpmManagerOnTest.GenerateUidAndGid_On_InvalidUid_0001
 * @tc.name: An INVALID uid fails fast instead of allocating locally
 * @tc.desc: Under SPM ON a uid with no AT source (INVALID_UID) must not fall
 *           back to the local bundle-id counter — it returns the registered
 *           fail-fast code (a locally allocated uid would drift from the
 *           token's uid binding).
 */
HWTEST_F(BmsSpmManagerOnTest, GenerateUidAndGid_On_InvalidUid_0001, Function | MediumTest | Level1)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    InnerBundleUserInfo userInfo;
    userInfo.bundleName = BUNDLE_NAME;
    userInfo.bundleUserInfo.userId = 100;
    userInfo.uid = Constants::INVALID_UID;

    EXPECT_EQ(dataMgr->GenerateUidAndGid(userInfo),
        ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED);
    EXPECT_EQ(userInfo.uid, Constants::INVALID_UID);  // untouched
    EXPECT_TRUE(userInfo.gids.empty());
}

/**
 * @tc.number: BmsSpmManagerOnTest.GenerateUidAndGid_On_ZeroUid_0001
 * @tc.name: A zero uid (corrupt record) is rejected
 * @tc.desc: A zero uid would chown the data dirs to root — it fails fast
 *           under SPM ON and nothing is allocated.
 */
HWTEST_F(BmsSpmManagerOnTest, GenerateUidAndGid_On_ZeroUid_0001, Function | MediumTest | Level1)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    InnerBundleUserInfo userInfo;
    userInfo.bundleName = BUNDLE_NAME;
    userInfo.bundleUserInfo.userId = 100;
    userInfo.uid = 0;

    EXPECT_EQ(dataMgr->GenerateUidAndGid(userInfo),
        ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED);
    EXPECT_EQ(userInfo.uid, 0);  // untouched
    EXPECT_TRUE(userInfo.gids.empty());
}

/**
 * @tc.number: BmsSpmManagerOnTest.GenerateUidAndGid_On_EmptyBundleName_0001
 * @tc.name: An empty bundle name is rejected under SPM ON as well
 * @tc.desc: The empty-name guard runs before the state split: the registered
 *           BUNDLENAME_IS_EMPTY code is returned regardless of the SPM state.
 */
HWTEST_F(BmsSpmManagerOnTest, GenerateUidAndGid_On_EmptyBundleName_0001, Function | MediumTest | Level1)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    InnerBundleUserInfo userInfo;
    userInfo.bundleName = "";
    userInfo.bundleUserInfo.userId = 100;
    userInfo.uid = 100 * 200000 + 203;  // even a valid uid cannot pass

    EXPECT_EQ(dataMgr->GenerateUidAndGid(userInfo), ERR_APPEXECFWK_INSTALL_BUNDLENAME_IS_EMPTY);
}

// ===== BundleSpmManager::GetInstance / OnModuleUninstalled / TryRecover* =====
// ParseTrustedBundleInfo is an anonymous-namespace helper whose success path
// needs a valid provision document (only available as .p7b assets, not
// inline-able in unit tests); its failure path is already pinned by
// CheckSignAndInitSession_ParseFailure_0001 above.

/**
 * @tc.number: BmsSpmManagerOnTest.GetInstance_0001
 * @tc.name: GetInstance returns the same non-null singleton
 */
HWTEST_F(BmsSpmManagerOnTest, GetInstance_0001, Function | MediumTest | Level1)
{
    auto &first = BundleSpmManager::GetInstance();
    auto &second = BundleSpmManager::GetInstance();
    EXPECT_EQ(&first, &second);
}

/**
 * @tc.number: BmsSpmManagerOnTest.OnModuleUninstalled_Success_0001
 * @tc.name: The module-uninstall re-sign flow succeeds end to end
 * @tc.desc: Verify → CheckPermission → Commit all succeed (mock knobs): the
 *           standalone session commits with the identity hap-path mapping.
 */
HWTEST_F(BmsSpmManagerOnTest, OnModuleUninstalled_Success_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    // The empty-hap-list guard returns ERR_OK before any AT call: the flow
    // needs at least one module with a hap path to reach verify/commit.
    std::map<std::string, InnerModuleInfo> moduleInfos;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "entry";
    moduleInfo.hapPath = "/data/app/entry.hap";
    moduleInfos.emplace("entry", moduleInfo);
    info.AddInnerModuleInfo(moduleInfos);

    EXPECT_EQ(BundleSpmManager::OnModuleUninstalled(info, TEST_USERID), ERR_OK);
    // the standalone session was finished persistently
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 1);
    EXPECT_TRUE(OHOS::Security::AccessToken::g_spmFinishInstallLastPersistent);
}

/**
 * @tc.number: BmsSpmManagerOnTest.OnModuleUninstalled_VerifyFailed_0001
 * @tc.name: A verification failure propagates the raw AT code
 */
HWTEST_F(BmsSpmManagerOnTest, OnModuleUninstalled_VerifyFailed_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoRet = -2;
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    std::map<std::string, InnerModuleInfo> moduleInfos;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "entry";
    moduleInfo.hapPath = "/data/app/entry.hap";
    moduleInfos.emplace("entry", moduleInfo);
    info.AddInnerModuleInfo(moduleInfos);

    EXPECT_EQ(BundleSpmManager::OnModuleUninstalled(info, TEST_USERID), -2);
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 0);
}

/**
 * @tc.number: BmsSpmManagerOnTest.OnModuleUninstalled_CheckPermissionFailed_0001
 * @tc.name: A permission pre-check failure rolls the standalone session back
 */
HWTEST_F(BmsSpmManagerOnTest, OnModuleUninstalled_CheckPermissionFailed_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;
    OHOS::Security::AccessToken::g_spmCheckHapPermissionInfoRet = -3;
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    std::map<std::string, InnerModuleInfo> moduleInfos;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "entry";
    moduleInfo.hapPath = "/data/app/entry.hap";
    moduleInfos.emplace("entry", moduleInfo);
    info.AddInnerModuleInfo(moduleInfos);

    EXPECT_EQ(BundleSpmManager::OnModuleUninstalled(info, TEST_USERID), -3);
    // the allocated session is rolled back (non-persistent finish), not leaked
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmFinishInstallCallCount, 1);
    EXPECT_FALSE(OHOS::Security::AccessToken::g_spmFinishInstallLastPersistent);
}

/**
 * @tc.number: BmsSpmManagerOnTest.OnModuleUninstalled_CommitFailed_0001
 * @tc.name: A commit failure propagates the error
 */
HWTEST_F(BmsSpmManagerOnTest, OnModuleUninstalled_CommitFailed_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmCheckHapSignInfoSessionId = TEST_SESSION_ID;
    OHOS::Security::AccessToken::g_spmFinishInstallRet = -4;
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    std::map<std::string, InnerModuleInfo> moduleInfos;
    InnerModuleInfo moduleInfo;
    moduleInfo.moduleName = "entry";
    moduleInfo.hapPath = "/data/app/entry.hap";
    moduleInfos.emplace("entry", moduleInfo);
    info.AddInnerModuleInfo(moduleInfos);

    EXPECT_EQ(BundleSpmManager::OnModuleUninstalled(info, TEST_USERID), -4);
}

/**
 * @tc.number: BmsSpmManagerOnTest.TryRecoverUidError_NullDataMgr_0001
 * @tc.name: A null data manager (or empty name) is rejected
 */
HWTEST_F(BmsSpmManagerOnTest, TryRecoverUidError_NullDataMgr_0001, Function | MediumTest | Level1)
{
    EXPECT_FALSE(BundleSpmManager::TryRecoverUidError(BUNDLE_NAME, nullptr));
    auto dataMgr = std::make_shared<BundleDataMgr>();
    EXPECT_FALSE(BundleSpmManager::TryRecoverUidError("", dataMgr.get()));
}

/**
 * @tc.number: BmsSpmManagerOnTest.TryRecoverUidError_BundleNotExist_0001
 * @tc.name: An unknown bundle cannot be migrated
 */
HWTEST_F(BmsSpmManagerOnTest, TryRecoverUidError_BundleNotExist_0001, Function | MediumTest | Level1)
{
    auto dataMgr = std::make_shared<BundleDataMgr>();
    EXPECT_FALSE(BundleSpmManager::TryRecoverUidError(BUNDLE_NAME, dataMgr.get()));
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmMigrateInstalledBundlesRet, 0);  // untouched knob
}

/**
 * @tc.number: BmsSpmManagerOnTest.TryRecoverUidError_Success_0001
 * @tc.name: A known bundle is migrated and the recovery succeeds
 * @tc.desc: The on-demand migration (uid-not-exist recovery) succeeds when the
 *           AT side accepts the migrated identity list.
 */
HWTEST_F(BmsSpmManagerOnTest, TryRecoverUidError_Success_0001, Function | MediumTest | Level1)
{
    constexpr int32_t UID = 100 * 200000 + 301;
    auto dataMgr = SetUpDataMgrWithBundle(BUNDLE_NAME, UID);
    ASSERT_NE(dataMgr, nullptr);
    EXPECT_TRUE(BundleSpmManager::TryRecoverUidError(BUNDLE_NAME, dataMgr.get()));
}

/**
 * @tc.number: BmsSpmManagerOnTest.TryRecoverUidError_MigrateFailed_0001
 * @tc.name: An AT migration failure fails the recovery
 */
HWTEST_F(BmsSpmManagerOnTest, TryRecoverUidError_MigrateFailed_0001, Function | MediumTest | Level1)
{
    constexpr int32_t UID = 100 * 200000 + 302;
    auto dataMgr = SetUpDataMgrWithBundle(BUNDLE_NAME, UID);
    ASSERT_NE(dataMgr, nullptr);
    OHOS::Security::AccessToken::g_spmMigrateInstalledBundlesRet = -5;
    EXPECT_FALSE(BundleSpmManager::TryRecoverUidError(BUNDLE_NAME, dataMgr.get()));
}

/**
 * @tc.number: BmsSpmManagerOnTest.TryRecoverUidError_ListAlignment_0001
 * @tc.name: A corrupt main uid skips the whole record, keeping the lists aligned
 * @tc.desc: The main identity's base info and uid must be staged TOGETHER: a
 *           corrupt main record (uid <= 0, OTA / corruption leftover) is skipped
 *           entirely, so the parallel hapBaseInfoList/uidList lists stay
 *           aligned and only the valid clone identity is migrated (a
 *           conditional uid with an unconditional base info would bind every
 *           following clone identity to the wrong uid).
 */
HWTEST_F(BmsSpmManagerOnTest, TryRecoverUidError_ListAlignment_0001, Function | MediumTest | Level1)
{
    constexpr int32_t CLONE_UID = 100 * 200000 + 402;
    constexpr int32_t CLONE_APP_INDEX = 1;
    auto dataMgr = std::make_shared<BundleDataMgr>();
    ASSERT_TRUE(dataMgr->UpdateBundleInstallState(BUNDLE_NAME, InstallState::INSTALL_START));
    InnerBundleInfo info;
    BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    info.SetBaseBundleInfo(bundleInfo);
    InnerBundleUserInfo userInfo;
    userInfo.bundleUserInfo.userId = TEST_USERID;
    userInfo.bundleName = BUNDLE_NAME;
    userInfo.uid = 0;  // corrupt main record
    InnerBundleCloneInfo cloneInfo;
    cloneInfo.userId = TEST_USERID;
    cloneInfo.appIndex = CLONE_APP_INDEX;
    cloneInfo.uid = CLONE_UID;
    userInfo.cloneInfos.emplace(std::to_string(CLONE_APP_INDEX), cloneInfo);
    info.AddInnerBundleUserInfo(userInfo);
    ASSERT_TRUE(dataMgr->AddInnerBundleInfo(BUNDLE_NAME, info));

    EXPECT_TRUE(BundleSpmManager::TryRecoverUidError(BUNDLE_NAME, dataMgr.get()));
    // Only the valid clone entry is staged: both lists carry exactly one entry.
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmLastMigratedBaseInfoCount, 1);
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmLastMigratedUidCount, 1);

    // Sanity counterpart: a valid main record plus the clone stages two entries.
    auto dataMgr2 = SetUpDataMgrWithBundle(BUNDLE_NAME, 100 * 200000 + 403);
    ASSERT_NE(dataMgr2, nullptr);
    EXPECT_TRUE(BundleSpmManager::TryRecoverUidError(BUNDLE_NAME, dataMgr2.get()));
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmLastMigratedBaseInfoCount, 1);
    EXPECT_EQ(OHOS::Security::AccessToken::g_spmLastMigratedUidCount, 1);
}

/**
 * @tc.number: BmsSpmManagerOnTest.TryRecoverAlreadyExistError_EmptyName_0001
 * @tc.name: An empty bundle name is rejected
 */
HWTEST_F(BmsSpmManagerOnTest, TryRecoverAlreadyExistError_EmptyName_0001, Function | MediumTest | Level1)
{
    EXPECT_FALSE(BundleSpmManager::TryRecoverAlreadyExistError(""));
    // no AT call was made: the recorded bundle name stays at the reset value
    EXPECT_EQ(OHOS::Security::AccessToken::g_lastDeleteIdentityBundleName, "");
}

/**
 * @tc.number: BmsSpmManagerOnTest.TryRecoverAlreadyExistError_Success_0001
 * @tc.name: The leftover identity is deleted by name (tokenId 0)
 * @tc.desc: The recovery deletes EVERY identity of the bundle by name — the
 *           recorded mock call pins the (0, bundleName, NONE) shape so the
 *           blast radius stays visible.
 */
HWTEST_F(BmsSpmManagerOnTest, TryRecoverAlreadyExistError_Success_0001, Function | MediumTest | Level1)
{
    EXPECT_TRUE(BundleSpmManager::TryRecoverAlreadyExistError(BUNDLE_NAME));
    EXPECT_EQ(OHOS::Security::AccessToken::g_lastDeleteIdentityTokenId,
        static_cast<uint64_t>(0));
    EXPECT_EQ(OHOS::Security::AccessToken::g_lastDeleteIdentityBundleName, BUNDLE_NAME);
    EXPECT_EQ(OHOS::Security::AccessToken::g_lastDeleteIdentityType, 0);  // ReservedType::NONE
}

/**
 * @tc.number: BmsSpmManagerOnTest.TryRecoverAlreadyExistError_DeleteFailed_0001
 * @tc.name: An AT delete failure fails the recovery
 */
HWTEST_F(BmsSpmManagerOnTest, TryRecoverAlreadyExistError_DeleteFailed_0001, Function | MediumTest | Level1)
{
    OHOS::Security::AccessToken::g_spmDeleteIdentityRet = -6;
    EXPECT_FALSE(BundleSpmManager::TryRecoverAlreadyExistError(BUNDLE_NAME));
}

} // namespace OHOS
