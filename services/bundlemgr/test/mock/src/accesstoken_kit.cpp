/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "accesstoken_kit.h"

#include <set>
#include <unordered_map>

#include "interfaces/hap_verify.h"
#include "parameters.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
#ifdef BUNDLE_PERMISSION_DEF_LIST
#ifdef BUNDLE_PERMISSION_DEF_TRUE
static constexpr int GRANT_STATUS = 100;
#endif
#endif
// Mirrors ACCESS_TOKEN_DB_ERROR_PARAM in bundle_service_constants.h; duplicated to keep the
// test mock free of service headers.
constexpr const char* MOCK_DB_ERROR_PARAM = "persist.accesstoken.permission.dberror";
// controllable per-permission results for VerifyAccessToken, empty by default (keeps original behavior)
std::unordered_map<std::string, int> g_verifyAccessTokenResults;
// runtime-controllable token type for GetTokenTypeFlag, defaults keep the
// original compile-time behavior of each section
#ifdef BUNDLE_PERMISSION_DEF_LIST
ATokenTypeEnum g_tokenTypeFlag = TOKEN_SHELL;
#else
#ifdef BUNDLE_FRAMEWORK_SYSTEM_APP_FALSE
ATokenTypeEnum g_tokenTypeFlag = TOKEN_INVALID;
#else
ATokenTypeEnum g_tokenTypeFlag = TOKEN_NATIVE;
#endif
#endif
unsigned int g_accessTokenID = 0;
int32_t g_errCode = 0;
std::vector<int32_t> g_initHapTokenRetSeq;
std::vector<HapInfoParams> g_initHapTokenCalls;
std::vector<HapPolicyParams> g_initHapPolicyCalls;
int32_t g_resetRecoveryStatusRet = 0;
int32_t g_resetRecoveryStatusCallCount = 0;
int32_t g_updateHapTokenCallCount = 0;
int32_t g_updateHapTokenRet = 0;
// ---- SPM ON-mode control variables: default values keep the symbol-only stub
// behavior for the OFF-mode targets; the ON-mode target
// (unittest/bms_spm_manager_on_test) drives the SPM branches through them. ----
int32_t g_spmCheckHapSignInfoRet = 0;
int32_t g_spmCheckHapSignInfoSessionId = 0;
// Records the userId of the last BundleHapList handed to CheckHapSignInfo so
// tests can pin the cross-process skip-resign contract (userId == -1).
int32_t g_spmCheckHapSignInfoLastUserId = 0;
std::vector<TrustedBundleInfo> g_spmTrustedBundleInfos;
int32_t g_spmCheckHapPermissionInfoRet = 0;
int32_t g_spmCheckHapPermissionInfoCallCount = 0;
int32_t g_spmPrepareHapIdentityRet = 0;
uint64_t g_spmPrepareIdentityTokenId = 0;
int32_t g_spmPrepareIdentityUid = 0;
// Session-id write-back knob for PrepareHapIdentity: mirrors the real AT
// contract where a deferred caller (session id 0) makes the AT side allocate
// the session and write the id back. CheckSignAndInitSession rejects an empty
// hap list (aligned with the OFF checker), so the unit tests engage an active
// session through the deferred InitToken path with this knob.
int32_t g_spmPrepareIdentitySessionId = 0;
// Forces PrepareHapIdentity to ignore the desired uid and return the knob uid,
// so tests can construct the "AT did not adopt the desired uid and reallocated
// a new one" (mismatch) path that the default adopt-or-reallocate mock cannot.
bool g_spmPrepareIdentityForceReallocate = false;
int32_t g_spmUpdateHapPolicyRet = 0;
// Out-param knob for GetHapBaseInfoByUid (the SPM ON reverse-lookup fallback):
// default -1 = not found, 0 + filled g_spmGetHapBaseInfo = resolved.
int32_t g_spmGetHapBaseInfoByUidRet = -1;
Security::AccessToken::HapBaseInfo g_spmGetHapBaseInfo;
// Out-param knob for UpdateHapPolicy's uidOut: drives the uid-change branch of
// InstallSession::UpdateToken (0 = no/unchanged uid reported).
int32_t g_spmUpdateHapPolicyUidOut = 0;
int32_t g_spmFinishInstallRet = 0;
// Optional result sequence: when non-empty each FinishInstall call pops the
// next entry (drives the transient-failure-then-retry-succeeds branch); when
// exhausted or empty the scalar g_spmFinishInstallRet applies.
std::vector<int32_t> g_spmFinishInstallRetSeq;
int32_t g_spmFinishInstallCallCount = 0;
bool g_spmFinishInstallLastPersistent = false;
// Return-value knobs for the recovery paths (TryRecoverUidError /
// TryRecoverAlreadyExistError) and the module-uninstall re-sign flow.
int32_t g_spmMigrateInstalledBundlesRet = 0;
int32_t g_spmDeleteIdentityRet = 0;
// Recording knobs for MigrateInstalledBundles: the parallel lists must carry
// the same entry count (alignment contract consumed by the AT side).
int32_t g_spmLastMigratedBaseInfoCount = 0;
int32_t g_spmLastMigratedUidCount = 0;
// Recording knobs for DeleteIdentity: the recovery path currently deletes by
// bundle name with tokenId == 0 (which the AT side interprets as "every token
// of the bundle"); tests can assert the call shape and make that blast radius
// visible instead of silently succeeding.
uint64_t g_lastDeleteIdentityTokenId = 0;
std::string g_lastDeleteIdentityBundleName;
int32_t g_lastDeleteIdentityType = 0;

void ResetSpmKitMockValuesForTest()
{
    g_spmCheckHapSignInfoRet = 0;
    g_spmCheckHapSignInfoSessionId = 0;
    g_spmCheckHapSignInfoLastUserId = 0;
    g_spmTrustedBundleInfos.clear();
    g_spmCheckHapPermissionInfoRet = 0;
    g_spmCheckHapPermissionInfoCallCount = 0;
    g_spmPrepareHapIdentityRet = 0;
    g_spmPrepareIdentityTokenId = 0;
    g_spmPrepareIdentityUid = 0;
    g_spmPrepareIdentitySessionId = 0;
    g_spmPrepareIdentityForceReallocate = false;
    g_spmUpdateHapPolicyRet = 0;
    g_spmUpdateHapPolicyUidOut = 0;
    g_spmGetHapBaseInfoByUidRet = -1;
    g_spmGetHapBaseInfo = Security::AccessToken::HapBaseInfo();
    g_spmFinishInstallRet = 0;
    g_spmFinishInstallRetSeq.clear();
    g_spmFinishInstallCallCount = 0;
    g_spmFinishInstallLastPersistent = false;
    g_spmMigrateInstalledBundlesRet = 0;
    g_spmLastMigratedBaseInfoCount = 0;
    g_spmLastMigratedUidCount = 0;
    g_spmDeleteIdentityRet = 0;
    g_lastDeleteIdentityTokenId = 0;
    g_lastDeleteIdentityBundleName.clear();
    g_lastDeleteIdentityType = 0;
}

void SetAccessTokenIDForTest(unsigned int value)
{
    g_accessTokenID = value;
}

void SetErrCodeForTest(int32_t value)
{
    g_errCode = value;
}

void PushInitHapTokenResultForTest(int32_t ret)
{
    g_initHapTokenRetSeq.push_back(ret);
}

void ClearInitHapTokenMockStateForTest()
{
    g_initHapTokenRetSeq.clear();
    g_initHapTokenCalls.clear();
    g_initHapPolicyCalls.clear();
    g_resetRecoveryStatusRet = 0;
    g_resetRecoveryStatusCallCount = 0;
    g_updateHapTokenCallCount = 0;
    g_updateHapTokenRet = 0;
}

size_t GetInitHapTokenCallCountForTest()
{
    return g_initHapTokenCalls.size();
}

HapInfoParams GetInitHapInfoParamsForTest(size_t index)
{
    if (index >= g_initHapTokenCalls.size()) {
        return HapInfoParams();
    }
    return g_initHapTokenCalls[index];
}

HapPolicyParams GetInitHapPolicyParamsForTest(size_t index)
{
    if (index >= g_initHapPolicyCalls.size()) {
        return HapPolicyParams();
    }
    return g_initHapPolicyCalls[index];
}

int32_t GetResetDatabaseRecoveryStatusCallCountForTest()
{
    return g_resetRecoveryStatusCallCount;
}

void SetResetDatabaseRecoveryStatusResultForTest(int32_t ret)
{
    g_resetRecoveryStatusRet = ret;
}

int32_t GetUpdateHapTokenCallCountForTest()
{
    return g_updateHapTokenCallCount;
}

void SetUpdateHapTokenResultForTest(int32_t ret)
{
    g_updateHapTokenRet = ret;
}

AccessTokenIDEx AccessTokenKit::AllocHapToken(const HapInfoParams& info, const HapPolicyParams& policy)
{
    AccessTokenIDEx token;
    token.tokenIDEx = 1;
    token.tokenIdExStruct.tokenID = 1;
    token.tokenIdExStruct.tokenAttr = 1;
    return token;
}

#ifdef BUNDLE_PERMISSION_START_FULL_FALSE
int AccessTokenKit::GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDef>& permList)
{
#ifdef BUNDLE_PERMISSION_DEF_TRUE
    PermissionDef PermissionDef;
    PermissionDef.permissionName = "testName";
    permList.push_back(PermissionDef);
    return 0;
#else
    return -1;
#endif
}
#else
int AccessTokenKit::GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDef>& permList)
{
    return 0;
}
#endif


#ifdef BUNDLE_PERMISSION_DEF_LIST
int AccessTokenKit::GetReqPermissions(AccessTokenID tokenID, std::vector<PermissionStateFull>& reqPermList,
    bool isSystemGrant)
{
    #ifdef BUNDLE_PERMISSION_DEF_TRUE
    PermissionStateFull permissionStateFull;
    permissionStateFull.permissionName = "testName";
    permissionStateFull.resDeviceID.push_back("100");
    permissionStateFull.grantStatus.push_back(GRANT_STATUS);
    reqPermList.push_back(permissionStateFull);
    return 0;
    #else
    return -1;
    #endif
}

int AccessTokenKit::GrantPermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag)
{
    return 1;
}

int AccessTokenKit::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    auto verifyIter = g_verifyAccessTokenResults.find(permissionName);
    if (verifyIter != g_verifyAccessTokenResults.end()) {
        return verifyIter->second;
    }
#ifdef BUNDLE_PERMISSION_DEF_TRUE
    if (permissionName == "testName") {
        return 0;
    } else {
        return -1;
    }
#else
    return -1;
#endif
}

int AccessTokenKit::GetDefPermission(const std::string& permissionName, PermissionDef& permissionDefResult)
{
    return 0;
}

ATokenTypeEnum AccessTokenKit::GetTokenTypeFlag(AccessTokenID tokenID)
{
    return g_tokenTypeFlag;
}
#else
int AccessTokenKit::GetReqPermissions(AccessTokenID tokenID, std::vector<PermissionStateFull>& reqPermList,
    bool isSystemGrant)
{
    return 0;
}

int AccessTokenKit::GrantPermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag)
{
    return 0;
}

int AccessTokenKit::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    auto verifyIter = g_verifyAccessTokenResults.find(permissionName);
    if (verifyIter != g_verifyAccessTokenResults.end()) {
        return verifyIter->second;
    }
    return 0;
}

int AccessTokenKit::GetDefPermission(const std::string& permissionName, PermissionDef& permissionDefResult)
{
    return -1;
}

ATokenTypeEnum AccessTokenKit::GetTokenTypeFlag(AccessTokenID tokenID)
{
    return g_tokenTypeFlag;
}
#endif

int AccessTokenKit::VerifyAccessToken(
    AccessTokenID callerTokenID, AccessTokenID firstTokenID, const std::string& permissionName)
{
    return 0;
}

int AccessTokenKit::DeleteToken(AccessTokenID tokenID, bool isTokenReserved)
{
    return 0;
}

int AccessTokenKit::ClearUserGrantedPermissionState(AccessTokenID tokenID)
{
    return 0;
}

AccessTokenID AccessTokenKit::GetHapTokenID(int userID, const std::string& bundleName, int instIndex)
{
    return 0;
}

AccessTokenIDEx AccessTokenKit::GetHapTokenIDEx(int userID, const std::string& bundleName, int instIndex)
{
    AccessTokenIDEx tokenIdEx;
    tokenIdEx.tokenIdExStruct.tokenID = g_accessTokenID;
    return tokenIdEx;
}

int AccessTokenKit::GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfo &nativeTokenInfo)
{
    nativeTokenInfo.processName = "foundation";
    return 0;
}

int32_t AccessTokenKit::InitHapToken(const HapInfoParams& info, HapPolicyParams& policy,
    AccessTokenIDEx& fullTokenId, HapInfoCheckResult& checkResult)
{
#ifdef X86_EMULATOR_MODE
    if (policy.checkIgnore != HapPolicyCheckIgnore::ACL_IGNORE_CHECK) {
        return -1;
    }
#endif
    g_initHapTokenCalls.push_back(info);
    g_initHapPolicyCalls.push_back(policy);
    int32_t ret = 0;
    if (!g_initHapTokenRetSeq.empty()) {
        ret = g_initHapTokenRetSeq.front();
        g_initHapTokenRetSeq.erase(g_initHapTokenRetSeq.begin());
    }
    if (ret == 0) {
        fullTokenId.tokenIDEx = 1;
        checkResult.permCheckResult.permissionName = "test"; // invalid Name
    }
    return ret;
}

int32_t AccessTokenKit::ResetDatabaseRecoveryStatus()
{
    ++g_resetRecoveryStatusCallCount;
    if (g_resetRecoveryStatusRet != 0) {
        // Faithful to the access_token service contract (4883.diff): on failure the
        // dberror parameter is left untouched, so the next mount point re-enters recovery.
        return g_resetRecoveryStatusRet;
    }
    // Success clears the marker, mirroring SetParameter("persist.accesstoken.permission.dberror",
    // "0") on the service side; this is the latch that makes the second mount point idempotent.
    OHOS::system::SetParameter(MOCK_DB_ERROR_PARAM, "0");
    return g_resetRecoveryStatusRet;
}

int32_t AccessTokenKit::UpdateHapToken(AccessTokenIDEx& tokenIdEx, const UpdateHapInfoParams& info,
    const HapPolicyParams& policy, HapInfoCheckResult& checkResult)
{
    ++g_updateHapTokenCallCount;
    if (g_updateHapTokenRet != 0) {
        return g_updateHapTokenRet;
    }
#ifdef X86_EMULATOR_MODE
    if (policy.checkIgnore != HapPolicyCheckIgnore::ACL_IGNORE_CHECK) {
        return -1;
    }
#endif
    if (info.isSystemApp) {
        tokenIdEx.tokenIdExStruct.tokenAttr = 1;
    } else {
        tokenIdEx.tokenIdExStruct.tokenAttr = 0;
    }
    checkResult.permCheckResult.permissionName = "test"; // invalid Name
    return 0;
}

int AccessTokenKit::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& hapTokenInfoRes)
{
    hapTokenInfoRes.bundleName = "tokenBundle";
    return g_errCode;
}

bool AccessTokenKit::IsCliToolToken(uint64_t tokenId)
{
    return true;
}

void SetVerifyAccessTokenResultForTest(const std::string& permissionName, int result)
{
    g_verifyAccessTokenResults[permissionName] = result;
}

void SetTokenTypeFlagForTest(ATokenTypeEnum tokenType)
{
    g_tokenTypeFlag = tokenType;
}

void ResetVerifyAccessTokenResultsForTest()
{
    g_verifyAccessTokenResults.clear();
}

// ---- SPM stubs: symbol-only with the default control values; the ON-mode
// target drives them through the g_spm* control variables above. ----
int32_t AccessTokenKit::CheckHapSignInfo(const BundleHapList& list, uint32_t flag, int32_t& sessionId,
    std::vector<TrustedBundleInfo>& bundleInfo, HapVerifyResultInfo& resultInfo)
{
    g_spmCheckHapSignInfoLastUserId = list.userId;
    sessionId = g_spmCheckHapSignInfoSessionId;
    bundleInfo = g_spmTrustedBundleInfos;
    return g_spmCheckHapSignInfoRet;
}

int32_t AccessTokenKit::CheckHapPermissionInfo(int32_t sessionId, InstallTypeEnum type,
    HapInfoCheckResult& result)
{
    ++g_spmCheckHapPermissionInfoCallCount;
    return g_spmCheckHapPermissionInfoRet;
}

int32_t AccessTokenKit::PrepareHapIdentity(int32_t& sessionId, const HapBaseInfo& info,
    const BundlePolicy& policy, Identity& identity)
{
    if (sessionId == 0 && g_spmPrepareIdentitySessionId != 0) {
        // Mirrors the real AT contract: a deferred caller (session id 0) makes
        // the AT side allocate the session and write the id back.
        sessionId = g_spmPrepareIdentitySessionId;
    }
    if (identity.uid != 0 && !g_spmPrepareIdentityForceReallocate) {
        // Mirrors the AT adopt-or-reallocate contract: a desired uid passed by the
        // caller is adopted and returned unchanged.
    } else {
        identity.uid = g_spmPrepareIdentityUid;
    }
    identity.tokenId = g_spmPrepareIdentityTokenId;
    return g_spmPrepareHapIdentityRet;
}

int32_t AccessTokenKit::UpdateHapPolicy(int32_t sessionId, int32_t tokenId,
    const BundlePolicy& policy, int32_t& uid)
{
    uid = g_spmUpdateHapPolicyUidOut;
    return g_spmUpdateHapPolicyRet;
}

int32_t AccessTokenKit::FinishInstall(int32_t sessionId, bool isPersistent,
    const std::map<std::string, std::string>& modulePathMap)
{
    ++g_spmFinishInstallCallCount;
    g_spmFinishInstallLastPersistent = isPersistent;
    if (!g_spmFinishInstallRetSeq.empty()) {
        int32_t ret = g_spmFinishInstallRetSeq.front();
        g_spmFinishInstallRetSeq.erase(g_spmFinishInstallRetSeq.begin());
        return ret;
    }
    return g_spmFinishInstallRet;
}

int32_t AccessTokenKit::GetHapSignInfo(const std::string& bundleName, uint32_t flag,
    std::vector<TrustedBundleInfo>& bundleInfo)
{
    return 0;
}

int32_t AccessTokenKit::GetCacheSignInfoBySessionId(int32_t sessionId, uint32_t flag,
    std::vector<TrustedBundleInfo>& bundleInfo)
{
    return 0;
}

int32_t AccessTokenKit::GetCachePolicyBySessionId(int32_t sessionId, const std::string& bundleName,
    BundlePolicyInfo& bundlePolicyInfo)
{
    return 0;
}

int32_t AccessTokenKit::DeleteIdentity(AccessTokenID tokenID, const std::string& bundleName,
    ReservedType type)
{
    g_lastDeleteIdentityTokenId = tokenID;
    g_lastDeleteIdentityBundleName = bundleName;
    g_lastDeleteIdentityType = static_cast<int32_t>(type);
    return g_spmDeleteIdentityRet;
}

int32_t AccessTokenKit::MigrateInstalledBundles(const std::vector<MigratedInfo>& migratedInfoList,
    std::vector<BundleMigrateResult>& results)
{
    // Recording knobs: the migration lists must stay aligned (one uid per base
    // info) — tests pin the alignment so a conditional staging bug cannot
    // silently bind clone identities to the wrong uids.
    if (!migratedInfoList.empty()) {
        g_spmLastMigratedBaseInfoCount =
            static_cast<int32_t>(migratedInfoList[0].hapBaseInfoList.size());
        g_spmLastMigratedUidCount = static_cast<int32_t>(migratedInfoList[0].uidList.size());
    } else {
        g_spmLastMigratedBaseInfoCount = 0;
        g_spmLastMigratedUidCount = 0;
    }
    return g_spmMigrateInstalledBundlesRet;
}

int32_t AccessTokenKit::FinishMigration()
{
    return 0;
}

int32_t AccessTokenKit::CheckMigratedUidSet(
    const std::set<int32_t, std::less<int32_t>, std::allocator<int32_t>>& totalUids,
    std::set<int32_t, std::less<int32_t>, std::allocator<int32_t>>& unreceivedUids)
{
    (void)totalUids;
    unreceivedUids.clear();
    return 0;
}

int32_t AccessTokenKit::GetHapBaseInfoByUid(int32_t uid, HapBaseInfo& info)
{
    if (g_spmGetHapBaseInfoByUidRet != 0) {
        return g_spmGetHapBaseInfoByUidRet;
    }
    info = g_spmGetHapBaseInfo;
    return 0;
}
}
}
}