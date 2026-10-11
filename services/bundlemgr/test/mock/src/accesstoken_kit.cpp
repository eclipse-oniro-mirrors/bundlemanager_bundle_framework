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
// controllable return value for IsCliToolToken, default true (CLI tool calling)
bool g_isCliToolToken = true;
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
// Forces PrepareHapIdentity to ignore the desired uid and return the knob uid,
// so tests can construct the "AT did not adopt the desired uid and reallocated
// a new one" (mismatch) path that the default adopt-or-reallocate mock cannot.
bool g_spmPrepareIdentityForceReallocate = false;
int32_t g_spmUpdateHapPolicyRet = 0;
int32_t g_spmFinishInstallRet = 0;
int32_t g_spmFinishInstallCallCount = 0;
bool g_spmFinishInstallLastPersistent = false;

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
    g_spmPrepareIdentityForceReallocate = false;
    g_spmUpdateHapPolicyRet = 0;
    g_spmFinishInstallRet = 0;
    g_spmFinishInstallCallCount = 0;
    g_spmFinishInstallLastPersistent = false;
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
    return TOKEN_SHELL;
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
    return 0;
}

int AccessTokenKit::GetDefPermission(const std::string& permissionName, PermissionDef& permissionDefResult)
{
    return -1;
}

ATokenTypeEnum AccessTokenKit::GetTokenTypeFlag(AccessTokenID tokenID)
{
#ifdef BUNDLE_FRAMEWORK_SYSTEM_APP_FALSE
    return TOKEN_INVALID;
#else
    return TOKEN_NATIVE;
#endif
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
    return g_isCliToolToken;
}

void SetIsCliToolTokenForTest(bool value)
{
    g_isCliToolToken = value;
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
    return g_spmUpdateHapPolicyRet;
}

int32_t AccessTokenKit::FinishInstall(int32_t sessionId, bool isPersistent,
    const std::map<std::string, std::string>& modulePathMap)
{
    ++g_spmFinishInstallCallCount;
    g_spmFinishInstallLastPersistent = isPersistent;
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
    return 0;
}

int32_t AccessTokenKit::MigrateInstalledBundles(const std::vector<MigratedInfo>& migratedInfoList,
    std::vector<BundleMigrateResult>& results)
{
    return 0;
}

int32_t AccessTokenKit::FinishMigration()
{
    return 0;
}

int32_t AccessTokenKit::GetHapBaseInfoByUid(int32_t uid, HapBaseInfo& info)
{
    return 0;
}
}
}
}