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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_MOCK_ACCESS_TOKEN_KIT_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_MOCK_ACCESS_TOKEN_KIT_H

#include <map>
#include <set>
#include <string>
#include <cstddef>
#include <vector>

#include "access_token.h"
#include "hap_token_info.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class AccessTokenKit {
public:
    static AccessTokenIDEx AllocHapToken(const HapInfoParams& info, const HapPolicyParams& policy);
    static int DeleteToken(AccessTokenID tokenID, bool isTokenReserved = false);
    /* Get token type by ATM service */
    static ATokenTypeEnum GetTokenType(AccessTokenID tokenID);
    /* Get token type from flag in tokenId, which doesn't depend on ATM service */
    static ATokenTypeEnum GetTokenTypeFlag(AccessTokenID tokenID);
    static int VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName);
    // ---- SPM interfaces mirrored from the real accesstoken_kit.h (test_spm_inter) ----
    static int32_t CheckHapSignInfo(const BundleHapList& list, uint32_t flag, int32_t& sessionId,
        std::vector<TrustedBundleInfo>& bundleInfo, HapVerifyResultInfo& resultInfo);
    static int32_t CheckHapPermissionInfo(int32_t sessionId, InstallTypeEnum type,
        MultipleMode mode, HapInfoCheckResult& result);
    static int32_t PrepareHapIdentity(int32_t& sessionId, const HapBaseInfo& info,
        const BundlePolicy& policy, Identity& identity);
    static int32_t UpdateHapPolicy(int32_t sessionId, AccessTokenIDEx& tokenIdEx,
        const BundlePolicy& policy, int32_t& uid);
    static int32_t FinishInstall(int32_t sessionId, bool isPersistent,
        const std::map<std::string, std::string>& modulePathMap);
    static int32_t GetHapSignInfo(const std::string& bundleName, uint32_t flag,
        std::vector<TrustedBundleInfo>& bundleInfo);
    static int32_t GetHapSignInfo(const std::string& bundleName, uint32_t flag,
        MultipleMode mode, std::vector<TrustedBundleInfo>& bundleInfo);
    static int32_t GetCacheSignInfoBySessionId(int32_t sessionId, uint32_t flag,
        std::vector<TrustedBundleInfo>& bundleInfo);
    static int32_t GetCachePolicyBySessionId(int32_t sessionId, const std::string& bundleName,
        BundlePolicyInfo& bundlePolicyInfo);
    static int32_t DeleteIdentity(AccessTokenID tokenID, const std::string& bundleName,
        ReservedType type);
    static int32_t MigrateInstalledBundles(const std::vector<MigratedInfo>& migratedInfoList,
        std::vector<BundleMigrateResult>& results);
    static int32_t FinishMigration();
    static int32_t CheckMigratedUidSet(
        const std::set<int32_t, std::less<int32_t>, std::allocator<int32_t>>& totalUids,
        std::set<int32_t, std::less<int32_t>, std::allocator<int32_t>>& unreceivedUids);
    static int32_t GetHapBaseInfoByUid(int32_t uid, HapBaseInfo& info);
    static int VerifyAccessToken(
        AccessTokenID callerTokenID, AccessTokenID firstTokenID, const std::string& permissionName);
    static int GetDefPermission(const std::string& permissionName, PermissionDef& permissionDefResult);
    static int GetDefPermissions(AccessTokenID tokenID, std::vector<PermissionDef>& permList);
    static int GetReqPermissions(
        AccessTokenID tokenID, std::vector<PermissionStateFull>& reqPermList, bool isSystemGrant);
    static int GrantPermission(AccessTokenID tokenID, const std::string& permissionName, uint32_t flag);
    static int ClearUserGrantedPermissionState(AccessTokenID tokenID);
    static AccessTokenID GetHapTokenID(int userID, const std::string& bundleName, int instIndex);
    static AccessTokenIDEx GetHapTokenIDEx(int userID, const std::string& bundleName, int instIndex);
    static int GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfo &nativeTokenInfo);
    static int32_t InitHapToken(const HapInfoParams& info, HapPolicyParams& policy,
        AccessTokenIDEx& fullTokenId, HapInfoCheckResult& checkResult);
    static int32_t UpdateHapToken(AccessTokenIDEx& tokenIdEx, const UpdateHapInfoParams& info,
        const HapPolicyParams& policy, HapInfoCheckResult& checkResult);
    static int GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& hapTokenInfoRes);
    static int32_t ResetDatabaseRecoveryStatus();
    static bool IsCliToolToken(uint64_t tokenId);
};

// Test hooks for BMS unit tests only.
void PushInitHapTokenResultForTest(int32_t ret);
void ClearInitHapTokenMockStateForTest();
size_t GetInitHapTokenCallCountForTest();
HapInfoParams GetInitHapInfoParamsForTest(size_t index);
HapPolicyParams GetInitHapPolicyParamsForTest(size_t index);
int32_t GetResetDatabaseRecoveryStatusCallCountForTest();
void SetResetDatabaseRecoveryStatusResultForTest(int32_t ret);
int32_t GetUpdateHapTokenCallCountForTest();
void SetUpdateHapTokenResultForTest(int32_t ret);
// SPM ON-mode hooks: feed the mocked access-token boundary with the sign
// answer the real AT side would return — the trusted bundle info cached under
// the session id allocated by CheckHapSignInfo, and the identity allocated
// for a fresh install.
void SetSpmTrustedBundleInfosForTest(const std::vector<TrustedBundleInfo>& bundleInfos);
void SetSpmCheckHapSignInfoSessionIdForTest(int32_t sessionId);
void SetSpmPrepareIdentityForTest(uint64_t tokenId, int32_t uid);
// Per-hap-file provision registry: for suites that install several bundles,
// or install a whole directory (whose hap enumeration order is not
// deterministic), tests register each hap file's provision by file name.
// CheckHapSignInfo then answers with exactly one entry per hap path of the
// current install, in the install's hap order — the shape the real AT side
// guarantees. An install containing an unregistered hap fails closed.
void SetSpmTrustedProvisionForHapFileForTest(const std::string& hapFileName,
    const std::string& provisionRaw);
// Minimal valid provisions mirroring what the real AT side verifies for the
// haps' profiles: a debug profile, or a release profile with the given
// app-distribution-type ("crowdtesting" / "os_integration" / "app_gallery").
// allowAppShareLibrary adds the "AllowAppShareLibrary" privilege, required by
// BundleInstallChecker::ProcessBundleInfoByPrivilegeCapability when installing
// a bundle whose bundleType is SHARED (cross-app shared libraries / HSPs).
std::string MakeSpmDebugProvisionRawForTest(const std::string& bundleName,
    bool allowAppShareLibrary = false);
std::string MakeSpmReleaseProvisionRawForTest(const std::string& bundleName,
    const std::string& appDistributionType, bool allowAppShareLibrary = false,
    const std::string& appFeature = "hos_normal_app");
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_ACCESS_TOKEN_KIT_H