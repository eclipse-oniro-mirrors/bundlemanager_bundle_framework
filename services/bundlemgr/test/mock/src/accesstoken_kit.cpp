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

#include <atomic>
#include <map>
#include <mutex>
#include <unordered_map>

#include "interfaces/hap_verify.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
#ifdef BUNDLE_PERMISSION_DEF_LIST
#ifdef BUNDLE_PERMISSION_DEF_TRUE
static constexpr int GRANT_STATUS = 100;
#endif
#endif
unsigned int g_accessTokenID = 0;
int32_t g_errCode = 0;
// Cache for sessionId and trustedBundleInfo
static std::map<int32_t, std::vector<TrustedBundleInfo>> g_signInfoCache;
static std::atomic<int32_t> g_nextSessionId{1};

void SetAccessTokenIDForTest(unsigned int value)
{
    g_accessTokenID = value;
}

void SetErrCodeForTest(int32_t value)
{
    g_errCode = value;
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
    fullTokenId.tokenIDEx = 1;
    checkResult.permCheckResult.permissionName = "test"; // invalid Name
    return 0;
}

int32_t AccessTokenKit::UpdateHapToken(AccessTokenIDEx& tokenIdEx, const UpdateHapInfoParams& info,
    const HapPolicyParams& policy, HapInfoCheckResult& checkResult)
{
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

int32_t AccessTokenKit::GetCacheSignInfoBySessionId(
    int32_t sessionId, std::vector<TrustedBundleInfo>& bundleInfo)
{
    auto it = g_signInfoCache.find(sessionId);
    if (it != g_signInfoCache.end()) {
        bundleInfo = it->second;
        return 0;
    }
    return 0;
}

int32_t AccessTokenKit::CheckHapPermissionInfo(
    int32_t sessionId, InstallTypeEnum type, HapInfoCheckResult& result)
{
    return 0;
}

namespace {
constexpr int32_t MOCK_BASE_APP_UID = 10000;
constexpr int32_t MOCK_BASE_USER_RANGE = 200000;

std::mutex g_mockUidMutex;
std::map<std::pair<std::string, int32_t>, int32_t> g_mockBundleIdMap;  // {bundleName, appIndex} -> bundleId
std::unordered_map<int32_t, std::pair<std::string, int32_t>> g_mockUidToBundleMap;  // uid -> {bundleName, appIndex}
int32_t g_mockNextBundleId = MOCK_BASE_APP_UID;

int32_t MockGenerateBundleId(const std::string &bundleName, int32_t appIndex)
{
    auto key = std::make_pair(bundleName, appIndex);
    auto iter = g_mockBundleIdMap.find(key);
    if (iter != g_mockBundleIdMap.end()) {
        return iter->second;
    }
    int32_t bundleId = g_mockNextBundleId++;
    g_mockBundleIdMap[key] = bundleId;
    return bundleId;
}
}  // namespace

int32_t AccessTokenKit::PrepareHapIdentity(
    int32_t& sessionId, const HapBaseInfo& info, const BundlePolicy& policy, Identity& identity)
{
    int32_t bundleId = MockGenerateBundleId(info.bundleName, info.instIndex);
    identity.uid = info.userID * MOCK_BASE_USER_RANGE + bundleId;
    identity.tokenId = 1;
    std::lock_guard<std::mutex> lock(g_mockUidMutex);
    g_mockUidToBundleMap[identity.uid] = {info.bundleName, info.instIndex};
    return 0;
}

int32_t AccessTokenKit::UpdateHapPolicy(int32_t sessionId, int32_t tokenId, const BundlePolicy& policy)
{
    return 0;
}

int32_t AccessTokenKit::FinishInstall(int32_t sessionId, bool isSuccess,
    const std::map<std::string, std::string>& modulePathMap)
{
    return 0;
}

int32_t AccessTokenKit::DeleteIdentity(
    AccessTokenID tokenID, const std::string& bundleName, ReservedType type)
{
    return 0;
}

int32_t g_preMigrateRet = 0;
int32_t g_migrateInstalledBundlesRet = 0;
std::vector<BundleMigrateResult> g_migrateResults;

void SetPreMigrateRetForTest(int32_t value)
{
    g_preMigrateRet = value;
}

void SetMigrateInstalledBundlesRetForTest(int32_t value)
{
    g_migrateInstalledBundlesRet = value;
}

void SetMigrateResultsForTest(const std::vector<BundleMigrateResult>& results)
{
    g_migrateResults = results;
}

int32_t AccessTokenKit::PreMigrateUIDList(const std::vector<int32_t>& uidList)
{
    return g_preMigrateRet;
}

int32_t AccessTokenKit::MigrateInstalledBundles(
    const std::vector<MigratedInfo>& migratedInfoList,
    std::vector<BundleMigrateResult>& results)
{
    results = g_migrateResults;
    return g_migrateInstalledBundlesRet;
}

int32_t AccessTokenKit::FinishMigration()
{
    return 0;
}

// Wraps VerifyOrParseHapPermission to produce TrustedBundleInfo, mirroring
// CheckMultipleHapsSignInfo's real HapVerify call path.
static TrustedBundleInfo BuildTrustedBundleInfoFromHap(const std::string &filePath)
{
    Security::Verify::VerifyParams params;
    params.filePath = filePath;
    params.type = Security::Verify::VerifyType::All;

    Security::Verify::BootstrapInfo bootstrapInfo;
    Security::Verify::ProvisionInfo provisionInfo;
    bool isChanged = false;
    (void)Security::Verify::VerifyOrParseHapPermission(
        params, bootstrapInfo, provisionInfo, isChanged);

    TrustedBundleInfo info;
    info.moduleInfo = bootstrapInfo.moduleRaw;
    info.sharedFiles = bootstrapInfo.shareFilesRaw;

    // profileJsonRaw from BootstrapInfo is the native JSON that ParseProvision expects
    info.profileData.provisionRaw = bootstrapInfo.profileJsonRaw;
    info.profileData.appId = provisionInfo.appId;
    info.profileData.fingerprint = provisionInfo.fingerprint;
    info.profileData.organization = provisionInfo.organization;
    info.profileData.isOpenHarmony = provisionInfo.isOpenHarmony;
    info.profileData.isEnterpriseResigned = provisionInfo.isEnterpriseResigned;
    info.profileData.profileBlockLength = provisionInfo.profileBlockLength;
    if (provisionInfo.profileBlock && provisionInfo.profileBlockLength > 0) {
        info.profileData.profileBlock.assign(
            provisionInfo.profileBlock.get(),
            provisionInfo.profileBlock.get() + provisionInfo.profileBlockLength);
    }
    return info;
}

int32_t AccessTokenKit::CheckHapSignInfo(const BundleHapList& hapList, int32_t& sessionId,
    std::vector<TrustedBundleInfo>& trustedBundleInfo, HapVerifyResultInfo& resultInfo)
{
    sessionId = g_nextSessionId++;
    for (const auto &bundlePath : hapList.hapPaths) {
        trustedBundleInfo.emplace_back(BuildTrustedBundleInfoFromHap(bundlePath));
    }
    g_signInfoCache[sessionId] = trustedBundleInfo;
    return 0;
}

int32_t AccessTokenKit::GetHapSignInfo(const std::string& bundleName,
    std::vector<TrustedBundleInfo>& trustedBundleInfo)
{
    return 0;
}

int32_t AccessTokenKit::GetHapBaseInfoByUid(int32_t uid, HapBaseInfo& info)
{
    std::lock_guard<std::mutex> lock(g_mockUidMutex);
    auto iter = g_mockUidToBundleMap.find(uid);
    if (iter != g_mockUidToBundleMap.end()) {
        info.bundleName = iter->second.first;
        info.instIndex = iter->second.second;
    }
    return 0;
}
}
}
}