/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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

#include "bundle_permission_mgr.h"

bool g_isSystemApp = true;
bool g_isNativeTokenType = true;
bool g_verifyPermission = true;
bool g_verifyCallingBundleSdkVersion  = true;
bool g_isBundleSelfCalling = true;
bool g_checkUserFromShell = true;
int32_t g_hapApiVersion = 0;
bool g_isSystemAppFalse = false;
bool g_verifyCallingBundleSdkVersionFalse = false;
bool g_userFromShell = false;
bool g_isSelfCalling = true;
bool g_isShellTokenType = true;
bool g_verifyUninstallPermission = true;
bool g_isCallingUidValid = true;
bool g_verifyPermissionFalse = false;
bool g_isBundleSelfCallingFalse = false;

void SetSystemAppForTest(bool value)
{
    g_isSystemApp = value;
}

void SetNativeTokenTypeForTest(bool value)
{
    g_isNativeTokenType = value;
}

void SetVerifyCallingPermissionForTest(bool value)
{
    g_verifyPermission = value;
}

void SetHapApiVersion(int32_t version)
{
    g_hapApiVersion = version;
}

void SetVerifyCallingBundleSdkVersionForTest(bool value)
{
    g_verifyCallingBundleSdkVersion = value;
}

void SetIsBundleSelfCallingForTest(bool value)
{
    g_isBundleSelfCalling = value;
}
void SetSystemAppFalseForTest(bool value)
{
    g_isSystemAppFalse = value;
}

void SetVerifyUninstallPermission(bool value)
{
    g_verifyUninstallPermission = value;
}

void SetVerifyCallingBundleSdkVersionForTestFalse(bool value)
{
    g_verifyCallingBundleSdkVersionFalse = value;
}

void SetUserFromShellForTest(bool value)
{
    g_userFromShell = value;
}

void SetIsSelfCalling(bool value)
{
    g_isSelfCalling = value;
}

void SetIsShellTokenType(bool value)
{
    g_isShellTokenType = value;
}

void SetIsCallingUidValid(bool value)
{
    g_isCallingUidValid = value;
}

void SetCheckUserFromShellForTest(bool value)
{
    g_checkUserFromShell = value;
}

void SetVerifyCallingPermissionForTestFalse(bool value)
{
    g_verifyPermissionFalse = value;
}

void SetIsBundleSelfCallingForTestFalse(bool value)
{
    g_isBundleSelfCallingFalse = value;
}

void ResetTestValues()
{
    g_isNativeTokenType = true;
    g_verifyPermission = true;
    g_isSystemApp = true;
    g_hapApiVersion = 0;
    g_verifyCallingBundleSdkVersion = true;
    g_isBundleSelfCalling = true;
    g_checkUserFromShell = true;
    g_isSystemAppFalse = false;
    g_verifyCallingBundleSdkVersionFalse = false;
    g_userFromShell = false;
    g_isSelfCalling = true;
    g_isShellTokenType = true;
    g_verifyUninstallPermission = true;
    g_isCallingUidValid = true;
    g_verifyPermissionFalse = false;
    g_isBundleSelfCallingFalse = false;
}
namespace OHOS {
int32_t g_testVerifyPermission = 0;
namespace AppExecFwk {
using namespace Security::AccessToken;

#ifdef BUNDLE_FRAMEWORK_PERMISSION_RETURN_FALSE

bool BundlePermissionMgr::VerifyCallingUid()
{
    return false;
}

bool BundlePermissionMgr::VerifyPreload(const AAFwk::Want &want)
{
    return false;
}

bool BundlePermissionMgr::IsCallingUidValid(int32_t uid)
{
    return false;
}

bool BundlePermissionMgr::VerifyPermissionByCallingTokenId(const std::string &permissionName,
    const Security::AccessToken::AccessTokenID callerToken)
{
    return false;
}

bool BundlePermissionMgr::VerifyCallingPermissionForAll(const std::string &permissionName)
{
    return g_verifyPermissionFalse;
}

bool BundlePermissionMgr::VerifyCallingPermissionsForAll(const std::vector<std::string> &permissionNames)
{
    return g_verifyPermissionFalse;
}

bool BundlePermissionMgr::IsSelfCalling()
{
    return false;
}

bool BundlePermissionMgr::VerifyRecoverPermission()
{
    return false;
}

bool BundlePermissionMgr::VerifyUninstallPermission()
{
    return false;
}

bool BundlePermissionMgr::IsBundleSelfCalling(const std::string &bundleName)
{
    return g_isBundleSelfCallingFalse;
}

bool BundlePermissionMgr::IsBundleSelfCalling(const std::string &bundleName, const int32_t &appIndex)
{
    return false;
}
int32_t BundlePermissionMgr::DeleteAccessTokenId(const AccessTokenID tokenId)
{
    return -1;
}
bool BundlePermissionMgr::VerifyAcrossUserPermission(int userId)
{
    return false;
}
#else
int32_t BundlePermissionMgr::DeleteAccessTokenId(const AccessTokenID tokenId)
{
    return 0;
}

bool BundlePermissionMgr::VerifyCallingUid()
{
    return true;
}

bool BundlePermissionMgr::VerifyPreload(const AAFwk::Want &want)
{
    return true;
}

bool BundlePermissionMgr::IsCallingUidValid(int32_t uid)
{
    return g_isCallingUidValid;
}

bool BundlePermissionMgr::VerifyPermissionByCallingTokenId(const std::string &permissionName,
    const Security::AccessToken::AccessTokenID callerToken)
{
    return true;
}

bool BundlePermissionMgr::VerifyCallingPermissionForAll(const std::string &permissionName)
{
    return g_verifyPermission;
}

bool BundlePermissionMgr::VerifyCallingPermissionsForAll(const std::vector<std::string> &permissionNames)
{
    return g_verifyPermission;
}

bool BundlePermissionMgr::IsSelfCalling()
{
    return g_isSelfCalling;
}

bool BundlePermissionMgr::VerifyRecoverPermission()
{
    return true;
}

bool BundlePermissionMgr::VerifyUninstallPermission()
{
    return g_verifyUninstallPermission;
}

bool BundlePermissionMgr::IsBundleSelfCalling(const std::string &bundleName)
{
    return g_isBundleSelfCalling;
}

bool BundlePermissionMgr::IsBundleSelfCalling(const std::string &bundleName, const int32_t &appIndex)
{
    return true;
}
bool BundlePermissionMgr::VerifyAcrossUserPermission(int userId)
{
    return true;
}
#endif

#ifdef BUNDLE_NOT_IS_NAYIVE_TOKEN_TYPE
bool BundlePermissionMgr::IsNativeTokenType()
{
    return false;
}
#else
bool BundlePermissionMgr::IsNativeTokenType()
{
    return g_isNativeTokenType;
}
#endif

bool BundlePermissionMgr::IsShellTokenType()
{
    return g_isShellTokenType;
}

bool BundlePermissionMgr::Init()
{
    return true;
}

void BundlePermissionMgr::UnInit()
{
}

int32_t BundlePermissionMgr::VerifyPermission(const std::string &bundleName, const std::string &permissionName,
    const int32_t userId)
{
    return g_testVerifyPermission;
}

ErrCode BundlePermissionMgr::GetPermissionDef(const std::string &permissionName, PermissionDef &permissionDef)
{
    return ERR_OK;
}

bool BundlePermissionMgr::RequestPermissionFromUser(
    const std::string &bundleName, const std::string &permissionName, const int32_t userId)
{
    return true;
}

bool BundlePermissionMgr::GetRequestPermissionStates(BundleInfo &bundleInfo, uint32_t tokenId,
    const std::string deviceId)
{
    return true;
}

int32_t BundlePermissionMgr::ClearUserGrantedPermissionState(const AccessTokenID tokenId)
{
    return 0;
}

bool BundlePermissionMgr::GetAllReqPermissionStateFull(AccessTokenID tokenId,
    std::vector<PermissionStateFull> &newPermissionState)
{
    return true;
}

#ifdef BUNDLE_FRAMEWORK_SYSTEM_APP_FALSE
bool BundlePermissionMgr::VerifySystemApp(int32_t beginApiVersion)
{
    return false;
}

bool BundlePermissionMgr::IsSystemApp()
{
    return g_isSystemAppFalse;
}

// for old api
bool BundlePermissionMgr::VerifyCallingBundleSdkVersion(int32_t beginApiVersion)
{
    return g_verifyCallingBundleSdkVersionFalse;
}

bool BundlePermissionMgr::CheckUserFromShell(int32_t userId)
{
    return g_userFromShell;
}
#else
bool BundlePermissionMgr::VerifySystemApp(int32_t beginApiVersion)
{
    return true;
}

bool BundlePermissionMgr::IsSystemApp()
{
    return g_isSystemApp;
}

bool BundlePermissionMgr::CheckUserFromShell(int32_t userId)
{
    return g_checkUserFromShell;
}

// for old api
bool BundlePermissionMgr::VerifyCallingBundleSdkVersion(int32_t beginApiVersion)
{
    return g_verifyCallingBundleSdkVersion;
}
#endif

int32_t BundlePermissionMgr::GetHapApiVersion()
{
    return g_hapApiVersion;
}

std::vector<Security::AccessToken::PermissionDef> BundlePermissionMgr::GetPermissionDefList(
    const InnerBundleInfo &innerBundleInfo)
{
    std::vector<Security::AccessToken::PermissionDef> vec;
    return vec;
}

std::vector<PermissionStateFull> BundlePermissionMgr::GetPermissionStateFullList(
    const InnerBundleInfo &innerBundleInfo)
{
    std::vector<PermissionStateFull> vec;
    return vec;
}

Security::AccessToken::ATokenAplEnum BundlePermissionMgr::GetTokenApl(const std::string &apl)
{
    return Security::AccessToken::ATokenAplEnum::APL_NORMAL;
}

Security::AccessToken::HapPolicyParams BundlePermissionMgr::CreateHapPolicyParam(
    const InnerBundleInfo &innerBundleInfo, const std::string &appServiceCapabilities)
{
    Security::AccessToken::HapPolicyParams policy;
    return policy;
}

void BundlePermissionMgr::ConvertPermissionDef(const Security::AccessToken::PermissionDef &permDef,
    PermissionDef &permissionDef)
{
}

void BundlePermissionMgr::ConvertPermissionDef(
    Security::AccessToken::PermissionDef &permDef, const DefinePermission &defPermission,
    const std::string &bundleName)
{
}

bool BundlePermissionMgr::GetDefaultPermission(const std::string &bundleName, DefaultPermission &permission)
{
    return true;
}

bool BundlePermissionMgr::MatchSignature(const DefaultPermission &permission,
    const std::string &signature)
{
    return true;
}

bool BundlePermissionMgr::MatchSignature(const DefaultPermission &permission,
    const std::vector<std::string> &signatures)
{
    return true;
}

bool BundlePermissionMgr::CheckPermissionInDefaultPermissions(const DefaultPermission &defaultPermission,
    const std::string &permissionName, bool &userCancellable)
{
    return true;
}

void BundlePermissionMgr::AddPermissionUsedRecord(
    const std::string &permission, int32_t successCount, int32_t failCount)
{
}


Security::AccessToken::HapInfoParams CreateHapInfoParams(const InnerBundleInfo &innerBundleInfo,
    const int32_t userId, const int32_t dlpType)
{
    Security::AccessToken::HapInfoParams params;
    return params;
}

#ifdef BUNDLE_FRAMEWORK_PERMISSION_RETURN_FALSE
int32_t BundlePermissionMgr::InitHapToken(const InnerBundleInfo &innerBundleInfo, const int32_t userId,
    const int32_t dlpType, Security::AccessToken::AccessTokenIDEx &tokenIdeEx,
    Security::AccessToken::HapInfoCheckResult &checkResult, const std::string &appServiceCapabilities)
{
    return -1;
}

int32_t BundlePermissionMgr::UpdateHapToken(Security::AccessToken::AccessTokenIDEx &tokenIdeEx,
    const InnerBundleInfo &innerBundleInfo, int32_t userId, Security::AccessToken::HapInfoCheckResult &checkResult,
    const std::string &appServiceCapabilities, bool dataRefresh)
{
    return -1;
}
#else
int32_t BundlePermissionMgr::InitHapToken(const InnerBundleInfo &innerBundleInfo, const int32_t userId,
    const int32_t dlpType, Security::AccessToken::AccessTokenIDEx &tokenIdeEx,
    Security::AccessToken::HapInfoCheckResult &checkResult, const std::string &appServiceCapabilities)
{
    return 0;
}

int32_t BundlePermissionMgr::UpdateHapToken(Security::AccessToken::AccessTokenIDEx &tokenIdeEx,
    const InnerBundleInfo &innerBundleInfo, int32_t userId, Security::AccessToken::HapInfoCheckResult &checkResult,
    const std::string &appServiceCapabilities, bool dataRefresh)
{
    return 0;
}
#endif
std::string BundlePermissionMgr::GetCheckResultMsg(const Security::AccessToken::HapInfoCheckResult &checkResult)
{
    return "";
}
} // AppExecFwk
} // OHOS