/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

namespace OHOS {
namespace AppExecFwk {
using namespace Security::AccessToken;

#ifdef IS_SYSTEM_APP_RETURN_TRUE
bool BundlePermissionMgr::IsSystemApp()
{
    return true;
}
#else
bool BundlePermissionMgr::IsSystemApp()
{
    return false;
}
#endif

#ifdef VERIFY_CALLING_PERMISSION_FOR_ALL_RETURN_TRUE
bool BundlePermissionMgr::VerifyCallingPermissionForAll(const std::string &permissionName)
{
    return true;
}
#else
bool BundlePermissionMgr::VerifyCallingPermissionForAll(const std::string &permissionName)
{
    return false;
}
#endif

#ifdef VERIFY_CALLING_PERMISSIONS_FOR_ALL_RETURN_TRUE
bool BundlePermissionMgr::VerifyCallingPermissionsForAll(const std::vector<std::string> &permissionNames)
{
    return true;
}
#else
bool BundlePermissionMgr::VerifyCallingPermissionsForAll(const std::vector<std::string> &permissionNames)
{
    return false;
}
#endif

#ifdef IS_BUNDLE_SELF_CALLING_RETURN_TRUE
bool BundlePermissionMgr::IsBundleSelfCalling(const std::string &bundleName)
{
    return true;
}

bool BundlePermissionMgr::IsBundleSelfCalling(const std::string &bundleName, const int32_t &appIndex)
{
    return true;
}
#else
bool BundlePermissionMgr::IsBundleSelfCalling(const std::string &bundleName)
{
    return false;
}

bool BundlePermissionMgr::IsBundleSelfCalling(const std::string &bundleName, const int32_t &appIndex)
{
    return false;
}
#endif

bool BundlePermissionMgr::Init()
{
    return true;
}

void BundlePermissionMgr::UnInit()
{
}

void BundlePermissionMgr::ConvertPermissionDef(
    const Security::AccessToken::PermissionDef &permDef, PermissionDef &permissionDef)
{
}

// Convert from the struct DefinePermission that parsed from config.json
void BundlePermissionMgr::ConvertPermissionDef(Security::AccessToken::PermissionDef &permDef,
    const DefinePermission &definePermission, const std::string &bundleName)
{
}

Security::AccessToken::ATokenAvailableTypeEnum BundlePermissionMgr::GetAvailableType(
    const std::string &availableType)
{
    return Security::AccessToken::ATokenAvailableTypeEnum::NORMAL;
}

Security::AccessToken::ATokenAplEnum BundlePermissionMgr::GetTokenApl(const std::string &apl)
{
    return Security::AccessToken::ATokenAplEnum::APL_NORMAL;
}

Security::AccessToken::HapPolicyParams BundlePermissionMgr::CreateHapPolicyParam(const InnerBundleInfo &innerBundleInfo,
    const std::string &appServiceCapabilities)
{
    Security::AccessToken::HapPolicyParams hapPolicy;
    return hapPolicy;
}

int32_t BundlePermissionMgr::DeleteAccessTokenId(const Security::AccessToken::AccessTokenID tokenId)
{
    return -1;
}

int32_t BundlePermissionMgr::ClearUserGrantedPermissionState(const Security::AccessToken::AccessTokenID tokenId)
{
    return -1;
}

std::vector<Security::AccessToken::PermissionDef> BundlePermissionMgr::GetPermissionDefList(
    const InnerBundleInfo &innerBundleInfo)
{
    std::vector<Security::AccessToken::PermissionDef> permList;
    return permList;
}

std::vector<Security::AccessToken::PermissionStateFull> BundlePermissionMgr::GetPermissionStateFullList(
    const InnerBundleInfo &innerBundleInfo)
{
    std::vector<Security::AccessToken::PermissionStateFull> permStateFullList;
    return permStateFullList;
}

bool BundlePermissionMgr::GetAllReqPermissionStateFull(Security::AccessToken::AccessTokenID tokenId,
    std::vector<Security::AccessToken::PermissionStateFull> &newPermissionState)
{
    return true;
}

bool BundlePermissionMgr::GetRequestPermissionStates(
    BundleInfo &bundleInfo, uint32_t tokenId, const std::string deviceId)
{
    return true;
}

bool BundlePermissionMgr::VerifyPermissionByCallingTokenId(const std::string &permissionName,
    const Security::AccessToken::AccessTokenID callerToken)
{
    return false;
}

int32_t BundlePermissionMgr::VerifyPermission(
    const std::string &bundleName, const std::string &permissionName, const int32_t userId)
{
    return -1;
}

ErrCode BundlePermissionMgr::GetPermissionDef(const std::string &permissionName, PermissionDef &permissionDef)
{
    return ERR_OK;
}

bool BundlePermissionMgr::CheckPermissionInDefaultPermissions(const DefaultPermission &defaultPermission,
    const std::string &permissionName, bool &userCancellable)
{
    return true;
}

bool BundlePermissionMgr::GetDefaultPermission(
    const std::string &bundleName, DefaultPermission &permission)
{
    return true;
}

bool BundlePermissionMgr::MatchSignature(
    const DefaultPermission &permission, const std::vector<std::string> &signatures)
{
    return false;
}

bool BundlePermissionMgr::MatchSignature(
    const DefaultPermission &permission, const std::string &signature)
{
    return false;
}

int32_t BundlePermissionMgr::GetHapApiVersion()
{
    return -1;
}

// if the api has been system api since it is published, then beginSystemApiVersion can be omitted
bool BundlePermissionMgr::VerifySystemApp(int32_t beginSystemApiVersion)
{
    return false;
}

bool BundlePermissionMgr::IsNativeTokenType()
{
    return false;
}

bool BundlePermissionMgr::IsShellTokenType()
{
    return false;
}

bool BundlePermissionMgr::IsNativeTokenTypeOnly()
{
    return true;
}

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

bool BundlePermissionMgr::IsSelfCalling()
{
    return false;
}

bool BundlePermissionMgr::VerifyUninstallPermission()
{
    return true;
}

bool BundlePermissionMgr::VerifyRecoverPermission()
{
    return true;
}

void BundlePermissionMgr::AddPermissionUsedRecord(
    const std::string &permission, int32_t successCount, int32_t failCount)
{
}

#ifdef VERIFY_CALLING_BUNDLE_SDK_VERSION_RETURN_TRUE
bool BundlePermissionMgr::VerifyCallingBundleSdkVersion(int32_t beginApiVersion)
{
    return true;
}
#else
bool BundlePermissionMgr::VerifyCallingBundleSdkVersion(int32_t beginApiVersion)
{
    return false;
}
#endif

Security::AccessToken::HapInfoParams BundlePermissionMgr::CreateHapInfoParams(const InnerBundleInfo &innerBundleInfo,
    const int32_t userId, const int32_t dlpType)
{
    Security::AccessToken::HapInfoParams hapInfo;
    return hapInfo;
}

int32_t BundlePermissionMgr::InitHapToken(const InnerBundleInfo &innerBundleInfo, const int32_t userId,
    const int32_t dlpType, Security::AccessToken::AccessTokenIDEx& tokenIdeEx,
    Security::AccessToken::HapInfoCheckResult &checkResult, const std::string &appServiceCapabilities)
{
    return ERR_OK;
}

int32_t BundlePermissionMgr::UpdateHapToken(Security::AccessToken::AccessTokenIDEx& tokenIdeEx,
    const InnerBundleInfo &innerBundleInfo, int32_t userId, Security::AccessToken::HapInfoCheckResult &checkResult,
    const std::string &appServiceCapabilities, bool dataRefresh)
{
    return ERR_OK;
}

std::string BundlePermissionMgr::GetCheckResultMsg(const Security::AccessToken::HapInfoCheckResult &checkResult)
{
    std::string result = "";
    return result;
}

bool BundlePermissionMgr::CheckUserFromShell(int32_t userId)
{
    return true;
}
}
}
