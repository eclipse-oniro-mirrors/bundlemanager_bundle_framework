/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

bool BundlePermissionMgr::VerifyCallingPermissionForAll(const std::string &permissionName)
{
    return false;
}

bool BundlePermissionMgr::VerifyCallingPermissionsForAll(const std::vector<std::string> &permissionNames)
{
    return false;
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
    return false;
}

bool BundlePermissionMgr::IsBundleSelfCalling(const std::string &bundleName, const int32_t &appIndex)
{
    return false;
}
#else

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
    return true;
}

bool BundlePermissionMgr::VerifyCallingPermissionForAll(const std::string &permissionName)
{
    return true;
}

bool BundlePermissionMgr::VerifyCallingPermissionsForAll(const std::vector<std::string> &permissionNames)
{
    return true;
}

bool BundlePermissionMgr::IsSelfCalling()
{
    return true;
}

bool BundlePermissionMgr::VerifyRecoverPermission()
{
    return true;
}

bool BundlePermissionMgr::VerifyUninstallPermission()
{
    return true;
}

bool BundlePermissionMgr::IsBundleSelfCalling(const std::string &bundleName)
{
    return true;
}

bool BundlePermissionMgr::IsBundleSelfCalling(const std::string &bundleName, const int32_t &appIndex)
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
    return true;
}
#endif

bool BundlePermissionMgr::IsShellTokenType()
{
    return true;
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
    return 0;
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

int32_t BundlePermissionMgr::DeleteAccessTokenId(const AccessTokenID tokenId)
{
    return 0;
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
    return false;
}

// for old api
bool BundlePermissionMgr::VerifyCallingBundleSdkVersion(int32_t beginApiVersion)
{
    return false;
}
#else
bool BundlePermissionMgr::VerifySystemApp(int32_t beginApiVersion)
{
    return true;
}

bool BundlePermissionMgr::IsSystemApp()
{
    return true;
}

// for old api
bool BundlePermissionMgr::VerifyCallingBundleSdkVersion(int32_t beginApiVersion)
{
    return true;
}
#endif

int32_t BundlePermissionMgr::GetHapApiVersion()
{
    return 0;
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

int32_t BundlePermissionMgr::InitHapToken(const InnerBundleInfo &innerBundleInfo, const int32_t userId,
    const int32_t dlpType, Security::AccessToken::AccessTokenIDEx &tokenIdeEx,
    Security::AccessToken::HapInfoCheckResult &checkResult, const std::string &appServiceCapabilities)
{
    return 0;
}

int32_t BundlePermissionMgr::UpdateHapToken(Security::AccessToken::AccessTokenIDEx &tokenIdeEx,
    const InnerBundleInfo &innerBundleInfo, int32_t userId, Security::AccessToken::HapInfoCheckResult &checkResult,
    const std::string &appServiceCapabilities)
{
    return 0;
}

std::string BundlePermissionMgr::GetCheckResultMsg(const Security::AccessToken::HapInfoCheckResult &checkResult)
{
    return "";
}
} // AppExecFwk
} // OHOS