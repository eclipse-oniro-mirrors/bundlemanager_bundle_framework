/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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
#include "access_token_error.h"
#include "app_log_tag_wrapper.h"
#include "app_log_wrapper.h"
#include "bundle_mgr_service.h"
#include "bundle_parser.h"
#include "installd_client.h"
#include "ipc_skeleton.h"
#include "parameter.h"
#include "privacy_kit.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
// pre bundle profile
constexpr const char* INSTALL_LIST_PERMISSIONS_CONFIG = "/etc/app/install_list_permissions.json";
constexpr const char* SCENEBOARD_BUNDLE_NAME = "com.ohos.sceneboard";
// install list permissions file
constexpr const char* INSTALL_LIST_PERMISSIONS_FILE_PATH = "/system/etc/app/install_list_permissions.json";
constexpr int16_t BASE_API_VERSION = 1000;
const char* IS_ROOT_MODE_PARAM = "const.debuggable";
const int32_t ROOT_MODE = 1;
const int32_t USER_MODE = 0;
}

using namespace OHOS::Security;
std::map<std::string, DefaultPermission> BundlePermissionMgr::defaultPermissions_;

bool BundlePermissionMgr::Init()
{
    std::vector<std::string> permissionFileList;
#ifdef USE_PRE_BUNDLE_PROFILE
    std::vector<std::string> rootDirList;
    BMSEventHandler::GetPreInstallRootDirList(rootDirList);
    if (rootDirList.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "rootDirList is empty");
        return false;
    }
    for (const auto &item : rootDirList) {
        permissionFileList.push_back(item + INSTALL_LIST_PERMISSIONS_CONFIG);
    }
#else
    permissionFileList.emplace_back(INSTALL_LIST_PERMISSIONS_FILE_PATH);
#endif
    BundleParser bundleParser;
    std::set<DefaultPermission> permissions;
    for (const auto &permissionFile : permissionFileList) {
        if (bundleParser.ParseDefaultPermission(permissionFile, permissions) != ERR_OK) {
            LOG_D(BMS_TAG_DEFAULT, "BundlePermissionMgr::Init failed");
            continue;
        }
    }

    defaultPermissions_.clear();
    for (const auto &permission : permissions) {
        defaultPermissions_.try_emplace(permission.bundleName, permission);
    }
    LOG_D(BMS_TAG_DEFAULT, "BundlePermissionMgr::Init success");
    return true;
}

void BundlePermissionMgr::UnInit()
{
    LOG_D(BMS_TAG_DEFAULT, "BundlePermissionMgr::UnInit");
    defaultPermissions_.clear();
}

void BundlePermissionMgr::ConvertPermissionDef(
    const AccessToken::PermissionDef &permDef, PermissionDef &permissionDef)
{
    permissionDef.permissionName = permDef.permissionName;
    permissionDef.bundleName = permDef.bundleName;
    permissionDef.grantMode = permDef.grantMode;
    permissionDef.availableLevel = permDef.availableLevel;
    permissionDef.provisionEnable = permDef.provisionEnable;
    permissionDef.distributedSceneEnable = permDef.distributedSceneEnable;
    permissionDef.isKernelEffect = permDef.isKernelEffect;
    permissionDef.hasValue = permDef.hasValue;
    permissionDef.label = permDef.label;
    permissionDef.labelId = permDef.labelId;
    permissionDef.description = permDef.description;
    permissionDef.descriptionId = permDef.descriptionId;
    permissionDef.availableType = permDef.availableType;
}

// Convert from the struct DefinePermission that parsed from config.json
void BundlePermissionMgr::ConvertPermissionDef(
    AccessToken::PermissionDef &permDef, const DefinePermission &definePermission, const std::string &bundleName)
{
    permDef.permissionName = definePermission.name;
    permDef.bundleName = bundleName;
    permDef.grantMode = [&definePermission]() -> int {
        if (definePermission.grantMode ==
            Profile::DEFINEPERMISSION_GRANT_MODE_SYSTEM_GRANT) {
            return AccessToken::GrantMode::SYSTEM_GRANT;
        }
        if (definePermission.grantMode ==
            Profile::DEFINEPERMISSION_GRANT_MODE_MANUAL_SETTINGS) {
            return AccessToken::GrantMode::MANUAL_SETTINGS;
        }
        return AccessToken::GrantMode::USER_GRANT;
    }();

    permDef.availableLevel = GetTokenApl(definePermission.availableLevel);
    permDef.provisionEnable = definePermission.provisionEnable;
    permDef.distributedSceneEnable = definePermission.distributedSceneEnable;
    permDef.isKernelEffect = definePermission.isKernelEffect;
    permDef.hasValue = definePermission.hasValue;
    permDef.label = definePermission.label;
    permDef.labelId = definePermission.labelId;
    permDef.description = definePermission.description;
    permDef.descriptionId = definePermission.descriptionId;
    permDef.availableType = GetAvailableType(definePermission.availableType);
}

AccessToken::ATokenAvailableTypeEnum BundlePermissionMgr::GetAvailableType(
    const std::string &availableType)
{
    if (availableType == Profile::DEFINEPERMISSION_AVAILABLE_TYPE_MDM) {
        return AccessToken::ATokenAvailableTypeEnum::MDM;
    }
    return AccessToken::ATokenAvailableTypeEnum::NORMAL;
}

AccessToken::ATokenAplEnum BundlePermissionMgr::GetTokenApl(const std::string &apl)
{
    if (apl == Profile::AVAILABLELEVEL_SYSTEM_CORE) {
        return AccessToken::ATokenAplEnum::APL_SYSTEM_CORE;
    }
    if (apl == Profile::AVAILABLELEVEL_SYSTEM_BASIC) {
        return AccessToken::ATokenAplEnum::APL_SYSTEM_BASIC;
    }
    return AccessToken::ATokenAplEnum::APL_NORMAL;
}

AccessToken::HapPolicyParams BundlePermissionMgr::CreateHapPolicyParam(const InnerBundleInfo &innerBundleInfo,
    const std::string &appServiceCapabilities, const bool isDebugGrant)
{
    AccessToken::HapPolicyParams hapPolicy;
    std::string apl = innerBundleInfo.GetAppPrivilegeLevel();
    std::vector<AccessToken::PermissionDef> permDef = GetPermissionDefList(innerBundleInfo);
    hapPolicy.apl = GetTokenApl(apl);
    hapPolicy.domain = "domain";
    hapPolicy.permList = permDef;
    hapPolicy.permStateList = GetPermissionStateFullList(innerBundleInfo);
    hapPolicy.aclRequestedList = innerBundleInfo.GetAllowedAcls();
    hapPolicy.isDebugGrant = isDebugGrant;
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "-n %{public}s apl:%{public}s req permission:%{public}zu acls:%{public}zu",
        innerBundleInfo.GetBundleName().c_str(), apl.c_str(), hapPolicy.permStateList.size(),
        hapPolicy.aclRequestedList.size());
    BundleParser bundleParser;
    hapPolicy.aclExtendedMap = bundleParser.ParseAclExtendedMap(appServiceCapabilities);
    // default permission list
    DefaultPermission permission;
    if (!GetDefaultPermission(innerBundleInfo.GetBundleName(), permission)) {
        return hapPolicy;
    }

#ifdef USE_PRE_BUNDLE_PROFILE
    if (!MatchSignature(permission, innerBundleInfo.GetCertificateFingerprint()) &&
        !MatchSignature(permission, innerBundleInfo.GetAppId()) &&
        !MatchSignature(permission, innerBundleInfo.GetAppIdentifier()) &&
        !MatchSignature(permission, innerBundleInfo.GetOldAppIds())) {
        LOG_W(BMS_TAG_DEFAULT, "bundleName:%{public}s MatchSignature failed", innerBundleInfo.GetBundleName().c_str());
        return hapPolicy;
    }
#endif
    for (const auto &perm: innerBundleInfo.GetAllRequestPermissions()) {
        bool userCancellable = false;
        if (!CheckPermissionInDefaultPermissions(permission, perm.name, userCancellable)) {
            continue;
        }
        AccessToken::PreAuthorizationInfo preAuthorizationInfo;
        preAuthorizationInfo.permissionName = perm.name;
        preAuthorizationInfo.userCancelable = userCancellable;
        hapPolicy.preAuthorizationInfo.emplace_back(preAuthorizationInfo);
    }
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "preAuthInfo size:%{public}zu", hapPolicy.preAuthorizationInfo.size());
    return hapPolicy;
}

int32_t BundlePermissionMgr::DeleteAccessTokenId(const AccessToken::AccessTokenID tokenId,
    const std::string &bundleName, AccessToken::ReservedType type)
{
    return AccessToken::AccessTokenKit::DeleteIdentity(tokenId, bundleName, type);
}

int32_t BundlePermissionMgr::ClearUserGrantedPermissionState(const AccessToken::AccessTokenID tokenId)
{
    return AccessToken::AccessTokenKit::ClearUserGrantedPermissionState(tokenId);
}

std::vector<AccessToken::PermissionDef> BundlePermissionMgr::GetPermissionDefList(
    const InnerBundleInfo &innerBundleInfo)
{
    const auto bundleName = innerBundleInfo.GetBundleName();
    const auto defPermissions = innerBundleInfo.GetAllDefinePermissions();
    std::vector<AccessToken::PermissionDef> permList;
    if (!defPermissions.empty()) {
        for (const auto &defPermission : defPermissions) {
            AccessToken::PermissionDef perm;
            LOG_D(BMS_TAG_DEFAULT, "defPermission %{public}s", defPermission.name.c_str());
            ConvertPermissionDef(perm, defPermission, bundleName);
            permList.emplace_back(perm);
        }
    }
    return permList;
}

std::vector<AccessToken::PermissionStateFull> BundlePermissionMgr::GetPermissionStateFullList(
    const InnerBundleInfo &innerBundleInfo)
{
    auto reqPermissions = innerBundleInfo.GetAllRequestPermissions();
    std::vector<AccessToken::PermissionStateFull> permStateFullList;
    if (!reqPermissions.empty()) {
        for (const auto &reqPermission : reqPermissions) {
            AccessToken::PermissionStateFull perState;
            perState.permissionName = reqPermission.name;
            perState.isGeneral = true;
            perState.resDeviceID.emplace_back(innerBundleInfo.GetBaseApplicationInfo().deviceId);
            perState.grantStatus.emplace_back(AccessToken::PermissionState::PERMISSION_DENIED);
            perState.grantFlags.emplace_back(AccessToken::PermissionFlag::PERMISSION_DEFAULT_FLAG);
            if (!reqPermission.requiredFeature.empty()) {
                perState.feature = reqPermission.requiredFeature;
            }
            permStateFullList.emplace_back(perState);
        }
    } else {
        LOG_D(BMS_TAG_DEFAULT, "BundlePermissionMgr::GetPermissionStateFullList requestPermission is empty");
    }
    return permStateFullList;
}

bool BundlePermissionMgr::GetAllReqPermissionStateFull(AccessToken::AccessTokenID tokenId,
    std::vector<AccessToken::PermissionStateFull> &newPermissionState)
{
    std::vector<AccessToken::PermissionStateFull> userGrantReqPermList;
    int32_t ret = AccessToken::AccessTokenKit::GetReqPermissions(tokenId, userGrantReqPermList, false);
    if (ret != AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        LOG_E(BMS_TAG_DEFAULT, "GetAllReqPermissionStateFull get user grant failed errcode: %{public}d", ret);
        return false;
    }
    std::vector<AccessToken::PermissionStateFull> systemGrantReqPermList;
    ret = AccessToken::AccessTokenKit::GetReqPermissions(tokenId, systemGrantReqPermList, true);
    if (ret != AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        LOG_E(BMS_TAG_DEFAULT, "GetAllReqPermissionStateFull get system grant failed errcode: %{public}d", ret);
        return false;
    }
    newPermissionState = userGrantReqPermList;
    std::copy(systemGrantReqPermList.begin(), systemGrantReqPermList.end(), std::back_inserter(newPermissionState));
    return true;
}

bool BundlePermissionMgr::GetRequestPermissionStates(
    BundleInfo &bundleInfo, uint32_t tokenId, const std::string deviceId)
{
    std::vector<std::string> requestPermission = bundleInfo.reqPermissions;
    if (requestPermission.empty()) {
        LOG_D(BMS_TAG_DEFAULT, "GetRequestPermissionStates requestPermission empty");
        return true;
    }
    std::vector<Security::AccessToken::PermissionStateFull> allPermissionState;
    if (!GetAllReqPermissionStateFull(tokenId, allPermissionState)) {
        LOG_W(BMS_TAG_DEFAULT, "BundlePermissionMgr::GetRequestPermissionStates failed");
    }
    for (auto &req : requestPermission) {
        auto iter = std::find_if(allPermissionState.begin(), allPermissionState.end(),
            [req](const auto &perm) {
                return perm.permissionName == req;
            });
        if (iter != allPermissionState.end()) {
            LOG_D(BMS_TAG_DEFAULT, "GetRequestPermissionStates request permission name: %{public}s", req.c_str());
            for (std::vector<std::string>::size_type i = 0; i < iter->resDeviceID.size(); i++) {
                if (iter->resDeviceID[i] == deviceId) {
                    bundleInfo.reqPermissionStates.emplace_back(iter->grantStatus[i]);
                    break;
                }
            }
        } else {
            LOG_NOFUNC_E(BMS_TAG_DEFAULT, "%{public}s not in ATM", req.c_str());
            bundleInfo.reqPermissionStates.emplace_back(
                static_cast<int32_t>(AccessToken::PermissionState::PERMISSION_DENIED));
        }
    }
    return true;
}

bool BundlePermissionMgr::VerifyPermissionByCallingTokenId(const std::string &permissionName,
    const Security::AccessToken::AccessTokenID callerToken)
{
    LOG_D(BMS_TAG_DEFAULT, "VerifyPermissionByCallingTokenId permission %{public}s, callerToken : %{public}u",
        permissionName.c_str(), callerToken);
    if (AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permissionName) ==
        AccessToken::PermissionState::PERMISSION_GRANTED) {
        return true;
    }
    LOG_D(BMS_TAG_DEFAULT, "permission denied caller:%{public}u", callerToken);
    return false;
}

bool BundlePermissionMgr::VerifyCallingPermissionForAll(const std::string &permissionName)
{
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    LOG_D(BMS_TAG_DEFAULT, "VerifyCallingPermission permission %{public}s, callerToken : %{public}u",
        permissionName.c_str(), callerToken);
    if (AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permissionName) ==
        AccessToken::PermissionState::PERMISSION_GRANTED) {
        return true;
    }
    LOG_D(BMS_TAG_DEFAULT, "permission denied caller:%{public}u", callerToken);
    return false;
}

bool BundlePermissionMgr::VerifyCallingPermissionsForAll(const std::vector<std::string> &permissionNames)
{
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    for (auto permissionName : permissionNames) {
        if (AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permissionName) ==
            AccessToken::PermissionState::PERMISSION_GRANTED) {
            LOG_D(BMS_TAG_DEFAULT, "verify success");
            return true;
        }
    }
    std::string errorMessage;
    for (auto deniedPermission : permissionNames) {
        errorMessage += deniedPermission + " ";
    }
    LOG_NOFUNC_W(BMS_TAG_DEFAULT, "%{public}s denied callerToken:%{public}u", errorMessage.c_str(), callerToken);
    return false;
}

int32_t BundlePermissionMgr::VerifyPermission(
    const std::string &bundleName, const std::string &permissionName, const int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "VerifyPermission bundleName %{public}s, permission %{public}s", bundleName.c_str(),
        permissionName.c_str());
    AccessToken::AccessTokenID tokenId = AccessToken::AccessTokenKit::GetHapTokenID(userId,
        bundleName, 0);
    return AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, permissionName);
}

ErrCode BundlePermissionMgr::GetPermissionDef(const std::string &permissionName, PermissionDef &permissionDef)
{
    LOG_D(BMS_TAG_DEFAULT, "BundlePermissionMgr::GetPermissionDef permission %{public}s", permissionName.c_str());
    AccessToken::PermissionDef accessTokenPermDef;
    int32_t ret = AccessToken::AccessTokenKit::GetDefPermission(permissionName, accessTokenPermDef);
    if (ret == AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        ConvertPermissionDef(accessTokenPermDef, permissionDef);
        return ERR_OK;
    }
    return ERR_BUNDLE_MANAGER_QUERY_PERMISSION_DEFINE_FAILED;
}

bool BundlePermissionMgr::CheckPermissionInDefaultPermissions(const DefaultPermission &defaultPermission,
    const std::string &permissionName, bool &userCancellable)
{
    auto &grantPermission = defaultPermission.grantPermission;
    auto iter = std::find_if(grantPermission.begin(), grantPermission.end(), [&permissionName](const auto &defPerm) {
            return defPerm.name == permissionName;
        });
    if (iter == grantPermission.end()) {
        LOG_D(BMS_TAG_DEFAULT, "can not find permission(%{public}s)", permissionName.c_str());
        return false;
    }

    userCancellable = iter->userCancellable;
    return true;
}

bool BundlePermissionMgr::GetDefaultPermission(
    const std::string &bundleName, DefaultPermission &permission)
{
    auto iter = defaultPermissions_.find(bundleName);
    if (iter == defaultPermissions_.end()) {
        LOG_NOFUNC_W(BMS_TAG_DEFAULT, "-n %{public}s not exist in defaultPermissions",
            bundleName.c_str());
        return false;
    }

    permission = iter->second;
    return true;
}

bool BundlePermissionMgr::MatchSignature(
    const DefaultPermission &permission, const std::vector<std::string> &signatures)
{
    if (permission.appSignature.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "appSignature is empty");
        return false;
    }
    for (const auto &signature : permission.appSignature) {
        if (std::find(signatures.begin(), signatures.end(), signature) != signatures.end()) {
            return true;
        }
    }

    return false;
}

bool BundlePermissionMgr::MatchSignature(
    const DefaultPermission &permission, const std::string &signature)
{
    if (permission.appSignature.empty() || signature.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "appSignature or signature is empty");
        return false;
    }
    return std::find(permission.appSignature.begin(), permission.appSignature.end(),
        signature) != permission.appSignature.end();
}

int32_t BundlePermissionMgr::GetHapApiVersion()
{
    // get appApiVersion from applicationInfo
    std::string bundleName;
    auto uid = IPCSkeleton::GetCallingUid();
    auto userId = uid / Constants::BASE_USER_RANGE;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return Constants::INVALID_API_VERSION;
    }
    auto ret = dataMgr->GetBundleNameForUid(uid, bundleName);
    if (!ret) {
        LOG_E(BMS_TAG_DEFAULT, "getBundleName failed, uid : %{public}d", uid);
        return Constants::INVALID_API_VERSION;
    }
    ApplicationInfo applicationInfo;
    auto res = dataMgr->GetApplicationInfoV9(bundleName,
        static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE), userId, applicationInfo);
    if (res != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "getApplicationInfo failed");
        return Constants::INVALID_API_VERSION;
    }
    auto appApiVersion = applicationInfo.apiTargetVersion % BASE_API_VERSION;
    LOG_D(BMS_TAG_DEFAULT, "appApiVersion is %{public}d", appApiVersion);
    auto systemApiVersion = GetSdkApiVersion();
    // api version is the minimum value of {appApiVersion, systemApiVersion}
    return systemApiVersion < appApiVersion ? systemApiVersion :appApiVersion;
}

// if the api has been system api since it is published, then beginSystemApiVersion can be omitted
bool BundlePermissionMgr::VerifySystemApp(int32_t beginSystemApiVersion)
{
    LOG_D(BMS_TAG_DEFAULT, "verifying systemApp");
    uint64_t accessTokenIdEx = IPCSkeleton::GetCallingFullTokenID();
    if (Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(accessTokenIdEx)) {
        return true;
    }
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    AccessToken::ATokenTypeEnum tokenType = AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    LOG_D(BMS_TAG_DEFAULT, "tokenType is %{private}d", tokenType);
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (tokenType == AccessToken::ATokenTypeEnum::TOKEN_NATIVE ||
        tokenType == AccessToken::ATokenTypeEnum::TOKEN_SHELL ||
        callingUid == Constants::ROOT_UID ||
        callingUid == ServiceConstants::SHELL_UID) {
        LOG_D(BMS_TAG_DEFAULT, "caller tokenType is native, verify success");
        return true;
    }
    if (beginSystemApiVersion != Constants::ALL_VERSIONCODE) {
        auto apiVersion = GetHapApiVersion();
        if (apiVersion == Constants::INVALID_API_VERSION) {
            LOG_E(BMS_TAG_DEFAULT, "get api version failed, system app verification failed");
            return false;
        }
        if (apiVersion < beginSystemApiVersion) {
            LOG_I(BMS_TAG_DEFAULT, "previous app calling, verify success");
            return true;
        }
    }
    LOG_E(BMS_TAG_DEFAULT, "system app verification failed");
    return false;
}

bool BundlePermissionMgr::IsSystemApp()
{
    LOG_D(BMS_TAG_DEFAULT, "verifying systemApp");
    uint64_t accessTokenIdEx = IPCSkeleton::GetCallingFullTokenID();
    if (Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(accessTokenIdEx)) {
        return true;
    }
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    AccessToken::ATokenTypeEnum tokenType = AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType == AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        LOG_W(BMS_TAG_DEFAULT, "IsSystemApp %{public}d,%{public}d,%{public}u",
            IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingPid(), callerToken);
        return false;
    }
    LOG_D(BMS_TAG_DEFAULT, "caller tokenType is not hap, ignore");
    return true;
}

bool BundlePermissionMgr::IsNativeTokenType()
{
    LOG_D(BMS_TAG_DEFAULT, "begin to verify token type");
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    AccessToken::ATokenTypeEnum tokenType = AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    LOG_D(BMS_TAG_DEFAULT, "tokenType is %{private}d", tokenType);
    if (tokenType == AccessToken::ATokenTypeEnum::TOKEN_NATIVE
        || tokenType == AccessToken::ATokenTypeEnum::TOKEN_SHELL) {
        LOG_D(BMS_TAG_DEFAULT, "caller tokenType is native, verify success");
        return true;
    }
    if (VerifyCallingUid()) {
        LOG_D(BMS_TAG_DEFAULT, "caller is root or foundation or BMS_UID, verify success");
        return true;
    }
    LOG_NOFUNC_W(BMS_TAG_DEFAULT, "caller tokenType not native");
    return false;
}

bool BundlePermissionMgr::IsShellTokenType()
{
    LOG_D(BMS_TAG_DEFAULT, "IsShellTokenType begin");
    if (IPCSkeleton::GetCallingUid() == Constants::DEV_ASSISTANT_UID) {
        LOG_I(BMS_TAG_DEFAULT, "caller is dev assistant, success");
        return true;
    }
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    AccessToken::ATokenTypeEnum tokenType = AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    LOG_D(BMS_TAG_DEFAULT, "tokenType is %{private}d", tokenType);
    if (tokenType == AccessToken::ATokenTypeEnum::TOKEN_SHELL) {
        LOG_D(BMS_TAG_DEFAULT, "caller is shell, success");
        return true;
    }
    LOG_D(BMS_TAG_DEFAULT, "caller not shell");
    return false;
}

bool BundlePermissionMgr::IsNativeTokenTypeOnly()
{
    LOG_D(BMS_TAG_DEFAULT, "IsNativeTokenTypeOnly begin");
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    AccessToken::ATokenTypeEnum tokenType = AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    LOG_D(BMS_TAG_DEFAULT, "tokenType is %{private}d", tokenType);
    if (tokenType == AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
        LOG_D(BMS_TAG_DEFAULT, "caller is native, success");
        return true;
    }
    LOG_D(BMS_TAG_DEFAULT, "caller not native");
    return false;
}

bool BundlePermissionMgr::VerifyCallingUid()
{
    LOG_D(BMS_TAG_DEFAULT, "begin to verify calling uid");
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    LOG_D(BMS_TAG_DEFAULT, "calling uid is %{public}d", callingUid);
    if (callingUid == Constants::ROOT_UID ||
        callingUid == Constants::FOUNDATION_UID ||
        callingUid == ServiceConstants::SHELL_UID ||
        callingUid == ServiceConstants::BMS_UID) {
        LOG_D(BMS_TAG_DEFAULT, "caller is root or foundation, verify success");
        return true;
    }
    LOG_D(BMS_TAG_DEFAULT, "verify calling uid failed");
    return false;
}

bool BundlePermissionMgr::VerifyPreload(const AAFwk::Want &want)
{
    std::string callingBundleName;
    auto uid = IPCSkeleton::GetCallingUid();
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return false;
    }
    auto ret = dataMgr->GetBundleNameForUid(uid, callingBundleName);
    if (!ret) {
        return BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    }
    std::string bundleName = want.GetElement().GetBundleName();
    return bundleName == callingBundleName || callingBundleName == SCENEBOARD_BUNDLE_NAME;
}

bool BundlePermissionMgr::IsCallingUidValid(int32_t uid)
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid == uid) {
        return true;
    }
    LOG_E(BMS_TAG_DEFAULT, "IsCallingUidValid failed, uid = %{public}d, calling uid = %{public}d", uid, callingUid);
    return false;
}

bool BundlePermissionMgr::IsSelfCalling()
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid == Constants::FOUNDATION_UID) {
        return true;
    }
    return false;
}

bool BundlePermissionMgr::VerifyUninstallPermission()
{
    if (!BundlePermissionMgr::IsSelfCalling() &&
        !BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_INSTALL_BUNDLE,
        ServiceConstants::PERMISSION_UNINSTALL_BUNDLE})) {
        LOG_E(BMS_TAG_DEFAULT, "uninstall bundle permission denied");
        return false;
    }
    return true;
}

bool BundlePermissionMgr::VerifyRecoverPermission()
{
    if (!BundlePermissionMgr::IsSelfCalling() &&
        !BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_INSTALL_BUNDLE,
        ServiceConstants::PERMISSION_RECOVER_BUNDLE})) {
        LOG_E(BMS_TAG_DEFAULT, "recover bundle permission denied");
        return false;
    }
    return true;
}

void BundlePermissionMgr::AddPermissionUsedRecord(
    const std::string &permission, int32_t successCount, int32_t failCount)
{
    LOG_D(BMS_TAG_DEFAULT, "AddPermissionUsedRecord permission:%{public}s", permission.c_str());
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    AccessToken::ATokenTypeEnum tokenType = AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType == AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        int32_t ret = AccessToken::PrivacyKit::AddPermissionUsedRecord(callerToken, permission,
            successCount, failCount);
        if (ret != AccessToken::AccessTokenKitRet::RET_SUCCESS) {
            APP_LOGE("AddPermissionUsedRecord failed, ret = %{public}d", ret);
        }
    }
}

bool BundlePermissionMgr::IsBundleSelfCalling(const std::string &bundleName)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return false;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    LOG_D(BMS_TAG_DEFAULT, "start, callingUid: %{public}d", callingUid);
    std::string callingBundleName;
    if (dataMgr->GetNameForUid(callingUid, callingBundleName) != ERR_OK) {
        return false;
    }
    LOG_D(BMS_TAG_DEFAULT, "bundleName :%{public}s, callingBundleName : %{public}s",
        bundleName.c_str(), callingBundleName.c_str());
    if (bundleName != callingBundleName) {
        LOG_W(BMS_TAG_DEFAULT, "failed, callingUid: %{public}d", callingUid);
        return false;
    }
    LOG_D(BMS_TAG_DEFAULT, "end, verify success");
    return true;
}

bool BundlePermissionMgr::IsBundleSelfCalling(const std::string &bundleName, const int32_t &appIndex)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return false;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    LOG_D(BMS_TAG_DEFAULT, "start, callingUid: %{public}d", callingUid);
    std::string callingBundleName;
    int32_t callerAppIndex = 0;
    ErrCode ret = dataMgr->GetBundleNameAndIndexForUid(callingUid, callingBundleName, callerAppIndex);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "failed, code: %{public}d", ret);
        return false;
    }
    LOG_D(BMS_TAG_DEFAULT,
        "bundleName :%{public}s, callingBundleName : %{public}s appIndex: %{public}d callerAppIndex: %{public}d",
        bundleName.c_str(), callingBundleName.c_str(), appIndex, callerAppIndex);
    if (bundleName != callingBundleName || appIndex != callerAppIndex) {
        LOG_W(BMS_TAG_DEFAULT, "failed, callingUid: %{public}d", callingUid);
        return false;
    }
    LOG_D(BMS_TAG_DEFAULT, "end, verify success");
    return true;
}

bool BundlePermissionMgr::VerifyAcrossUserPermission(const int32_t userId)
{
    // sa no need to check across user permission
    if (BundlePermissionMgr::IsNativeTokenType()) {
        return true;
    }
    if (userId == BundleUtil::GetUserIdByCallingUid()) {
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_BMS_INTERACT_ACROSS_LOCAL_ACCOUNTS)) {
        LOG_E(BMS_TAG_DEFAULT, "verify permission across local account failed");
        return false;
    }
    return true;
}

bool BundlePermissionMgr::VerifyCallingBundleSdkVersion(int32_t beginApiVersion)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return false;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    LOG_D(BMS_TAG_DEFAULT, "start, callingUid: %{public}d", callingUid);
    std::string callingBundleName;
    if (dataMgr->GetNameForUid(callingUid, callingBundleName) != ERR_OK) {
        return false;
    }
    auto userId = callingUid / Constants::BASE_USER_RANGE;
    ApplicationInfo applicationInfo;
    auto res = dataMgr->GetApplicationInfoV9(callingBundleName,
        static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE), userId, applicationInfo);
    if (res != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "getApplicationInfo failed, callingBundleName:%{public}s", callingBundleName.c_str());
        return false;
    }
    auto systemApiVersion = GetSdkApiVersion();
    auto appApiVersion = applicationInfo.apiTargetVersion;
    // api version is the minimum value of {appApiVersion, systemApiVersion}
    appApiVersion = systemApiVersion < appApiVersion ? systemApiVersion : appApiVersion;
    LOG_D(BMS_TAG_DEFAULT, "appApiVersion: %{public}d", appApiVersion);

    if ((appApiVersion % BASE_API_VERSION) < beginApiVersion) {
        LOG_I(BMS_TAG_DEFAULT, "previous app calling, verify success");
        return true;
    }
    return false;
}

Security::AccessToken::HapInfoParams BundlePermissionMgr::CreateHapInfoParams(const InnerBundleInfo &innerBundleInfo,
    const int32_t userId, const int32_t dlpType)
{
    AccessToken::HapInfoParams hapInfo;
    hapInfo.userID = userId;
    hapInfo.bundleName = innerBundleInfo.GetBundleName();
    hapInfo.instIndex = innerBundleInfo.GetAppIndex();
    hapInfo.appIDDesc = innerBundleInfo.GetAppId();
    hapInfo.dlpType = dlpType;
    hapInfo.apiVersion = innerBundleInfo.GetBaseApplicationInfo().apiTargetVersion;
    hapInfo.isSystemApp = innerBundleInfo.IsSystemApp();
    hapInfo.appDistributionType = innerBundleInfo.GetAppDistributionType();
    hapInfo.isAtomicService = innerBundleInfo.GetApplicationBundleType() == BundleType::ATOMIC_SERVICE;
    hapInfo.appProvisionType = innerBundleInfo.GetAppProvisionType();
    hapInfo.isSkillHap = innerBundleInfo.GetApplicationBundleType() == BundleType::SKILL;
    return hapInfo;
}

int32_t BundlePermissionMgr::InitHapToken(InnerBundleInfo &innerBundleInfo, const int32_t userId,
    const int32_t dlpType, Security::AccessToken::AccessTokenIDEx& tokenIdeEx,
    const std::string &appServiceCapabilities,
    const bool isDebugGrant, int32_t &sessionId)
{
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "InitHapToken -n %{public}s -t: %{public}s -g: %{public}d",
        innerBundleInfo.GetBundleName().c_str(), innerBundleInfo.GetAppProvisionType().c_str(), isDebugGrant);

    Security::AccessToken::Identity identity;
    int32_t ret = PrepareHapIdentity(innerBundleInfo, userId, dlpType, isDebugGrant,
        appServiceCapabilities, sessionId, identity);
    if (ret == Security::AccessToken::AccessTokenError::ERR_SERVICE_ABNORMAL ||
        ret == Security::AccessToken::AccessTokenError::ERR_READ_PARCEL_FAILED ||
        ret == Security::AccessToken::AccessTokenError::ERR_WRITE_PARCEL_FAILED) {
        // try again for transient errors
        ret = PrepareHapIdentity(innerBundleInfo, userId, dlpType, isDebugGrant,
            appServiceCapabilities, sessionId, identity);
    }
    if (ret == ERR_OK) {
        tokenIdeEx.tokenIDEx = identity.tokenId;
        if (identity.uid != Constants::INVALID_UID) {
            InnerBundleUserInfo curUserInfo;
            bool hasUserInfo = innerBundleInfo.GetInnerBundleUserInfo(userId, curUserInfo);
            if (hasUserInfo) {
                curUserInfo.uid = identity.uid;
                curUserInfo.gids.clear();
                curUserInfo.gids.emplace_back(identity.uid);
                innerBundleInfo.AddInnerBundleUserInfo(curUserInfo);
            } else {
                InnerBundleUserInfo newUserInfo;
                newUserInfo.bundleName = innerBundleInfo.GetBundleName();
                newUserInfo.bundleUserInfo.userId = userId;
                newUserInfo.uid = identity.uid;
                newUserInfo.gids.emplace_back(identity.uid);
                innerBundleInfo.AddInnerBundleUserInfo(newUserInfo);
            }
            auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
            if (dataMgr != nullptr) {
                dataMgr->UpdateUidMap(identity.uid, innerBundleInfo.GetBundleName(),
                    innerBundleInfo.GetAppIndex());
            }
            int32_t bundleId = identity.uid - userId * Constants::BASE_USER_RANGE;
            BundleUtil::MakeFsConfig(innerBundleInfo.GetBundleName(), bundleId,
                ServiceConstants::HMDFS_CONFIG_PATH);
            BundleUtil::MakeFsConfig(innerBundleInfo.GetBundleName(), bundleId,
                ServiceConstants::SHAREFS_CONFIG_PATH);
        }
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "InitHapToken -n %{public}s -t %{public}u",
            innerBundleInfo.GetBundleName().c_str(), tokenIdeEx.tokenIdExStruct.tokenID);
        return ERR_OK;
    }
    LOG_E(BMS_TAG_DEFAULT, "InitHapToken failed, bundleName:%{public}s errCode:%{public}d",
        innerBundleInfo.GetBundleName().c_str(), ret);
    return ret;
}

int32_t BundlePermissionMgr::UpdateHapToken(Security::AccessToken::AccessTokenIDEx& tokenIdeEx,
    InnerBundleInfo &innerBundleInfo, int32_t userId, Security::AccessToken::HapInfoCheckResult &checkResult,
    const std::string &appServiceCapabilities, bool dataRefresh, const bool isDebugGrant, int32_t sessionId)
{
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "start UpdateHapToken -n %{public}s -t: %{public}s -g: %{public}d",
        innerBundleInfo.GetBundleName().c_str(), innerBundleInfo.GetAppProvisionType().c_str(), isDebugGrant);

    int32_t ret = UpdateHapPolicy(sessionId, tokenIdeEx.tokenIdExStruct.tokenID,
        innerBundleInfo, isDebugGrant, appServiceCapabilities);
    if (ret == ERR_OK) {
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "UpdateHapToken success");
        return ERR_OK;
    }
    if (ret == Security::AccessToken::AccessTokenError::ERR_SERVICE_ABNORMAL ||
        ret == Security::AccessToken::AccessTokenError::ERR_READ_PARCEL_FAILED ||
        ret == Security::AccessToken::AccessTokenError::ERR_WRITE_PARCEL_FAILED) {
        // try again for transient errors
        ret = UpdateHapPolicy(sessionId, tokenIdeEx.tokenIdExStruct.tokenID,
            innerBundleInfo, isDebugGrant, appServiceCapabilities);
        if (ret == ERR_OK) {
            LOG_NOFUNC_I(BMS_TAG_DEFAULT, "UpdateHapToken success after retry");
            return ERR_OK;
        }
    }
    if (ret == Security::AccessToken::AccessTokenError::ERR_TOKENID_NOT_EXIST) {
        // token was deleted, try to re-init
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "token not exist, fallback to InitHapToken");
        return InitHapToken(innerBundleInfo, userId, 0, tokenIdeEx,
            appServiceCapabilities, isDebugGrant, sessionId);
    }
    LOG_NOFUNC_E(BMS_TAG_DEFAULT, "UpdateHapToken failed, bundleName:%{public}s errCode:%{public}d",
        innerBundleInfo.GetBundleName().c_str(), ret);
    return ret;
}

int32_t BundlePermissionMgr::CheckHapPermissionInfo(int32_t sessionId,
    Security::AccessToken::InstallTypeEnum type, Security::AccessToken::HapInfoCheckResult &checkResult)
{
    return Security::AccessToken::AccessTokenKit::CheckHapPermissionInfo(sessionId, type, checkResult);
}

std::string BundlePermissionMgr::GetCheckResultMsg(const Security::AccessToken::HapInfoCheckResult &checkResult)
{
    std::string result = "";
    auto permissionName = checkResult.permCheckResult.permissionName;
    auto reason = checkResult.permCheckResult.rule;
    if (reason == Security::AccessToken::PERMISSION_ACL_RULE) {
        result = "PermissionName: " + permissionName;
        return result;
    }
    return result;
}

bool BundlePermissionMgr::CheckUserFromShell(int32_t userId)
{
    // check if from shell call, specified user must be foreground user
    int32_t mode = GetIntParameter(IS_ROOT_MODE_PARAM, USER_MODE);
    if (mode == ROOT_MODE) {
        return true;
    }
    if (!BundlePermissionMgr::IsShellTokenType()) {
        return true;
    }
    if (userId == Constants::DEFAULT_USERID || userId == Constants::U1 ||
        userId == Constants::UNSPECIFIED_USERID) {
        return true;
    }
    if (!AccountHelper::IsUserForeground(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "specified user %{public}d is not foreground user", userId);
        return false;
    }
    return true;
}

Security::AccessToken::BundlePolicy BundlePermissionMgr::CreateBundlePolicy(
    const InnerBundleInfo &innerBundleInfo, const bool isDebugGrant, int32_t dlpType)
{
    Security::AccessToken::BundlePolicy policy;
    policy.isDebugGrant = isDebugGrant;
    policy.dlpType = static_cast<Security::AccessToken::DlpType>(dlpType);

    // Populate preAuthorizationInfo from default permissions
    DefaultPermission permission;
    if (GetDefaultPermission(innerBundleInfo.GetBundleName(), permission)) {
#ifdef USE_PRE_BUNDLE_PROFILE
        if (!MatchSignature(permission, innerBundleInfo.GetCertificateFingerprint()) &&
            !MatchSignature(permission, innerBundleInfo.GetAppId()) &&
            !MatchSignature(permission, innerBundleInfo.GetAppIdentifier()) &&
            !MatchSignature(permission, innerBundleInfo.GetOldAppIds())) {
            LOG_W(BMS_TAG_DEFAULT, "bundleName:%{public}s MatchSignature failed",
                innerBundleInfo.GetBundleName().c_str());
            return policy;
        }
#endif
        // Merge GetAllRequestPermissions with aggregated permissions, dedup first
        std::unordered_set<std::string> mergedPermNames;
        std::vector<RequestPermission> allPerms;
        auto collectPerms = [&](const std::vector<RequestPermission> &perms) {
            for (const auto &perm : perms) {
                if (mergedPermNames.insert(perm.name).second) {
                    allPerms.emplace_back(perm);
                }
            }
        };
        collectPerms(innerBundleInfo.GetAllRequestPermissions());
        collectPerms(innerBundleInfo.GetAggregatedRequestPermissions());

        for (const auto &perm : allPerms) {
            bool userCancellable = false;
            if (!CheckPermissionInDefaultPermissions(permission, perm.name, userCancellable)) {
                continue;
            }
            Security::AccessToken::PreAuthorizationInfo preAuthInfo;
            preAuthInfo.permissionName = perm.name;
            preAuthInfo.userCancelable = userCancellable;
            policy.preAuthorizationInfo.emplace_back(preAuthInfo);
        }
    }
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "CreateBundlePolicy preAuthInfo size:%{public}zu",
        policy.preAuthorizationInfo.size());
    return policy;
}

Security::AccessToken::HapBaseInfo BundlePermissionMgr::CreateHapBaseInfo(
    const InnerBundleInfo &innerBundleInfo, const int32_t userId)
{
    Security::AccessToken::HapBaseInfo hapBaseInfo;
    hapBaseInfo.userID = userId;
    hapBaseInfo.bundleName = innerBundleInfo.GetBundleName();
    hapBaseInfo.instIndex = innerBundleInfo.GetAppIndex();
    return hapBaseInfo;
}

int32_t BundlePermissionMgr::PrepareHapIdentity(
    const InnerBundleInfo &innerBundleInfo,
    int32_t userId,
    int32_t dlpType,
    bool isDebugGrant,
    const std::string &appServiceCapabilities,
    int32_t &sessionId,
    Security::AccessToken::Identity &identity)
{
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "PrepareHapIdentity -n %{public}s -u %{public}d -s %{public}d",
        innerBundleInfo.GetBundleName().c_str(), userId, sessionId);

    Security::AccessToken::HapBaseInfo hapBaseInfo = CreateHapBaseInfo(innerBundleInfo, userId);
    Security::AccessToken::BundlePolicy bundlePolicy = CreateBundlePolicy(innerBundleInfo, isDebugGrant, dlpType);

    int32_t ret = AccessToken::AccessTokenKit::PrepareHapIdentity(sessionId, hapBaseInfo, bundlePolicy, identity);
    if (ret == Security::AccessToken::AccessTokenKitRet::RET_SUCCESS && identity.tokenId != 0) {
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "PrepareHapIdentity success, uid=%{public}d, tokenId=%{public}llu",
            identity.uid, static_cast<unsigned long long>(identity.tokenId));
        return ERR_OK;
    }
    LOG_E(BMS_TAG_DEFAULT, "PrepareHapIdentity failed, bundleName:%{public}s ret:%{public}d tokenId:%{public}llu",
        innerBundleInfo.GetBundleName().c_str(), ret,
        static_cast<unsigned long long>(identity.tokenId));
    return (ret != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) ? ret :
        Security::AccessToken::AccessTokenError::ERR_TOKENID_NOT_EXIST;
}

int32_t BundlePermissionMgr::UpdateHapPolicy(
    int32_t sessionId,
    int32_t tokenId,
    const InnerBundleInfo &innerBundleInfo,
    bool isDebugGrant,
    const std::string &appServiceCapabilities)
{
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "UpdateHapPolicy -n %{public}s -s %{public}d -t %{public}x",
        innerBundleInfo.GetBundleName().c_str(), sessionId, tokenId);

    Security::AccessToken::BundlePolicy bundlePolicy = CreateBundlePolicy(innerBundleInfo, isDebugGrant, 0);

    int32_t ret = Security::AccessToken::AccessTokenKit::UpdateHapPolicy(sessionId, tokenId, bundlePolicy);
    if (ret != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        LOG_E(BMS_TAG_DEFAULT, "UpdateHapPolicy failed, bundleName:%{public}s errCode:%{public}d",
            innerBundleInfo.GetBundleName().c_str(), ret);
        return ret;
    }
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "UpdateHapPolicy success");
    return ERR_OK;
}

int32_t BundlePermissionMgr::FinishHapInstall(
    int32_t sessionId,
    bool isSuccess,
    const std::map<std::string, std::string> &modulePathMap)
{
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "FinishHapInstall sessionId:%{public}d success:%{public}d",
        sessionId, isSuccess);

    int32_t ret = Security::AccessToken::AccessTokenKit::FinishInstall(sessionId, isSuccess, modulePathMap);
    if (ret == Security::AccessToken::AccessTokenError::ERR_SERVICE_ABNORMAL ||
        ret == Security::AccessToken::AccessTokenError::ERR_READ_PARCEL_FAILED ||
        ret == Security::AccessToken::AccessTokenError::ERR_WRITE_PARCEL_FAILED) {
        // try again for transient errors
        ret = Security::AccessToken::AccessTokenKit::FinishInstall(sessionId, isSuccess, modulePathMap);
    }
    if (ret != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        LOG_E(BMS_TAG_DEFAULT, "FinishHapInstall failed, sessionId:%{public}d errCode:%{public}d",
            sessionId, ret);
        return ret;
    }
    InstalldClient::GetInstance()->ClearSessionProvisionCache(sessionId);
    return ERR_OK;
}

int32_t BundlePermissionMgr::UpdateAppPermission(InnerBundleInfo &innerBundleInfo, int32_t userId,
    Security::AccessToken::InstallTypeEnum installType)
{
    std::vector<std::string> bundlePaths;
    for (const auto &[packageName, moduleInfo] : innerBundleInfo.GetInnerModuleInfos()) {
        std::string hapPath = innerBundleInfo.GetModuleHapPath(packageName);
        if (!hapPath.empty()) {
            bundlePaths.emplace_back(hapPath);
        }
    }
    if (bundlePaths.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "UpdateAppPermission failed, no valid module hap paths");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }

    int32_t sessionId = 0;
    Security::AccessToken::BundleHapList hapList;
    hapList.hapPaths = bundlePaths;
    hapList.isPreInstalled = innerBundleInfo.IsPreInstallApp();
    hapList.userId = userId;
    std::vector<Security::AccessToken::TrustedBundleInfo> trustedBundleInfo;
    Security::AccessToken::HapVerifyResultInfo resultInfo;
    int32_t signRet = Security::AccessToken::AccessTokenKit::CheckHapSignInfo(
        hapList, sessionId, trustedBundleInfo, resultInfo);
    if (signRet == Security::AccessToken::AccessTokenError::ERR_CHECK_MULTIPLE_HAP_FAILED) {
        LOG_E(BMS_TAG_DEFAULT, "UpdateAppPermission CheckHapSignInfo incompatible, err=%{public}d", signRet);
        return ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE;
    }
    if (signRet != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        LOG_E(BMS_TAG_DEFAULT, "UpdateAppPermission CheckHapSignInfo failed, err=%{public}d", signRet);
        return ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE;
    }
    LOG_I(BMS_TAG_DEFAULT, "UpdateAppPermission sessionId=%{public}d", sessionId);

    Security::AccessToken::HapInfoCheckResult checkResult;
    int32_t permRet = CheckHapPermissionInfo(sessionId, installType, checkResult);
    if (permRet != ERR_OK) {
        auto msg = GetCheckResultMsg(checkResult);
        LOG_E(BMS_TAG_DEFAULT, "UpdateAppPermission CheckHapPermissionInfo failed, msg=%{public}s err=%{public}d",
            msg.c_str(), permRet);
        (void)FinishHapInstall(sessionId, false, {});
        return permRet;
    }

    std::map<std::string, std::string> modulePathMap;
    for (const auto &hapPath : bundlePaths) {
        modulePathMap[hapPath] = hapPath;
    }
    int32_t finishRet = FinishHapInstall(sessionId, true, modulePathMap);
    if (finishRet != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "UpdateAppPermission FinishHapInstall failed, err=%{public}d", finishRet);
        return finishRet;
    }
    return ERR_OK;
}

}  // namespace AppExecFwk
}  // namespace OHOS
