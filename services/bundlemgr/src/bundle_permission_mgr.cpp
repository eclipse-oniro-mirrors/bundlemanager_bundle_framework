/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "app_log_wrapper.h"
#include "bundle_mgr_service.h"
#include "bundle_parser.h"
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
const int32_t BASE_API_VERSION = 1000;
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
        APP_LOGE("rootDirList is empty");
        return false;
    }
    for (const auto &item : rootDirList) {
        permissionFileList.push_back(item + INSTALL_LIST_PERMISSIONS_CONFIG);
    }
#else
    permissionFileList.emplace_back(Constants::INSTALL_LIST_PERMISSIONS_FILE_PATH);
#endif
    BundleParser bundleParser;
    std::set<DefaultPermission> permissions;
    for (const auto &permissionFile : permissionFileList) {
        if (bundleParser.ParseDefaultPermission(permissionFile, permissions) != ERR_OK) {
            APP_LOGD("BundlePermissionMgr::Init failed");
            continue;
        }
    }

    defaultPermissions_.clear();
    for (const auto &permission : permissions) {
        defaultPermissions_.try_emplace(permission.bundleName, permission);
    }
    APP_LOGD("BundlePermissionMgr::Init success");
    return true;
}

void BundlePermissionMgr::UnInit()
{
    APP_LOGD("BundlePermissionMgr::UnInit");
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
        return AccessToken::GrantMode::USER_GRANT;
    }();

    permDef.availableLevel = GetTokenApl(definePermission.availableLevel);
    permDef.provisionEnable = definePermission.provisionEnable;
    permDef.distributedSceneEnable = definePermission.distributedSceneEnable;
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

AccessToken::HapPolicyParams BundlePermissionMgr::CreateHapPolicyParam(const InnerBundleInfo &innerBundleInfo)
{
    AccessToken::HapPolicyParams hapPolicy;
    std::string apl = innerBundleInfo.GetAppPrivilegeLevel();
    std::vector<AccessToken::PermissionDef> permDef = GetPermissionDefList(innerBundleInfo);
    hapPolicy.apl = GetTokenApl(apl);
    hapPolicy.domain = "domain";
    hapPolicy.permList = permDef;
    hapPolicy.permStateList = GetPermissionStateFullList(innerBundleInfo);
    hapPolicy.aclRequestedList = innerBundleInfo.GetAllowedAcls();
    APP_LOGI("bundleName: %{public}s, apl:%{public}s, req permission size:%{public}zu, acls size:%{public}zu",
        innerBundleInfo.GetBundleName().c_str(), apl.c_str(), hapPolicy.permStateList.size(),
        hapPolicy.aclRequestedList.size());
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
        APP_LOGW("bundleName:%{public}s MatchSignature failed", innerBundleInfo.GetBundleName().c_str());
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
    APP_LOGI("end, preAuthorizationInfo size :%{public}zu", hapPolicy.preAuthorizationInfo.size());
    return hapPolicy;
}

int32_t BundlePermissionMgr::DeleteAccessTokenId(const AccessToken::AccessTokenID tokenId)
{
    return AccessToken::AccessTokenKit::DeleteToken(tokenId);
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
            APP_LOGD("defPermission %{public}s", defPermission.name.c_str());
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
    APP_LOGI("bundleName:%{public}s requestPermission size :%{public}zu",
        innerBundleInfo.GetBundleName().c_str(), reqPermissions.size());
    std::vector<AccessToken::PermissionStateFull> permStateFullList;
    if (!reqPermissions.empty()) {
        for (const auto &reqPermission : reqPermissions) {
            AccessToken::PermissionStateFull perState;
            perState.permissionName = reqPermission.name;
            perState.isGeneral = true;
            perState.resDeviceID.emplace_back(innerBundleInfo.GetBaseApplicationInfo().deviceId);
            perState.grantStatus.emplace_back(AccessToken::PermissionState::PERMISSION_DENIED);
            perState.grantFlags.emplace_back(AccessToken::PermissionFlag::PERMISSION_DEFAULT_FLAG);
            permStateFullList.emplace_back(perState);
        }
    } else {
        APP_LOGD("BundlePermissionMgr::GetPermissionStateFullList requestPermission is empty");
    }
    return permStateFullList;
}

bool BundlePermissionMgr::GetAllReqPermissionStateFull(AccessToken::AccessTokenID tokenId,
    std::vector<AccessToken::PermissionStateFull> &newPermissionState)
{
    std::vector<AccessToken::PermissionStateFull> userGrantReqPermList;
    int32_t ret = AccessToken::AccessTokenKit::GetReqPermissions(tokenId, userGrantReqPermList, false);
    if (ret != AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        APP_LOGE("GetAllReqPermissionStateFull get user grant failed errcode: %{public}d", ret);
        return false;
    }
    std::vector<AccessToken::PermissionStateFull> systemGrantReqPermList;
    ret = AccessToken::AccessTokenKit::GetReqPermissions(tokenId, systemGrantReqPermList, true);
    if (ret != AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        APP_LOGE("GetAllReqPermissionStateFull get system grant failed errcode: %{public}d", ret);
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
        APP_LOGD("GetRequestPermissionStates requestPermission empty");
        return true;
    }
    std::vector<Security::AccessToken::PermissionStateFull> allPermissionState;
    if (!GetAllReqPermissionStateFull(tokenId, allPermissionState)) {
        APP_LOGW("BundlePermissionMgr::GetRequestPermissionStates failed");
    }
    for (auto &req : requestPermission) {
        auto iter = std::find_if(allPermissionState.begin(), allPermissionState.end(),
            [&req](const auto &perm) {
                return perm.permissionName == req;
            });
        if (iter != allPermissionState.end()) {
            APP_LOGD("GetRequestPermissionStates request permission name: %{public}s", req.c_str());
            for (std::vector<std::string>::size_type i = 0; i < iter->resDeviceID.size(); i++) {
                if (iter->resDeviceID[i] == deviceId) {
                    bundleInfo.reqPermissionStates.emplace_back(iter->grantStatus[i]);
                    break;
                }
            }
        } else {
            APP_LOGE("request permission name : %{public}s is not exit in AccessTokenMgr", req.c_str());
            bundleInfo.reqPermissionStates.emplace_back(Constants::PERMISSION_NOT_GRANTED);
        }
    }
    return true;
}

bool BundlePermissionMgr::VerifyCallingPermissionForAll(const std::string &permissionName)
{
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    APP_LOGD("VerifyCallingPermission permission %{public}s, callerToken : %{public}u",
        permissionName.c_str(), callerToken);
    if (AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permissionName) ==
        AccessToken::PermissionState::PERMISSION_GRANTED) {
        return true;
    }
    APP_LOGE("permission %{public}s denied, callerToken : %{public}u", permissionName.c_str(),
        callerToken);
    return false;
}

bool BundlePermissionMgr::VerifyCallingPermissionsForAll(const std::vector<std::string> &permissionNames)
{
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    for (auto permissionName : permissionNames) {
        if (AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permissionName) ==
            AccessToken::PermissionState::PERMISSION_GRANTED) {
                APP_LOGD("verify success");
                return true;
            }
    }
    std::string errorMessage;
    for (auto deniedPermission : permissionNames) {
        errorMessage += deniedPermission + " ";
    }
    APP_LOGE("permission %{public}s denied, callerToken : %{public}u", errorMessage.c_str(), callerToken);
    return false;
}

int32_t BundlePermissionMgr::VerifyPermission(
    const std::string &bundleName, const std::string &permissionName, const int32_t userId)
{
    APP_LOGD("VerifyPermission bundleName %{public}s, permission %{public}s", bundleName.c_str(),
             permissionName.c_str());
    AccessToken::AccessTokenID tokenId = AccessToken::AccessTokenKit::GetHapTokenID(userId,
        bundleName, 0);
    return AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, permissionName);
}

ErrCode BundlePermissionMgr::GetPermissionDef(const std::string &permissionName, PermissionDef &permissionDef)
{
    APP_LOGD("BundlePermissionMgr::GetPermissionDef permission %{public}s", permissionName.c_str());
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
        APP_LOGW("can not find permission(%{public}s)", permissionName.c_str());
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
        APP_LOGW("bundleName: %{public}s does not exist in defaultPermissions",
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
        APP_LOGW("appSignature is empty");
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
        APP_LOGW("appSignature or signature is empty");
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
        APP_LOGE("DataMgr is nullptr");
        return Constants::INVALID_API_VERSION;
    }
    auto ret = dataMgr->GetBundleNameForUid(uid, bundleName);
    if (!ret) {
        APP_LOGE("getBundleName failed, uid : %{public}d", uid);
        return Constants::INVALID_API_VERSION;
    }
    ApplicationInfo applicationInfo;
    auto res = dataMgr->GetApplicationInfoV9(bundleName,
        static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE), userId, applicationInfo);
    if (res != ERR_OK) {
        APP_LOGE("getApplicationInfo failed");
        return Constants::INVALID_API_VERSION;
    }
    auto appApiVersion = applicationInfo.apiTargetVersion;
    APP_LOGD("appApiVersion is %{public}d", appApiVersion);
    auto systemApiVersion = GetSdkApiVersion();
    // api version is the minimum value of {appApiVersion, systemApiVersion}
    return systemApiVersion < appApiVersion ? systemApiVersion :appApiVersion;
}

// if the api has been system api since it is published, then beginSystemApiVersion can be omitted
bool BundlePermissionMgr::VerifySystemApp(int32_t beginSystemApiVersion)
{
    APP_LOGD("verifying systemApp");
    uint64_t accessTokenIdEx = IPCSkeleton::GetCallingFullTokenID();
    if (Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(accessTokenIdEx)) {
        return true;
    }
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    AccessToken::ATokenTypeEnum tokenType = AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    APP_LOGD("tokenType is %{private}d", tokenType);
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (tokenType == AccessToken::ATokenTypeEnum::TOKEN_NATIVE ||
        tokenType == AccessToken::ATokenTypeEnum::TOKEN_SHELL ||
        callingUid == Constants::ROOT_UID ||
        callingUid == Constants::SHELL_UID) {
        APP_LOGD("caller tokenType is native, verify success");
        return true;
    }
    if (beginSystemApiVersion != Constants::ALL_VERSIONCODE) {
        auto apiVersion = GetHapApiVersion();
        if (apiVersion == Constants::INVALID_API_VERSION) {
            APP_LOGE("get api version failed, system app verification failed");
            return false;
        }
        if (apiVersion < beginSystemApiVersion) {
            APP_LOGI("previous app calling, verify success");
            return true;
        }
    }
    APP_LOGE("system app verification failed");
    return false;
}

bool BundlePermissionMgr::IsSystemApp()
{
    APP_LOGD("verifying systemApp");
    uint64_t accessTokenIdEx = IPCSkeleton::GetCallingFullTokenID();
    if (Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(accessTokenIdEx)) {
        return true;
    }
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    AccessToken::ATokenTypeEnum tokenType = AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType == AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        APP_LOGE("system app verification failed");
        return false;
    }
    APP_LOGD("caller tokenType is not hap, ignore");
    return true;
}

bool BundlePermissionMgr::IsNativeTokenType()
{
    APP_LOGD("begin to verify token type");
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    AccessToken::ATokenTypeEnum tokenType = AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    APP_LOGD("tokenType is %{private}d", tokenType);
    if (tokenType == AccessToken::ATokenTypeEnum::TOKEN_NATIVE
        || tokenType == AccessToken::ATokenTypeEnum::TOKEN_SHELL) {
        APP_LOGD("caller tokenType is native, verify success");
        return true;
    }
    if (VerifyCallingUid()) {
        APP_LOGD("caller is root or foundation or BMS_UID, verify success");
        return true;
    }
    APP_LOGE("caller tokenType not native, verify failed");
    return false;
}

bool BundlePermissionMgr::VerifyCallingUid()
{
    APP_LOGD("begin to verify calling uid");
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    APP_LOGD("calling uid is %{public}d", callingUid);
    if (callingUid == Constants::ROOT_UID ||
        callingUid == Constants::FOUNDATION_UID ||
        callingUid == Constants::SHELL_UID ||
        callingUid == Constants::BMS_UID) {
        APP_LOGD("caller is root or foundation, verify success");
        return true;
    }
    APP_LOGE("verify calling uid failed");
    return false;
}

bool BundlePermissionMgr::VerifyPreload(const AAFwk::Want &want)
{
    std::string callingBundleName;
    auto uid = IPCSkeleton::GetCallingUid();
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
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
    APP_LOGE("IsCallingUidValid failed, uid = %{public}d, calling uid = %{public}d", uid, callingUid);
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
        Constants::PERMISSION_UNINSTALL_BUNDLE})) {
        APP_LOGE("uninstall bundle permission denied");
        return false;
    }
    return true;
}

bool BundlePermissionMgr::VerifyRecoverPermission()
{
    if (!BundlePermissionMgr::IsSelfCalling() &&
        !BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_INSTALL_BUNDLE,
        Constants::PERMISSION_RECOVER_BUNDLE})) {
        APP_LOGE("recover bundle permission denied");
        return false;
    }
    return true;
}

void BundlePermissionMgr::AddPermissionUsedRecord(
    const std::string &permission, int32_t successCount, int32_t failCount)
{
    APP_LOGD("AddPermissionUsedRecord permission:%{public}s", permission.c_str());
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    AccessToken::ATokenTypeEnum tokenType = AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType == AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        AccessToken::PrivacyKit::AddPermissionUsedRecord(callerToken, permission, successCount, failCount);
    }
}

bool BundlePermissionMgr::IsBundleSelfCalling(const std::string &bundleName)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    APP_LOGD("start, callingUid: %{public}d", callingUid);
    std::string callingBundleName;
    if (dataMgr->GetNameForUid(callingUid, callingBundleName) != ERR_OK) {
        return false;
    }
    APP_LOGD("bundleName :%{public}s, callingBundleName : %{public}s",
        bundleName.c_str(), callingBundleName.c_str());
    if (bundleName != callingBundleName) {
        APP_LOGW("failed, callingUid: %{public}d", callingUid);
        return false;
    }
    APP_LOGD("end, verify success");
    return true;
}

bool BundlePermissionMgr::VerifyCallingBundleSdkVersion(int32_t beginApiVersion)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    APP_LOGD("start, callingUid: %{public}d", callingUid);
    std::string callingBundleName;
    if (dataMgr->GetNameForUid(callingUid, callingBundleName) != ERR_OK) {
        return false;
    }
    auto userId = callingUid / Constants::BASE_USER_RANGE;
    ApplicationInfo applicationInfo;
    auto res = dataMgr->GetApplicationInfoV9(callingBundleName,
        static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE), userId, applicationInfo);
    if (res != ERR_OK) {
        APP_LOGE("getApplicationInfo failed, callingBundleName:%{public}s", callingBundleName.c_str());
        return false;
    }
    auto systemApiVersion = GetSdkApiVersion();
    auto appApiVersion = applicationInfo.apiTargetVersion;
    // api version is the minimum value of {appApiVersion, systemApiVersion}
    appApiVersion = systemApiVersion < appApiVersion ? systemApiVersion : appApiVersion;
    APP_LOGD("appApiVersion: %{public}d", appApiVersion);

    if ((appApiVersion % BASE_API_VERSION) < beginApiVersion) {
        APP_LOGI("previous app calling, verify success");
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
    return hapInfo;
}

int32_t BundlePermissionMgr::InitHapToken(const InnerBundleInfo &innerBundleInfo, const int32_t userId,
    const int32_t dlpType, Security::AccessToken::AccessTokenIDEx& tokenIdeEx)
{
    APP_LOGI("start, init hap token bundleName:%{public}s", innerBundleInfo.GetBundleName().c_str());
    AccessToken::HapInfoParams hapInfo = CreateHapInfoParams(innerBundleInfo, userId, dlpType);
    AccessToken::HapPolicyParams hapPolicy = CreateHapPolicyParam(innerBundleInfo);
    auto ret = AccessToken::AccessTokenKit::InitHapToken(hapInfo, hapPolicy, tokenIdeEx);
    if (ret != AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        APP_LOGE("InitHapToken failed, bundleName:%{public}s errCode:%{public}d",
            innerBundleInfo.GetBundleName().c_str(), ret);
        return ret;
    }
    APP_LOGI("end, init hap token bundleName: %{public}s tokenId:%{public}u", innerBundleInfo.GetBundleName().c_str(),
        tokenIdeEx.tokenIdExStruct.tokenID);
    return ERR_OK;
}

int32_t BundlePermissionMgr::UpdateHapToken(
    Security::AccessToken::AccessTokenIDEx& tokenIdeEx, const InnerBundleInfo &innerBundleInfo)
{
    APP_LOGI("start, update hap token bundleName:%{public}s", innerBundleInfo.GetBundleName().c_str());
    AccessToken::UpdateHapInfoParams updateHapInfoParams;
    updateHapInfoParams.appIDDesc = innerBundleInfo.GetAppId();
    updateHapInfoParams.apiVersion = innerBundleInfo.GetBaseApplicationInfo().apiTargetVersion;
    updateHapInfoParams.isSystemApp = innerBundleInfo.IsSystemApp();
    updateHapInfoParams.appDistributionType = innerBundleInfo.GetAppDistributionType();

    AccessToken::HapPolicyParams hapPolicy = CreateHapPolicyParam(innerBundleInfo);

    auto ret = AccessToken::AccessTokenKit::UpdateHapToken(tokenIdeEx, updateHapInfoParams, hapPolicy);
    if (ret != AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        APP_LOGE("UpdateHapToken failed, bundleName:%{public}s errCode:%{public}d",
            innerBundleInfo.GetBundleName().c_str(), ret);
        return ret;
    }
    APP_LOGI("end, update hap token bundleName:%{public}s", innerBundleInfo.GetBundleName().c_str());
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS