/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
            APP_LOGW("BundlePermissionMgr::Init failed");
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

AccessToken::HapPolicyParams BundlePermissionMgr::CreateHapPolicyParam(
    const InnerBundleInfo &innerBundleInfo)
{
    std::vector<AccessToken::PermissionStateFull> permStateFull = GetPermissionStateFullList(innerBundleInfo);
    return CreateHapPolicyParam(innerBundleInfo, permStateFull);
}

AccessToken::HapPolicyParams BundlePermissionMgr::CreateHapPolicyParam(
    const InnerBundleInfo &innerBundleInfo, const std::vector<Security::AccessToken::PermissionStateFull> &permissions)
{
    AccessToken::HapPolicyParams hapPolicy;
    std::string apl = innerBundleInfo.GetAppPrivilegeLevel();
    APP_LOGD("BundlePermissionMgr::CreateHapPolicyParam apl : %{public}s", apl.c_str());
    std::vector<AccessToken::PermissionDef> permDef = GetPermissionDefList(innerBundleInfo);
    hapPolicy.apl = GetTokenApl(apl);
    hapPolicy.domain = "domain";
    hapPolicy.permList = permDef;
    hapPolicy.permStateList = permissions;
    return hapPolicy;
}

AccessToken::AccessTokenIDEx BundlePermissionMgr::CreateAccessTokenIdEx(
    const InnerBundleInfo &innerBundleInfo, const std::string bundleName, const int32_t userId)
{
    APP_LOGD("BundlePermissionMgr::CreateAccessTokenId bundleName = %{public}s, userId = %{public}d",
        bundleName.c_str(), userId);
    AccessToken::HapPolicyParams hapPolicy = CreateHapPolicyParam(innerBundleInfo);
    return CreateAccessTokenIdEx(innerBundleInfo, bundleName, userId, 0, hapPolicy);
}

AccessToken::AccessTokenIDEx BundlePermissionMgr::CreateAccessTokenIdEx(
    const InnerBundleInfo &innerBundleInfo, const std::string bundleName, const int32_t userId, const int32_t dlpType,
    const AccessToken::HapPolicyParams &hapPolicy)
{
    APP_LOGD("CreateAccessTokenId bundleName = %{public}s, userId = %{public}d, dlpType = %{public}d",
        bundleName.c_str(), userId, dlpType);
    AccessToken::HapInfoParams hapInfo;
    hapInfo.userID = userId;
    hapInfo.bundleName = bundleName;
    hapInfo.instIndex = innerBundleInfo.GetAppIndex();
    hapInfo.appIDDesc = innerBundleInfo.GetAppId();
    hapInfo.dlpType = dlpType;
    hapInfo.apiVersion = innerBundleInfo.GetBaseApplicationInfo().apiTargetVersion;
    hapInfo.isSystemApp = innerBundleInfo.IsSystemApp();
    AccessToken::AccessTokenIDEx accessToken = AccessToken::AccessTokenKit::AllocHapToken(hapInfo, hapPolicy);
    APP_LOGD("BundlePermissionMgr::CreateAccessTokenId bundleName: %{public}s, accessTokenId = %{public}u",
             bundleName.c_str(), accessToken.tokenIdExStruct.tokenID);
    return accessToken;
}

bool BundlePermissionMgr::UpdateDefineAndRequestPermissions(Security::AccessToken::AccessTokenIDEx &tokenIdEx,
    const InnerBundleInfo &oldInfo, const InnerBundleInfo &newInfo, std::vector<std::string> &newRequestPermName)
{
    APP_LOGD("UpdateDefineAndRequestPermissions bundleName = %{public}s", newInfo.GetBundleName().c_str());
    std::vector<AccessToken::PermissionDef> newDefPermList;
    if (!InnerUpdateDefinePermission(tokenIdEx.tokenIdExStruct.tokenID, oldInfo, newInfo, newDefPermList)) {
        APP_LOGE("UpdateDefineAndRequestPermissions InnerUpdateDefinePermission failed");
        return false;
    }

    std::vector<AccessToken::PermissionStateFull> newPermissionStateList;
    if (!InnerUpdateRequestPermission(tokenIdEx.tokenIdExStruct.tokenID, oldInfo, newInfo,
        newPermissionStateList, newRequestPermName)) {
        APP_LOGE("UpdateDefineAndRequestPermissions InnerUpdateRequestPermission failed");
        return false;
    }

    AccessToken::HapPolicyParams hapPolicy;
    std::string apl = newInfo.GetAppPrivilegeLevel();
    APP_LOGD("newDefPermList size:%{public}zu, newPermissionStateList size:%{public}zu, isSystemApp: %{public}d",
             newDefPermList.size(), newPermissionStateList.size(), newInfo.IsSystemApp());
    hapPolicy.apl = GetTokenApl(apl);
    hapPolicy.domain = "domain"; // default
    hapPolicy.permList = newDefPermList;
    hapPolicy.permStateList = newPermissionStateList;
    std::string appId = newInfo.GetAppId();
    int32_t ret = AccessToken::AccessTokenKit::UpdateHapToken(tokenIdEx, newInfo.IsSystemApp(), appId,
        newInfo.GetBaseApplicationInfo().apiTargetVersion, hapPolicy);
    if (ret != AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        APP_LOGE("UpdateDefineAndRequestPermissions UpdateHapToken failed errcode: %{public}d", ret);
        return false;
    }
    APP_LOGD("BundlePermissionMgr::UpdateDefineAndRequestPermissions end");
    return true;
}

std::vector<std::string> BundlePermissionMgr::GetNeedDeleteDefinePermissionName(const InnerBundleInfo &oldInfo,
    const InnerBundleInfo &newInfo)
{
    std::vector<DefinePermission> oldDefinePermissions = oldInfo.GetAllDefinePermissions();
    std::vector<DefinePermission> newDefinePermissions = newInfo.GetAllDefinePermissions();
    std::vector<std::string> needDeleteDefinePermission;
    for (const auto &defPerm : oldDefinePermissions) {
        auto iter = std::find_if(newDefinePermissions.begin(), newDefinePermissions.end(),
            [&defPerm](const auto &perm) {
            return defPerm.name == perm.name;
        });
        if (iter == newDefinePermissions.end()) {
            APP_LOGD("GetNeedDeleteDefinePermissionName need delete %{public}s", defPerm.name.c_str());
            needDeleteDefinePermission.emplace_back(defPerm.name);
        }
    }
    return needDeleteDefinePermission;
}

std::vector<std::string> BundlePermissionMgr::GetNeedDeleteRequestPermissionName(const InnerBundleInfo &oldInfo,
    const InnerBundleInfo &newInfo)
{
    std::vector<RequestPermission> oldRequestPermissions = oldInfo.GetAllRequestPermissions();
    std::vector<RequestPermission> newRequestPermissions = newInfo.GetAllRequestPermissions();
    std::vector<std::string> needDeleteRequestPermission;
    for (const auto &reqPerm : oldRequestPermissions) {
        auto iter = std::find_if(newRequestPermissions.begin(), newRequestPermissions.end(),
            [&reqPerm](const auto &perm) {
            return reqPerm.name == perm.name;
        });
        if (iter == newRequestPermissions.end()) {
            APP_LOGD("GetNeedDeleteRequestPermissionName need delete %{public}s", reqPerm.name.c_str());
            needDeleteRequestPermission.emplace_back(reqPerm.name);
        }
    }
    return needDeleteRequestPermission;
}

bool BundlePermissionMgr::GetNewPermissionDefList(Security::AccessToken::AccessTokenID tokenId,
    const std::vector<Security::AccessToken::PermissionDef> &permissionDef,
    std::vector<Security::AccessToken::PermissionDef> &newPermissionDef)
{
    int32_t ret = AccessToken::AccessTokenKit::GetDefPermissions(tokenId, newPermissionDef);
    if (ret != AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        APP_LOGE("BundlePermissionMgr::GetNewPermissionDefList GetDefPermissions failed errcode: %{public}d", ret);
        return false;
    }
    for (const auto &perm : permissionDef) {
        if (std::find_if(newPermissionDef.begin(), newPermissionDef.end(), [&perm](const auto &newPerm) {
            return newPerm.permissionName == perm.permissionName;
            }) == newPermissionDef.end()) {
            APP_LOGD("BundlePermissionMgr::GetNewPermissionDefList add define permission %{public}s",
                     perm.permissionName.c_str());
            newPermissionDef.emplace_back(perm);
        }
    }
    return true;
}

bool BundlePermissionMgr::GetNewPermissionStateFull(Security::AccessToken::AccessTokenID tokenId,
    const std::vector<Security::AccessToken::PermissionStateFull> &permissionState,
    std::vector<Security::AccessToken::PermissionStateFull> &newPermissionState,
    std::vector<std::string> &newRequestPermName)
{
    if (!GetAllReqPermissionStateFull(tokenId, newPermissionState)) {
        APP_LOGE("BundlePermissionMgr::GetNewPermissionStateFull failed");
        return false;
    }
    // add old permission which need grant again
    for (const auto &state : newPermissionState) {
        if ((state.grantStatus[0] == AccessToken::PermissionState::PERMISSION_DENIED) &&
            (state.grantFlags[0] == AccessToken::PermissionFlag::PERMISSION_DEFAULT_FLAG)) {
            APP_LOGD("BundlePermissionMgr::GetNewPermissionStateFull add old permission:%{public}s",
                state.permissionName.c_str());
            newRequestPermName.emplace_back(state.permissionName);
        }
    }

    for (const auto &perm : permissionState) {
        if (std::find_if(newPermissionState.begin(), newPermissionState.end(), [&perm](const auto &newPerm) {
            return newPerm.permissionName == perm.permissionName;
            }) == newPermissionState.end()) {
            APP_LOGD("BundlePermissionMgr::GetNewPermissionStateFull add request permission %{public}s",
                     perm.permissionName.c_str());
            newPermissionState.emplace_back(perm);
            newRequestPermName.emplace_back(perm.permissionName);
        }
    }
    return true;
}

bool BundlePermissionMgr::AddDefineAndRequestPermissions(Security::AccessToken::AccessTokenIDEx &tokenIdEx,
    const InnerBundleInfo &innerBundleInfo, std::vector<std::string> &newRequestPermName)
{
    APP_LOGD("BundlePermissionMgr::AddDefineAndRequestPermissions start");
    std::vector<AccessToken::PermissionDef> defPermList = GetPermissionDefList(innerBundleInfo);
    std::vector<AccessToken::PermissionDef> newDefPermList;
    if (!GetNewPermissionDefList(tokenIdEx.tokenIdExStruct.tokenID, defPermList, newDefPermList)) {
        return false;
    }

    std::vector<AccessToken::PermissionStateFull> reqPermissionStateList = GetPermissionStateFullList(innerBundleInfo);
    std::vector<AccessToken::PermissionStateFull> newPermissionStateList;
    if (!GetNewPermissionStateFull(tokenIdEx.tokenIdExStruct.tokenID, reqPermissionStateList,
        newPermissionStateList, newRequestPermName)) {
        return false;
    }

    AccessToken::HapPolicyParams hapPolicy;
    std::string apl = innerBundleInfo.GetAppPrivilegeLevel();
    APP_LOGD("BundlePermissionMgr::AddDefineAndRequestPermissions apl : %{public}s, newDefPermList size : %{public}zu, \
             newPermissionStateList size : %{public}zu", apl.c_str(), newDefPermList.size(),
             newPermissionStateList.size());
    hapPolicy.apl = GetTokenApl(apl);
    hapPolicy.domain = "domain"; // default
    hapPolicy.permList = newDefPermList;
    hapPolicy.permStateList = newPermissionStateList;
    std::string appId = innerBundleInfo.GetAppId();
    int32_t ret = AccessToken::AccessTokenKit::UpdateHapToken(tokenIdEx, innerBundleInfo.IsSystemApp(), appId,
        innerBundleInfo.GetBaseApplicationInfo().apiTargetVersion, hapPolicy);
    if (ret != AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        APP_LOGE("BundlePermissionMgr::AddDefineAndRequestPermissions UpdateHapToken failed errcode: %{public}d", ret);
        return false;
    }
    APP_LOGD("BundlePermissionMgr::AddDefineAndRequestPermissions end");
    return true;
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

bool BundlePermissionMgr::GrantPermission(
    const Security::AccessToken::AccessTokenID tokenId,
    const std::string &permissionName,
    const Security::AccessToken::PermissionFlag flag,
    const std::string &bundleName)
{
    int32_t ret = AccessToken::AccessTokenKit::GrantPermission(tokenId, permissionName, flag);
    if (ret != AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        APP_LOGE("GrantPermission failed, bundleName:%{public}s, request permission:%{public}s, err:%{public}d",
            bundleName.c_str(), permissionName.c_str(), ret);
        return false;
    }
    return true;
}

bool BundlePermissionMgr::InnerGrantRequestPermissions(Security::AccessToken::AccessTokenID tokenId,
    const std::vector<RequestPermission> &reqPermissions,
    const InnerBundleInfo &innerBundleInfo)
{
    std::string bundleName = innerBundleInfo.GetBundleName();
    APP_LOGD("InnerGrantRequestPermissions start, bundleName:%{public}s", bundleName.c_str());
    std::string apl = innerBundleInfo.GetAppPrivilegeLevel();
    std::vector<std::string> acls = innerBundleInfo.GetAllowedAcls();
    std::vector<std::string> systemGrantPermList;
    std::vector<std::string> userGrantPermList;
    for (const auto &reqPermission : reqPermissions) {
        APP_LOGD("InnerGrantRequestPermissions add request permission %{public}s", reqPermission.name.c_str());
        AccessToken::PermissionDef permDef;
        int32_t ret = AccessToken::AccessTokenKit::GetDefPermission(reqPermission.name, permDef);
        if (ret != AccessToken::AccessTokenKitRet::RET_SUCCESS) {
            APP_LOGE("get permission def failed, request permission name: %{public}s", reqPermission.name.c_str());
            continue;
        }
        if (CheckGrantPermission(permDef, apl, acls)) {
            if (permDef.grantMode == AccessToken::GrantMode::SYSTEM_GRANT) {
                systemGrantPermList.emplace_back(reqPermission.name);
            } else {
                userGrantPermList.emplace_back(reqPermission.name);
            }
        } else {
            return false;
        }
    }
    APP_LOGD("bundleName:%{public}s, add system_grant permission: %{public}zu, add user_grant permission: %{public}zu",
        bundleName.c_str(), systemGrantPermList.size(), userGrantPermList.size());
    for (const auto &perm : systemGrantPermList) {
        if (!GrantPermission(tokenId, perm, AccessToken::PermissionFlag::PERMISSION_SYSTEM_FIXED, bundleName)) {
            return false;
        }
    }
    if (innerBundleInfo.IsPreInstallApp()) {
        for (const auto &perm: userGrantPermList) {
            bool userCancellable = false;
            DefaultPermission permission;
            if (!GetDefaultPermission(bundleName, permission)) {
                continue;
            }

#ifdef USE_PRE_BUNDLE_PROFILE
            if (!MatchSignature(permission, innerBundleInfo.GetCertificateFingerprint())) {
                continue;
            }
#endif

            if (!CheckPermissionInDefaultPermissions(permission, perm, userCancellable)) {
                continue;
            }
            AccessToken::PermissionFlag flag = userCancellable ?
                AccessToken::PermissionFlag::PERMISSION_GRANTED_BY_POLICY :
                AccessToken::PermissionFlag::PERMISSION_SYSTEM_FIXED;
            if (!GrantPermission(tokenId, perm, flag, bundleName)) {
                return false;
            }
        }
    }
    APP_LOGD("InnerGrantRequestPermissions end, bundleName:%{public}s", bundleName.c_str());
    return true;
}

bool BundlePermissionMgr::GrantRequestPermissions(const InnerBundleInfo &innerBundleInfo,
    const AccessToken::AccessTokenID tokenId)
{
    std::vector<RequestPermission> reqPermissions = innerBundleInfo.GetAllRequestPermissions();
    return InnerGrantRequestPermissions(tokenId, reqPermissions, innerBundleInfo);
}

bool BundlePermissionMgr::GrantRequestPermissions(const InnerBundleInfo &innerBundleInfo,
    const std::vector<std::string> &requestPermName,
    const AccessToken::AccessTokenID tokenId)
{
    std::vector<RequestPermission> reqPermissions = innerBundleInfo.GetAllRequestPermissions();
    std::vector<RequestPermission> newRequestPermissions;
    for (const auto &name : requestPermName) {
        auto iter = find_if(reqPermissions.begin(), reqPermissions.end(), [&name](const auto &req) {
            return name == req.name;
        });
        if (iter != reqPermissions.end()) {
            newRequestPermissions.emplace_back(*iter);
        }
    }
    return InnerGrantRequestPermissions(tokenId, newRequestPermissions, innerBundleInfo);
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

bool BundlePermissionMgr::CheckGrantPermission(
    const AccessToken::PermissionDef &permDef,
    const std::string &apl,
    const std::vector<std::string> &acls)
{
    AccessToken::ATokenAplEnum availableLevel = permDef.availableLevel;
    APP_LOGD("BundlePermissionMgr::CheckGrantPermission availableLevel %{public}d, apl %{public}s",
             availableLevel, apl.c_str());
    switch (availableLevel) {
        case AccessToken::ATokenAplEnum::APL_NORMAL: {
            return true;
        }
        case AccessToken::ATokenAplEnum::APL_SYSTEM_BASIC: {
            if ((apl == Profile::AVAILABLELEVEL_SYSTEM_BASIC) ||
                (apl == Profile::AVAILABLELEVEL_SYSTEM_CORE)) {
                return true;
            }
            break;
        }
        case AccessToken::ATokenAplEnum::APL_SYSTEM_CORE: {
            if (apl == Profile::AVAILABLELEVEL_SYSTEM_CORE) {
                return true;
            }
            break;
        }
        default:
            APP_LOGE("availableLevel %{public}d error", availableLevel);
            break;
    }
    if (permDef.provisionEnable) {
        APP_LOGD("CheckGrantPermission acls size: %{public}zu", acls.size());
        auto res = std::any_of(acls.begin(), acls.end(), [permDef](const auto &perm) {
            return permDef.permissionName == perm;
        });
        if (res) {
            return res;
        }
    }
    APP_LOGE("BundlePermissionMgr::CheckGrantPermission failed permission name : %{public}s",
             permDef.permissionName.c_str());
    return false;
}

bool BundlePermissionMgr::VerifyCallingPermission(const std::string &permissionName)
{
    APP_LOGD("VerifyCallingPermission permission %{public}s", permissionName.c_str());
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    APP_LOGD("callerToken : %{private}u", callerToken);
    AccessToken::ATokenTypeEnum tokenType = AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (tokenType == AccessToken::ATokenTypeEnum::TOKEN_NATIVE || callingUid == Constants::ROOT_UID) {
        APP_LOGD("caller tokenType is native, verify success");
        return true;
    }
    int32_t ret = AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permissionName);
    if (ret == AccessToken::PermissionState::PERMISSION_DENIED) {
        APP_LOGE("permission %{public}s: PERMISSION_DENIED", permissionName.c_str());
        return false;
    }
    APP_LOGD("verify AccessToken success");
    return true;
}

bool BundlePermissionMgr::VerifyCallingPermissionForAll(const std::string &permissionName)
{
    AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    APP_LOGD("VerifyCallingPermission permission %{public}s, callerToken : %{private}u",
        permissionName.c_str(), callerToken);
    if (AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permissionName) ==
        AccessToken::PermissionState::PERMISSION_DENIED) {
        APP_LOGE("permission %{public}s: PERMISSION_DENIED", permissionName.c_str());
        return false;
    }
    return true;
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
    const DefaultPermission &permission, const std::string &signature)
{
    if (permission.appSignature.empty()) {
        APP_LOGW("appSignature is empty");
        return false;
    }

    return std::find(permission.appSignature.begin(),
        permission.appSignature.end(), signature) != permission.appSignature.end();
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
        APP_LOGE("getBundleName failed");
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
    if (VerifyCallingUid()) {
        return true;
    }
    std::string callingBundleName;
    auto uid = IPCSkeleton::GetCallingUid();
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    auto ret = dataMgr->GetBundleNameForUid(uid, callingBundleName);
    if (!ret) {
        APP_LOGE("getBundleName failed");
        return false;
    }
    std::string bundleName = want.GetElement().GetBundleName();
    return bundleName == callingBundleName || callingBundleName == SCENEBOARD_BUNDLE_NAME;
}

bool BundlePermissionMgr::InnerUpdateDefinePermission(
    const Security::AccessToken::AccessTokenID tokenId,
    const InnerBundleInfo &oldInfo,
    const InnerBundleInfo &newInfo,
    std::vector<Security::AccessToken::PermissionDef> &newDefPermList)
{
    std::vector<AccessToken::PermissionDef> defPermList = GetPermissionDefList(newInfo);
    if (!GetNewPermissionDefList(tokenId, defPermList, newDefPermList)) {
        return false;
    }

    // delete old definePermission
    std::vector<std::string> needDeleteDefinePermission = GetNeedDeleteDefinePermissionName(oldInfo, newInfo);
    for (const auto &name : needDeleteDefinePermission) {
        auto iter = std::find_if(newDefPermList.begin(), newDefPermList.end(), [&name](const auto &defPerm) {
            return defPerm.permissionName == name;
        });
        if (iter != newDefPermList.end()) {
            APP_LOGD("delete definePermission %{public}s", name.c_str());
            newDefPermList.erase(iter);
        }
    }
    return true;
}

bool BundlePermissionMgr::InnerUpdateRequestPermission(
    const Security::AccessToken::AccessTokenID tokenId,
    const InnerBundleInfo &oldInfo,
    const InnerBundleInfo &newInfo,
    std::vector<Security::AccessToken::PermissionStateFull> &newPermissionStateList,
    std::vector<std::string> &newRequestPermName)
{
    // get access token permission
    std::vector<AccessToken::PermissionStateFull> reqPermissionStateList = GetPermissionStateFullList(newInfo);
    if (!GetNewPermissionStateFull(tokenId, reqPermissionStateList,
        newPermissionStateList, newRequestPermName)) {
        return false;
    }
    // delete old requestPermission
    std::vector<std::string> needDeleteRequestPermission = GetNeedDeleteRequestPermissionName(oldInfo, newInfo);
    for (const auto &name : needDeleteRequestPermission) {
        auto iter = std::find_if(newPermissionStateList.begin(), newPermissionStateList.end(),
            [&name](const auto &defPerm) {
            return defPerm.permissionName == name;
        });
        if (iter != newPermissionStateList.end()) {
            APP_LOGD("delete requestPermission %{public}s", name.c_str());
            newPermissionStateList.erase(iter);
        }
        auto deleteIter = std::find(newRequestPermName.begin(), newRequestPermName.end(), name);
        if (deleteIter != newRequestPermName.end()) {
            newRequestPermName.erase(deleteIter);
        }
    }
    return true;
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
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_UNINSTALL_BUNDLE)) {
        APP_LOGE("uninstall bundle permission denied");
        return false;
    }
    return true;
}

bool BundlePermissionMgr::VerifyRecoverPermission()
{
    if (!BundlePermissionMgr::IsSelfCalling() &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_RECOVER_BUNDLE)) {
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
}  // namespace AppExecFwk
}  // namespace OHOS