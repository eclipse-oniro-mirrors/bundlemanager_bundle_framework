/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "bundle_clone_installer.h"

#include <sstream>

#include "ability_manager_helper.h"
#include "account_helper.h"
#include "bms_extension_data_mgr.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_resource_helper.h"
#include "bundle_service_constants.h"
#include "code_protect_bundle_info.h"
#include "datetime_ex.h"
#include "hitrace_meter.h"
#include "installd_client.h"
#include "inner_bundle_clone_common.h"
#include "parameters.h"
#include "perf_profile.h"
#include "scope_guard.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::Security;

std::mutex gCloneInstallerMutex;

BundleCloneInstaller::BundleCloneInstaller()
{
    APP_LOGD("bundle clone installer instance is created");
}

BundleCloneInstaller::~BundleCloneInstaller()
{
    APP_LOGD("bundle clone installer instance is destroyed");
}

ErrCode BundleCloneInstaller::InstallCloneApp(const std::string &bundleName,
    const int32_t userId, int32_t &appIndex)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("InstallCloneApp %{public}s begin", bundleName.c_str());

    PerfProfile::GetInstance().SetBundleInstallStartTime(GetTickCount());

    ErrCode result = ProcessCloneBundleInstall(bundleName, userId, appIndex);
    NotifyBundleEvents installRes = {
        .type = NotifyType::INSTALL,
        .resultCode = result,
        .accessTokenId = accessTokenId_,
        .uid = uid_,
        .appIndex = appIndex,
        .bundleName = bundleName,
        .appId = appId_,
        .appIdentifier = appIdentifier_,
    };
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    commonEventMgr->NotifyBundleStatus(installRes, dataMgr);

    SendBundleSystemEvent(bundleName, BundleEventType::INSTALL, userId, appIndex,
        false, false, InstallScene::NORMAL, result);

    ResetInstallProperties();
    PerfProfile::GetInstance().SetBundleInstallEndTime(GetTickCount());
    return result;
}

ErrCode BundleCloneInstaller::UninstallCloneApp(
    const std::string &bundleName, const int32_t userId, const int32_t appIndex)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("UninstallCloneApp %{public}s _ %{public}d begin", bundleName.c_str(), appIndex);

    PerfProfile::GetInstance().SetBundleUninstallStartTime(GetTickCount());

    ErrCode result = ProcessCloneBundleUninstall(bundleName, userId, appIndex);
    NotifyBundleEvents installRes = {
        .type = NotifyType::UNINSTALL_BUNDLE,
        .resultCode = result,
        .accessTokenId = accessTokenId_,
        .bundleName = bundleName,
        .uid = uid_,
        .appIndex = appIndex,
        .appId = appId_,
        .appIdentifier = appIdentifier_,
        .developerId = GetDeveloperId(bundleName),
        .assetAccessGroups = GetAssetAccessGroups(bundleName)
    };
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    commonEventMgr->NotifyBundleStatus(installRes, dataMgr);

    SendBundleSystemEvent(bundleName, BundleEventType::UNINSTALL, userId, appIndex,
        false, false, InstallScene::NORMAL, result);

    ResetInstallProperties();

    PerfProfile::GetInstance().SetBundleUninstallEndTime(GetTickCount());
    return result;
}

ErrCode BundleCloneInstaller::UninstallAllCloneApps(const std::string &bundleName, int32_t userId)
{
    // All clone will be uninstalled when the original application is updated or uninstalled
    APP_LOGI_NOFUNC("UninstallAllCloneApps begin");
    if (bundleName.empty()) {
        APP_LOGE("UninstallAllCloneApps failed due to empty bundle name");
        return ERR_APPEXECFWK_CLONE_UNINSTALL_INVALID_BUNDLE_NAME;
    }
    if (GetDataMgr() != ERR_OK) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return ERR_APPEXECFWK_CLONE_UNINSTALL_INTERNAL_ERROR;
    }
    if (!dataMgr_->HasUserId(userId)) {
        APP_LOGE("install clone app user %{public}d not exist", userId);
        return ERR_APPEXECFWK_CLONE_UNINSTALL_USER_NOT_EXIST;
    }
    InnerBundleInfo info;
    bool isExist = dataMgr_->FetchInnerBundleInfo(bundleName, info);
    if (!isExist) {
        APP_LOGE("the bundle is not installed");
        return ERR_APPEXECFWK_CLONE_UNINSTALL_APP_NOT_EXISTED;
    }
    InnerBundleUserInfo userInfo;
    if (!info.GetInnerBundleUserInfo(userId, userInfo)) {
        APP_LOGE_NOFUNC("the origin application is not installed at current user");
        return ERR_APPEXECFWK_CLONE_UNINSTALL_NOT_INSTALLED_AT_SPECIFIED_USERID;
    }
    ErrCode result = ERR_OK;
    for (auto it = userInfo.cloneInfos.begin(); it != userInfo.cloneInfos.end(); it++) {
        if (UninstallCloneApp(bundleName, userId, std::stoi(it->first)) != ERR_OK) {
            APP_LOGE("UninstallCloneApp failed, appIndex %{public}s", it->first.c_str());
            result = ERR_APPEXECFWK_CLONE_UNINSTALL_INTERNAL_ERROR;
        }
    }
    APP_LOGI_NOFUNC("UninstallAllCloneApps end");
    return result;
}

ErrCode BundleCloneInstaller::ProcessCloneBundleInstall(const std::string &bundleName,
    const int32_t userId, int32_t &appIndex)
{
    if (bundleName.empty()) {
        APP_LOGE("the bundle name is empty");
        return ERR_APPEXECFWK_CLONE_INSTALL_PARAM_ERROR;
    }

    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();

    std::lock_guard<std::mutex> cloneGuard(gCloneInstallerMutex);
    // 1. check whether original application installed or not
    InnerBundleInfo info;
    bool isExist = dataMgr->FetchInnerBundleInfo(bundleName, info);
    if (!isExist) {
        APP_LOGE("the bundle is not installed");
        return ERR_APPEXECFWK_CLONE_INSTALL_APP_NOT_EXISTED;
    }

    // 2. obtain userId
    if (userId < Constants::DEFAULT_USERID) {
        APP_LOGE("userId(%{public}d) invalid", userId);
        return ERR_APPEXECFWK_CLONE_INSTALL_USER_NOT_EXIST;
    }
    if (!dataMgr->HasUserId(userId)) {
        APP_LOGE("install clone app user %{public}d not exist", userId);
        return ERR_APPEXECFWK_CLONE_INSTALL_USER_NOT_EXIST;
    }

    // 3. check whether original application installed at current userId or not
    InnerBundleUserInfo userInfo;
    if (!info.GetInnerBundleUserInfo(userId, userInfo)) {
        APP_LOGE("the origin application is not installed at current user");
        return ERR_APPEXECFWK_CLONE_INSTALL_NOT_INSTALLED_AT_SPECIFIED_USERID;
    }

    ErrCode ackRes = info.VerifyAndAckCloneAppIndex(userId, appIndex);
    if (ackRes != ERR_OK) {
        APP_LOGE("installCloneApp fail for verifyAndAck res %{public}d", ackRes);
        return ackRes;
    }

    // uid
    std::string cloneBundleName = BundleCloneCommonHelper::GetCloneBundleIdKey(bundleName, appIndex);
    InnerBundleUserInfo tmpUserInfo;
    tmpUserInfo.bundleName = cloneBundleName;
    tmpUserInfo.bundleUserInfo.userId = userId;
    dataMgr->GenerateUidAndGid(tmpUserInfo);
    int32_t uid = tmpUserInfo.uid;

    // 4. generate the accesstoken id and inherit original permissions
    info.SetAppIndex(appIndex);
    Security::AccessToken::AccessTokenIDEx newTokenIdEx;
    if (BundlePermissionMgr::InitHapToken(info, userId, 0, newTokenIdEx) != ERR_OK) {
        APP_LOGE("bundleName:%{public}s InitHapToken failed", bundleName.c_str());
        return ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED;
    }
    ScopeGuard applyAccessTokenGuard([&] {
        BundlePermissionMgr::DeleteAccessTokenId(newTokenIdEx.tokenIdExStruct.tokenID);
    });

    InnerBundleCloneInfo attr = {
        .userId = userId,
        .appIndex = appIndex,
        .uid = uid,
        .gids = tmpUserInfo.gids,
        .accessTokenId = newTokenIdEx.tokenIdExStruct.tokenID,
        .accessTokenIdEx = newTokenIdEx.tokenIDEx,
    };
    uid_ = uid;
    accessTokenId_ = newTokenIdEx.tokenIdExStruct.tokenID;
    versionCode_ = info.GetVersionCode();
    appId_ = info.GetAppId();
    appIdentifier_ = info.GetAppIdentifier();

    ScopeGuard createCloneDataDirGuard([&] { RemoveCloneDataDir(bundleName, userId, appIndex); });
    ErrCode result = CreateCloneDataDir(info, userId, uid, appIndex);
    if (result != ERR_OK) {
        APP_LOGE("InstallCloneApp create clone dir failed");
        return result;
    }

    ScopeGuard addCloneBundleGuard([&] { dataMgr->RemoveCloneBundle(bundleName, userId, appIndex); });
    ErrCode addRes = dataMgr->AddCloneBundle(bundleName, attr);
    if (addRes != ERR_OK) {
        APP_LOGE("dataMgr add clone bundle fail, bundleName: %{public}s, userId: %{public}d, appIndex: %{public}d",
            bundleName.c_str(), userId, appIndex);
        return addRes;
    }

    ScopeGuard createEl5DirGuard([&] { RemoveEl5Dir(userInfo, uid, userId, appIndex); });
    CreateEl5Dir(info, userId, uid, appIndex);

    // process icon and label
    {
        auto appIndexes = info.GetCloneBundleAppIndexes();
        // appIndex not exist, need parse
        if (appIndexes.find(appIndex) == appIndexes.end()) {
            BundleResourceHelper::AddCloneBundleResourceInfo(bundleName, appIndex, userId);
        }
    }

    // total to commit, avoid rollback
    applyAccessTokenGuard.Dismiss();
    createCloneDataDirGuard.Dismiss();
    addCloneBundleGuard.Dismiss();
    createEl5DirGuard.Dismiss();
    APP_LOGI("InstallCloneApp %{public}s appIndex:%{public}d succesfully", bundleName.c_str(), appIndex);
    return ERR_OK;
}

ErrCode BundleCloneInstaller::ProcessCloneBundleUninstall(const std::string &bundleName,
    int32_t userId, int32_t appIndex)
{
    if (bundleName.empty()) {
        APP_LOGE("UninstallCloneApp failed due to empty bundle name");
        return ERR_APPEXECFWK_CLONE_UNINSTALL_INVALID_BUNDLE_NAME;
    }
    if (appIndex < ServiceConstants::CLONE_APP_INDEX_MIN || appIndex > ServiceConstants::CLONE_APP_INDEX_MAX) {
        APP_LOGE("Add Clone Bundle Fail, appIndex: %{public}d not in valid range", appIndex);
        return ERR_APPEXECFWK_CLONE_UNINSTALL_INVALID_APP_INDEX;
    }
    if (GetDataMgr() != ERR_OK) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return ERR_APPEXECFWK_CLONE_UNINSTALL_INTERNAL_ERROR;
    }
    std::lock_guard<std::mutex> cloneGuard(gCloneInstallerMutex);
    if (!dataMgr_->HasUserId(userId)) {
        APP_LOGE("install clone app user %{public}d not exist", userId);
        return ERR_APPEXECFWK_CLONE_UNINSTALL_USER_NOT_EXIST;
    }
    InnerBundleInfo info;
    bool isExist = dataMgr_->FetchInnerBundleInfo(bundleName, info);
    if (!isExist) {
        APP_LOGE("the bundle is not installed");
        return ERR_APPEXECFWK_CLONE_UNINSTALL_APP_NOT_EXISTED;
    }
    InnerBundleUserInfo userInfo;
    if (!info.GetInnerBundleUserInfo(userId, userInfo)) {
        APP_LOGE("the origin application is not installed at current user");
        return ERR_APPEXECFWK_CLONE_UNINSTALL_NOT_INSTALLED_AT_SPECIFIED_USERID;
    }
    auto it = userInfo.cloneInfos.find(std::to_string(appIndex));
    if (it == userInfo.cloneInfos.end()) {
        APP_LOGE("the clone app is not installed");
        return ERR_APPEXECFWK_CLONE_UNINSTALL_APP_NOT_CLONED;
    }
    uid_ = it->second.uid;
    accessTokenId_ = it->second.accessTokenId;
    versionCode_ = info.GetVersionCode();
    appId_ = info.GetAppId();
    appIdentifier_ = info.GetAppIdentifier();
    if (!AbilityManagerHelper::UninstallApplicationProcesses(bundleName, uid_, false, appIndex)) {
        APP_LOGE("fail to kill running application");
    }
    if (BundlePermissionMgr::DeleteAccessTokenId(accessTokenId_) !=
        AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        APP_LOGE("delete AT failed clone");
    }
    if (dataMgr_->RemoveCloneBundle(bundleName, userId, appIndex)) {
        APP_LOGE("RemoveCloneBundle failed");
        return ERR_APPEXECFWK_CLONE_UNINSTALL_INTERNAL_ERROR;
    }
    if (RemoveCloneDataDir(bundleName, userId, appIndex) != ERR_OK) {
        APP_LOGW("RemoveCloneDataDir failed");
    }
    RemoveEl5Dir(userInfo, uid_, userId, appIndex);
    // process icon and label
    {
        InnerBundleInfo info;
        if (dataMgr_->FetchInnerBundleInfo(bundleName, info)) {
            auto appIndexes = info.GetCloneBundleAppIndexes();
            if (appIndexes.find(appIndex) == appIndexes.end()) {
                BundleResourceHelper::DeleteCloneBundleResourceInfo(bundleName, appIndex, userId);
            }
        }
    }
#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
    std::shared_ptr<AppControlManager> appControlMgr = DelayedSingleton<AppControlManager>::GetInstance();
    if (appControlMgr != nullptr) {
        APP_LOGD("Delete disposed rule when bundleName :%{public}s uninstall", bundleName.c_str());
        appControlMgr->DeleteAllDisposedRuleByBundle(info, appIndex, userId);
    }
#endif
    UninstallDebugAppSandbox(bundleName, uid_, appIndex, userId, info);
    APP_LOGI("UninstallCloneApp %{public}s _ %{public}d succesfully", bundleName.c_str(), appIndex);
    return ERR_OK;
}

void BundleCloneInstaller::UninstallDebugAppSandbox(const std::string &bundleName, const int32_t uid,
    int32_t appIndex, int32_t userId, const InnerBundleInfo& innerBundleInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("call UninstallDebugAppSandbox start");
    ApplicationInfo appInfo;
    innerBundleInfo.GetApplicationInfo(ApplicationFlag::GET_BASIC_APPLICATION_INFO, userId, appInfo);
    bool isDebugApp = appInfo.appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG;
    bool isDeveloperMode = OHOS::system::GetBoolParameter(ServiceConstants::DEVELOPERMODE_STATE, false);
    if (isDeveloperMode && isDebugApp) {
        AppSpawnRemoveSandboxDirMsg removeSandboxDirMsg;
        removeSandboxDirMsg.code = MSG_UNINSTALL_DEBUG_HAP;
        removeSandboxDirMsg.bundleName = bundleName;
        removeSandboxDirMsg.bundleIndex = appIndex;
        removeSandboxDirMsg.uid = uid;
        removeSandboxDirMsg.flags = APP_FLAGS_CLONE_ENABLE;
        if (BundleAppSpawnClient::GetInstance().RemoveSandboxDir(removeSandboxDirMsg) != 0) {
            APP_LOGE("RemoveSandboxDir failed");
        }
    }
    APP_LOGD("call UninstallDebugAppSandbox end");
}


ErrCode BundleCloneInstaller::CreateCloneDataDir(InnerBundleInfo &info,
    const int32_t userId, const int32_t &uid, const int32_t &appIndex) const
{
    APP_LOGD("CreateCloneDataDir %{public}s _ %{public}d begin", info.GetBundleName().c_str(), appIndex);
    std::string innerDataDir = BundleCloneCommonHelper::GetCloneDataDir(info.GetBundleName(), appIndex);
    CreateDirParam createDirParam;
    createDirParam.bundleName = innerDataDir;
    createDirParam.userId = userId;
    createDirParam.uid = uid;
    createDirParam.gid = uid;
    createDirParam.apl = info.GetAppPrivilegeLevel();
    createDirParam.isPreInstallApp = info.IsPreInstallApp();
    createDirParam.debug = info.GetBaseApplicationInfo().appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG;
    auto result = InstalldClient::GetInstance()->CreateBundleDataDir(createDirParam);
    if (result != ERR_OK) {
        // if user is not activated, access el2-el4 may return ok but dir cannot be created
        if (AccountHelper::IsOsAccountVerified(userId)) {
            APP_LOGE("fail to create data dir, error is %{public}d", result);
            return result;
        } else {
            APP_LOGW("user %{public}d is not activated", userId);
        }
    }
    APP_LOGI("CreateCloneDataDir successfully");
    return result;
}

ErrCode BundleCloneInstaller::RemoveCloneDataDir(const std::string bundleName, int32_t userId, int32_t appIndex)
{
    std::string key = BundleCloneCommonHelper::GetCloneDataDir(bundleName, appIndex);
    if (InstalldClient::GetInstance()->RemoveBundleDataDir(key, userId) != ERR_OK) {
        APP_LOGW("CloneApp cannot remove the data dir");
        return ERR_APPEXECFWK_CLONE_INSTALL_INTERNAL_ERROR;
    }
    return ERR_OK;
}

void BundleCloneInstaller::CreateEl5Dir(InnerBundleInfo &info, const int32_t userId,
    const int32_t uid, const int32_t appIndex)
{
    std::vector<RequestPermission> reqPermissions = info.GetAllRequestPermissions();
    auto it = std::find_if(reqPermissions.begin(), reqPermissions.end(), [](const RequestPermission& permission) {
        return permission.name == ServiceConstants::PERMISSION_PROTECT_SCREEN_LOCK_DATA;
    });
    if (it == reqPermissions.end()) {
        APP_LOGD("no el5 permission");
        return;
    }
    APP_LOGI("el5 -n %{public}s -i %{public}d", info.GetBundleName().c_str(), appIndex);
    CreateDirParam el5Param;
    el5Param.bundleName = info.GetBundleName();
    el5Param.userId = userId;
    el5Param.uid = uid;
    el5Param.gid = uid;
    el5Param.apl = info.GetAppPrivilegeLevel();
    el5Param.isPreInstallApp = info.IsPreInstallApp();
    el5Param.debug = info.GetBaseApplicationInfo().appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG;
    el5Param.appIndex = appIndex;
    if (GetDataMgr() != ERR_OK) {
        return;
    }
    dataMgr_->CreateEl5Dir(std::vector<CreateDirParam> {el5Param}, true);
}

void BundleCloneInstaller::RemoveEl5Dir(InnerBundleUserInfo &userInfo, const int32_t uid,
    int32_t userId, const int32_t appIndex)
{
    APP_LOGI("el5 -n %{public}s -i %{public}d", userInfo.bundleName.c_str(), appIndex);
    std::string key = BundleCloneCommonHelper::GetCloneDataDir(userInfo.bundleName, appIndex);
    std::vector<std::string> dirs;
    dirs.emplace_back(std::string(ServiceConstants::SCREEN_LOCK_FILE_DATA_PATH) + ServiceConstants::PATH_SEPARATOR +
        std::to_string(userId) + ServiceConstants::BASE + key);
    dirs.emplace_back(std::string(ServiceConstants::SCREEN_LOCK_FILE_DATA_PATH) + ServiceConstants::PATH_SEPARATOR +
        std::to_string(userId) + ServiceConstants::DATABASE + key);
    for (const std::string &dir : dirs) {
        if (InstalldClient::GetInstance()->RemoveDir(dir) != ERR_OK) {
            APP_LOGW("remove el5 dir %{public}s failed", dir.c_str());
        }
    }
    auto it = userInfo.cloneInfos.find(std::to_string(appIndex));
    if (it == userInfo.cloneInfos.end()) {
        APP_LOGE("find cloneInfo failed");
        return;
    }
    if (it->second.keyId.empty()) {
        return;
    }
    if (InstalldClient::GetInstance()->DeleteEncryptionKeyId(key, userId) != ERR_OK) {
        APP_LOGW("delete encryption key id failed");
    }
}

ErrCode BundleCloneInstaller::GetDataMgr()
{
    if (dataMgr_ == nullptr) {
        dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        if (dataMgr_ == nullptr) {
            APP_LOGE("Get dataMgr shared_ptr nullptr");
            return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        }
    }
    return ERR_OK;
}

void BundleCloneInstaller::SendBundleSystemEvent(const std::string &bundleName, BundleEventType bundleEventType,
    int32_t userId, int32_t appIndex, bool isPreInstallApp, bool isFreeInstallMode,
    InstallScene preBundleScene, ErrCode errCode)
{
    EventInfo sysEventInfo;
    sysEventInfo.bundleName = bundleName;
    sysEventInfo.isPreInstallApp = isPreInstallApp;
    sysEventInfo.errCode = errCode;
    sysEventInfo.isFreeInstallMode = isFreeInstallMode;
    sysEventInfo.userId = userId;
    sysEventInfo.appIndex = appIndex;
    sysEventInfo.callingUid = IPCSkeleton::GetCallingUid();
    sysEventInfo.versionCode = versionCode_;
    sysEventInfo.preBundleScene = preBundleScene;
    GetCallingEventInfo(sysEventInfo);
    EventReport::SendBundleSystemEvent(bundleEventType, sysEventInfo);
}

void BundleCloneInstaller::GetCallingEventInfo(EventInfo &eventInfo)
{
    APP_LOGD("GetCallingEventInfo start, bundleName:%{public}s", eventInfo.callingBundleName.c_str());
    if (dataMgr_ == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return;
    }
    if (!dataMgr_->GetBundleNameForUid(eventInfo.callingUid, eventInfo.callingBundleName)) {
        APP_LOGE("CallingUid %{public}d is not hap, no bundleName", eventInfo.callingUid);
        eventInfo.callingBundleName = Constants::EMPTY_STRING;
        return;
    }
    BundleInfo bundleInfo;
    if (!dataMgr_->GetBundleInfo(eventInfo.callingBundleName, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo,
        eventInfo.callingUid / Constants::BASE_USER_RANGE)) {
        APP_LOGE("GetBundleInfo failed, bundleName: %{public}s", eventInfo.callingBundleName.c_str());
        return;
    }
    eventInfo.callingAppId = bundleInfo.appId;
}

void BundleCloneInstaller::ResetInstallProperties()
{
    uid_ = 0;
    accessTokenId_ = 0;
    versionCode_ = 0;
    appId_ = "";
    appIdentifier_ = "";
}

std::string BundleCloneInstaller::GetAssetAccessGroups(const std::string &bundleName)
{
    if (GetDataMgr() != ERR_OK) {
        APP_LOGE("DataMgr null");
        return Constants::EMPTY_STRING;
    }
    std::vector<std::string> assetAccessGroups;
    ErrCode ret = dataMgr_->GetAssetAccessGroups(bundleName, assetAccessGroups);
    if (ret != ERR_OK) {
        APP_LOGE("GetAssetAccessGroups failed, ret=%{public}d", ret);
        return Constants::EMPTY_STRING;
    }
    std::string assetAccessGroupsStr;
    if (!assetAccessGroups.empty()) {
        std::stringstream assetAccessGroupsStream;
        std::copy(assetAccessGroups.begin(), assetAccessGroups.end(),
            std::ostream_iterator<std::string>(assetAccessGroupsStream, ","));
        assetAccessGroupsStr = assetAccessGroupsStream.str();
        if (!assetAccessGroupsStr.empty()) {
            assetAccessGroupsStr.pop_back();
        }
    }
    return assetAccessGroupsStr;
}

std::string BundleCloneInstaller::GetDeveloperId(const std::string &bundleName)
{
    if (GetDataMgr() != ERR_OK) {
        APP_LOGE("DataMgr null");
        return Constants::EMPTY_STRING;
    }
    std::string developerId;
    ErrCode ret = dataMgr_->GetDeveloperId(bundleName, developerId);
    if (ret != ERR_OK) {
        APP_LOGE("GetDeveloperId failed, ret=%{public}d", ret);
    }
    return developerId;
}
} // AppExecFwk
} // OHOS
