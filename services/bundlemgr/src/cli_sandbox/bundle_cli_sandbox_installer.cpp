/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "bundle_cli_sandbox_installer.h"

#include <algorithm>
#include <cstdlib>

#include "ability_manager_helper.h"
#include "account_helper.h"
#include "bundle_app_spawn_client.h"
#include "bundle_common_event.h"
#include "bundle_common_event_mgr.h"
#include "bundle_file_util.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_resource_helper.h"
#include "bundle_service_constants.h"
#include "bundle_util.h"
#include "bms_update_selinux_mgr.h"
#include "datetime_ex.h"
#include "hitrace_meter.h"
#include "installd_client.h"
#include "inner_bundle_clone_common.h"
#include "ipc_skeleton.h"
#include "parameters.h"
#include "perf_profile.h"
#include "scope_guard.h"
#include "share_file_helper.h"

#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
#include "app_control_manager.h"
#endif

namespace OHOS {
namespace AppExecFwk {

std::mutex gCliSandboxInstallerMutex;

BundleCliSandboxInstaller::BundleCliSandboxInstaller()
{
    APP_LOGD("bundle cli sandbox installer instance is created");
}

BundleCliSandboxInstaller::~BundleCliSandboxInstaller()
{
    APP_LOGD("bundle cli sandbox installer instance is destroyed");
}

ErrCode BundleCliSandboxInstaller::CreateCliSandboxApp(const std::string &creatorBundleName,
    const std::string &bundleName, int32_t userId, int32_t &appIndex)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    APP_LOGI_NOFUNC("CreateCliSandboxApp %{public}s begin, caller: %{public}s",
        bundleName.c_str(), creatorBundleName.c_str());

    PerfProfile::GetInstance().SetBundleInstallStartTime(GetTickCount());
    startTime_ = BundleUtil::GetCurrentTimeMs();

    if (creatorBundleName.empty()) {
        APP_LOGE("creatorBundleName is empty");
        return ERR_APPEXECFWK_CLI_SANDBOX_INSTALL_INVALID_CREATOR_BUNDLE_NAME;
    }

    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return ERR_APPEXECFWK_CLI_SANDBOX_INSTALL_INVALID_BUNDLE_NAME;
    }

    ErrCode result = ProcessCreateCliSandbox(creatorBundleName, bundleName, userId, appIndex);

    NotifyBundleEvents installRes = {
        .type = NotifyType::INSTALL,
        .resultCode = result,
        .accessTokenId = accessTokenId_,
        .uid = uid_,
        .appIndex = appIndex,
        .userId = userId,
        .bundleName = bundleName,
        .appId = appId_,
        .appIdentifier = appIdentifier_,
        .appDistributionType = appDistributionType_,
        .sandboxCreatorBundleName = creatorBundleName,
        .crossAppSharedConfig = isBundleCrossAppSharedConfig_,
    };
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    if (result == ERR_OK) {
        commonEventMgr->NotifyCliSandboxAppStatus(installRes, COMMON_EVENT_SANDBOX_BUNDLE_ADDED);
    }

    ResetInstallProperties();
    PerfProfile::GetInstance().SetBundleInstallEndTime(GetTickCount());
    return result;
}

ErrCode BundleCliSandboxInstaller::ProcessCreateCliSandbox(const std::string &creatorBundleName,
    const std::string &bundleName, int32_t userId, int32_t &appIndex)
{
    if (GetDataMgr() != ERR_OK) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return ERR_APPEXECFWK_CLI_SANDBOX_INSTALL_INTERNAL_ERROR;
    }

    std::lock_guard<std::mutex> guard(gCliSandboxInstallerMutex);

    // 1. check whether original application installed
    InnerBundleInfo info;
    bool isExist = dataMgr_->FetchInnerBundleInfo(bundleName, info);
    if (!isExist) {
        APP_LOGE("bundle %{public}s not installed", bundleName.c_str());
        return ERR_APPEXECFWK_CLI_SANDBOX_INSTALL_APP_NOT_EXISTED;
    }
    isBundleCrossAppSharedConfig_ = info.IsBundleCrossAppSharedConfig();
    appDistributionType_ = info.GetAppDistributionType();

    // 2. check userId
    if (userId < Constants::DEFAULT_USERID) {
        APP_LOGE("userId(%{public}d) invalid", userId);
        return ERR_APPEXECFWK_CLI_SANDBOX_INSTALL_USER_NOT_EXIST;
    }
    if (!dataMgr_->HasUserId(userId)) {
        APP_LOGE("user %{public}d not exist", userId);
        return ERR_APPEXECFWK_CLI_SANDBOX_INSTALL_USER_NOT_EXIST;
    }

    // 3. check whether original application installed for this user
    InnerBundleUserInfo userInfo;
    if (!info.GetInnerBundleUserInfo(userId, userInfo)) {
        APP_LOGE("bundle %{public}s not installed for user %{public}d", bundleName.c_str(), userId);
        return ERR_APPEXECFWK_CLI_SANDBOX_INSTALL_NOT_INSTALLED_AT_SPECIFIED_USERID;
    }

    // 4. check whether creator application installed for this user
    InnerBundleInfo creatorInfo;
    InnerBundleUserInfo creatorUserInfo;
    if (!dataMgr_->FetchInnerBundleInfo(creatorBundleName, creatorInfo) ||
        !creatorInfo.GetInnerBundleUserInfo(userId, creatorUserInfo)) {
        APP_LOGE("creator %{public}s not installed for user %{public}d", creatorBundleName.c_str(), userId);
        return ERR_APPEXECFWK_CLI_SANDBOX_INSTALL_CREATOR_NOT_INSTALLED;
    }

    // 5. check creator's sandbox count limit
    int32_t creatorCount = dataMgr_->GetCliSandboxCountByCreator(bundleName, userId, creatorBundleName);
    if (creatorCount >= ServiceConstants::CLI_SANDBOX_MAX_COUNT_PER_CREATOR) {
        APP_LOGE("creator %{public}s has reached max sandbox count %{public}d for bundle %{public}s",
            creatorBundleName.c_str(), ServiceConstants::CLI_SANDBOX_MAX_COUNT_PER_CREATOR, bundleName.c_str());
        return ERR_APPEXECFWK_CLI_SANDBOX_INSTALL_OUT_OF_LIMIT_PER_CREATOR;
    }

    // 6. generate new appIndex
    appIndex = ServiceConstants::CLI_SANDBOX_APP_INDEX_MIN;
    while (userInfo.sandboxInfos.find(InnerBundleUserInfo::AppIndexToKey(appIndex)) != userInfo.sandboxInfos.end()) {
        appIndex++;
    }
    if (appIndex > ServiceConstants::CLI_SANDBOX_APP_INDEX_MAX) {
        APP_LOGE("no available appIndex in range 2000-3000");
        return ERR_APPEXECFWK_CLI_SANDBOX_INSTALL_OUT_OF_LIMIT;
    }

    // 7. HMDFS config
    int32_t uid = 0;
    std::vector<int32_t> gids;
    BundleUtil::MakeFsConfig(info.GetBundleName(), ServiceConstants::HMDFS_CONFIG_PATH,
        info.GetAppProvisionType(), Constants::APP_PROVISION_TYPE_FILE_NAME);

    // 8. create access token
    info.SetAppIndex(appIndex);
    Security::AccessToken::AccessTokenIDEx newTokenIdEx;
    AppProvisionInfo appProvisionInfo;
    if (dataMgr_->GetAppProvisionInfo(bundleName, userId, appProvisionInfo) != ERR_OK) {
        APP_LOGE("GetAppProvisionInfo failed bundleName:%{public}s", bundleName.c_str());
    }
    Security::AccessToken::HapInfoCheckResult checkResult;
    if (BundlePermissionMgr::InitHapToken(info, userId, 0, newTokenIdEx, checkResult,
        appProvisionInfo.appServiceCapabilities) != ERR_OK) {
        APP_LOGE("bundleName:%{public}s InitHapToken failed", bundleName.c_str());
        return ERR_APPEXECFWK_CLI_SANDBOX_INSTALL_GRANT_PERMISSION_FAILED;
    }

    ScopeGuard applyAccessTokenGuard([&] {
        BundlePermissionMgr::DeleteAccessTokenId(newTokenIdEx.tokenIdExStruct.tokenID);
    });

    uid = info.GetUid(userId);
    if (uid == Constants::INVALID_UID) {
        APP_LOGE_NOFUNC("InitHapToken returned invalid uid for bundle:%{public}s", bundleName.c_str());
        return ERR_APPEXECFWK_CLI_SANDBOX_INSTALL_INTERNAL_ERROR;
    }
    gids.emplace_back(uid);

    // 9. create data directory
    ScopeGuard createDataDirGuard([&] {
        RemoveSandboxDataDir(bundleName, userId, appIndex, true);
    });
    ErrCode result = CreateSandboxDataDir(info, userId, uid, appIndex);
    if (result != ERR_OK) {
        APP_LOGE("CreateSandboxDataDir failed");
        return result;
    }

    // 10. build InnerCliSandboxInfo
    InnerCliSandboxInfo sandboxInfo;
    sandboxInfo.userId = userId;
    sandboxInfo.appIndex = appIndex;
    sandboxInfo.uid = uid;
    sandboxInfo.accessTokenId = newTokenIdEx.tokenIdExStruct.tokenID;
    sandboxInfo.accessTokenIdEx = newTokenIdEx.tokenIDEx;
    sandboxInfo.gids = gids;
    sandboxInfo.sandboxType = SandboxIsolationType::FullIsolation;
    sandboxInfo.installTime = BundleUtil::GetCurrentTimeMs();
    sandboxInfo.creatorBundleNames.push_back(creatorBundleName);

    // 11. save to data manager
    ScopeGuard addSandboxGuard([&] {
        dataMgr_->RemoveCliSandboxBundle(bundleName, userId, appIndex);
    });
    ErrCode addRes = dataMgr_->AddCliSandboxBundle(bundleName, sandboxInfo);
    if (addRes != ERR_OK) {
        APP_LOGE("AddCliSandboxBundle failed, bundleName: %{public}s, appIndex: %{public}d",
            bundleName.c_str(), appIndex);
        return addRes;
    }

    ScopeGuard createEl5DirGuard([&] {
        RemoveEl5Dir(bundleName, userId, appIndex);
    });
    CreateEl5Dir(info, userId, uid, appIndex);

    // commit
    applyAccessTokenGuard.Dismiss();
    createDataDirGuard.Dismiss();
    addSandboxGuard.Dismiss();
    createEl5DirGuard.Dismiss();

    uid_ = uid;
    accessTokenId_ = newTokenIdEx.tokenIdExStruct.tokenID;
    versionCode_ = info.GetVersionCode();
    appId_ = info.GetAppId();
    appIdentifier_ = info.GetAppIdentifier();

    APP_LOGI("CreateCliSandboxApp %{public}s appIndex:%{public}d successfully", bundleName.c_str(), appIndex);
    return ERR_OK;
}

ErrCode BundleCliSandboxInstaller::CreateSandboxDataDir(InnerBundleInfo &info,
    int32_t userId, int32_t uid, int32_t appIndex) const
{
    APP_LOGD("CreateSandboxDataDir %{public}s appIndex:%{public}d", info.GetBundleName().c_str(), appIndex);
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
        if (AccountHelper::IsOsAccountVerified(userId)) {
            APP_LOGE("fail to create data dir, error is %{public}d", result);
            return result;
        }
        APP_LOGW("user %{public}d is not activated", userId);
    }
    APP_LOGI("CreateSandboxDataDir successfully");
    return ERR_OK;
}

ErrCode BundleCliSandboxInstaller::RemoveSandboxDataDir(
    const std::string &bundleName, int32_t userId, int32_t appIndex, bool sync) const
{
    std::string key = BundleCloneCommonHelper::GetCloneDataDir(bundleName, appIndex);
    if (InstalldClient::GetInstance()->RemoveBundleDataDir(key, userId, false, !sync) != ERR_OK) {
        APP_LOGW("RemoveSandboxDataDir failed for %{public}s", key.c_str());
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleCliSandboxInstaller::GetDataMgr()
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

void BundleCliSandboxInstaller::CreateEl5Dir(InnerBundleInfo &info, const int32_t userId,
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

void BundleCliSandboxInstaller::RemoveEl5Dir(const std::string &bundleName,
    int32_t userId, const int32_t appIndex)
{
    APP_LOGI("el5 -n %{public}s -i %{public}d", bundleName.c_str(), appIndex);
    std::string key = BundleCloneCommonHelper::GetCloneDataDir(bundleName, appIndex);
    std::vector<std::string> dirs;
    dirs.emplace_back(std::string(ServiceConstants::SCREEN_LOCK_FILE_DATA_PATH) + ServiceConstants::PATH_SEPARATOR +
        std::to_string(userId) + ServiceConstants::BASE + key);
    dirs.emplace_back(std::string(ServiceConstants::SCREEN_LOCK_FILE_DATA_PATH) + ServiceConstants::PATH_SEPARATOR +
        std::to_string(userId) + ServiceConstants::DATABASE + key);
    for (const std::string &dir : dirs) {
        if (InstalldClient::GetInstance()->RemoveDir(
            dir, BundleDirScene::REMOVE_SCREEN_LOCK_DATA_DIR, bundleName) != ERR_OK) {
            APP_LOGW("remove el5 dir %{public}s failed", dir.c_str());
        }
    }
    EncryptionParam encryptionParam(key, "", 0, userId, EncryptionDirType::APP);
    if (InstalldClient::GetInstance()->DeleteEncryptionKeyId(encryptionParam) != ERR_OK) {
        APP_LOGD("delete encryption key id failed");
    }
}

void BundleCliSandboxInstaller::ResetInstallProperties()
{
    uid_ = 0;
    accessTokenId_ = 0;
    versionCode_ = 0;
    appId_.clear();
    appIdentifier_.clear();
    isBundleCrossAppSharedConfig_ = false;
    appDistributionType_.clear();
}

ErrCode BundleCliSandboxInstaller::DestroyCliSandboxApp(const std::string &creatorBundleName,
    const std::string &envCallerBundleName, const std::string &bundleName,
    int32_t userId, int32_t appIndex, bool skipCallerCheck)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    APP_LOGD("DestroyCliSandboxApp %{public}s creator:%{public}s appIndex:%{public}d begin",
        bundleName.c_str(), creatorBundleName.c_str(), appIndex);

    PerfProfile::GetInstance().SetBundleUninstallStartTime(GetTickCount());
    startTime_ = BundleUtil::GetCurrentTimeMs();

    ErrCode result = ProcessDestroyCliSandbox(creatorBundleName, envCallerBundleName,
        bundleName, userId, appIndex, skipCallerCheck);
    ResetInstallProperties();
    PerfProfile::GetInstance().SetBundleUninstallEndTime(GetTickCount());
    return result;
}

ErrCode BundleCliSandboxInstaller::ProcessDestroyCliSandbox(const std::string &creatorBundleName,
    const std::string &envCallerBundleName, const std::string &bundleName,
    int32_t userId, int32_t appIndex, bool skipCallerCheck)
{
    if (bundleName.empty()) {
        APP_LOGE("DestroyCliSandboxApp failed due to empty bundle name");
        return ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INVALID_BUNDLE_NAME;
    }
    if (appIndex < ServiceConstants::CLI_SANDBOX_APP_INDEX_MIN ||
        appIndex > ServiceConstants::CLI_SANDBOX_APP_INDEX_MAX) {
        APP_LOGE("DestroyCliSandboxBundle Fail, appIndex: %{public}d not in valid range", appIndex);
        return ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INVALID_APP_INDEX;
    }
    if (GetDataMgr() != ERR_OK) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INTERNAL_ERROR;
    }

    std::lock_guard<std::mutex> guard(gCliSandboxInstallerMutex);
    if (!dataMgr_->HasUserId(userId)) {
        APP_LOGE("destroy sandbox app user %{public}d not exist", userId);
        return ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_USER_NOT_EXIST;
    }
    InnerBundleInfo info;
    bool isExist = dataMgr_->FetchInnerBundleInfo(bundleName, info);
    if (!isExist) {
        APP_LOGE("the bundle is not installed");
        return ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_APP_NOT_EXISTED;
    }
    isBundleCrossAppSharedConfig_ = info.IsBundleCrossAppSharedConfig();
    appDistributionType_ = info.GetAppDistributionType();

    InnerBundleUserInfo userInfo;
    if (!info.GetInnerBundleUserInfo(userId, userInfo)) {
        APP_LOGE("the origin application is not installed at current user");
        return ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_NOT_INSTALLED_AT_SPECIFIED_USERID;
    }

    auto it = userInfo.sandboxInfos.find(InnerBundleUserInfo::AppIndexToKey(appIndex));
    if (it == userInfo.sandboxInfos.end()) {
        APP_LOGE("the sandbox app is not installed");
        return ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_APP_INDEX_NOT_FOUND;
    }

    // Check if creatorBundleName is in the creatorBundleNames list
    if (!skipCallerCheck) {
        std::string actualCreatorBundleName = GetActualCreatorBundleName(creatorBundleName, envCallerBundleName,
            userId);
        if (actualCreatorBundleName.empty()) {
            return ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INVALID_CREATOR_BUNDLE_NAME;
        }
        int32_t permissionResult = BundlePermissionMgr::VerifyPermission(actualCreatorBundleName,
            Constants::PERMISSION_MANAGE_SANDBOX_BUNDLE, userId);
        if (permissionResult != Constants::PERMISSION_GRANTED) {
            APP_LOGE("%{public}s does not have permission to destroy cli sandbox app",
                actualCreatorBundleName.c_str());
            return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
        }
        auto &callerNames = it->second.creatorBundleNames;
        if (std::find(callerNames.begin(), callerNames.end(), actualCreatorBundleName) == callerNames.end()) {
            APP_LOGE("caller %{public}s is not allowed to destroy sandbox %{public}s appIndex:%{public}d",
                actualCreatorBundleName.c_str(), bundleName.c_str(), appIndex);
            return ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INVALID_CREATOR_BUNDLE_NAME;
        }
    }

    uid_ = it->second.uid;
    accessTokenId_ = it->second.accessTokenId;
    versionCode_ = info.GetVersionCode();
    appId_ = info.GetAppId();
    appIdentifier_ = info.GetAppIdentifier();

    if (!AbilityManagerHelper::UninstallApplicationProcesses(bundleName, uid_, false, appIndex)) {
        APP_LOGE("fail to kill running application");
    }
    if (dataMgr_->RemoveCliSandboxBundle(bundleName, userId, appIndex) != ERR_OK) {
        APP_LOGE("RemoveCliSandboxBundle failed");
        return ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INTERNAL_ERROR;
    }

#ifdef BMS_ACCESSCONTROL_SANDBOX_MANAGER
    // Unset shareFileInfo for this cli sandbox app
    std::string sandboxBundleName = BundleCloneCommonHelper::GetCloneBundleIdKey(bundleName, appIndex);
    int32_t unsetRet = ShareFileHelper::UnsetShareFileInfo(accessTokenId_, sandboxBundleName, userId);
    if (unsetRet != 0) {
        APP_LOGW("DestroyCliSandboxApp unset shareFiles failed, bundle=%{public}s, ret=%{public}d",
            sandboxBundleName.c_str(), unsetRet);
    }
#endif

    if (RemoveSandboxDataDir(bundleName, userId, appIndex, false) != ERR_OK) {
        APP_LOGW("RemoveSandboxDataDir failed");
    }
    RemoveEl5Dir(bundleName, userId, appIndex);
    if (BundlePermissionMgr::DeleteAccessTokenId(accessTokenId_) !=
        Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        APP_LOGE("delete AT failed sandbox");
    }
    UninstallDebugAppSandbox(bundleName, uid_, appIndex, info);
    APP_LOGI("DestroyCliSandboxApp %{public}s appIndex:%{public}d successfully", bundleName.c_str(), appIndex);
    // Send event
    NotifyBundleEvents uninstallRes = {
        .type = NotifyType::UNINSTALL_BUNDLE,
        .resultCode = ERR_OK,
        .accessTokenId = accessTokenId_,
        .uid = uid_,
        .appIndex = appIndex,
        .userId = userId,
        .bundleName = bundleName,
        .appId = appId_,
        .appIdentifier = appIdentifier_,
        .appDistributionType = appDistributionType_,
        .sandboxCreatorBundleName = it->second.creatorBundleNames.empty()
            ? Constants::EMPTY_STRING : it->second.creatorBundleNames.front(),
        .crossAppSharedConfig = isBundleCrossAppSharedConfig_,
    };
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    commonEventMgr->NotifyCliSandboxAppStatus(uninstallRes, COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    return ERR_OK;
}

void BundleCliSandboxInstaller::UninstallDebugAppSandbox(const std::string &bundleName, const int32_t uid,
    int32_t appIndex, const InnerBundleInfo& innerBundleInfo)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    APP_LOGD("call UninstallDebugAppSandbox start");
    bool isDebugApp = innerBundleInfo.GetBaseApplicationInfo().appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG;
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

std::string BundleCliSandboxInstaller::GetActualCreatorBundleName(
    const std::string &creatorBundleName, const std::string &envCallerBundleName, int32_t userId)
{
    if (envCallerBundleName.empty()) {
        APP_LOGW("env caller bundle is empty.");
        return "";
    }

    int32_t permissionResult = BundlePermissionMgr::VerifyPermission(envCallerBundleName,
        Constants::PERMISSION_CLI_MANAGE_WEB_SANDBOX, userId);
    if (permissionResult == Constants::PERMISSION_GRANTED) {
        APP_LOGD("Env bundle %{public}s has permission, use creator bundle: %{public}s",
            envCallerBundleName.c_str(), creatorBundleName.c_str());
        return creatorBundleName;
    } else {
        APP_LOGD("Env bundle %{public}s has no permission, use env bundle name", envCallerBundleName.c_str());
        return envCallerBundleName;
    }
}

ErrCode BundleCliSandboxInstaller::DestroyAllCliSandboxApps(
    const std::string &bundleName, int32_t userId)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    APP_LOGD("begin, bundleName=%{public}s, userId=%{public}d", bundleName.c_str(), userId);
    if (bundleName.empty()) {
        APP_LOGE("DestroyAllCliSandboxAppsByBundle failed due to empty bundle name");
        return ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INVALID_BUNDLE_NAME;
    }
    if (GetDataMgr() != ERR_OK) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INTERNAL_ERROR;
    }
    if (!dataMgr_->HasUserId(userId)) {
        APP_LOGE("destroy sandbox app user %{public}d not exist", userId);
        return ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_USER_NOT_EXIST;
    }
    // Check if bundle is installed
    InnerBundleInfo info;
    if (!dataMgr_->FetchInnerBundleInfo(bundleName, info)) {
        APP_LOGE("the bundle is not installed");
        return ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_APP_NOT_EXISTED;
    }
    InnerBundleUserInfo userInfo;
    if (!info.GetInnerBundleUserInfo(userId, userInfo)) {
        APP_LOGE("the origin application is not installed at current user");
        return ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_NOT_INSTALLED_AT_SPECIFIED_USERID;
    }
    ErrCode result = ERR_OK;
    // uninstall all CLI sandbox app
    for (auto it = userInfo.sandboxInfos.begin(); it != userInfo.sandboxInfos.end(); it++) {
        int32_t appIndex = it->second.appIndex;
        APP_LOGD("uninstall CLI sandbox: bundle=%{public}s, userId=%{public}d, appIndex=%{public}d",
            bundleName.c_str(), userId, appIndex);
        if (ProcessDestroyCliSandbox(Constants::EMPTY_STRING, Constants::EMPTY_STRING,
            bundleName, userId, appIndex, true) != ERR_OK) {
            APP_LOGE("Destroy CLI sandbox failed, bundleName=%{public}s, userId=%{public}d, appIndex %{public}d",
                bundleName.c_str(), userId, appIndex);
            result = ERR_APPEXECFWK_CLI_SANDBOX_UNINSTALL_INTERNAL_ERROR;
        }
    }
    APP_LOGD("end, bundleName=%{public}s, userId=%{public}d, result=%{public}d", bundleName.c_str(), userId, result);
    return result;
}
} // namespace AppExecFwk
} // namespace OHOS
