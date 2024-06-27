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

#include "ability_manager_helper.h"
#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_common_event_mgr.h"
#include "bundle_constants.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_resource_helper.h"
#include "bundle_sandbox_data_mgr.h"
#include "bundle_util.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "datetime_ex.h"
#include "hitrace_meter.h"
#include "installd_client.h"
#include "inner_bundle_clone_common.h"
#include "perf_profile.h"
#include "scope_guard.h"
#include "string_ex.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::Security;

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
        .bundleName = bundleName,
        .resultCode = result,
        .type = NotifyType::INSTALL,
        .uid = uid_,
        .accessTokenId = accessTokenId_,
        .appIndex = appIndex,
    };
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    commonEventMgr->NotifyBundleStatus(installRes, dataMgr);

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
        .bundleName = bundleName,
        .resultCode = result,
        .type = NotifyType::UNINSTALL_BUNDLE,
        .uid = uid_,
        .accessTokenId = accessTokenId_,
        .appIndex = appIndex,
    };
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    commonEventMgr->NotifyBundleStatus(installRes, dataMgr);

    ResetInstallProperties();
    PerfProfile::GetInstance().SetBundleUninstallEndTime(GetTickCount());
    return result;
}

ErrCode BundleCloneInstaller::UninstallAllCloneApps(const std::string &bundleName, int32_t userId)
{
    // All clone will be uninstalled when the original application is updated or uninstalled
    APP_LOGI("begin");
    if (bundleName.empty()) {
        APP_LOGE("UninstallAllCloneApps failed due to empty bundle name");
        return ERR_APPEXECFWK_CLONE_UNINSTALL_INVALID_BUNDLE_NAME;
    }
    if (GetDataMgr() != ERR_OK) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return ERR_APPEXECFWK_CLONE_UNINSTALL_INTERNAL_ERROR;
    }
    if (!dataMgr_->HasUserId(userId)) {
        APP_LOGE("install clone app user %{public}d not exist.", userId);
        return ERR_APPEXECFWK_CLONE_UNINSTALL_USER_NOT_EXIST;
    }
    ScopeGuard bundleEnabledGuard([&] { dataMgr_->EnableBundle(bundleName); });
    InnerBundleInfo info;
    bool isExist = dataMgr_->GetInnerBundleInfo(bundleName, info);
    if (!isExist) {
        APP_LOGE("the bundle is not installed");
        return ERR_APPEXECFWK_CLONE_UNINSTALL_APP_NOT_EXISTED;
    }
    InnerBundleUserInfo userInfo;
    if (!info.GetInnerBundleUserInfo(userId, userInfo)) {
        APP_LOGE("the origin application is not installed at current user");
        return ERR_APPEXECFWK_CLONE_UNINSTALL_NOT_INSTALLED_AT_SPECIFIED_USERID;
    }
    ErrCode result = ERR_OK;
    for (auto it = userInfo.cloneInfos.begin(); it != userInfo.cloneInfos.end(); it++) {
        if (UninstallCloneApp(bundleName, userId, std::stoi(it->first)) != ERR_OK) {
            APP_LOGE("UninstallCloneApp failed, appIndex %{public}s", it->first.c_str());
            result = ERR_APPEXECFWK_CLONE_UNINSTALL_INTERNAL_ERROR;
        }
    }
    APP_LOGI("end");
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

    // 1. check whether original application installed or not
    ScopeGuard bundleEnabledGuard([&] { dataMgr->EnableBundle(bundleName); });
    InnerBundleInfo info;
    bool isExist = dataMgr->GetInnerBundleInfo(bundleName, info);
    if (!isExist) {
        APP_LOGE("the bundle is not installed");
        return ERR_APPEXECFWK_CLONE_INSTALL_APP_NOT_EXISTED;
    }

    // 2. obtain userId
    if (userId < Constants::DEFAULT_USERID) {
        APP_LOGE("userId(%{public}d) invalid.", userId);
        return ERR_APPEXECFWK_CLONE_INSTALL_USER_NOT_EXIST;
    }
    if (!dataMgr->HasUserId(userId)) {
        APP_LOGE("install clone app user %{public}d not exist.", userId);
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
    ErrCode addRes = dataMgr->AddCloneBundle(bundleName, attr);
    if (addRes != ERR_OK) {
        APP_LOGE("dataMgr add clone bundle fail, bundleName: %{public}s, userId: %{public}d, appIndex: %{public}d",
            bundleName.c_str(), userId, appIndex);
        return addRes;
    }
    ScopeGuard addCloneBundleGuard([&] { dataMgr->RemoveCloneBundle(bundleName, userId, appIndex); });

    ErrCode result = CreateCloneDataDir(info, userId, uid, appIndex);
    if (result != ERR_OK) {
        APP_LOGE("InstallCloneApp create clone dir failed");
        return result;
    }
    ScopeGuard createCloneDataDirGuard([&] { RemoveCloneDataDir(bundleName, userId, appIndex); });

    // process icon and label
    if (!BundleResourceHelper::AddCloneBundleResourceInfo(bundleName, appIndex, userId)) {
        APP_LOGW("add clone bundle resource info failed, bundleName:%{public}s appIndex:%{public}d",
            bundleName.c_str(), appIndex);
    }
    // total to commit, avoid rollback
    applyAccessTokenGuard.Dismiss();
    createCloneDataDirGuard.Dismiss();
    addCloneBundleGuard.Dismiss();
    APP_LOGD("InstallCloneApp %{public}s succesfully", bundleName.c_str());
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
    if (!dataMgr_->HasUserId(userId)) {
        APP_LOGE("install clone app user %{public}d not exist.", userId);
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
    if (!AbilityManagerHelper::UninstallApplicationProcesses(bundleName, uid_, false, appIndex)) {
        APP_LOGE("fail to kill running application");
    }
    if (dataMgr_->RemoveCloneBundle(bundleName, userId, appIndex)) {
        APP_LOGE("RemoveCloneBundle failed");
        return ERR_APPEXECFWK_CLONE_UNINSTALL_INTERNAL_ERROR;
    }
    if (RemoveCloneDataDir(bundleName, userId, appIndex) != ERR_OK) {
        APP_LOGW("RemoveCloneDataDir failed");
    }
    // process icon and label
    if (!BundleResourceHelper::DeleteCloneBundleResourceInfo(bundleName, appIndex, userId)) {
        APP_LOGW("delete clone resource failed %{public}s appIndex %{public}d",
            bundleName.c_str(), appIndex);
    }
#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
    std::shared_ptr<AppControlManager> appControlMgr = DelayedSingleton<AppControlManager>::GetInstance();
    if (appControlMgr != nullptr) {
        APP_LOGD("Delete disposed rule when bundleName :%{public}s uninstall", bundleName.c_str());
        appControlMgr->DeleteAllDisposedRuleByBundle(info, appIndex, userId);
    }
#endif
    APP_LOGD("UninstallCloneApp %{public}s _ %{public}d succesfully", bundleName.c_str(), appIndex);
    return ERR_OK;
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
    createDirParam.isPreInstallApp = info.GetIsPreInstallApp();
    createDirParam.debug = info.GetBaseApplicationInfo().appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG;
    auto result = InstalldClient::GetInstance()->CreateBundleDataDir(createDirParam);
    if (result != ERR_OK) {
        APP_LOGE("fail to create sandbox data dir, error is %{public}d", result);
        return result;
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

void BundleCloneInstaller::ResetInstallProperties()
{
    uid_ = 0;
    accessTokenId_ = 0;
}
} // AppExecFwk
} // OHOS
