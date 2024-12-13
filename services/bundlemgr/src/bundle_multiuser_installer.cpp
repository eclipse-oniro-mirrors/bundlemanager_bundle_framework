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

#include "bundle_multiuser_installer.h"

#include "ability_manager_helper.h"
#include "account_helper.h"
#include "bms_extension_data_mgr.h"
#include "bundle_constants.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_resource_helper.h"
#include "bundle_util.h"
#include "datetime_ex.h"
#include "hitrace_meter.h"
#include "installd_client.h"
#include "perf_profile.h"
#include "scope_guard.h"


namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::Security;

BundleMultiUserInstaller::BundleMultiUserInstaller()
{
    APP_LOGD("created");
}

BundleMultiUserInstaller::~BundleMultiUserInstaller()
{
    APP_LOGD("~");
}

ErrCode BundleMultiUserInstaller::InstallExistedApp(const std::string &bundleName, const int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGI("-n %{public}s -u %{public}d begin", bundleName.c_str(), userId);

    BmsExtensionDataMgr bmsExtensionDataMgr;
    if (bmsExtensionDataMgr.IsAppInBlocklist(bundleName, userId)) {
        APP_LOGE("app %{public}s is in blocklist", bundleName.c_str());
        return ERR_APPEXECFWK_INSTALL_APP_IN_BLOCKLIST;
    }

    if (GetDataMgr() != ERR_OK) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }

    PerfProfile::GetInstance().SetBundleInstallStartTime(GetTickCount());
    ErrCode result = ProcessBundleInstall(bundleName, userId);
    NotifyBundleEvents installRes = {
        .type = NotifyType::INSTALL,
        .resultCode = result,
        .accessTokenId = accessTokenId_,
        .uid = uid_,
        .appIndex = 0,
        .bundleName = bundleName
    };
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    commonEventMgr->NotifyBundleStatus(installRes, dataMgr_);

    ResetInstallProperties();
    PerfProfile::GetInstance().SetBundleInstallEndTime(GetTickCount());
    APP_LOGI("-n %{public}s -u %{public}d, ret:%{public}d finished",
        bundleName.c_str(), userId, result);
    return result;
}

ErrCode BundleMultiUserInstaller::ProcessBundleInstall(const std::string &bundleName, const int32_t userId)
{
    if (bundleName.empty()) {
        APP_LOGE("bundleName empty");
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }

    if (userId <= Constants::DEFAULT_USERID) {
        APP_LOGE("userId(%{public}d) invalid", userId);
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    if (GetDataMgr() != ERR_OK) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }

    // 1. check whether original application installed or not
    ScopeGuard bundleEnabledGuard([&] { dataMgr_->EnableBundle(bundleName); });
    InnerBundleInfo info;
    bool isExist = dataMgr_->GetInnerBundleInfoWithDisable(bundleName, info);
    if (!isExist) {
        APP_LOGE("the bundle is not installed");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    // 2. obtain userId
    if (!dataMgr_->HasUserId(userId)) {
        APP_LOGE("install app user %{public}d not exist", userId);
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    // 3. check whether original application installed at current userId or not
    InnerBundleUserInfo userInfo;
    if (info.GetInnerBundleUserInfo(userId, userInfo)) {
        APP_LOGE("the origin application had installed at current user");
        return ERR_OK;
    }
 
    std::string appDistributionType = info.GetAppDistributionType();
    if (appDistributionType == Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE
        || appDistributionType == Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_NORMAL
        || appDistributionType == Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM) {
        APP_LOGE("the origin application is enterprise, not allow to install here");
        return ERR_APPEXECFWK_INSTALL_EXISTED_ENTERPRISE_BUNDLE_NOT_ALLOWED;
    }
    if (appDistributionType == Constants::APP_DISTRIBUTION_TYPE_INTERNALTESTING) {
        APP_LOGE("the origin application is inrternaltesting, not allow to install here");
        return ERR_APPEXECFWK_INSTALL_FAILED_CONTROLLED;
    }

    // uid
    InnerBundleUserInfo newUserInfo;
    newUserInfo.bundleName = bundleName;
    newUserInfo.bundleUserInfo.userId = userId;
    if (!dataMgr_->GenerateUidAndGid(newUserInfo)) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    int32_t uid = newUserInfo.uid;

    // 4. generate the accesstoken id and inherit original permissions
    Security::AccessToken::AccessTokenIDEx newTokenIdEx;
    if (!RecoverHapToken(bundleName, userId, newTokenIdEx, info)) {
        if (BundlePermissionMgr::InitHapToken(info, userId, 0, newTokenIdEx) != ERR_OK) {
            APP_LOGE("bundleName:%{public}s InitHapToken failed", bundleName.c_str());
            return ERR_APPEXECFWK_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED;
        }
    }
    ScopeGuard applyAccessTokenGuard([&] {
        BundlePermissionMgr::DeleteAccessTokenId(newTokenIdEx.tokenIdExStruct.tokenID);
    });
    newUserInfo.accessTokenId = newTokenIdEx.tokenIdExStruct.tokenID;
    newUserInfo.accessTokenIdEx = newTokenIdEx.tokenIDEx;
    uid_ = uid;
    accessTokenId_ = newTokenIdEx.tokenIdExStruct.tokenID;
    int64_t now = BundleUtil::GetCurrentTime();
    newUserInfo.installTime = now;
    newUserInfo.updateTime = now;

    ScopeGuard createUserDataDirGuard([&] { RemoveDataDir(bundleName, userId); });
    ErrCode result = CreateDataDir(info, userId, uid);
    if (result != ERR_OK) {
        APP_LOGE("InstallExisted create dir failed");
        return result;
    }

    ScopeGuard addBundleUserGuard([&] { dataMgr_->RemoveInnerBundleUserInfo(bundleName, userId); });
    if (!dataMgr_->AddInnerBundleUserInfo(bundleName, newUserInfo)) {
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }

    CreateEl5Dir(info, userId, uid);

    // total to commit, avoid rollback
    applyAccessTokenGuard.Dismiss();
    createUserDataDirGuard.Dismiss();
    addBundleUserGuard.Dismiss();
    APP_LOGI("InstallExisted %{public}s succesfully", bundleName.c_str());
    return ERR_OK;
}

ErrCode BundleMultiUserInstaller::CreateDataDir(InnerBundleInfo &info,
    const int32_t userId, const int32_t &uid) const
{
    APP_LOGD("CreateDataDir %{public}s begin", info.GetBundleName().c_str());
    std::string innerDataDir = info.GetBundleName();
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
    APP_LOGI("CreateDataDir successfully");
    return result;
}

void BundleMultiUserInstaller::CreateEl5Dir(InnerBundleInfo &info, const int32_t userId, const int32_t &uid)
{
    std::vector<RequestPermission> reqPermissions = info.GetAllRequestPermissions();
    auto it = std::find_if(reqPermissions.begin(), reqPermissions.end(), [](const RequestPermission& permission) {
        return permission.name == ServiceConstants::PERMISSION_PROTECT_SCREEN_LOCK_DATA;
    });
    if (it == reqPermissions.end()) {
        APP_LOGI("no el5 permission %{public}s", info.GetBundleName().c_str());
        return;
    }
    if (GetDataMgr() != ERR_OK) {
        APP_LOGE("get dataMgr failed");
        return;
    }
    CreateDirParam el5Param;
    el5Param.bundleName = info.GetBundleName();
    el5Param.userId = userId;
    el5Param.uid = uid;
    el5Param.apl = info.GetAppPrivilegeLevel();
    el5Param.isPreInstallApp = info.IsPreInstallApp();
    el5Param.debug = info.GetBaseApplicationInfo().appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG;
    dataMgr_->CreateEl5Dir(std::vector<CreateDirParam> {el5Param}, true);
    return;
}

ErrCode BundleMultiUserInstaller::RemoveDataDir(const std::string bundleName, int32_t userId)
{
    std::string key = bundleName;
    if (InstalldClient::GetInstance()->RemoveBundleDataDir(key, userId) != ERR_OK) {
        APP_LOGW("App cannot remove the data dir");
        return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMultiUserInstaller::GetDataMgr()
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

void BundleMultiUserInstaller::ResetInstallProperties()
{
    uid_ = 0;
    accessTokenId_ = 0;
}

bool BundleMultiUserInstaller::RecoverHapToken(const std::string &bundleName, const int32_t userId,
    Security::AccessToken::AccessTokenIDEx& accessTokenIdEx, const InnerBundleInfo &innerBundleInfo)
{
    UninstallBundleInfo uninstallBundleInfo;
    if (!dataMgr_->GetUninstallBundleInfo(bundleName, uninstallBundleInfo)) {
        return false;
    }
    APP_LOGI("bundleName:%{public}s getUninstallBundleInfo success", bundleName.c_str());
    if (uninstallBundleInfo.userInfos.empty()) {
        APP_LOGW("bundleName:%{public}s empty userInfos", bundleName.c_str());
        return false;
    }
    if (uninstallBundleInfo.userInfos.find(std::to_string(userId)) != uninstallBundleInfo.userInfos.end()) {
        accessTokenIdEx.tokenIdExStruct.tokenID =
            uninstallBundleInfo.userInfos.at(std::to_string(userId)).accessTokenId;
        accessTokenIdEx.tokenIDEx = uninstallBundleInfo.userInfos.at(std::to_string(userId)).accessTokenIdEx;
        if (BundlePermissionMgr::UpdateHapToken(accessTokenIdEx, innerBundleInfo) == ERR_OK) {
            return true;
        } else {
            APP_LOGW("bundleName:%{public}s UpdateHapToken failed", bundleName.c_str());
        }
    }
    return false;
}
} // AppExecFwk
} // OHOS
