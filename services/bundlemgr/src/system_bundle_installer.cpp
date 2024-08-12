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

#include "system_bundle_installer.h"

#include "app_log_wrapper.h"
#include "app_service_fwk_installer.h"
#include "bms_key_event_mgr.h"
#include "bundle_mgr_service.h"

namespace OHOS {
namespace AppExecFwk {
SystemBundleInstaller::SystemBundleInstaller()
{
    APP_LOGD("system bundle installer instance is created");
}

SystemBundleInstaller::~SystemBundleInstaller()
{
    APP_LOGD("system bundle installer instance is destroyed");
}

ErrCode SystemBundleInstaller::InstallSystemBundle(
    const std::string &filePath,
    InstallParam &installParam,
    Constants::AppType appType)
{
    MarkPreBundleSyeEventBootTag(true);
    ErrCode result = InstallBundle(filePath, installParam, appType);
    if (result != ERR_OK) {
        APP_LOGE("install system bundle fail, error: %{public}d", result);
        if (result != ERR_APPEXECFWK_INSTALL_ZERO_USER_WITH_NO_SINGLETON) {
            BmsKeyEventMgr::ProcessMainBundleInstallFailed(filePath, result);
        }
    }
    return result;
}

bool SystemBundleInstaller::InstallSystemSharedBundle(
    InstallParam &installParam,
    bool isOTA,
    Constants::AppType appType)
{
    MarkPreBundleSyeEventBootTag(!isOTA);
    std::vector<std::string> bundlePaths{};
    ErrCode result = InstallBundle(bundlePaths, installParam, appType);
    if (result != ERR_OK) {
        APP_LOGE("install system bundle fail, error: %{public}d", result);
        return false;
    }
    return true;
}

ErrCode SystemBundleInstaller::OTAInstallSystemBundle(
    const std::vector<std::string> &filePaths,
    InstallParam &installParam,
    Constants::AppType appType)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    ErrCode result = ERR_OK;
    for (auto allUserId : dataMgr->GetAllUser()) {
        installParam.userId = allUserId;
        MarkPreBundleSyeEventBootTag(false);
        otaInstall_ = true;
        ErrCode errCode = InstallBundle(filePaths, installParam, appType);
        if ((errCode != ERR_OK) && (errCode != ERR_APPEXECFWK_INSTALL_ZERO_USER_WITH_NO_SINGLETON)) {
            APP_LOGE("install system bundle fail, error: %{public}d", errCode);
            result = errCode;
            if (!filePaths.empty()) {
                BmsKeyEventMgr::ProcessMainBundleInstallFailed(filePaths[0], result);
            }
        }
        ResetInstallProperties();
    }

    return result;
}

ErrCode SystemBundleInstaller::OTAInstallSystemBundleNeedCheckUser(
    const std::vector<std::string> &filePaths,
    InstallParam &installParam,
    const std::string &bundleName,
    Constants::AppType appType)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }

    auto currentBundleUserIds = dataMgr->GetUserIds(bundleName);
    std::set<int32_t> userIdSet;
    for (auto userId : currentBundleUserIds) {
        userIdSet.insert(userId);
    }
    if (userIdSet.empty() || (userIdSet.find(Constants::DEFAULT_USERID) != userIdSet.end())) {
        // for singleton hap or no user
        userIdSet = dataMgr->GetAllUser();
    } else {
        // for non-singleton hap
        userIdSet.insert(Constants::DEFAULT_USERID);
    }
    ErrCode result = ERR_OK;
    for (auto userId : userIdSet) {
        APP_LOGI_NOFUNC("start ota install -n %{public}s -u %{public}d", bundleName.c_str(), userId);
        installParam.userId = userId;
        MarkPreBundleSyeEventBootTag(false);
        otaInstall_ = true;
        ErrCode errCode = InstallBundle(filePaths, installParam, appType);
        if ((errCode != ERR_OK) && (errCode != ERR_APPEXECFWK_INSTALL_ZERO_USER_WITH_NO_SINGLETON)) {
            APP_LOGE("install system bundle %{public}s fail err %{public}d", bundleName.c_str(), errCode);
            result = errCode;
            BmsKeyEventMgr::ProcessMainBundleInstallFailed(bundleName, result);
        }
        ResetInstallProperties();
    }

    return result;
}

bool SystemBundleInstaller::UninstallSystemBundle(const std::string &bundleName)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return false;
    }
    BundleType type;
    if (dataMgr->GetBundleType(bundleName, type) && (type == BundleType::APP_SERVICE_FWK)) {
        AppServiceFwkInstaller installer;
        return installer.UnInstall(bundleName) == ERR_OK;
    }

    InstallParam installParam;
    for (auto userId : dataMgr->GetAllUser()) {
        installParam.userId = userId;
        installParam.needSavePreInstallInfo = true;
        installParam.isPreInstallApp = true;
        installParam.noSkipsKill = false;
        installParam.needSendEvent = false;
        MarkPreBundleSyeEventBootTag(false);
        ErrCode result = UninstallBundle(bundleName, installParam);
        if (result != ERR_OK) {
            APP_LOGW("uninstall system bundle fail, error: %{public}d", result);
        }

        ResetInstallProperties();
    }
    return true;
}

bool SystemBundleInstaller::UninstallSystemBundle(const std::string &bundleName, bool isKeepData)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return false;
    }

    InstallParam installParam;
    for (auto userId : dataMgr->GetAllUser()) {
        installParam.userId = userId;
        installParam.needSavePreInstallInfo = true;
        installParam.isPreInstallApp = true;
        installParam.noSkipsKill = false;
        installParam.needSendEvent = false;
        installParam.isKeepData = isKeepData;
        MarkPreBundleSyeEventBootTag(false);
        ErrCode result = UninstallBundle(bundleName, installParam);
        if (result != ERR_OK) {
            APP_LOGW("uninstall system bundle fail, error: %{public}d", result);
        }

        ResetInstallProperties();
    }
    return true;
}

bool SystemBundleInstaller::UninstallSystemBundle(const std::string &bundleName, const std::string &modulePackage)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return false;
    }

    InstallParam installParam;
    for (auto userId : dataMgr->GetAllUser()) {
        installParam.userId = userId;
        installParam.needSavePreInstallInfo = true;
        installParam.isPreInstallApp = true;
        installParam.noSkipsKill = false;
        installParam.needSendEvent = false;
        MarkPreBundleSyeEventBootTag(false);
        ErrCode result = UninstallBundle(bundleName, modulePackage, installParam);
        if (result != ERR_OK) {
            APP_LOGW("uninstall system bundle fail, error: %{public}d", result);
        }

        ResetInstallProperties();
    }
    CheckUninstallSystemHsp(bundleName);

    return true;
}

bool SystemBundleInstaller::UninstallSystemBundle(const std::string &bundleName, const InstallParam &installParam)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return false;
    }
    MarkPreBundleSyeEventBootTag(false);
    ErrCode result = UninstallBundle(bundleName, installParam);
    if ((result != ERR_OK) && (result != ERR_APPEXECFWK_USER_NOT_INSTALL_HAP)) {
        APP_LOGW("uninstall system bundle %{public}s userId %{public}d fail, error: %{public}d", bundleName.c_str(),
            installParam.userId, result);
        return false;
    }
    return true;
}

void SystemBundleInstaller::CheckUninstallSystemHsp(const std::string &bundleName)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return;
    }
    InnerBundleInfo info;
    if (!(dataMgr->FetchInnerBundleInfo(bundleName, info))) {
        APP_LOGD("bundleName %{public}s not existed local", bundleName.c_str());
        return;
    }
    if (info.GetApplicationBundleType() != BundleType::APP_SERVICE_FWK) {
        APP_LOGD("bundleName %{public}s is not a system hsp", bundleName.c_str());
        return;
    }
    bool isExistHsp = false;
    for (const auto &item : info.GetInnerModuleInfos()) {
        if (item.second.distro.moduleType == "shared") {
            isExistHsp = true;
            return;
        }
    }
    if (!isExistHsp) {
        InstallParam installParam;
        installParam.userId = Constants::DEFAULT_USERID;
        installParam.needSavePreInstallInfo = true;
        installParam.isPreInstallApp = true;
        installParam.noSkipsKill = false;
        installParam.needSendEvent = false;
        installParam.isKeepData = true;
        MarkPreBundleSyeEventBootTag(false);
        ErrCode result = UninstallBundle(bundleName, installParam);
        if (result != ERR_OK) {
            APP_LOGW("uninstall system bundle fail, error: %{public}d", result);
            return;
        }
        PreInstallBundleInfo preInstallBundleInfo;
        if ((dataMgr->GetPreInstallBundleInfo(bundleName, preInstallBundleInfo))) {
            dataMgr->DeletePreInstallBundleInfo(bundleName, preInstallBundleInfo);
        }
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
