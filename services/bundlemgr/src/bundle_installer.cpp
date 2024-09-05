/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "bundle_installer.h"

#include <cinttypes>

#include "app_log_tag_wrapper.h"
#include "bundle_mgr_service.h"

namespace OHOS {
namespace AppExecFwk {
BundleInstaller::BundleInstaller(const int64_t installerId, const sptr<IStatusReceiver> &statusReceiver)
    : installerId_(installerId), statusReceiver_(statusReceiver)
{
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "create bundle installer instance id:%{public}" PRId64 "", installerId_);
}

BundleInstaller::~BundleInstaller()
{
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "destroy installer id:%{public}" PRId64 "", installerId_);
}

void BundleInstaller::Install(const std::string &bundleFilePath, const InstallParam &installParam)
{
    ErrCode resultCode = ERR_OK;
    if (installParam.userId == Constants::ALL_USERID) {
        auto userInstallParam = installParam;
        userInstallParam.allUser = true;
        for (auto userId : GetExistsCommonUserIds()) {
            userInstallParam.userId = userId;
            userInstallParam.installFlag = InstallFlag::REPLACE_EXISTING;
            resultCode = InstallBundle(
                bundleFilePath, userInstallParam, Constants::AppType::THIRD_PARTY_APP);
            ResetInstallProperties();
        }

        NotifyAllBundleStatus();
    } else {
        resultCode = InstallBundle(
            bundleFilePath, installParam, Constants::AppType::THIRD_PARTY_APP);
        InstallDriverForAllUsers(bundleFilePath, installParam);
    }
    std::string resultMsg = GetCheckResultMsg();
    SetCheckResultMsg("");
    if (statusReceiver_ != nullptr) {
        statusReceiver_->OnFinished(resultCode, resultMsg);
    }
}

void BundleInstaller::Recover(const std::string &bundleName, const InstallParam &installParam)
{
    ErrCode resultCode = ERR_OK;
    if (installParam.userId == Constants::ALL_USERID) {
        auto userInstallParam = installParam;
        for (auto userId : GetExistsCommonUserIds()) {
            userInstallParam.userId = userId;
            userInstallParam.installFlag = InstallFlag::REPLACE_EXISTING;
            resultCode = BaseBundleInstaller::Recover(bundleName, userInstallParam);
            ResetInstallProperties();
        }
    } else {
        resultCode = BaseBundleInstaller::Recover(bundleName, installParam);
        RecoverDriverForAllUsers(bundleName, installParam);
    }

    if (statusReceiver_ != nullptr) {
        statusReceiver_->OnFinished(resultCode, "");
    }
}

void BundleInstaller::Install(const std::vector<std::string> &bundleFilePaths, const InstallParam &installParam)
{
    ErrCode resultCode = ERR_OK;
    if (installParam.userId == Constants::ALL_USERID) {
        auto userInstallParam = installParam;
        userInstallParam.allUser = true;
        for (auto userId : GetExistsCommonUserIds()) {
            userInstallParam.userId = userId;
            userInstallParam.installFlag = InstallFlag::REPLACE_EXISTING;
            resultCode = InstallBundle(
                bundleFilePaths, userInstallParam, Constants::AppType::THIRD_PARTY_APP);
            ResetInstallProperties();
        }

        NotifyAllBundleStatus();
    } else {
        resultCode = InstallBundle(bundleFilePaths, installParam, Constants::AppType::THIRD_PARTY_APP);
        InstallDriverForAllUsers(bundleFilePaths, installParam);
    }
    std::string resultMsg = GetCheckResultMsg();
    SetCheckResultMsg("");
    if (statusReceiver_ != nullptr) {
        statusReceiver_->OnFinished(resultCode, resultMsg);
    }
}

void BundleInstaller::InstallByBundleName(const std::string &bundleName, const InstallParam &installParam)
{
    ErrCode resultCode = InstallBundleByBundleName(bundleName, installParam);
    if (statusReceiver_ != nullptr) {
        statusReceiver_->OnFinished(resultCode, "");
    }
}

void BundleInstaller::Uninstall(const std::string &bundleName, const InstallParam &installParam)
{
    ErrCode resultCode = ERR_OK;
    if (installParam.userId == Constants::ALL_USERID ||
        (!installParam.isRemoveUser && HasDriverExtensionAbility(bundleName))) {
        std::vector<ErrCode> errCode;
        auto userInstallParam = installParam;
        for (auto userId : GetExistsCommonUserIds()) {
            userInstallParam.userId = userId;
            resultCode = UninstallBundle(bundleName, userInstallParam);
            errCode.push_back(resultCode);
            ResetInstallProperties();
        }
        if (std::find(errCode.begin(), errCode.end(), ERR_OK) != errCode.end()) {
            for (const auto &err : errCode) {
                if (!(err == ERR_APPEXECFWK_UNINSTALL_MISSING_INSTALLED_BUNDLE ||
                    err == ERR_APPEXECFWK_USER_NOT_INSTALL_HAP || err == ERR_OK)) {
                    resultCode = err;
                    break;
                }
                resultCode = ERR_OK;
            }
        } else {
            resultCode = (errCode.size() > 0) ? errCode[0] : ERR_OK;
        }
    } else {
        resultCode = UninstallBundle(bundleName, installParam);
    }

    if (statusReceiver_ != nullptr) {
        statusReceiver_->OnFinished(resultCode, "");
    }
}

void BundleInstaller::Uninstall(const UninstallParam &uninstallParam)
{
    ErrCode resultCode = ERR_OK;
    resultCode = UninstallBundleByUninstallParam(uninstallParam);
    if (statusReceiver_ != nullptr) {
        statusReceiver_->OnFinished(resultCode, "");
    }
}

void BundleInstaller::Uninstall(
    const std::string &bundleName, const std::string &modulePackage, const InstallParam &installParam)
{
    ErrCode resultCode = ERR_OK;
    if (installParam.userId == Constants::ALL_USERID || HasDriverExtensionAbility(bundleName)) {
        std::vector<ErrCode> errCode;
        auto userInstallParam = installParam;
        for (auto userId : GetExistsCommonUserIds()) {
            userInstallParam.userId = userId;
            resultCode = UninstallBundle(bundleName, modulePackage, userInstallParam);
            errCode.push_back(resultCode);
            ResetInstallProperties();
        }
        if (std::find(errCode.begin(), errCode.end(), ERR_OK) != errCode.end()) {
            for (const auto &err : errCode) {
                if (!(err == ERR_APPEXECFWK_UNINSTALL_MISSING_INSTALLED_BUNDLE ||
                    err == ERR_APPEXECFWK_UNINSTALL_MISSING_INSTALLED_MODULE ||
                    err == ERR_APPEXECFWK_USER_NOT_INSTALL_HAP || err == ERR_OK)) {
                    resultCode = err;
                    break;
                }
                resultCode = ERR_OK;
            }
        } else {
            resultCode = (errCode.size() > 0) ? errCode[0] : ERR_OK;
        }
    } else {
        resultCode = UninstallBundle(bundleName, modulePackage, installParam);
    }

    if (statusReceiver_ != nullptr) {
        statusReceiver_->OnFinished(resultCode, "");
    }
}

void BundleInstaller::UpdateInstallerState(const InstallerState state)
{
    LOG_I(BMS_TAG_INSTALLER, "state: %{public}d", static_cast<int32_t>(state));
    SetInstallerState(state);
    if (statusReceiver_) {
        statusReceiver_->OnStatusNotify(static_cast<int>(state));
    }
}

std::set<int32_t> BundleInstaller::GetExistsCommonUserIds()
{
    std::set<int32_t> userIds;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "Get dataMgr shared_ptr nullptr");
        return userIds;
    }

    for (auto userId : dataMgr->GetAllUser()) {
        if (userId >= Constants::START_USERID) {
            userIds.insert(userId);
        }
    }
    return userIds;
}

void BundleInstaller::InstallDriverForAllUsers(const std::string &bundleFilePath, const InstallParam &installParam)
{
    std::vector<std::string> bundleFilePaths { bundleFilePath };
    InstallDriverForAllUsers(bundleFilePaths, installParam);
}

void BundleInstaller::InstallDriverForAllUsers(const std::vector<std::string> &bundleFilePaths,
    const InstallParam &installParam)
{
    std::string bundleName = GetCurrentBundleName();
    if (!HasDriverExtensionAbility(bundleName)) {
        APP_LOGD("bundle %{public}s has no driver extension ability", bundleName.c_str());
        return;
    }
    APP_LOGI("bundle %{public}s has driver extension ability, need to install for all users", bundleName.c_str());
    ResetInstallProperties();
    auto userInstallParam = installParam;
    userInstallParam.allUser = true;
    for (auto userId : GetExistsCommonUserIds()) {
        if (userId == installParam.userId) {
            continue;
        }
        userInstallParam.userId = userId;
        userInstallParam.installFlag = InstallFlag::REPLACE_EXISTING;
        ErrCode resultCode = InstallBundle(
            bundleFilePaths, userInstallParam, Constants::AppType::THIRD_PARTY_APP);
        ResetInstallProperties();
        if (resultCode != ERR_OK) {
            APP_LOGE("install driver for user %{public}d failed, resultCode: %{public}d", userId, resultCode);
        }
    }
    NotifyAllBundleStatus();
}

void BundleInstaller::RecoverDriverForAllUsers(const std::string &bundleName, const InstallParam &installParam)
{
    if (!HasDriverExtensionAbility(bundleName)) {
        APP_LOGD("bundle %{public}s has no driver extension ability", bundleName.c_str());
        return;
    }
    APP_LOGI("bundle %{public}s has driver extension ability, need to recover for all users", bundleName.c_str());
    ResetInstallProperties();
    auto userInstallParam = installParam;
    for (auto userId : GetExistsCommonUserIds()) {
        if (userId == installParam.userId) {
            continue;
        }
        userInstallParam.userId = userId;
        userInstallParam.installFlag = InstallFlag::REPLACE_EXISTING;
        ErrCode resultCode = BaseBundleInstaller::Recover(bundleName, userInstallParam);
        ResetInstallProperties();
        if (resultCode != ERR_OK) {
            APP_LOGE("recover driver for user %{public}d failed, resultCode: %{public}d", userId, resultCode);
        }
    }
}

bool BundleInstaller::HasDriverExtensionAbility(const std::string &bundleName)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return false;
    }

    InnerBundleInfo info;
    bool isAppExist = dataMgr->FetchInnerBundleInfo(bundleName, info);
    if (isAppExist) {
        const auto extensions = info.GetInnerExtensionInfos();
        for (const auto &item : extensions) {
            if (item.second.type == ExtensionAbilityType::DRIVER) {
                APP_LOGI("find driver extension ability, bundleName: %{public}s, moduleName: %{public}s",
                    item.second.bundleName.c_str(), item.second.moduleName.c_str());
                return true;
            }
        }
    }
    return false;
}

void BundleInstaller::UninstallAndRecover(const std::string &bundleName, const InstallParam &installParam)
{
    ErrCode resultCode = ERR_OK;
    std::vector<ErrCode> errCode;
    auto userInstallParam = installParam;
    std::vector<int32_t> userIds;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr != nullptr) {
        userIds = dataMgr->GetUserIds(bundleName);
    }
    for (auto userId : userIds) {
        userInstallParam.userId = userId;
        userInstallParam.SetIsUninstallAndRecover(true);
        resultCode = UninstallBundle(bundleName, userInstallParam);
        errCode.push_back(resultCode);
        ResetInstallProperties();
    }
    for (auto userId : userIds) {
        userInstallParam.userId = userId;
        userInstallParam.installFlag = InstallFlag::REPLACE_EXISTING;
        resultCode = BaseBundleInstaller::Recover(bundleName, userInstallParam);
        errCode.push_back(resultCode);
        ResetInstallProperties();
    }

    if (std::find(errCode.begin(), errCode.end(), ERR_OK) != errCode.end()) {
        for (const auto &err : errCode) {
            if (err != ERR_OK) {
                resultCode = err;
                break;
            }
            resultCode = ERR_OK;
        }
    } else {
        resultCode = (errCode.size() > 0) ? errCode[0] : ERR_APPEXECFWK_UNINSTALL_MISSING_INSTALLED_BUNDLE;
    }
    if (statusReceiver_ != nullptr) {
        statusReceiver_->OnFinished(resultCode, "");
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS