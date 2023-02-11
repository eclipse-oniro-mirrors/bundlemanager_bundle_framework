/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "bundle_overlay_data_manager.h"
#include "bundle_mgr_service.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
int32_t DEFAULT_OVERLAY_ENABLE_STATUS = 1;
} // namespace

ErrCode OverlayDataMgr::UpdateOverlayInfo(const InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo)
{
    // 1. update internal overlay info
    if (newInfo.GetOverlayType() == OVERLAY_INTERNAL_BUNDLE) {
        return UpdateInternalOverlayInfo(newInfo, oldInfo);
    }
    // 2. update external overlay info
    if (newInfo.GetOverlayType() == OVERLAY_EXTERNAL_BUNDLE) {
        return UpdateExternalOverlayInfo(newInfo);
    }
    // 3. update overlay connection
    if (newInfo.GetOverlayType() == NON_OVERLAY_TYPE) {
        return BuildOverlayConnection(newInfo, oldInfo);
    }
    return ERR_OK;
}

bool OverlayDataMgr::IsExistedNonOverlayHap(const std::string &bundleName)
{
    if (bundleName.empty()) {
        APP_LOGE("bundle name %{public}s is invalid", bundleName.c_str());
        return false;
    }

    if (GetBundleDataMgr() != ERR_OK) {
        return false;
    }
    InnerBundleInfo innerBundleInfo;
    if (!dataMgr_->GetOverlayInnerBundleInfo(bundleName, innerBundleInfo)) {
        APP_LOGE("no bundle with bundleName %{public}s installed", bundleName.c_str());
        return false;
    }
    dataMgr_->EnableOverlayBundle(bundleName);
    const auto &innerModuleInfos = innerBundleInfo.GetInnerModuleInfos();
    if (innerModuleInfos.empty()) {
        APP_LOGE("innerModuleInfo in innerBundleInfo is empty");
        return false;
    }
    for (const auto &innerModuleInfo : innerModuleInfos) {
        if (innerModuleInfo.second.targetModuleName.empty()) {
            return true;
        }
    }
    APP_LOGW("only overlay hap existed");
    return false;
}

ErrCode OverlayDataMgr::UpdateInternalOverlayInfo(const InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo) const
{
    APP_LOGD("start to update internal overlay info");
    auto &innerModuleInfos = newInfo.GetInnerModuleInfos();
    if (innerModuleInfos.empty()) {
        APP_LOGE("innerModuleInfos is empty");
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR;
    }
    // build module overlay info
    OverlayModuleInfo overlayModuleInfo;
    overlayModuleInfo.bundleName = newInfo.GetBundleName();
    overlayModuleInfo.moduleName = (innerModuleInfos.begin()->second).moduleName;
    overlayModuleInfo.targetModuleName = (innerModuleInfos.begin()->second).targetModuleName;
    overlayModuleInfo.hapPath = newInfo.GetModuleHapPath(newInfo.GetCurrentModulePackage());
    overlayModuleInfo.priority = (innerModuleInfos.begin()->second).targetPriority;
    overlayModuleInfo.state = DEFAULT_OVERLAY_ENABLE_STATUS;
    oldInfo.AddOverlayModuleInfo(overlayModuleInfo);
    return ERR_OK;
}

ErrCode OverlayDataMgr::UpdateExternalOverlayInfo(const InnerBundleInfo &newInfo)
{
    APP_LOGD("start to update external overlay info");
    std::string targetBundleName = newInfo.GetTargetBundleName();

    if (GetBundleDataMgr() != ERR_OK) {
        return false;
    }

    InnerBundleInfo targetInnerBundleInfo;
    if (!dataMgr_->GetOverlayInnerBundleInfo(targetBundleName, targetInnerBundleInfo)) {
        APP_LOGE("no target bundle %{public}s is installed", targetBundleName.c_str());
        return ERR_OK;
    }

    const auto &innerModuleInfos = newInfo.GetInnerModuleInfos();
    if (innerModuleInfos.empty()) {
        APP_LOGE("innerModuleInfos is empty");
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR;
    }
    OverlayModuleInfo overlayModuleInfo;
    overlayModuleInfo.bundleName = newInfo.GetBundleName();
    overlayModuleInfo.moduleName = (innerModuleInfos.begin()->second).moduleName;
    overlayModuleInfo.targetModuleName = (innerModuleInfos.begin()->second).targetModuleName;
    overlayModuleInfo.hapPath = newInfo.GetModuleHapPath(newInfo.GetCurrentModulePackage());
    overlayModuleInfo.priority = (innerModuleInfos.begin()->second).targetPriority;
    overlayModuleInfo.state = DEFAULT_OVERLAY_ENABLE_STATUS;
    // build bundle overlay info
    std::string bundleDir;
    const std::string &moduleHapPath = newInfo.GetModuleHapPath(newInfo.GetCurrentModulePackage());
    GetBundleDir(moduleHapPath, bundleDir);
    OverlayBundleInfo overlayBundleInfo;
    overlayBundleInfo.bundleName = newInfo.GetBundleName();
    overlayBundleInfo.bundleDir = bundleDir;
    overlayBundleInfo.state = DEFAULT_OVERLAY_ENABLE_STATUS;
    overlayBundleInfo.priority = newInfo.GetTargetPriority();
    targetInnerBundleInfo.AddOverlayBundleInfo(overlayBundleInfo);
    targetInnerBundleInfo.AddOverlayModuleInfo(overlayModuleInfo);

    // storage target bundle info
    dataMgr_->SaveOverlayInfo(targetBundleName, targetInnerBundleInfo);
    dataMgr_->EnableOverlayBundle(targetBundleName);
    return ERR_OK;
}

ErrCode OverlayDataMgr::BuildOverlayConnection(const InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo)
{
    APP_LOGD("start to update overlay connection");
#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
    // 1. build overlay connection for internal overlay
    const auto &moduleInfos = newInfo.GetInnerModuleInfos();
    std::string moduleName = (moduleInfos.begin()->second).moduleName;
    BuildInternalOverlayConnection(moduleName, oldInfo);

    // 2. build overlay connection for external overlay
    BuildExternalOverlayConnection(moduleName, oldInfo);
#endif
    return ERR_OK;
}

void OverlayDataMgr::BuildInternalOverlayConnection(const std::string &moduleName, InnerBundleInfo &oldInfo)
{
    APP_LOGD("start to update internal overlay connection");
    if (oldInfo.GetOverlayType() != OVERLAY_INTERNAL_BUNDLE) {
        APP_LOGW("the old bundle is not internal overlay");
        return;
    }
    const auto &oldInnerModuleInfos = oldInfo.GetInnerModuleInfos();
    for (const auto &moduleInfo : oldInnerModuleInfos) {
        if (moduleInfo.second.targetModuleName == moduleName) {
            OverlayModuleInfo overlayModuleInfo;
            overlayModuleInfo.bundleName = oldInfo.GetBundleName();
            overlayModuleInfo.moduleName = moduleInfo.second.moduleName;
            overlayModuleInfo.targetModuleName = moduleInfo.second.targetModuleName;
            overlayModuleInfo.hapPath = oldInfo.GetModuleHapPath(moduleInfo.second.moduleName);
            overlayModuleInfo.priority = moduleInfo.second.targetPriority;
            overlayModuleInfo.state = DEFAULT_OVERLAY_ENABLE_STATUS;
            oldInfo.AddOverlayModuleInfo(overlayModuleInfo);
        }
    }
}

void OverlayDataMgr::BuildExternalOverlayConnection(const std::string &moduleName, InnerBundleInfo &oldInfo)
{
    APP_LOGD("start to update external overlay connection");
    if (GetBundleDataMgr() != ERR_OK) {
        return;
    }

    auto bundleInfos = dataMgr_->GetAllOverlayInnerbundleInfos();
    for (const auto &info : bundleInfos) {
        if (info.second.GetTargetBundleName() != oldInfo.GetBundleName()) {
            continue;
        }
        // check target bundle is preInstall application
        if (!oldInfo.IsPreInstallApp()) {
            APP_LOGW("target bundle is not preInstall application");
            return;
        }

        // check fingerprint of current bundle with target bundle
        if (oldInfo.GetCertificateFingerprint() != info.second.GetCertificateFingerprint()) {
            APP_LOGW("target bundle has different fingerprint with current bundle");
            return;
        }
        // external overlay does not support FA model
        if (!oldInfo.GetIsNewVersion()) {
            APP_LOGW("target bundle is not stage model");
            return;
        }
        // external overlay does not support service
        if (oldInfo.GetEntryInstallationFree()) {
            APP_LOGW("target bundle is service");
            return;
        }

        const auto &innerModuleInfos = info.second.GetInnerModuleInfos();
        for (const auto &moduleInfo : innerModuleInfos) {
            if (moduleInfo.second.targetModuleName != moduleName) {
                continue;
            }
            OverlayModuleInfo overlayModuleInfo;
            overlayModuleInfo.bundleName = info.second.GetBundleName();
            overlayModuleInfo.moduleName = moduleInfo.second.moduleName;
            overlayModuleInfo.targetModuleName = moduleInfo.second.targetModuleName;
            overlayModuleInfo.hapPath = info.second.GetModuleHapPath(moduleInfo.second.moduleName);
            overlayModuleInfo.priority = moduleInfo.second.targetPriority;
            overlayModuleInfo.state = DEFAULT_OVERLAY_ENABLE_STATUS;
            oldInfo.AddOverlayModuleInfo(overlayModuleInfo);
        }
        std::string bundleDir;
        const std::string &moduleHapPath =
            info.second.GetModuleHapPath((innerModuleInfos.begin()->second).moduleName);
        GetBundleDir(moduleHapPath, bundleDir);
        OverlayBundleInfo overlayBundleInfo;
        overlayBundleInfo.bundleName = info.second.GetBundleName();
        overlayBundleInfo.bundleDir = bundleDir;
        overlayBundleInfo.state = DEFAULT_OVERLAY_ENABLE_STATUS;
        overlayBundleInfo.priority = info.second.GetTargetPriority();
        oldInfo.AddOverlayBundleInfo(overlayBundleInfo);
    }
}

ErrCode OverlayDataMgr::GetBundleDir(const std::string &moduleHapPath, std::string &bundleDir) const
{
    bundleDir = moduleHapPath;
    if (moduleHapPath.back() == Constants::FILE_SEPARATOR_CHAR) {
        bundleDir = moduleHapPath.substr(0, moduleHapPath.length() - 1);
    }
    size_t pos = bundleDir.find_last_of(Constants::PATH_SEPARATOR);
    if (pos == std::string::npos) {
        APP_LOGE("bundleDir is invalid");
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INVALID_BUNDLE_DIR;
    }
    bundleDir = bundleDir.substr(0, pos);
    APP_LOGD("bundleDir is %{public}s", bundleDir.c_str());
    return ERR_OK;
}

ErrCode OverlayDataMgr::RemoveOverlayModuleConnection(const InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo)
{
    APP_LOGD("start to remove overlay connection before update");
    const auto &innerModuleInfos = newInfo.GetInnerModuleInfos();
    if (innerModuleInfos.empty()) {
        APP_LOGE("innerModuleInfos is empty");
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR;
    }
    std::string moduleName = (innerModuleInfos.begin()->second).moduleName;
    const auto &oldInnerModuleInfos = oldInfo.GetInnerModuleInfos();
    if (oldInnerModuleInfos.find(moduleName) == oldInnerModuleInfos.end()) {
        APP_LOGE("module %{public}s is not existed", moduleName.c_str());
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR;
    }
    if (newInfo.GetOverlayType() == OVERLAY_INTERNAL_BUNDLE) {
        oldInfo.RemoveOverlayModuleInfo(oldInnerModuleInfos.at(moduleName).targetModuleName, newInfo.GetBundleName(),
            moduleName);
        return ERR_OK;
    }
    if (newInfo.GetOverlayType() == OVERLAY_EXTERNAL_BUNDLE) {
        if (GetBundleDataMgr() != ERR_OK) {
            return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR;
        }
        InnerBundleInfo targetInnerBundleInfo;
        const auto &targetBundleName = oldInfo.GetTargetBundleName();
        if (!dataMgr_->GetOverlayInnerBundleInfo(targetBundleName, targetInnerBundleInfo)) {
            APP_LOGE("no bundle with bundleName %{public}s installed", targetBundleName.c_str());
            return ERR_OK;
        }

        if (newInfo.GetTargetBundleName() != oldInfo.GetTargetBundleName()) {
            // remove all module connection in old targetBundle
            targetInnerBundleInfo.RemoveAllOverlayModuleInfo(newInfo.GetBundleName());
            targetInnerBundleInfo.RemoveOverLayBundleInfo(newInfo.GetBundleName());
        } else {
            targetInnerBundleInfo.RemoveOverlayModuleInfo(oldInnerModuleInfos.at(moduleName).targetModuleName,
                newInfo.GetBundleName(), moduleName);
        }
        // save target innerBundleInfo
        dataMgr_->SaveOverlayInfo(targetBundleName, targetInnerBundleInfo);
        dataMgr_->EnableOverlayBundle(targetBundleName);
    }
    return ERR_OK;
}

void OverlayDataMgr::RemoveOverlayBundleInfo(const std::string &targetBundleName, const std::string &bundleName)
{
    APP_LOGD("start to remove overlay bundleInfo under uninstalling external overlay");
    if (GetBundleDataMgr() != ERR_OK) {
        return;
    }

    InnerBundleInfo targetInnerBundleInfo;
    if (!dataMgr_->GetOverlayInnerBundleInfo(targetBundleName, targetInnerBundleInfo)) {
        APP_LOGD("target bundle %{public}s is not installed", targetBundleName.c_str());
        return;
    }

    targetInnerBundleInfo.RemoveOverLayBundleInfo(bundleName);
    targetInnerBundleInfo.RemoveAllOverlayModuleInfo(bundleName);

    // save target innerBundleInfo
    dataMgr_->SaveOverlayInfo(targetBundleName, targetInnerBundleInfo);
    dataMgr_->EnableOverlayBundle(targetBundleName);
    APP_LOGD("finish to remove overlay bundleInfo");
}

void OverlayDataMgr::RemoveOverlayModuleInfo(
    const std::string &bundleName, const std::string &modulePackage, InnerBundleInfo &oldInfo)
{
    APP_LOGD("start to remove overlay moduleInfo under uninstalling overlay module");
    if (!oldInfo.FindModule(modulePackage)) {
        return;
    }
    auto &innerModuleInfos = oldInfo.FetchInnerModuleInfos();
    std::string targetModuleName = innerModuleInfos.at(modulePackage).targetModuleName;
    // remove internal overlay info from target module
    if (oldInfo.GetOverlayType() == OVERLAY_INTERNAL_BUNDLE) {
        if (targetModuleName.empty() || !oldInfo.FindModule(targetModuleName)) {
            return;
        }
        oldInfo.RemoveOverlayModuleInfo(targetModuleName, bundleName, modulePackage);
        return;
    }

    // remove external overlay info from target bundle
    if (oldInfo.GetOverlayType() == OVERLAY_EXTERNAL_BUNDLE) {
        std::string targetBundleName = oldInfo.GetTargetBundleName();
        if (GetBundleDataMgr() != ERR_OK) {
            return;
        }
        InnerBundleInfo targetInnerBundleInfo;
        if (!dataMgr_->GetOverlayInnerBundleInfo(targetBundleName, targetInnerBundleInfo)) {
            APP_LOGD("target bundle %{public}s is not installed", targetBundleName.c_str());
            return;
        }

        targetInnerBundleInfo.RemoveOverlayModuleInfo(targetModuleName, bundleName, modulePackage);
        // save target innerBundleInfo
        dataMgr_->SaveOverlayInfo(targetBundleName, targetInnerBundleInfo);
        dataMgr_->EnableOverlayBundle(targetBundleName);
    }
    APP_LOGD("finish to remove overlay moduleInfo");
}

bool OverlayDataMgr::GetOverlayInnerBundleInfo(const std::string &bundleName, InnerBundleInfo &info)
{
    if (GetBundleDataMgr() != ERR_OK) {
        return false;
    }
    if (!dataMgr_->GetOverlayInnerBundleInfo(bundleName, info)) {
        APP_LOGE("target bundle %{public}s is not installed", bundleName.c_str());
        return false;
    }
    return true;
}

void OverlayDataMgr::EnableOverlayBundle(const std::string &bundleName)
{
    if (GetBundleDataMgr() != ERR_OK) {
        return;
    }
    dataMgr_->EnableOverlayBundle(bundleName);
}

ErrCode OverlayDataMgr::GetBundleDataMgr()
{
    if (dataMgr_ == nullptr) {
        dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        if (dataMgr_ == nullptr) {
            APP_LOGE("overlayDataMgr gets data mgr ptr failed");
            return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_SERVICE_EXCEPTION;
        }
    }
    return ERR_OK;
}

ErrCode OverlayDataMgr::GetAllOverlayModuleInfo(const std::string &bundleName,
    std::vector<OverlayModuleInfo> &overlayModuleInfos, int32_t userId)
{
    APP_LOGD("start to get all overlay moduleInfo");
    if (GetBundleDataMgr() != ERR_OK) {
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR;
    }
    InnerBundleInfo info;
    if (!dataMgr_->GetOverlayInnerBundleInfo(bundleName, info)) {
        APP_LOGE("overlay bundle is not existed %{public}s", bundleName.c_str());
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_MISSING_OVERLAY_BUNDLE;
    }
    dataMgr_->EnableOverlayBundle(bundleName);
    InnerBundleUserInfo userInfo;
    if (!info.GetInnerBundleUserInfo(userId, userInfo)) {
        APP_LOGE("the bundle %{public}s is not installed at user %{public}d", bundleName.c_str(), userId);
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_BUNDLE_NOT_INSTALLED_AT_SPECIFIED_USERID;
    }

    if (info.GetOverlayType() == NON_OVERLAY_TYPE) {
        APP_LOGE("bundle %{public}s is non-overlay bundle", bundleName.c_str());
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_NON_OVERLAY_BUNDLE;
    }

    const auto &InnerModuleInfos = info.GetInnerModuleInfos();
    for (const auto &moduleInfo : InnerModuleInfos) {
        if (!moduleInfo.second.targetModuleName.empty()) {
            OverlayModuleInfo overlayModuleInfo;
            overlayModuleInfo.bundleName = bundleName;
            overlayModuleInfo.moduleName = moduleInfo.second.moduleName;
            overlayModuleInfo.targetModuleName = moduleInfo.second.targetModuleName;
            overlayModuleInfo.hapPath = info.GetModuleHapPath(moduleInfo.second.moduleName);
            overlayModuleInfo.priority = moduleInfo.second.targetPriority;
            overlayModuleInfo.state = DEFAULT_OVERLAY_ENABLE_STATUS;
            overlayModuleInfos.emplace_back(overlayModuleInfo);
        }
    }
    return ERR_OK;
}

ErrCode OverlayDataMgr::GetOverlayModuleInfo(const std::string &bundleName, const std::string &moduleName,
    OverlayModuleInfo &overlayModuleInfo, int32_t userId)
{
    APP_LOGD("start to get specific overlay moduleInfo");
    if (GetBundleDataMgr() != ERR_OK) {
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR;
    }
    InnerBundleInfo info;
    if (!dataMgr_->GetOverlayInnerBundleInfo(bundleName, info)) {
        APP_LOGE("overlay bundle is not existed %{public}s", bundleName.c_str());
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_MISSING_OVERLAY_BUNDLE;
    }
    dataMgr_->EnableOverlayBundle(bundleName);
    InnerBundleUserInfo userInfo;
    if (!info.GetInnerBundleUserInfo(userId, userInfo)) {
        APP_LOGE("the bundle %{public}s is not installed at user %{public}d", bundleName.c_str(), userId);
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_BUNDLE_NOT_INSTALLED_AT_SPECIFIED_USERID;
    }

    if (info.GetOverlayType() == NON_OVERLAY_TYPE) {
        APP_LOGE("bundle %{public}s is non-overlay bundle", bundleName.c_str());
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_NON_OVERLAY_BUNDLE;
    }

    if (!info.FindModule(moduleName)) {
        APP_LOGE("overlay bundle %{public}s does not contain module %{public}s", bundleName.c_str(),
            moduleName.c_str());
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_MISSING_OVERLAY_MODULE;
    }

    if (!info.isOverlayModule(moduleName)) {
        APP_LOGE("module %{public}s is non-overlay module", moduleName.c_str());
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_NON_OVERLAY_MODULE;
    }

    auto innerModuleInfo = info.GetInnerModuleInfoByModuleName(moduleName);
    if (innerModuleInfo == std::nullopt) {
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR;
    }

    const auto &moduleInfo = innerModuleInfo.value();
    overlayModuleInfo.bundleName = bundleName;
    overlayModuleInfo.moduleName = moduleName;
    overlayModuleInfo.targetModuleName = moduleInfo.targetModuleName;
    overlayModuleInfo.hapPath = info.GetModuleHapPath(moduleInfo.moduleName);
    overlayModuleInfo.priority = moduleInfo.targetPriority;
    overlayModuleInfo.state = DEFAULT_OVERLAY_ENABLE_STATUS;

    return ERR_OK;
}

ErrCode OverlayDataMgr::GetOverlayBundleInfoForTarget(const std::string &targetBundleName,
    std::vector<OverlayBundleInfo> &overlayBundleInfo, int32_t userId)
{
    APP_LOGD("start to get target overlay bundle info");
    if (GetBundleDataMgr() != ERR_OK) {
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR;
    }
    InnerBundleInfo targetInnerBundleInfo;
    if (!dataMgr_->GetOverlayInnerBundleInfo(targetBundleName, targetInnerBundleInfo)) {
        APP_LOGE("target bundle is not existed %{public}s", targetBundleName.c_str());
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_TARGET_BUNDLE_NOT_EXISTED;
    }
    dataMgr_->EnableOverlayBundle(targetBundleName);
    InnerBundleUserInfo userInfo;
    if (!targetInnerBundleInfo.GetInnerBundleUserInfo(userId, userInfo)) {
        APP_LOGE("the bundle %{public}s is not installed at user %{public}d", targetBundleName.c_str(), userId);
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_BUNDLE_NOT_INSTALLED_AT_SPECIFIED_USERID;
    }

    overlayBundleInfo = targetInnerBundleInfo.GetOverlayBundleInfo();
    if (overlayBundleInfo.empty()) {
        APP_LOGE("no overlay bundle info in data mgr");
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_NO_OVERLAY_BUNDLE_INFO;
    }
    return ERR_OK;
}

ErrCode OverlayDataMgr::GetOverlayModuleInfoForTarget(const std::string &targetBundleName,
    const std::string &targetModuleName, std::vector<OverlayModuleInfo> &overlayModuleInfo, int32_t userId)
{
    APP_LOGD("start to get target overlay module infos");
    if (GetBundleDataMgr() != ERR_OK) {
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR;
    }
    InnerBundleInfo targetInnerBundleInfo;
    if (!dataMgr_->GetOverlayInnerBundleInfo(targetBundleName, targetInnerBundleInfo)) {
        APP_LOGE("target bundle is not existed %{public}s", targetBundleName.c_str());
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_TARGET_BUNDLE_NOT_EXISTED;
    }
    dataMgr_->EnableOverlayBundle(targetBundleName);
    InnerBundleUserInfo userInfo;
    if (!targetInnerBundleInfo.GetInnerBundleUserInfo(userId, userInfo)) {
        APP_LOGE("the bundle %{public}s is not installed at user %{public}d", targetBundleName.c_str(), userId);
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_BUNDLE_NOT_INSTALLED_AT_SPECIFIED_USERID;
    }

    if (!targetInnerBundleInfo.FindModule(targetModuleName)) {
        APP_LOGE("the target module %{public}s is not existed in bundle %{public}s", targetModuleName.c_str(),
            targetBundleName.c_str());
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_TARGET_MODULE_NOT_EXISTED;
    }
    auto targetModuleInfo = targetInnerBundleInfo.GetInnerModuleInfoByModuleName(targetModuleName);
    if (targetModuleInfo == std::nullopt) {
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR;
    }
    const auto &moduleInfo = targetModuleInfo.value();
    overlayModuleInfo = moduleInfo.overlayModuleInfo;
    if (overlayModuleInfo.empty()) {
        APP_LOGE("no overlay module info in target module %{public}s", targetModuleName.c_str());
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_NO_OVERLAY_MODULE_INFO;
    }
    return ERR_OK;
}
} // AppExecFwk
} // OHOS