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
    OverlayModuleInfo overlayModuleInfo {
        .bundleName = newInfo.GetBundleName(),
        .moduleName = (innerModuleInfos.begin()->second).moduleName,
        .targetModuleName = (innerModuleInfos.begin()->second).targetModuleName,
        .hapPath = newInfo.GetModuleHapPath(newInfo.GetCurrentModulePackage()),
        .priority = (innerModuleInfos.begin()->second).targetPriority,
        .state = DEFAULT_OVERLAY_ENABLE_STATUS
    };
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
    OverlayModuleInfo overlayModuleInfo {
        .bundleName = newInfo.GetBundleName(),
        .moduleName = (innerModuleInfos.begin()->second).moduleName,
        .targetModuleName = (innerModuleInfos.begin()->second).targetModuleName,
        .hapPath = newInfo.GetModuleHapPath(newInfo.GetCurrentModulePackage()),
        .priority = (innerModuleInfos.begin()->second).targetPriority,
        .state = DEFAULT_OVERLAY_ENABLE_STATUS
    };
    // build bundle overlay info
    std::string bundleDir;
    const std::string &moduleHapPath = newInfo.GetModuleHapPath(newInfo.GetCurrentModulePackage());
    GetBundleDir(moduleHapPath, bundleDir);
    OverlayBundleInfo overlayBundleInfo = {
        .bundleName = newInfo.GetBundleName(),
        .bundleDir = bundleDir,
        .state = DEFAULT_OVERLAY_ENABLE_STATUS,
        .priority = newInfo.GetTargetPriority(),
    };
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
            OverlayModuleInfo overlayModuleInfo {
                .bundleName = oldInfo.GetBundleName(),
                .moduleName = moduleInfo.second.moduleName,
                .targetModuleName = moduleInfo.second.targetModuleName,
                .hapPath = oldInfo.GetModuleHapPath(moduleInfo.second.moduleName),
                .priority = moduleInfo.second.targetPriority,
                .state = DEFAULT_OVERLAY_ENABLE_STATUS
            };
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
        if (!oldInfo.IsSystemApp()) {
            APP_LOGW("target bundle is not preInstall application");
            return;
        }

        // check fingerprint of current bundle with target bundle
        if (oldInfo.GetCertificateFingerprint() != info.second.GetCertificateFingerprint()) {
            APP_LOGW("target bundle has different fingerprint with current bundle");
            return;
        }

        const auto &innerModuleInfos = info.second.GetInnerModuleInfos();
        for (const auto &moduleInfo : innerModuleInfos) {
            if (moduleInfo.second.targetModuleName != moduleName) {
                continue;
            }
            OverlayModuleInfo overlayModuleInfo {
                .bundleName = info.second.GetBundleName(),
                .moduleName = moduleInfo.second.moduleName,
                .targetModuleName = moduleInfo.second.targetModuleName,
                .hapPath = info.second.GetModuleHapPath(moduleInfo.second.moduleName),
                .priority = moduleInfo.second.targetPriority,
                .state = DEFAULT_OVERLAY_ENABLE_STATUS
            };
            oldInfo.AddOverlayModuleInfo(overlayModuleInfo);
        }
        std::string bundleDir;
        const std::string &moduleHapPath =
            info.second.GetModuleHapPath((innerModuleInfos.begin()->second).moduleName);
        GetBundleDir(moduleHapPath, bundleDir);
        OverlayBundleInfo overlayBundleInfo = {
            .bundleName = info.second.GetBundleName(),
            .bundleDir = bundleDir,
            .state = DEFAULT_OVERLAY_ENABLE_STATUS,
            .priority = info.second.GetTargetPriority(),
        };
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
} // AppExecFwk
} // OHOS