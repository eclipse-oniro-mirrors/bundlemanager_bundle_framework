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

#include "bundle_overlay_install_checker.h"

#include "bundle_overlay_manager.h"
#include "bundle_permission_mgr.h"

namespace OHOS {
namespace AppExecFwk {
ErrCode BundleOverlayInstallChecker::CheckInternalBundle(const InnerBundleInfo &innerBundleInfo) const
{
    APP_LOGD("start to check internal overlay installation");
    // 1. check hap type
    ErrCode result = CheckHapType(innerBundleInfo);
    if (result != ERR_OK) {
        APP_LOGE("check hap type failed");
        return result;
    }
    // 2. check bundle type
    if ((result = CheckBundleType(innerBundleInfo)) != ERR_OK) {
        APP_LOGE("check bundle type failed");
        return result;
    }
    // 3. check module target priority range
    const std::map<std::string, InnerModuleInfo> &innerModuleInfos = innerBundleInfo.GetInnerModuleInfos();
    if (innerModuleInfos.empty()) {
        APP_LOGE("no module in the overlay hap");
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR;
    }
    std::string moduleName = innerBundleInfo.GetCurrentModulePackage();
    if ((result = CheckTargetPriority(innerModuleInfos.at(moduleName).targetPriority)) != ERR_OK) {
        APP_LOGE("target priority of module is invalid");
        return result;
    }
    // 4. check TargetModule with moduleName
    std::string targetModuleName = innerModuleInfos.at(moduleName).targetModuleName;
    if (targetModuleName == moduleName) {
        APP_LOGE("target moduleName cannot be same with moudleName");
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INVALID_MODULE_NAME;
    }
    // 5. check target module is non-overlay hap
    if ((result = CheckTargetModule(innerBundleInfo.GetBundleName(), targetModuleName)) != ERR_OK) {
        return result;
    }
    // 6. check version code, overlay hap has same version code with non-overlay hap
    if ((result = CheckVersionCode(innerBundleInfo)) != ERR_OK) {
        return result;
    }
    APP_LOGD("check internal overlay installation successfully");
    return ERR_OK;
}

ErrCode BundleOverlayInstallChecker::CheckExternalBundle(const InnerBundleInfo &innerBundleInfo, int32_t userId) const
{
    APP_LOGD("start to check external overlay installation");
    // 1. check bundle type
    ErrCode result = CheckBundleType(innerBundleInfo);
    if (result != ERR_OK) {
        APP_LOGE("check bundle type failed");
        return result;
    }

    // 2. check priority
    // 2.1 check bundle priority range
    // 2.2 check module priority range
    int32_t priority = innerBundleInfo.GetTargetPriority();
    if ((result = CheckTargetPriority(priority)) != ERR_OK) {
        APP_LOGE("check bundle priority failed due to %{public}d", result);
        return result;
    }

    const std::map<std::string, InnerModuleInfo> &innerModuleInfos = innerBundleInfo.GetInnerModuleInfos();
    if (innerModuleInfos.empty()) {
        APP_LOGE("no module in the overlay hap");
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INTERNAL_ERROR;
    }
    std::string moduleName = innerBundleInfo.GetCurrentModulePackage();
    priority = innerModuleInfos.at(moduleName).targetPriority;
    if ((result = CheckTargetPriority(priority)) != ERR_OK) {
        APP_LOGE("target priority of module is invalid");
        return result;
    }

    // 3. bundleName cannot be same with targetBundleName
    if (innerBundleInfo.GetBundleName() == innerBundleInfo.GetTargetBundleName()) {
        APP_LOGE("bundleName %{public}s is same with targetBundleName %{public}s",
            innerBundleInfo.GetBundleName().c_str(), innerBundleInfo.GetTargetBundleName().c_str());
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_BUNDLE_NAME_SAME_WITH_TARGET_BUNDLE_NAME;
    }

    // 4. overlay hap should be preInstall application
    if (!innerBundleInfo.IsSystemApp()) {
        APP_LOGE("no preInstall application for external overlay installation");
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_NO_SYSTEM_APPLICATION_FOR_EXTERNAL_OVERLAY;
    }

    // 5. check target bundle
    std::string targetModuleName = innerModuleInfos.at(moduleName).targetModuleName;
    std::string fingerprint = innerBundleInfo.GetCertificateFingerprint();
    if ((result =
        CheckTargetBundle(innerBundleInfo.GetTargetBundleName(), targetModuleName, fingerprint, userId)) != ERR_OK) {
        APP_LOGE("check target bundle failed");
        return result;
    }
    APP_LOGD("check external overlay installation successfully");
    return ERR_OK;
}

ErrCode BundleOverlayInstallChecker::CheckHapType(const InnerBundleInfo &info) const
{
    if (info.HasEntry()) {
        APP_LOGE("overlay hap cannot be entry hap in internal overlay installation");
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_ERROR_HAP_TYPE;
    }
    return ERR_OK;
}

ErrCode BundleOverlayInstallChecker::CheckBundleType(const InnerBundleInfo &info) const
{
    if (info.GetEntryInstallationFree()) {
        APP_LOGE("overlay hap cannot be service type");
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_ERROR_BUNDLE_TYPE;
    }
    return ERR_OK;
}

ErrCode BundleOverlayInstallChecker::CheckTargetPriority(int32_t priority) const
{
    APP_LOGD("start to check overlay priority");
    if ((priority < Constants::OVERLAY_MINIMUM_PRIORITY) || (priority > Constants::OVERLAY_MAXIMUM_PRIORITY)) {
        APP_LOGE("overlay hap has invalid module priority %{public}d", priority);
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INVALID_PRIORITY;
    }
    return ERR_OK;
}

ErrCode BundleOverlayInstallChecker::CheckVersionCode(const InnerBundleInfo &info) const
{
    APP_LOGD("start to check version code");
    std::string bundleName = info.GetBundleName();
    InnerBundleInfo oldInfo;
    ErrCode result = ERR_OK;
    auto isExisted = BundleOverlayManager::GetInstance()->GetInnerBundleInfo(bundleName, oldInfo);
    auto isNonOverlayHapExisted = BundleOverlayManager::GetInstance()->IsExistedNonOverlayHap(bundleName);
    if (isExisted) {
        if (isNonOverlayHapExisted && (info.GetVersionCode() != oldInfo.GetVersionCode())) {
            APP_LOGE("overlay hap needs has same version code with current bundle");
            result = ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INCONSISTENT_VERSION_CODE;
        }
    }
    return result;
}

ErrCode BundleOverlayInstallChecker::CheckTargetBundle(const std::string &targetBundleName,
    const std::string &targetModuleName, const std::string &fingerprint, int32_t userId) const
{
    APP_LOGD("start to check target bundle");
    if (targetBundleName.empty()) {
        APP_LOGE("invalid target bundle name");
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_INVALID_BUNDLE_NAME;
    }
    InnerBundleInfo oldInfo;
    if (!BundleOverlayManager::GetInstance()->GetInnerBundleInfo(targetBundleName, oldInfo)) {
        APP_LOGW("target bundle is not installed");
        return ERR_OK;
    }
    // 1. check target bundle is not external overlay bundle
    if (oldInfo.GetOverlayType() == OVERLAY_EXTERNAL_BUNDLE) {
        APP_LOGE("target bundle is cannot be external overlay bundle");
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_TARGET_BUNDLE_IS_OVERLAY_BUNDLE;
    }
    // 2. check target bundle is system application
    if (!oldInfo.IsSystemApp()) {
        APP_LOGE("target bundle is not preInstall application");
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_NO_SYSTEM_APPLICATION_FOR_EXTERNAL_OVERLAY;
    }

    // 3. check fingerprint of current bundle with target bundle
    if (oldInfo.GetCertificateFingerprint() != fingerprint) {
        APP_LOGE("target bundle has different fingerprint with current bundle");
        return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_DIFFERENT_SIGNATURE_CERTIFICATE;
    }

    // 4. check target module is non-overlay hap
    auto result = CheckTargetModule(targetBundleName, targetModuleName);
    if (result != ERR_OK) {
        return result;
    }
    return ERR_OK;
}

ErrCode BundleOverlayInstallChecker::CheckTargetModule(const std::string &bundleName,
    const std::string &targetModuleName) const
{
    InnerBundleInfo oldInfo;
    if (BundleOverlayManager::GetInstance()->GetInnerBundleInfo(bundleName, oldInfo)) {
        if (oldInfo.FindModule(targetModuleName) && oldInfo.isOverlayModule(targetModuleName)) {
            APP_LOGE("check target module failed");
            return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_TARGET_MODULE_IS_OVERLAY_MODULE;
        }
    }
    return ERR_OK;
}
} // AppExecFwk
} // OHOS