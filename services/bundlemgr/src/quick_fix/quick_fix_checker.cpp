/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "quick_fix_checker.h"

#include <set>

#include "bundle_install_checker.h"
#include "bundle_util.h"

namespace OHOS {
namespace AppExecFwk {
size_t QuickFixChecker::QUICK_FIX_MAP_SIZE = 1;

ErrCode QuickFixChecker::CheckMultipleHqfsSignInfo(
    const std::vector<std::string> &bundlePaths,
    std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes)
{
    APP_LOGD("Check multiple hqfs signInfo");
    BundleInstallChecker checker;
    return checker.CheckMultipleHapsSignInfo(bundlePaths, hapVerifyRes);
}

ErrCode QuickFixChecker::CheckAppQuickFixInfos(const std::unordered_map<std::string, AppQuickFix> &infos)
{
    APP_LOGD("Check quick fix files start.");
    if (infos.size() <= QUICK_FIX_MAP_SIZE) {
        return ERR_OK;
    }
    const AppQuickFix &appQuickFix = infos.begin()->second;
    std::set<std::string> moduleNames;
    for (const auto &info : infos) {
        if (appQuickFix.bundleName != info.second.bundleName) {
            APP_LOGE("error: appQuickFix bundleName not same");
            return ERR_BUNDLEMANAGER_QUICK_FIX_BUNDLE_NAME_NOT_SAME;
        }
        if (appQuickFix.versionCode != info.second.versionCode) {
            APP_LOGE("error: appQuickFix versionCode not same");
            return ERR_BUNDLEMANAGER_QUICK_FIX_VERSION_CODE_NOT_SAME;
        }
        if (appQuickFix.versionName != info.second.versionName) {
            APP_LOGE("error: appQuickFix versionName not same");
            return ERR_BUNDLEMANAGER_QUICK_FIX_VERSION_NAME_NOT_SAME;
        }
        if (appQuickFix.deployingAppqfInfo.versionCode != info.second.deployingAppqfInfo.versionCode) {
            APP_LOGE("error: appQuickFix patchVersionCode not same");
            return ERR_BUNDLEMANAGER_QUICK_FIX_PATCH_VERSION_CODE_NOT_SAME;
        }
        if (appQuickFix.deployingAppqfInfo.versionName != info.second.deployingAppqfInfo.versionName) {
            APP_LOGE("error: appQuickFix patchVersionName not same");
            return ERR_BUNDLEMANAGER_QUICK_FIX_PATCH_VERSION_NAME_NOT_SAME;
        }
        if (appQuickFix.deployingAppqfInfo.type != info.second.deployingAppqfInfo.type) {
            APP_LOGE("error: QuickFixType not same");
            return ERR_BUNDLEMANAGER_QUICK_FIX_PATCH_TYPE_NOT_SAME;
        }
        if (info.second.deployingAppqfInfo.hqfInfos.empty()) {
            APP_LOGE("error: hqfInfo is empty, moduleName does not exist");
            return ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED;
        }
        const std::string &moduleName = info.second.deployingAppqfInfo.hqfInfos[0].moduleName;
        if (moduleNames.find(moduleName) != moduleNames.end()) {
            APP_LOGE("error: moduleName %{public}s is already exist", moduleName.c_str());
            return ERR_BUNDLEMANAGER_QUICK_FIX_MODULE_NAME_SAME;
        }
        moduleNames.insert(moduleName);
    }
    APP_LOGD("Check quick fix files end.");
    return ERR_OK;
}

ErrCode QuickFixChecker::CheckPatchWithInstalledBundle(const AppQuickFix &appQuickFix,
    const BundleInfo &bundleInfo, const Security::Verify::ProvisionInfo &provisionInfo)
{
    ErrCode ret = CheckCommonWithInstalledBundle(appQuickFix, bundleInfo);
    if (ret != ERR_OK) {
        return ret;
    }
    bool isDebug = bundleInfo.applicationInfo.debug &&
        (bundleInfo.applicationInfo.appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG);
    APP_LOGD("application isDebug: %{public}d", isDebug);
    if (isDebug && (bundleInfo.applicationInfo.appQuickFix.deployedAppqfInfo.type == QuickFixType::HOT_RELOAD)) {
        // patch and hot reload can not both exist
        APP_LOGE("error: hot reload type already existed, hot reload and patch type can not both exist");
        return ERR_BUNDLEMANAGER_QUICK_FIX_HOT_RELOAD_ALREADY_EXISTED;
    }
    if (bundleInfo.versionName != appQuickFix.versionName) {
        APP_LOGE("error: versionName not same, appQuickFix: %{public}s, bundleInfo: %{public}s",
            appQuickFix.versionName.c_str(), bundleInfo.versionName.c_str());
        return ERR_BUNDLEMANAGER_QUICK_FIX_VERSION_NAME_NOT_SAME;
    }

    const auto &qfInfo = appQuickFix.deployingAppqfInfo;
    ret = CheckPatchNativeSoWithInstalledBundle(bundleInfo, qfInfo);
    if (ret != ERR_OK) {
        APP_LOGE("error: CheckPatchNativeSoWithInstalledBundle failed");
        return ret;
    }

    ret = CheckSignatureInfo(bundleInfo, provisionInfo);
    if (ret != ERR_OK) {
        APP_LOGE("error: CheckSignatureInfo failed, appId or apl not same");
        return ret;
    }
    return ERR_OK;
}

ErrCode QuickFixChecker::CheckPatchNativeSoWithInstalledBundle(
    const BundleInfo &bundleInfo, const AppqfInfo &qfInfo)
{
    bool hasAppLib =
        (!qfInfo.nativeLibraryPath.empty() && !bundleInfo.applicationInfo.nativeLibraryPath.empty());
    if (hasAppLib) {
        if (qfInfo.cpuAbi != bundleInfo.applicationInfo.cpuAbi) {
            APP_LOGE("qfInfo.cpuAbi: %{public}s, applicationInfo.cpuAbi: %{public}s",
                qfInfo.cpuAbi.c_str(), bundleInfo.applicationInfo.cpuAbi.c_str());
            return ERR_BUNDLEMANAGER_QUICK_FIX_SO_INCOMPATIBLE;
        }

        if (qfInfo.nativeLibraryPath != bundleInfo.applicationInfo.nativeLibraryPath) {
            APP_LOGE("qfInfo.nativeLibraryPath: %{public}s, applicationInfo.nativeLibraryPath: %{public}s",
                qfInfo.nativeLibraryPath.c_str(), bundleInfo.applicationInfo.nativeLibraryPath.c_str());
            return ERR_BUNDLEMANAGER_QUICK_FIX_SO_INCOMPATIBLE;
        }
    }

    for (const auto &hqfInfo : qfInfo.hqfInfos) {
        auto iter = std::find_if(bundleInfo.hapModuleInfos.begin(), bundleInfo.hapModuleInfos.end(),
            [moduleName = hqfInfo.moduleName](const auto &hapModuleInfo) {
                return hapModuleInfo.moduleName == moduleName;
            });
        if (iter == bundleInfo.hapModuleInfos.end()) {
            continue;
        }

        auto &hapModuleInfoNativeLibraryPath = iter->nativeLibraryPath;
        auto &hqfInfoNativeLibraryPath = iter->nativeLibraryPath;
        if ((!hapModuleInfoNativeLibraryPath.empty() && !hqfInfoNativeLibraryPath.empty()) &&
            (hapModuleInfoNativeLibraryPath != hqfInfoNativeLibraryPath)) {
            APP_LOGE("hqfInfoNativeLibraryPath: %{public}s, hapModuleInfoNativeLibraryPath: %{public}s",
                hqfInfoNativeLibraryPath.c_str(), hapModuleInfoNativeLibraryPath.c_str());
            return ERR_BUNDLEMANAGER_QUICK_FIX_SO_INCOMPATIBLE;
        }
    }

    return ERR_OK;
}

ErrCode QuickFixChecker::CheckHotReloadWithInstalledBundle(const AppQuickFix &appQuickFix, const BundleInfo &bundleInfo)
{
    ErrCode ret = CheckCommonWithInstalledBundle(appQuickFix, bundleInfo);
    if (ret != ERR_OK) {
        return ret;
    }
    bool isDebug = bundleInfo.applicationInfo.debug &&
        (bundleInfo.applicationInfo.appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG);
    APP_LOGD("application isDebug: %{public}d", isDebug);
    if (!isDebug) {
        APP_LOGE("error: hot reload type does not support release bundle");
        return ERR_BUNDLEMANAGER_QUICK_FIX_HOT_RELOAD_NOT_SUPPORT_RELEASE_BUNDLE;
    }
    if (bundleInfo.applicationInfo.appQuickFix.deployedAppqfInfo.type == QuickFixType::PATCH) {
        // patch and hot reload can not both exist
        APP_LOGE("error: patch type already existed, hot reload and patch can not both exist");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PATCH_ALREADY_EXISTED;
    }
    return ERR_OK;
}

ErrCode QuickFixChecker::CheckCommonWithInstalledBundle(const AppQuickFix &appQuickFix, const BundleInfo &bundleInfo)
{
    // check bundleName
    if (appQuickFix.bundleName != bundleInfo.name) {
        APP_LOGE("error: bundleName not same, appQuickBundleName: %{public}s, bundleInfo name: %{public}s",
            appQuickFix.bundleName.c_str(), bundleInfo.name.c_str());
        return ERR_BUNDLEMANAGER_QUICK_FIX_BUNDLE_NAME_NOT_EXIST;
    }
    // check versionCode
    if (bundleInfo.versionCode != appQuickFix.versionCode) {
        APP_LOGE("error: versionCode not same, appQuickFix: %{public}u, bundleInfo: %{public}u",
            appQuickFix.versionCode, bundleInfo.versionCode);
        return ERR_BUNDLEMANAGER_QUICK_FIX_VERSION_CODE_NOT_SAME;
    }
    const auto &deployedAppqfInfo = bundleInfo.applicationInfo.appQuickFix.deployedAppqfInfo;
    if (deployedAppqfInfo.hqfInfos.empty()) {
        APP_LOGD("no patch used in bundleName: %{public}s", bundleInfo.name.c_str());
        return ERR_OK;
    }
    const auto &qfInfo = appQuickFix.deployingAppqfInfo;
    if (qfInfo.versionCode <= deployedAppqfInfo.versionCode) {
        APP_LOGE("qhf version code %{public}u should be greater than the original %{public}u",
            qfInfo.versionCode, deployedAppqfInfo.versionCode);
        return ERR_BUNDLEMANAGER_QUICK_FIX_VERSION_CODE_ERROR;
    }
    return ERR_OK;
}

ErrCode QuickFixChecker::CheckModuleNameExist(const BundleInfo &bundleInfo,
    const std::unordered_map<std::string, AppQuickFix> &infos)
{
    for (const auto &info : infos) {
        if (info.second.deployingAppqfInfo.hqfInfos.empty()) {
            return ERR_BUNDLEMANAGER_QUICK_FIX_MODULE_NAME_NOT_EXIST;
        }
        auto iter = std::find(bundleInfo.moduleNames.begin(), bundleInfo.moduleNames.end(),
            info.second.deployingAppqfInfo.hqfInfos[0].moduleName);
        if (iter == bundleInfo.moduleNames.end()) {
            APP_LOGE("error: moduleName %{public}s does not exist",
                info.second.deployingAppqfInfo.hqfInfos[0].moduleName.c_str());
            return ERR_BUNDLEMANAGER_QUICK_FIX_MODULE_NAME_NOT_EXIST;
        }
    }
    return ERR_OK;
}

ErrCode QuickFixChecker::CheckSignatureInfo(const BundleInfo &bundleInfo,
    const Security::Verify::ProvisionInfo &provisionInfo)
{
    std::string quickFixAppId = bundleInfo.name + Constants::FILE_UNDERLINE + provisionInfo.appId;
    if ((bundleInfo.appId != quickFixAppId) ||
        (bundleInfo.applicationInfo.appPrivilegeLevel != provisionInfo.bundleInfo.apl)) {
            APP_LOGE("Quick fix signature info is different with installed bundle : %{public}s",
                bundleInfo.name.c_str());
            return ERR_BUNDLEMANAGER_QUICK_FIX_SIGNATURE_INFO_NOT_SAME;
    }
    if (bundleInfo.name != provisionInfo.bundleInfo.bundleName) {
        APP_LOGE("CheckSignatureInfo failed provisionBundleName:%{public}s, bundleName:%{public}s",
            provisionInfo.bundleInfo.bundleName.c_str(), bundleInfo.name.c_str());
        return ERR_BUNDLEMANAGER_QUICK_FIX_SIGNATURE_INFO_NOT_SAME;
    }
    return ERR_OK;
}

ErrCode QuickFixChecker::CheckMultiNativeSo(
    std::unordered_map<std::string, AppQuickFix> &infos)
{
    if (infos.size() <= QUICK_FIX_MAP_SIZE) {
        return ERR_OK;
    }
    const AppqfInfo &appqfInfo = (infos.begin()->second).deployingAppqfInfo;
    std::string nativeLibraryPath = appqfInfo.nativeLibraryPath;
    std::string cpuAbi = appqfInfo.cpuAbi;
    for (const auto &info : infos) {
        const AppqfInfo &qfInfo = info.second.deployingAppqfInfo;
        if (qfInfo.nativeLibraryPath.empty()) {
            continue;
        }
        if (nativeLibraryPath.empty()) {
            nativeLibraryPath = qfInfo.nativeLibraryPath;
            cpuAbi = qfInfo.cpuAbi;
            continue;
        }
        if (!qfInfo.nativeLibraryPath.empty()) {
            if ((nativeLibraryPath != qfInfo.nativeLibraryPath) || (cpuAbi != qfInfo.cpuAbi)) {
                APP_LOGE("check native so with installed bundle failed");
                return ERR_BUNDLEMANAGER_QUICK_FIX_SO_INCOMPATIBLE;
            }
        }
    }

    // Ensure the so is consistent in multiple haps
    if (!nativeLibraryPath.empty()) {
        for (auto &info : infos) {
            info.second.deployingAppqfInfo.nativeLibraryPath = nativeLibraryPath;
            info.second.deployingAppqfInfo.cpuAbi = cpuAbi;
        }
    }

    return ERR_OK;
}

std::string QuickFixChecker::GetAppDistributionType(const Security::Verify::AppDistType &type)
{
    std::unordered_map<Security::Verify::AppDistType, std::string> map = {
        { Security::Verify::AppDistType::NONE_TYPE, Constants::APP_DISTRIBUTION_TYPE_NONE },
        { Security::Verify::AppDistType::APP_GALLERY, Constants::APP_DISTRIBUTION_TYPE_APP_GALLERY },
        { Security::Verify::AppDistType::ENTERPRISE, Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE },
        { Security::Verify::AppDistType::OS_INTEGRATION, Constants::APP_DISTRIBUTION_TYPE_OS_INTEGRATION },
        { Security::Verify::AppDistType::CROWDTESTING, Constants::APP_DISTRIBUTION_TYPE_CROWDTESTING },
    };
    auto typeIter = map.find(type);
    if (typeIter == map.end()) {
        APP_LOGE("wrong AppDistType");
        return Constants::APP_DISTRIBUTION_TYPE_NONE;
    }

    return typeIter->second;
}

std::string QuickFixChecker::GetAppProvisionType(const Security::Verify::ProvisionType &type)
{
    if (type == Security::Verify::ProvisionType::DEBUG) {
        return Constants::APP_PROVISION_TYPE_DEBUG;
    }

    return Constants::APP_PROVISION_TYPE_RELEASE;
}
} // AppExecFwk
} // OHOS
