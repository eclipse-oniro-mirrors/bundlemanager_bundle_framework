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

#include "app_log_tag_wrapper.h"
#include "bundle_install_checker.h"
#include "bundle_util.h"

namespace OHOS {
namespace AppExecFwk {
size_t QuickFixChecker::QUICK_FIX_MAP_SIZE = 1;

ErrCode QuickFixChecker::CheckMultipleHqfsSignInfo(
    const std::vector<std::string> &bundlePaths,
    std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes)
{
    LOG_D(BMSTag::QUICK_FIX, "Check multiple hqfs signInfo");
    BundleInstallChecker checker;
    return checker.CheckMultipleHapsSignInfo(bundlePaths, hapVerifyRes);
}

ErrCode QuickFixChecker::CheckAppQuickFixInfos(const std::unordered_map<std::string, AppQuickFix> &infos)
{
    LOG_D(BMSTag::QUICK_FIX, "Check quick fix files start.");
    if (infos.size() <= QUICK_FIX_MAP_SIZE) {
        return ERR_OK;
    }
    const AppQuickFix &appQuickFix = infos.begin()->second;
    std::set<std::string> moduleNames;
    for (const auto &info : infos) {
        if (appQuickFix.bundleName != info.second.bundleName) {
            LOG_E(BMSTag::QUICK_FIX, "error: appQuickFix bundleName not same");
            return ERR_BUNDLEMANAGER_QUICK_FIX_BUNDLE_NAME_NOT_SAME;
        }
        if (appQuickFix.versionCode != info.second.versionCode) {
            LOG_E(BMSTag::QUICK_FIX, "error: appQuickFix versionCode not same");
            return ERR_BUNDLEMANAGER_QUICK_FIX_VERSION_CODE_NOT_SAME;
        }
        if (appQuickFix.deployingAppqfInfo.versionCode != info.second.deployingAppqfInfo.versionCode) {
            LOG_E(BMSTag::QUICK_FIX, "error: appQuickFix patchVersionCode not same");
            return ERR_BUNDLEMANAGER_QUICK_FIX_PATCH_VERSION_CODE_NOT_SAME;
        }
        if (appQuickFix.deployingAppqfInfo.type != info.second.deployingAppqfInfo.type) {
            LOG_E(BMSTag::QUICK_FIX, "error: QuickFixType not same");
            return ERR_BUNDLEMANAGER_QUICK_FIX_PATCH_TYPE_NOT_SAME;
        }
        if (info.second.deployingAppqfInfo.hqfInfos.empty()) {
            LOG_E(BMSTag::QUICK_FIX, "error: hqfInfo is empty, moduleName does not exist");
            return ERR_BUNDLEMANAGER_QUICK_FIX_PROFILE_PARSE_FAILED;
        }
        const std::string &moduleName = info.second.deployingAppqfInfo.hqfInfos[0].moduleName;
        if (moduleNames.find(moduleName) != moduleNames.end()) {
            LOG_E(BMSTag::QUICK_FIX, "error: moduleName %{public}s is already exist", moduleName.c_str());
            return ERR_BUNDLEMANAGER_QUICK_FIX_MODULE_NAME_SAME;
        }
        moduleNames.insert(moduleName);
    }
    LOG_D(BMSTag::QUICK_FIX, "Check quick fix files end.");
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
    LOG_D(BMSTag::QUICK_FIX, "application isDebug: %{public}d", isDebug);
    if (isDebug && (bundleInfo.applicationInfo.appQuickFix.deployedAppqfInfo.type == QuickFixType::HOT_RELOAD)) {
        // patch and hot reload can not both exist
        LOG_E(BMSTag::QUICK_FIX, "hot reload type already existed, hot reload and patch type can not both exist");
        return ERR_BUNDLEMANAGER_QUICK_FIX_HOT_RELOAD_ALREADY_EXISTED;
    }

    const auto &qfInfo = appQuickFix.deployingAppqfInfo;
    ret = CheckPatchNativeSoWithInstalledBundle(bundleInfo, qfInfo);
    if (ret != ERR_OK) {
        LOG_E(BMSTag::QUICK_FIX, "error: CheckPatchNativeSoWithInstalledBundle failed");
        return ret;
    }

    ret = CheckSignatureInfo(bundleInfo, provisionInfo);
    if (ret != ERR_OK) {
        LOG_E(BMSTag::QUICK_FIX, "error: CheckSignatureInfo failed, appId or apl not same");
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
            LOG_E(BMSTag::QUICK_FIX, "qfInfo.cpuAbi: %{public}s, applicationInfo.cpuAbi: %{public}s",
                qfInfo.cpuAbi.c_str(), bundleInfo.applicationInfo.cpuAbi.c_str());
            return ERR_BUNDLEMANAGER_QUICK_FIX_SO_INCOMPATIBLE;
        }

        if (qfInfo.nativeLibraryPath != bundleInfo.applicationInfo.nativeLibraryPath) {
            LOG_E(BMSTag::QUICK_FIX, "qfInfo path: %{public}s, applicationInfo path: %{public}s",
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
        auto &hqfInfoNativeLibraryPath = hqfInfo.nativeLibraryPath;
        if (!hapModuleInfoNativeLibraryPath.empty() && !hqfInfoNativeLibraryPath.empty()) {
            if ((hapModuleInfoNativeLibraryPath.find(hqfInfoNativeLibraryPath) == std::string::npos) &&
                (hapModuleInfoNativeLibraryPath.find(hqfInfo.cpuAbi) == std::string::npos)) {
                LOG_E(BMSTag::QUICK_FIX, "hqfNativeLibraryPath: %{public}s, moduleNativeLibraryPath: %{public}s",
                    hqfInfoNativeLibraryPath.c_str(), hapModuleInfoNativeLibraryPath.c_str());
                return ERR_BUNDLEMANAGER_QUICK_FIX_SO_INCOMPATIBLE;
            }
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
    LOG_D(BMSTag::QUICK_FIX, "application isDebug: %{public}d", isDebug);
    if (!isDebug) {
        LOG_E(BMSTag::QUICK_FIX, "error: hot reload type does not support release bundle");
        return ERR_BUNDLEMANAGER_QUICK_FIX_HOT_RELOAD_NOT_SUPPORT_RELEASE_BUNDLE;
    }
    if (bundleInfo.applicationInfo.appQuickFix.deployedAppqfInfo.type == QuickFixType::PATCH) {
        // patch and hot reload can not both exist
        LOG_E(BMSTag::QUICK_FIX, "error: patch type already existed, hot reload and patch can not both exist");
        return ERR_BUNDLEMANAGER_QUICK_FIX_PATCH_ALREADY_EXISTED;
    }
    return ERR_OK;
}

ErrCode QuickFixChecker::CheckCommonWithInstalledBundle(const AppQuickFix &appQuickFix, const BundleInfo &bundleInfo)
{
    // check bundleName
    if (appQuickFix.bundleName != bundleInfo.name) {
        LOG_E(BMSTag::QUICK_FIX, "appQuickBundleName:%{public}s, bundleInfo name:%{public}s not same",
            appQuickFix.bundleName.c_str(), bundleInfo.name.c_str());
        return ERR_BUNDLEMANAGER_QUICK_FIX_BUNDLE_NAME_NOT_EXIST;
    }
    // check versionCode
    if (bundleInfo.versionCode != appQuickFix.versionCode) {
        LOG_E(BMSTag::QUICK_FIX, "error: versionCode not same, appQuickFix: %{public}u, bundleInfo: %{public}u",
            appQuickFix.versionCode, bundleInfo.versionCode);
        return ERR_BUNDLEMANAGER_QUICK_FIX_VERSION_CODE_NOT_SAME;
    }
    const auto &deployedAppqfInfo = bundleInfo.applicationInfo.appQuickFix.deployedAppqfInfo;
    if (deployedAppqfInfo.hqfInfos.empty()) {
        LOG_D(BMSTag::QUICK_FIX, "no patch used in bundleName: %{public}s", bundleInfo.name.c_str());
        return ERR_OK;
    }
    const auto &qfInfo = appQuickFix.deployingAppqfInfo;
    if (qfInfo.versionCode <= deployedAppqfInfo.versionCode) {
        LOG_E(BMSTag::QUICK_FIX, "qhf version code %{public}u should be greater than the original %{public}u",
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
            LOG_E(BMSTag::QUICK_FIX, "error: moduleName %{public}s does not exist",
                info.second.deployingAppqfInfo.hqfInfos[0].moduleName.c_str());
            return ERR_BUNDLEMANAGER_QUICK_FIX_MODULE_NAME_NOT_EXIST;
        }
    }
    return ERR_OK;
}

ErrCode QuickFixChecker::CheckSignatureInfo(const BundleInfo &bundleInfo,
    const Security::Verify::ProvisionInfo &provisionInfo)
{
#ifndef X86_EMULATOR_MODE
    std::string quickFixAppId = bundleInfo.name + Constants::FILE_UNDERLINE + provisionInfo.appId;
    if (bundleInfo.applicationInfo.appPrivilegeLevel != provisionInfo.bundleInfo.apl) {
        LOG_E(BMSTag::QUICK_FIX, "Quick fix signature info is different with installed bundle : %{public}s",
            bundleInfo.name.c_str());
        return ERR_BUNDLEMANAGER_QUICK_FIX_SIGNATURE_INFO_NOT_SAME;
    }
    if (bundleInfo.signatureInfo.appIdentifier.empty() || provisionInfo.bundleInfo.appIdentifier.empty()) {
        if (bundleInfo.appId != quickFixAppId) {
            LOG_E(BMSTag::QUICK_FIX, "Quick fix signature info is different with installed bundle : %{public}s",
                bundleInfo.name.c_str());
            return ERR_BUNDLEMANAGER_QUICK_FIX_SIGNATURE_INFO_NOT_SAME;
        }
    } else if (bundleInfo.signatureInfo.appIdentifier != provisionInfo.bundleInfo.appIdentifier) {
        LOG_E(BMSTag::QUICK_FIX, "Quick fix appIdentifier info is different with installed bundle : %{public}s",
            bundleInfo.name.c_str());
        return ERR_BUNDLEMANAGER_QUICK_FIX_SIGNATURE_INFO_NOT_SAME;
    }
    if (bundleInfo.name != provisionInfo.bundleInfo.bundleName) {
        LOG_E(BMSTag::QUICK_FIX, "CheckSignatureInfo failed provisionBundleName:%{public}s, bundleName:%{public}s",
            provisionInfo.bundleInfo.bundleName.c_str(), bundleInfo.name.c_str());
        return ERR_BUNDLEMANAGER_QUICK_FIX_SIGNATURE_INFO_NOT_SAME;
    }
#endif
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
                LOG_E(BMSTag::QUICK_FIX, "check native so with installed bundle failed");
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
        { Security::Verify::AppDistType::ENTERPRISE_NORMAL, Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_NORMAL },
        { Security::Verify::AppDistType::ENTERPRISE_MDM, Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM },
        { Security::Verify::AppDistType::OS_INTEGRATION, Constants::APP_DISTRIBUTION_TYPE_OS_INTEGRATION },
        { Security::Verify::AppDistType::CROWDTESTING, Constants::APP_DISTRIBUTION_TYPE_CROWDTESTING },
    };
    auto typeIter = map.find(type);
    if (typeIter == map.end()) {
        LOG_E(BMSTag::QUICK_FIX, "wrong AppDistType");
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
