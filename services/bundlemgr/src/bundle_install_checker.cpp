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

#include "bundle_install_checker.h"

#include "bundle_parser.h"
#include "bundle_util.h"
#include "parameter.h"
#include "systemcapability.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::unordered_map<Security::Verify::AppDistType, std::string> APP_DISTRIBUTION_TYPE_MAPS = {
    { Security::Verify::AppDistType::NONE_TYPE, Constants::APP_DISTRIBUTION_TYPE_NONE },
    { Security::Verify::AppDistType::APP_GALLERY, Constants::APP_DISTRIBUTION_TYPE_APP_GALLERY },
    { Security::Verify::AppDistType::ENTERPRISE, Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE },
    { Security::Verify::AppDistType::OS_INTEGRATION, Constants::APP_DISTRIBUTION_TYPE_OS_INTEGRATION },
    { Security::Verify::AppDistType::CROWDTESTING, Constants::APP_DISTRIBUTION_TYPE_CROWDTESTING },
};

std::string GetAppDistributionType(const Security::Verify::AppDistType &type)
{
    auto typeIter = APP_DISTRIBUTION_TYPE_MAPS.find(type);
    if (typeIter == APP_DISTRIBUTION_TYPE_MAPS.end()) {
        APP_LOGE("wrong AppDistType");
        return Constants::APP_DISTRIBUTION_TYPE_NONE;
    }

    return typeIter->second;
}

std::string GetAppProvisionType(const Security::Verify::ProvisionType &type)
{
    if (type == Security::Verify::ProvisionType::DEBUG) {
        return Constants::APP_PROVISION_TYPE_DEBUG;
    }

    return Constants::APP_PROVISION_TYPE_RELEASE;
}
}

ErrCode BundleInstallChecker::CheckSysCap(const std::vector<std::string> &bundlePaths)
{
    APP_LOGD("check hap syscaps start.");
    if (bundlePaths.empty()) {
        APP_LOGE("check hap syscaps failed due to empty bundlePaths!");
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }

    ErrCode result = ERR_OK;
    BundleParser bundleParser;
    for (const auto &bundlePath : bundlePaths) {
        std::vector<std::string> bundleSysCaps;
        result = bundleParser.ParseSysCap(bundlePath, bundleSysCaps);
        if (result != ERR_OK) {
            APP_LOGE("parse bundle syscap failed, error: %{public}d", result);
            return result;
        }

        for (const auto &bundleSysCapItem : bundleSysCaps) {
            APP_LOGD("check syscap(%{public}s)", bundleSysCapItem.c_str());
            if (!HasSystemCapability(bundleSysCapItem.c_str())) {
                APP_LOGE("check syscap failed which %{public}s is not exsit",
                    bundleSysCapItem.c_str());
                return ERR_APPEXECFWK_INSTALL_CHECK_SYSCAP_FAILED;
            }
        }
    }

    APP_LOGD("finish check hap syscaps");
    return result;
}

ErrCode BundleInstallChecker::CheckMultipleHapsSignInfo(
    const std::vector<std::string> &bundlePaths,
    std::vector<Security::Verify::HapVerifyResult>& hapVerifyRes)
{
    APP_LOGD("Check multiple haps signInfo");
    if (bundlePaths.empty()) {
        APP_LOGE("check hap sign info failed due to empty bundlePaths!");
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }

    for (const std::string &bundlePath : bundlePaths) {
        Security::Verify::HapVerifyResult hapVerifyResult;
        auto verifyRes = BundleVerifyMgr::HapVerify(bundlePath, hapVerifyResult);
        if (verifyRes != ERR_OK) {
            APP_LOGE("hap file verify failed");
            return verifyRes;
        }
        hapVerifyRes.emplace_back(hapVerifyResult);
    }

    if (hapVerifyRes.empty()) {
        APP_LOGE("no sign info in the all haps!");
        return ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE;
    }

    auto appId = hapVerifyRes[0].GetProvisionInfo().appId;
    auto apl = hapVerifyRes[0].GetProvisionInfo().bundleInfo.apl;
    auto appDistributionType = hapVerifyRes[0].GetProvisionInfo().distributionType;
    auto appProvisionType = hapVerifyRes[0].GetProvisionInfo().type;
    bool isInvalid = std::any_of(hapVerifyRes.begin(), hapVerifyRes.end(),
        [appId, apl, appDistributionType, appProvisionType](const auto &hapVerifyResult) {
            if (appId != hapVerifyResult.GetProvisionInfo().appId) {
                APP_LOGE("error: hap files have different appId");
                return true;
            }
            if (apl != hapVerifyResult.GetProvisionInfo().bundleInfo.apl) {
                APP_LOGE("error: hap files have different apl");
                return true;
            }
            if (appDistributionType != hapVerifyResult.GetProvisionInfo().distributionType) {
                APP_LOGE("error: hap files have different appDistributionType");
                return true;
            }
            if (appProvisionType != hapVerifyResult.GetProvisionInfo().type) {
                APP_LOGE("error: hap files have different appProvisionType");
                return true;
            }
        return false;
    });
    if (isInvalid) {
        return ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE;
    }
    APP_LOGD("finish check multiple haps signInfo");
    return ERR_OK;
}

ErrCode BundleInstallChecker::ParseHapFiles(
    const std::vector<std::string> &bundlePaths,
    const InstallCheckParam &checkParam,
    std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes,
    std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    APP_LOGD("Parse hap file");
    ErrCode result = ERR_OK;
    BundlePackInfo packInfo;
    for (uint32_t i = 0; i < bundlePaths.size(); ++i) {
        InnerBundleInfo newInfo;
        newInfo.SetAppType(checkParam.appType);
        Security::Verify::ProvisionInfo provisionInfo = hapVerifyRes[i].GetProvisionInfo();
        bool isSystemApp = (provisionInfo.bundleInfo.appFeature == Constants::HOS_SYSTEM_APP ||
            provisionInfo.bundleInfo.appFeature == Constants::OHOS_SYSTEM_APP);
        if (isSystemApp) {
            newInfo.SetAppType(Constants::AppType::SYSTEM_APP);
        }

        newInfo.SetIsPreInstallApp(checkParam.isPreInstallApp);
        result = ParseBundleInfo(bundlePaths[i], newInfo, packInfo);
        if (result != ERR_OK) {
            APP_LOGE("bundle parse failed %{public}d", result);
            return result;
        }

        if (newInfo.HasEntry()) {
            if (isContainEntry_) {
                APP_LOGE("more than one entry hap in the direction!");
                return ERR_APPEXECFWK_INSTALL_INVALID_NUMBER_OF_ENTRY_HAP;
            } else {
                isContainEntry_ = true;
            }
        }

        SetEntryInstallationFree(packInfo, newInfo);
        newInfo.SetProvisionId(provisionInfo.appId);
        newInfo.SetAppFeature(provisionInfo.bundleInfo.appFeature);
        newInfo.SetAppPrivilegeLevel(provisionInfo.bundleInfo.apl);
        newInfo.SetAllowedAcls(provisionInfo.acls.allowedAcls);
        newInfo.SetCertificateFingerprint(provisionInfo.fingerprint);
        newInfo.SetAppDistributionType(GetAppDistributionType(provisionInfo.distributionType));
        newInfo.SetAppProvisionType(GetAppProvisionType(provisionInfo.type));
        if (provisionInfo.distributionType == Security::Verify::AppDistType::CROWDTESTING) {
            newInfo.SetAppCrowdtestDeadline(checkParam.crowdtestDeadline);
        } else {
            newInfo.SetAppCrowdtestDeadline(Constants::INVALID_CROWDTEST_DEADLINE);
        }
        if ((result = CheckSystemSize(bundlePaths[i], checkParam.appType)) != ERR_OK) {
            APP_LOGE("install failed due to insufficient disk memory");
            return result;
        }

        infos.emplace(bundlePaths[i], newInfo);
    }

    APP_LOGD("finish parse hap file");
    return result;
}

ErrCode BundleInstallChecker::ParseBundleInfo(
    const std::string &bundleFilePath,
    InnerBundleInfo &info,
    BundlePackInfo &packInfo) const
{
    BundleParser bundleParser;
    ErrCode result = bundleParser.Parse(bundleFilePath, info);
    if (result != ERR_OK) {
        APP_LOGE("parse bundle info failed, error: %{public}d", result);
        return result;
    }

    if (!packInfo.GetValid()) {
        result = bundleParser.ParsePackInfo(bundleFilePath, packInfo);
        if (result != ERR_OK) {
            APP_LOGE("parse bundle pack info failed, error: %{public}d", result);
            return result;
        }

        info.SetBundlePackInfo(packInfo);
        packInfo.SetValid(true);
    }

    return ERR_OK;
}

void BundleInstallChecker::SetEntryInstallationFree(
    const BundlePackInfo &bundlePackInfo,
    InnerBundleInfo &innrBundleInfo)
{
    APP_LOGI("SetEntryInstallationFree start");
    if (!bundlePackInfo.GetValid()) {
        APP_LOGW("no pack.info in the hap file");
        return;
    }

    auto packageModule = bundlePackInfo.summary.modules;
    auto installationFree = std::any_of(packageModule.begin(), packageModule.end(), [&](auto &module) {
        return module.distro.moduleType == "entry" && module.distro.installationFree;
    });
    if (installationFree) {
        APP_LOGI("install or upddate hm service");
    }

    innrBundleInfo.SetEntryInstallationFree(installationFree);
    APP_LOGI("SetEntryInstallationFree end");
}

ErrCode BundleInstallChecker::CheckSystemSize(
    const std::string &bundlePath,
    const Constants::AppType appType) const
{
    if ((appType == Constants::AppType::SYSTEM_APP) &&
        (BundleUtil::CheckSystemSize(bundlePath, Constants::SYSTEM_APP_INSTALL_PATH))) {
        return ERR_OK;
    }

    if ((appType == Constants::AppType::THIRD_SYSTEM_APP) &&
        (BundleUtil::CheckSystemSize(bundlePath, Constants::THIRD_SYSTEM_APP_INSTALL_PATH))) {
        return ERR_OK;
    }

    if ((appType == Constants::AppType::THIRD_PARTY_APP) &&
        (BundleUtil::CheckSystemSize(bundlePath, Constants::THIRD_PARTY_APP_INSTALL_PATH))) {
        return ERR_OK;
    }

    APP_LOGE("install failed due to insufficient disk memory");
    return ERR_APPEXECFWK_INSTALL_DISK_MEM_INSUFFICIENT;
}

ErrCode BundleInstallChecker::CheckHapHashParams(
    std::unordered_map<std::string, InnerBundleInfo> &infos,
    std::map<std::string, std::string> hashParams)
{
    if (hashParams.empty()) {
        APP_LOGD("hashParams is empty");
        return ERR_OK;
    }

    std::vector<std::string> hapModuleNames;
    for (auto &info : infos) {
        std::vector<std::string> moduleNames;
        info.second.GetModuleNames(moduleNames);
        if (moduleNames.empty()) {
            APP_LOGE("hap(%{public}s) moduleName is empty", info.first.c_str());
            return ERR_APPEXECFWK_INSTALL_FAILED_MODULE_NAME_EMPTY;
        }

        if (std::find(hapModuleNames.begin(), hapModuleNames.end(), moduleNames[0]) != hapModuleNames.end()) {
            APP_LOGE("hap moduleName(%{public}s) duplicate", moduleNames[0].c_str());
            return ERR_APPEXECFWK_INSTALL_FAILED_MODULE_NAME_DUPLICATE;
        }

        hapModuleNames.emplace_back(moduleNames[0]);
        auto hashParamIter = hashParams.find(moduleNames[0]);
        if (hashParamIter != hashParams.end()) {
            info.second.SetModuleHashValue(hashParamIter->second);
            hashParams.erase(hashParamIter);
        }
    }

    if (!hashParams.empty()) {
        APP_LOGE("Some hashParam moduleName is not exist in hap moduleNames");
        return ERR_APPEXECFWK_INSTALL_FAILED_CHECK_HAP_HASH_PARAM;
    }

    return ERR_OK;
}

ErrCode BundleInstallChecker::CheckAppLabelInfo(
    const std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    APP_LOGD("Check APP label");
    ErrCode ret = ERR_OK;
    std::string bundleName = (infos.begin()->second).GetBundleName();
    std::string vendor = (infos.begin()->second).GetVendor();
    uint32_t versionCode = (infos.begin()->second).GetVersionCode();
    std::string versionName = (infos.begin()->second).GetVersionName();
    uint32_t minCompatibleVersionCode = (infos.begin()->second).GetMinCompatibleVersionCode();
    uint32_t target = (infos.begin()->second).GetTargetVersion();
    std::string releaseType = (infos.begin()->second).GetReleaseType();
    uint32_t compatible = (infos.begin()->second).GetCompatibleVersion();
    bool singleton = (infos.begin()->second).IsSingleton();
    Constants::AppType appType = (infos.begin()->second).GetAppType();

    for (const auto &info : infos) {
        // check bundleName
        if (bundleName != info.second.GetBundleName()) {
            return ERR_APPEXECFWK_INSTALL_BUNDLENAME_NOT_SAME;
        }
        // check version
        if (versionCode != info.second.GetVersionCode()) {
            return ERR_APPEXECFWK_INSTALL_VERSIONCODE_NOT_SAME;
        }
        if (versionName != info.second.GetVersionName()) {
            return ERR_APPEXECFWK_INSTALL_VERSIONNAME_NOT_SAME;
        }
        if (minCompatibleVersionCode != info.second.GetMinCompatibleVersionCode()) {
            return ERR_APPEXECFWK_INSTALL_MINCOMPATIBLE_VERSIONCODE_NOT_SAME;
        }
        // check vendor
        if (vendor != info.second.GetVendor()) {
            return ERR_APPEXECFWK_INSTALL_VENDOR_NOT_SAME;
        }
        // check release type
        if (target != info.second.GetTargetVersion()) {
            return ERR_APPEXECFWK_INSTALL_RELEASETYPE_TARGET_NOT_SAME;
        }
        if (compatible != info.second.GetCompatibleVersion()) {
            return ERR_APPEXECFWK_INSTALL_RELEASETYPE_COMPATIBLE_NOT_SAME;
        }
        if (releaseType != info.second.GetReleaseType()) {
            return ERR_APPEXECFWK_INSTALL_RELEASETYPE_NOT_SAME;
        }
        if (singleton != info.second.IsSingleton()) {
            return ERR_APPEXECFWK_INSTALL_SINGLETON_NOT_SAME;
        }
        if (appType != info.second.GetAppType()) {
            return ERR_APPEXECFWK_INSTALL_APPTYPE_NOT_SAME;
        }
    }
    // check api sdk version
    if ((infos.begin()->second).GetCompatibleVersion() > static_cast<uint32_t>(GetSdkApiVersion())) {
        return ERR_APPEXECFWK_INSTALL_SDK_INCOMPATIBLE;
    }
    APP_LOGD("finish check APP label");
    return ret;
}

ErrCode BundleInstallChecker::CheckMultiNativeSo(
    std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    std::string nativeLibraryPath = (infos.begin()->second).GetNativeLibraryPath();
    std::string cpuAbi = (infos.begin()->second).GetCpuAbi();
    for (const auto &info : infos) {
        if (info.second.GetNativeLibraryPath().empty()) {
            continue;
        }
        if (nativeLibraryPath.empty()) {
            nativeLibraryPath = info.second.GetNativeLibraryPath();
            cpuAbi = info.second.GetCpuAbi();
            continue;
        }
        if (nativeLibraryPath != info.second.GetNativeLibraryPath()
            || cpuAbi != info.second.GetCpuAbi()) {
            return ERR_APPEXECFWK_INSTALL_SO_INCOMPATIBLE;
        }
    }

    // Ensure the so is consistent in multiple haps
    if (!nativeLibraryPath.empty()) {
        for (auto &info : infos) {
            info.second.SetNativeLibraryPath(nativeLibraryPath);
            info.second.SetCpuAbi(cpuAbi);
        }
    }

    return ERR_OK;
}

void BundleInstallChecker::ResetProperties()
{
    isContainEntry_ = false;
}
}  // namespace AppExecFwk
}  // namespace OHOS