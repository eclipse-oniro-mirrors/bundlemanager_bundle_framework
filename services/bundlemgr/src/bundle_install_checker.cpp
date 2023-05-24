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

#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "bundle_mgr_service_event_handler.h"
#include "bundle_parser.h"
#include "bundle_util.h"
#include "parameter.h"
#include "privilege_extension_ability_type.h"
#include "scope_guard.h"
#include "systemcapability.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string PRIVILEGE_ALLOW_APP_DATA_NOT_CLEARED = "AllowAppDataNotCleared";
const std::string PRIVILEGE_ALLOW_APP_MULTI_PROCESS = "AllowAppMultiProcess";
const std::string PRIVILEGE_ALLOW_APP_DESKTOP_ICON_HIDE = "AllowAppDesktopIconHide";
const std::string PRIVILEGE_ALLOW_ABILITY_PRIORITY_QUERIED = "AllowAbilityPriorityQueried";
const std::string PRIVILEGE_ALLOW_ABILITY_EXCLUDE_FROM_MISSIONS = "AllowAbilityExcludeFromMissions";
const std::string PRIVILEGE_ALLOW_APP_USE_PRIVILEGE_EXTENSION = "AllowAppUsePrivilegeExtension";
const std::string PRIVILEGE_ALLOW_FORM_VISIBLE_NOTIFY = "AllowFormVisibleNotify";
const std::string ALLOW_APP_DATA_NOT_CLEARED = "allowAppDataNotCleared";
const std::string ALLOW_APP_MULTI_PROCESS = "allowAppMultiProcess";
const std::string ALLOW_APP_DESKTOP_ICON_HIDE = "allowAppDesktopIconHide";
const std::string ALLOW_ABILITY_PRIORITY_QUERIED = "allowAbilityPriorityQueried";
const std::string ALLOW_ABILITY_EXCLUDE_FROM_MISSIONS = "allowAbilityExcludeFromMissions";
const std::string ALLOW_APP_USE_PRIVILEGE_EXTENSION = "allowAppUsePrivilegeExtension";
const std::string ALLOW_FORM_VISIBLE_NOTIFY = "allowFormVisibleNotify";
const std::string APP_TEST_BUNDLE_NAME = "com.OpenHarmony.app.test";
const std::string BUNDLE_NAME_XTS_TEST = "com.acts.";

const std::unordered_map<Security::Verify::AppDistType, std::string> APP_DISTRIBUTION_TYPE_MAPS = {
    { Security::Verify::AppDistType::NONE_TYPE, Constants::APP_DISTRIBUTION_TYPE_NONE },
    { Security::Verify::AppDistType::APP_GALLERY, Constants::APP_DISTRIBUTION_TYPE_APP_GALLERY },
    { Security::Verify::AppDistType::ENTERPRISE, Constants::APP_DISTRIBUTION_TYPE_ENTERPRISE },
    { Security::Verify::AppDistType::OS_INTEGRATION, Constants::APP_DISTRIBUTION_TYPE_OS_INTEGRATION },
    { Security::Verify::AppDistType::CROWDTESTING, Constants::APP_DISTRIBUTION_TYPE_CROWDTESTING },
};

const std::unordered_map<std::string, void (*)(AppPrivilegeCapability &appPrivilegeCapability)>
        PRIVILEGE_MAP = {
            { PRIVILEGE_ALLOW_APP_DATA_NOT_CLEARED,
                [] (AppPrivilegeCapability &appPrivilegeCapability) {
                    appPrivilegeCapability.userDataClearable = false;
                } },
            { PRIVILEGE_ALLOW_APP_MULTI_PROCESS,
                [] (AppPrivilegeCapability &appPrivilegeCapability) {
                    appPrivilegeCapability.allowMultiProcess = true;
                } },
            { PRIVILEGE_ALLOW_APP_DESKTOP_ICON_HIDE,
                [] (AppPrivilegeCapability &appPrivilegeCapability) {
                    appPrivilegeCapability.hideDesktopIcon = true;
                } },
            { PRIVILEGE_ALLOW_ABILITY_PRIORITY_QUERIED,
                [] (AppPrivilegeCapability &appPrivilegeCapability) {
                    appPrivilegeCapability.allowQueryPriority = true;
                } },
            { PRIVILEGE_ALLOW_ABILITY_EXCLUDE_FROM_MISSIONS,
                [] (AppPrivilegeCapability &appPrivilegeCapability) {
                    appPrivilegeCapability.allowExcludeFromMissions = true;
                } },
            { PRIVILEGE_ALLOW_APP_USE_PRIVILEGE_EXTENSION,
                [] (AppPrivilegeCapability &appPrivilegeCapability) {
                    appPrivilegeCapability.allowUsePrivilegeExtension = true;
                } },
            { PRIVILEGE_ALLOW_FORM_VISIBLE_NOTIFY,
                [] (AppPrivilegeCapability &appPrivilegeCapability) {
                    appPrivilegeCapability.formVisibleNotify = true;
                } },
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

bool IsPrivilegeExtensionAbilityType(ExtensionAbilityType type)
{
    return PRIVILEGE_EXTENSION_ABILITY_TYPE.find(type) != PRIVILEGE_EXTENSION_ABILITY_TYPE.end();
}

bool IsSystemExtensionAbilityType(ExtensionAbilityType type)
{
    return SYSTEM_EXTENSION_ABILITY_TYPE.find(type) != SYSTEM_EXTENSION_ABILITY_TYPE.end();
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
#ifndef X86_EMULATOR_MODE
        auto verifyRes = BundleVerifyMgr::HapVerify(bundlePath, hapVerifyResult);
        if (verifyRes != ERR_OK) {
            APP_LOGE("hap file verify failed");
            return verifyRes;
        }
#else
        BundleVerifyMgr::ParseHapProfile(bundlePath, hapVerifyResult);
#endif
        hapVerifyRes.emplace_back(hapVerifyResult);
    }

    if (hapVerifyRes.empty()) {
        APP_LOGE("no sign info in the all haps!");
        return ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE;
    }

#ifndef X86_EMULATOR_MODE
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
#endif
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
    for (uint32_t i = 0; i < bundlePaths.size(); ++i) {
        InnerBundleInfo newInfo;
        BundlePackInfo packInfo;
        newInfo.SetAppType(checkParam.appType);
        Security::Verify::ProvisionInfo provisionInfo = hapVerifyRes[i].GetProvisionInfo();
        bool isSystemApp = (provisionInfo.bundleInfo.appFeature == Constants::HOS_SYSTEM_APP ||
            provisionInfo.bundleInfo.appFeature == Constants::OHOS_SYSTEM_APP) ||
            (bundlePaths[i].find(Constants::SYSTEM_APP_SCAN_PATH) == 0);
        if (isSystemApp) {
            newInfo.SetAppType(Constants::AppType::SYSTEM_APP);
        }

        newInfo.SetIsPreInstallApp(checkParam.isPreInstallApp);
        result = ParseBundleInfo(bundlePaths[i], newInfo, packInfo);
        if (result != ERR_OK) {
            APP_LOGE("bundle parse failed %{public}d", result);
            return result;
        }
#ifndef X86_EMULATOR_MODE
        result = CheckBundleName(provisionInfo.bundleInfo.bundleName, newInfo.GetBundleName());
        if (result != ERR_OK) {
            APP_LOGE("check provision bundleName failed");
            return result;
        }
#endif
        if (newInfo.HasEntry()) {
            if (isContainEntry_) {
                APP_LOGE("more than one entry hap in the direction!");
                return ERR_APPEXECFWK_INSTALL_INVALID_NUMBER_OF_ENTRY_HAP;
            }
            isContainEntry_ = true;
        }

        SetEntryInstallationFree(packInfo, newInfo);
        result = CheckMainElement(newInfo);
        if (result != ERR_OK) {
            return result;
        }
        AppPrivilegeCapability appPrivilegeCapability;
        // from provision file
        ParseAppPrivilegeCapability(provisionInfo, appPrivilegeCapability);
        // form install_list_capability.json, higher priority than provision file
        FetchPrivilegeCapabilityFromPreConfig(
            newInfo.GetBundleName(), provisionInfo.fingerprint, appPrivilegeCapability);
        // process bundleInfo by appPrivilegeCapability
        result = ProcessBundleInfoByPrivilegeCapability(appPrivilegeCapability, newInfo);
        if (result != ERR_OK) {
            return result;
        }
        CollectProvisionInfo(provisionInfo, appPrivilegeCapability, newInfo);
#ifdef USE_PRE_BUNDLE_PROFILE
        GetPrivilegeCapability(checkParam, newInfo);
#endif
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
    if ((result = CheckModuleNameForMulitHaps(infos)) != ERR_OK) {
        APP_LOGE("install failed due to duplicated moduleName");
        return result;
    }
    APP_LOGD("finish parse hap file");
    return result;
}

ErrCode BundleInstallChecker::CheckDependency(std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    APP_LOGD("CheckDependency");

    for (const auto &info : infos) {
        if (info.second.GetInnerModuleInfos().empty()) {
            continue;
        }
        // There is only one innerModuleInfo when installing
        InnerModuleInfo moduleInfo = info.second.GetInnerModuleInfos().begin()->second;
        bool isModuleExist = false;
        for (const auto &dependency : moduleInfo.dependencies) {
            if (!NeedCheckDependency(dependency, info.second)) {
                APP_LOGD("deliveryWithInstall is false, do not check whether the dependency exists.");
                continue;
            }

            std::string bundleName =
                dependency.bundleName.empty() ? info.second.GetBundleName() : dependency.bundleName;
            isModuleExist = FindModuleInInstallingPackage(dependency.moduleName, bundleName, infos);
            if (!isModuleExist) {
                APP_LOGW("The depend module:%{public}s is not exist in installing package.",
                    dependency.moduleName.c_str());
                isModuleExist = FindModuleInInstalledPackage(dependency.moduleName, bundleName,
                    info.second.GetVersionCode());
                if (!isModuleExist) {
                    APP_LOGE("The depend module:%{public}s is not exist.", dependency.moduleName.c_str());
                    return ERR_APPEXECFWK_INSTALL_DEPENDENT_MODULE_NOT_EXIST;
                }
            }
        }
    }

    return ERR_OK;
}

bool BundleInstallChecker::NeedCheckDependency(const Dependency &dependency, const InnerBundleInfo &info)
{
    APP_LOGD("NeedCheckDependency the moduleName is %{public}s, the bundleName is %{public}s.",
        dependency.moduleName.c_str(), dependency.bundleName.c_str());

    if (!dependency.bundleName.empty() && dependency.bundleName != info.GetBundleName()) {
        APP_LOGD("Cross-app dependencies, need check dependency.");
        return true;
    }
    std::vector<PackageModule> modules = info.GetBundlePackInfo().summary.modules;
    if (modules.empty()) {
        APP_LOGD("NeedCheckDependency modules is empty, need check dependency.");
        return true;
    }
    for (const auto &module : modules) {
        if (module.distro.moduleName == dependency.moduleName) {
            return module.distro.deliveryWithInstall;
        }
    }

    APP_LOGD("NeedCheckDependency the module not found, need check dependency.");
    return true;
}

bool BundleInstallChecker::FindModuleInInstallingPackage(
    const std::string &moduleName,
    const std::string &bundleName,
    const std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    APP_LOGD("FindModuleInInstallingPackage the moduleName is %{public}s, the bundleName is %{public}s.",
        moduleName.c_str(), bundleName.c_str());
    for (const auto &info : infos) {
        if (info.second.GetBundleName() == bundleName) {
            if (info.second.GetInnerModuleInfos().empty()) {
                continue;
            }
            // There is only one innerModuleInfo when installing
            InnerModuleInfo moduleInfo = info.second.GetInnerModuleInfos().begin()->second;
            if (moduleInfo.moduleName == moduleName) {
                return true;
            }
        }
    }
    return false;
}

bool BundleInstallChecker::FindModuleInInstalledPackage(
    const std::string &moduleName,
    const std::string &bundleName,
    uint32_t versionCode)
{
    APP_LOGD("FindModuleInInstalledPackage the moduleName is %{public}s, the bundleName is %{public}s.",
        moduleName.c_str(), bundleName.c_str());
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return false;
    }

    ScopeGuard enableGuard([&dataMgr, &bundleName] { dataMgr->EnableBundle(bundleName); });
    InnerBundleInfo bundleInfo;
    bool isBundleExist = dataMgr->GetInnerBundleInfo(bundleName, bundleInfo);
    if (!isBundleExist) {
        APP_LOGE("the bundle: %{public}s is not install", bundleName.c_str());
        return false;
    }
    if (!bundleInfo.FindModule(moduleName)) {
        APP_LOGE("the module: %{public}s is not install", moduleName.c_str());
        return false;
    }
    if (bundleInfo.GetVersionCode() != versionCode) {
        APP_LOGE("the versionCode %{public}d of dependency is not consistent with the installed module",
            bundleInfo.GetVersionCode());
        return false;
    }
    return true;
}

ErrCode BundleInstallChecker::CheckBundleName(const std::string &provisionBundleName, const std::string &bundleName)
{
    APP_LOGD("CheckBundleName provisionBundleName:%{public}s, bundleName:%{public}s",
        provisionBundleName.c_str(), bundleName.c_str());
    if (provisionBundleName.empty() || bundleName.empty()) {
        APP_LOGE("CheckBundleName provisionBundleName:%{public}s, bundleName:%{public}s failed",
            provisionBundleName.c_str(), bundleName.c_str());
        return ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE;
    }
    if (provisionBundleName == bundleName) {
        return ERR_OK;
    }
    APP_LOGE("CheckBundleName failed provisionBundleName:%{public}s, bundleName:%{public}s",
        provisionBundleName.c_str(), bundleName.c_str());
    return ERR_APPEXECFWK_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE;
}

void BundleInstallChecker::CollectProvisionInfo(
    const Security::Verify::ProvisionInfo &provisionInfo,
    const AppPrivilegeCapability &appPrivilegeCapability,
    InnerBundleInfo &newInfo)
{
    newInfo.SetProvisionId(provisionInfo.appId);
    newInfo.SetAppFeature(provisionInfo.bundleInfo.appFeature);
    newInfo.SetAppPrivilegeLevel(provisionInfo.bundleInfo.apl);
    newInfo.SetAllowedAcls(provisionInfo.acls.allowedAcls);
    newInfo.SetCertificateFingerprint(provisionInfo.fingerprint);
    newInfo.SetAppDistributionType(GetAppDistributionType(provisionInfo.distributionType));
    newInfo.SetAppProvisionType(GetAppProvisionType(provisionInfo.type));
    SetAppProvisionMetadata(provisionInfo.metadatas, newInfo);
#ifdef USE_PRE_BUNDLE_PROFILE
    newInfo.SetUserDataClearable(appPrivilegeCapability.userDataClearable);
    newInfo.SetHideDesktopIcon(appPrivilegeCapability.hideDesktopIcon);
    newInfo.SetFormVisibleNotify(appPrivilegeCapability.formVisibleNotify);
#endif
}

void BundleInstallChecker::SetAppProvisionMetadata(const std::vector<Security::Verify::Metadata> &provisionMetadatas,
    InnerBundleInfo &newInfo)
{
    if (provisionMetadatas.empty()) {
        return;
    }
    std::vector<Metadata> metadatas;
    for (const auto &it : provisionMetadatas) {
        Metadata metadata;
        metadata.name = it.name;
        metadata.value = it.value;
        metadatas.emplace_back(metadata);
    }
    newInfo.SetAppProvisionMetadata(metadatas);
}

void BundleInstallChecker::GetPrivilegeCapability(
    const InstallCheckParam &checkParam, InnerBundleInfo &newInfo)
{
    // Reset privilege capability
    newInfo.SetKeepAlive(false);
    newInfo.SetSingleton(false);

    newInfo.SetRemovable(checkParam.removable);
    PreBundleConfigInfo preBundleConfigInfo;
    preBundleConfigInfo.bundleName = newInfo.GetBundleName();
    BMSEventHandler::GetPreInstallCapability(preBundleConfigInfo);
    bool ret = false;
    if (!preBundleConfigInfo.appSignature.empty()) {
        ret = std::find(
            preBundleConfigInfo.appSignature.begin(),
            preBundleConfigInfo.appSignature.end(),
            newInfo.GetCertificateFingerprint()) !=
            preBundleConfigInfo.appSignature.end();
    }

    if (!ret) {
        APP_LOGW("appSignature is incompatible");
        return;
    }

    newInfo.SetKeepAlive(preBundleConfigInfo.keepAlive);
    newInfo.SetSingleton(preBundleConfigInfo.singleton);
    newInfo.SetRunningResourcesApply(preBundleConfigInfo.runningResourcesApply);
    newInfo.SetAssociatedWakeUp(preBundleConfigInfo.associatedWakeUp);
    newInfo.SetAllowCommonEvent(preBundleConfigInfo.allowCommonEvent);
}

void BundleInstallChecker::SetPackInstallationFree(BundlePackInfo &bundlePackInfo,
    const InnerBundleInfo &innerBundleInfo) const
{
    if (innerBundleInfo.GetIsNewVersion()) {
        if (innerBundleInfo.GetApplicationBundleType() == BundleType::ATOMIC_SERVICE) {
            for (auto &item : bundlePackInfo.summary.modules) {
                item.distro.installationFree = true;
            }
            return;
        }
        for (auto &item : bundlePackInfo.summary.modules) {
            item.distro.installationFree = false;
        }
    }
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

        SetPackInstallationFree(packInfo, info);
        info.SetBundlePackInfo(packInfo);
        packInfo.SetValid(true);
    }

    return ERR_OK;
}

void BundleInstallChecker::SetEntryInstallationFree(
    const BundlePackInfo &bundlePackInfo,
    InnerBundleInfo &innerBundleInfo)
{
    APP_LOGI("SetEntryInstallationFree start");
    if (!bundlePackInfo.GetValid()) {
        APP_LOGW("no pack.info in the hap file");
        return;
    }

    auto packageModule = bundlePackInfo.summary.modules;
    auto installationFree = std::any_of(packageModule.begin(), packageModule.end(), [&](const auto &module) {
        return module.distro.moduleType == "entry" && module.distro.installationFree;
    });
    if (installationFree) {
        APP_LOGI("install or update hm service");
    }
    if (innerBundleInfo.GetIsNewVersion()) {
        installationFree = innerBundleInfo.GetApplicationBundleType() == BundleType::ATOMIC_SERVICE;
    }

    innerBundleInfo.SetEntryInstallationFree(installationFree);
    if (installationFree && !innerBundleInfo.GetIsNewVersion()) {
        innerBundleInfo.SetApplicationBundleType(BundleType::ATOMIC_SERVICE);
    }
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
    bool isStage = (infos.begin()->second).GetIsNewVersion();
    bool asanEnabled = (infos.begin()->second).GetAsanEnabled();
    BundleType bundleType = (infos.begin()->second).GetApplicationBundleType();
    bool isHmService = (infos.begin()->second).GetEntryInstallationFree();

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
        // check model type(FA or stage)
        if (isStage != info.second.GetIsNewVersion()) {
            APP_LOGE("must be all FA model or all stage model");
            return ERR_APPEXECFWK_INSTALL_STATE_ERROR;
        }
        // check asanEnabled
        if (asanEnabled != info.second.GetAsanEnabled()) {
            APP_LOGE("asanEnabled is not same");
            return ERR_APPEXECFWK_INSTALL_ASAN_ENABLED_NOT_SAME;
        }
        if (bundleType != info.second.GetApplicationBundleType()) {
            return ERR_APPEXECFWK_BUNDLE_TYPE_NOT_SAME;
        }
        if (isHmService != info.second.GetEntryInstallationFree()) {
            APP_LOGE("application and hm service are not allowed installed simultaneously.");
            return ERR_APPEXECFWK_INSTALL_TYPE_ERROR;
        }
    }
    // check api sdk version
    if ((infos.begin()->second).GetCompatibleVersion() > static_cast<uint32_t>(GetSdkApiVersion())) {
        return ERR_APPEXECFWK_INSTALL_SDK_INCOMPATIBLE;
    }
    APP_LOGD("finish check APP label");
    return ret;
}

ErrCode BundleInstallChecker::CheckMultiNativeFile(
    std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    ErrCode result = CheckMultiNativeSo(infos);
    if (result != ERR_OK) {
        APP_LOGE("Check multi nativeSo failed, result: %{public}d", result);
        return result;
    }

    result = CheckMultiArkNativeFile(infos);
    if (result != ERR_OK) {
        APP_LOGE("Check multi arkNativeFile failed, result: %{public}d", result);
        return result;
    }

    return ERR_OK;
}

ErrCode BundleInstallChecker::CheckMultiArkNativeFile(
    std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    std::string arkNativeFileAbi = (infos.begin()->second).GetArkNativeFileAbi();
    for (const auto &info : infos) {
        if (info.second.GetArkNativeFileAbi().empty()) {
            continue;
        }
        if (arkNativeFileAbi.empty()) {
            arkNativeFileAbi = info.second.GetArkNativeFileAbi();
            continue;
        }
        if (arkNativeFileAbi != info.second.GetArkNativeFileAbi()) {
            return ERR_APPEXECFWK_INSTALL_AN_INCOMPATIBLE;
        }
    }

    // Ensure the an is consistent in multiple haps
    if (!arkNativeFileAbi.empty()) {
        for (auto &info : infos) {
            info.second.SetArkNativeFileAbi(arkNativeFileAbi);
        }
    }

    return ERR_OK;
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

void BundleInstallChecker::ParseAppPrivilegeCapability(
    const Security::Verify::ProvisionInfo &provisionInfo,
    AppPrivilegeCapability &appPrivilegeCapability)
{
    for (const auto &appPrivilege : provisionInfo.appPrivilegeCapabilities) {
        auto iter = PRIVILEGE_MAP.find(appPrivilege);
        if (iter != PRIVILEGE_MAP.end()) {
            iter->second(appPrivilegeCapability);
        }
    }
    if ((provisionInfo.bundleInfo.bundleName != APP_TEST_BUNDLE_NAME) &&
        (provisionInfo.bundleInfo.bundleName.find(BUNDLE_NAME_XTS_TEST) != 0)) {
        appPrivilegeCapability.allowMultiProcess = false;
        appPrivilegeCapability.allowUsePrivilegeExtension = false;
        appPrivilegeCapability.formVisibleNotify = false;
    }
    APP_LOGD("AppPrivilegeCapability %{public}s",
        appPrivilegeCapability.ToString().c_str());
#ifndef USE_PRE_BUNDLE_PROFILE
    appPrivilegeCapability.allowMultiProcess = true;
    appPrivilegeCapability.allowUsePrivilegeExtension = true;
#endif
}

ErrCode BundleInstallChecker::CheckModuleNameForMulitHaps(
    const std::unordered_map<std::string, InnerBundleInfo> &infos) const
{
    std::set<std::string> moduleSet;
    for (const auto &info : infos) {
        std::vector<std::string> moduleVec = info.second.GetDistroModuleName();
        if (moduleVec.empty()) {
            APP_LOGE("moduleName vector is empty");
            return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        }
        moduleSet.insert(moduleVec[0]);
    }

    if (moduleSet.size() != infos.size()) {
        APP_LOGE("someone moduleName is not unique in the haps");
        return ERR_APPEXECFWK_INSTALL_NOT_UNIQUE_DISTRO_MODULE_NAME;
    }
    return ERR_OK;
}

bool BundleInstallChecker::IsExistedDistroModule(const InnerBundleInfo &newInfo, const InnerBundleInfo &info) const
{
    std::string moduleName = newInfo.GetCurModuleName();
    std::string packageName = newInfo.GetCurrentModulePackage();
    if (packageName.empty() || moduleName.empty()) {
        APP_LOGE("IsExistedDistroModule failed due to invalid packageName or moduleName");
        return false;
    }
    std::string oldModuleName = info.GetModuleNameByPackage(packageName);
    // if FA update to Stage, allow module name inconsistent
    bool isFAToStage = !info.GetIsNewVersion() && newInfo.GetIsNewVersion();
    if (!isFAToStage) {
        // if not FA update to Stage, check consistency of module name
        if (moduleName.compare(oldModuleName) != 0) {
            APP_LOGE("no moduleName in the innerModuleInfo");
            return false;
        }
    }
    // check consistency of module type
    std::string newModuleType = newInfo.GetModuleTypeByPackage(packageName);
    std::string oldModuleType = info.GetModuleTypeByPackage(packageName);
    if (newModuleType.compare(oldModuleType) != 0) {
        APP_LOGE("moduleType is different between the new hap and the original hap");
        return false;
    }

    return true;
}

bool BundleInstallChecker::IsContainModuleName(const InnerBundleInfo &newInfo, const InnerBundleInfo &info) const
{
    std::string moduleName = newInfo.GetCurModuleName();
    std::vector<std::string> moduleVec = info.GetDistroModuleName();
    if (moduleName.empty() || moduleVec.empty()) {
        APP_LOGE("IsContainModuleName failed due to invalid moduleName or modulevec");
        return false;
    }
    return (find(moduleVec.cbegin(), moduleVec.cend(), moduleName) == moduleVec.cend()) ? false : true;
}

ErrCode BundleInstallChecker::CheckMainElement(const InnerBundleInfo &info)
{
    const std::map<std::string, InnerModuleInfo> &innerModuleInfos = info.GetInnerModuleInfos();
    if (innerModuleInfos.empty()) {
        return ERR_OK;
    }
    if (innerModuleInfos.cbegin()->second.distro.moduleType == Profile::MODULE_TYPE_SHARED) {
        return ERR_OK;
    }
    if (info.GetEntryInstallationFree() && innerModuleInfos.cbegin()->second.mainAbility.empty()) {
        APP_LOGE("atomic service's mainElement can't be empty.");
        return ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR;
    }
    return ERR_OK;
}

bool BundleInstallChecker::GetPrivilegeCapabilityValue(
    const std::vector<std::string> &existInJson,
    const std::string &key,
    bool existInPreJson,
    bool existInProvision)
{
    if (find(existInJson.cbegin(), existInJson.cend(), key) != existInJson.cend()) {
        return existInPreJson;
    }
    return existInProvision;
}

void BundleInstallChecker::FetchPrivilegeCapabilityFromPreConfig(
    const std::string &bundleName,
    const std::string &appSignature,
    AppPrivilegeCapability &appPrivilegeCapability)
{
#ifdef USE_PRE_BUNDLE_PROFILE
    APP_LOGD("bundleName: %{public}s, FetchPrivilegeCapabilityFromPreConfig start", bundleName.c_str());
    PreBundleConfigInfo configInfo;
    configInfo.bundleName = bundleName;
    if (!BMSEventHandler::GetPreInstallCapability(configInfo)) {
        APP_LOGW("bundleName: %{public}s is not exist in pre install capability list", bundleName.c_str());
        return;
    }
    if (!MatchSignature(configInfo.appSignature, appSignature)) {
        APP_LOGE("bundleName: %{public}s signature verify failed", bundleName.c_str());
        return;
    }
    appPrivilegeCapability.allowUsePrivilegeExtension = GetPrivilegeCapabilityValue(configInfo.existInJsonFile,
        ALLOW_APP_USE_PRIVILEGE_EXTENSION,
        configInfo.allowUsePrivilegeExtension, appPrivilegeCapability.allowUsePrivilegeExtension);

    appPrivilegeCapability.allowMultiProcess = GetPrivilegeCapabilityValue(configInfo.existInJsonFile,
        ALLOW_APP_MULTI_PROCESS,
        configInfo.allowMultiProcess, appPrivilegeCapability.allowMultiProcess);

    appPrivilegeCapability.hideDesktopIcon = GetPrivilegeCapabilityValue(configInfo.existInJsonFile,
        ALLOW_APP_DESKTOP_ICON_HIDE,
        configInfo.hideDesktopIcon, appPrivilegeCapability.hideDesktopIcon);

    appPrivilegeCapability.allowQueryPriority = GetPrivilegeCapabilityValue(configInfo.existInJsonFile,
        ALLOW_ABILITY_PRIORITY_QUERIED,
        configInfo.allowQueryPriority, appPrivilegeCapability.allowQueryPriority);

    appPrivilegeCapability.allowExcludeFromMissions = GetPrivilegeCapabilityValue(configInfo.existInJsonFile,
        ALLOW_ABILITY_EXCLUDE_FROM_MISSIONS,
        configInfo.allowExcludeFromMissions, appPrivilegeCapability.allowExcludeFromMissions);

    appPrivilegeCapability.formVisibleNotify = GetPrivilegeCapabilityValue(configInfo.existInJsonFile,
        ALLOW_FORM_VISIBLE_NOTIFY,
        configInfo.formVisibleNotify, appPrivilegeCapability.formVisibleNotify);

    appPrivilegeCapability.userDataClearable = GetPrivilegeCapabilityValue(configInfo.existInJsonFile,
        ALLOW_APP_DATA_NOT_CLEARED,
        configInfo.userDataClearable, appPrivilegeCapability.userDataClearable);
    APP_LOGD("AppPrivilegeCapability %{public}s", appPrivilegeCapability.ToString().c_str());
#endif
}

bool BundleInstallChecker::MatchSignature(
    const std::vector<std::string> &appSignatures, const std::string &signature)
{
    if (appSignatures.empty()) {
        APP_LOGW("appSignature is empty");
        return false;
    }

    return std::find(
        appSignatures.begin(), appSignatures.end(), signature) != appSignatures.end();
}

ErrCode BundleInstallChecker::ProcessBundleInfoByPrivilegeCapability(
    const AppPrivilegeCapability &appPrivilegeCapability,
    InnerBundleInfo &innerBundleInfo)
{
    // process application
    ApplicationInfo applicationInfo = innerBundleInfo.GetBaseApplicationInfo();
    if (!appPrivilegeCapability.allowMultiProcess || applicationInfo.process.empty()) {
        applicationInfo.process = applicationInfo.bundleName;
    }
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleInfo bundleInfo = innerBundleInfo.GetBaseBundleInfo();
    // process ability
    auto &abilityInfos = innerBundleInfo.FetchAbilityInfos();
    for (auto iter = abilityInfos.begin(); iter != abilityInfos.end(); ++iter) {
#ifdef USE_PRE_BUNDLE_PROFILE
        if (!appPrivilegeCapability.allowQueryPriority) {
            iter->second.priority = 0;
        }
        if (!appPrivilegeCapability.allowExcludeFromMissions) {
            iter->second.excludeFromMissions = false;
        }
#else
        if (!applicationInfo.isSystemApp || !bundleInfo.isPreInstallApp) {
            iter->second.priority = 0;
            iter->second.excludeFromMissions = false;
        }
#endif
    }
    // process ExtensionAbility
    auto &extensionAbilityInfos = innerBundleInfo.FetchInnerExtensionInfos();
    for (auto iter = extensionAbilityInfos.begin(); iter != extensionAbilityInfos.end(); ++iter) {
        bool privilegeType = IsPrivilegeExtensionAbilityType(iter->second.type);
        if (privilegeType && !appPrivilegeCapability.allowUsePrivilegeExtension) {
            APP_LOGE("not allow use privilege extension");
            return ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR;
        }

        bool systemType = IsSystemExtensionAbilityType(iter->second.type);
        if (systemType && !applicationInfo.isSystemApp) {
            APP_LOGE("not allow use system extension");
            return ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR;
        }

#ifdef USE_PRE_BUNDLE_PROFILE
        if (!appPrivilegeCapability.allowQueryPriority) {
            iter->second.priority = 0;
        }
#else
        if (!applicationInfo.isSystemApp || !bundleInfo.isPreInstallApp) {
            iter->second.priority = 0;
        }
#endif
    }
    // process InnerModuleInfo
    auto &innerModuleInfos = innerBundleInfo.FetchInnerModuleInfos();
    for (auto iter = innerModuleInfos.begin(); iter != innerModuleInfos.end(); ++iter) {
        if (iter->second.isModuleJson && (!appPrivilegeCapability.allowMultiProcess || iter->second.process.empty())) {
            iter->second.process = applicationInfo.bundleName;
        }
    }
    return ERR_OK;
}

ErrCode BundleInstallChecker::CheckDeviceType(std::unordered_map<std::string, InnerBundleInfo> &infos) const
{
    std::string deviceType = GetDeviceType();
    APP_LOGD("deviceType is %{public}s", deviceType.c_str());
    for (const auto &info : infos) {
        std::vector<std::string> devVec = info.second.GetDeviceType(info.second.GetCurrentModulePackage());
        if (devVec.empty()) {
            APP_LOGW("deviceTypes is empty");
            continue;
        }

        if ((deviceType == Constants::DEVICE_TYPE_OF_PHONE) &&
            (find(devVec.begin(), devVec.end(), Constants::DEVICE_TYPE_OF_DEFAULT) != devVec.end())) {
            APP_LOGW("current deviceType is phone and bundle is matched with default");
            continue;
        }

        if ((deviceType == Constants::DEVICE_TYPE_OF_DEFAULT) &&
            (find(devVec.begin(), devVec.end(), Constants::DEVICE_TYPE_OF_PHONE) != devVec.end())) {
            APP_LOGW("current deviceType is default and bundle is matched with phone");
            continue;
        }

        if (find(devVec.begin(), devVec.end(), deviceType) == devVec.end()) {
            APP_LOGE("%{public}s is not supported", deviceType.c_str());
            return ERR_APPEXECFWK_INSTALL_DEVICE_TYPE_NOT_SUPPORTED;
        }
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS