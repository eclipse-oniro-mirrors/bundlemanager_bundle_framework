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

#include <regex>

#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "bundle_mgr_service_event_handler.h"
#include "bundle_parser.h"
#include "bundle_permission_mgr.h"
#include "bundle_util.h"
#include "parameter.h"
#include "parameters.h"
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
const std::string PRIVILEGE_ALLOW_MISSION_NOT_CLEARED = "AllowMissionNotCleared";
const std::string PRIVILEGE_ALLOW_APP_USE_PRIVILEGE_EXTENSION = "AllowAppUsePrivilegeExtension";
const std::string PRIVILEGE_ALLOW_FORM_VISIBLE_NOTIFY = "AllowFormVisibleNotify";
const std::string PRIVILEGE_ALLOW_APP_SHARE_LIBRARY = "AllowAppShareLibrary";
const std::string PRIVILEGE_ALLOW_ENABLE_NOTIFICATION = "AllowEnableNotification";
const std::string ALLOW_APP_DATA_NOT_CLEARED = "allowAppDataNotCleared";
const std::string ALLOW_APP_MULTI_PROCESS = "allowAppMultiProcess";
const std::string ALLOW_APP_DESKTOP_ICON_HIDE = "allowAppDesktopIconHide";
const std::string ALLOW_ABILITY_PRIORITY_QUERIED = "allowAbilityPriorityQueried";
const std::string ALLOW_ABILITY_EXCLUDE_FROM_MISSIONS = "allowAbilityExcludeFromMissions";
const std::string ALLOW_MISSION_NOT_CLEARED = "allowMissionNotCleared";
const std::string ALLOW_APP_USE_PRIVILEGE_EXTENSION = "allowAppUsePrivilegeExtension";
const std::string ALLOW_FORM_VISIBLE_NOTIFY = "allowFormVisibleNotify";
const std::string ALLOW_APP_SHARE_LIBRARY = "allowAppShareLibrary";
const std::string ALLOW_ENABLE_NOTIFICATION = "allowEnableNotification";
const std::string APP_TEST_BUNDLE_NAME = "com.OpenHarmony.app.test";
const std::string BUNDLE_NAME_XTS_TEST = "com.acts.";
const std::string APL_NORMAL = "normal";
const std::string SLASH = "/";
const std::string DOUBLE_SLASH = "//";
const std::string SUPPORT_ISOLATION_MODE = "persist.bms.supportIsolationMode";
const std::string VALUE_TRUE = "true";
const std::string VALUE_TRUE_BOOL = "1";
const std::string VALUE_FALSE = "false";
const std::string NONISOLATION_ONLY = "nonisolationOnly";
const std::string ISOLATION_ONLY = "isolationOnly";
const std::string SUPPORT_APP_TYPES = "const.bms.supportAppTypes";
const std::string SUPPORT_APP_TYPES_SEPARATOR = ",";
const int32_t SLAH_OFFSET = 2;
const int32_t THRESHOLD_VAL_LEN = 40;
constexpr const char* SYSTEM_APP_SCAN_PATH = "/system/app";
constexpr const char* DEVICE_TYPE_OF_DEFAULT = "default";
constexpr const char* DEVICE_TYPE_OF_PHONE = "phone";
constexpr const char* APP_INSTALL_PATH = "/data/app/el1/bundle";

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
            { PRIVILEGE_ALLOW_MISSION_NOT_CLEARED,
                [] (AppPrivilegeCapability &appPrivilegeCapability) {
                    appPrivilegeCapability.allowMissionNotCleared = true;
                } },
            { PRIVILEGE_ALLOW_APP_USE_PRIVILEGE_EXTENSION,
                [] (AppPrivilegeCapability &appPrivilegeCapability) {
                    appPrivilegeCapability.allowUsePrivilegeExtension = true;
                } },
            { PRIVILEGE_ALLOW_FORM_VISIBLE_NOTIFY,
                [] (AppPrivilegeCapability &appPrivilegeCapability) {
                    appPrivilegeCapability.formVisibleNotify = true;
                } },
            { PRIVILEGE_ALLOW_APP_SHARE_LIBRARY,
                [] (AppPrivilegeCapability &appPrivilegeCapability) {
                    appPrivilegeCapability.appShareLibrary = true;
                } },
            { PRIVILEGE_ALLOW_ENABLE_NOTIFICATION,
                [] (AppPrivilegeCapability &appPrivilegeCapability) {
                    appPrivilegeCapability.allowEnableNotification = true;
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
        auto verifyRes = BundleVerifyMgr::HapVerify(bundlePath, hapVerifyResult);
#ifndef X86_EMULATOR_MODE
        if (verifyRes != ERR_OK) {
            APP_LOGE("hap file verify failed");
            return verifyRes;
        }
#endif
        hapVerifyRes.emplace_back(hapVerifyResult);
    }

    if (hapVerifyRes.empty()) {
        APP_LOGE("no sign info in the all haps!");
        return ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE;
    }

    if (!CheckProvisionInfoIsValid(hapVerifyRes)) {
#ifndef X86_EMULATOR_MODE
        return ERR_APPEXECFWK_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE;
#else
        // on emulator if check signature failed clear appid
        for (auto &verifyRes : hapVerifyRes) {
            Security::Verify::ProvisionInfo provisionInfo = verifyRes.GetProvisionInfo();
            provisionInfo.appId = Constants::EMPTY_STRING;
            verifyRes.SetProvisionInfo(provisionInfo);
        }
#endif
    }
    APP_LOGD("finish check multiple haps signInfo");
    return ERR_OK;
}

bool BundleInstallChecker::CheckProvisionInfoIsValid(
    const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes)
{
    auto appId = hapVerifyRes[0].GetProvisionInfo().appId;
    auto appIdentifier = hapVerifyRes[0].GetProvisionInfo().bundleInfo.appIdentifier;
    auto apl = hapVerifyRes[0].GetProvisionInfo().bundleInfo.apl;
    auto appDistributionType = hapVerifyRes[0].GetProvisionInfo().distributionType;
    auto appProvisionType = hapVerifyRes[0].GetProvisionInfo().type;
    bool isInvalid = std::any_of(hapVerifyRes.begin(), hapVerifyRes.end(),
        [appId, apl, appDistributionType, appProvisionType, appIdentifier](const auto &hapVerifyResult) {
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
            if (appIdentifier != hapVerifyResult.GetProvisionInfo().bundleInfo.appIdentifier) {
                APP_LOGE("error: hap files have different appIdentifier");
                return true;
            }
        return false;
    });
    return !isInvalid;
}

bool BundleInstallChecker::VaildInstallPermission(const InstallParam &installParam,
    const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes)
{
    PermissionStatus installBundleStatus = installParam.installBundlePermissionStatus;
    PermissionStatus installEnterpriseBundleStatus = installParam.installEnterpriseBundlePermissionStatus;
    PermissionStatus installEtpMdmBundleStatus = installParam.installEtpMdmBundlePermissionStatus;
    bool isCallByShell = installParam.isCallByShell;
    if (!isCallByShell && installBundleStatus == PermissionStatus::HAVE_PERMISSION_STATUS &&
        installEnterpriseBundleStatus == PermissionStatus::HAVE_PERMISSION_STATUS &&
        installEtpMdmBundleStatus == PermissionStatus::HAVE_PERMISSION_STATUS) {
        return true;
    }
    for (uint32_t i = 0; i < hapVerifyRes.size(); ++i) {
        Security::Verify::ProvisionInfo provisionInfo = hapVerifyRes[i].GetProvisionInfo();
        if (provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE) {
            if (isCallByShell && provisionInfo.type != Security::Verify::ProvisionType::DEBUG) {
                APP_LOGE("enterprise bundle can not be installed by shell");
                return false;
            }
            if (!isCallByShell && installEnterpriseBundleStatus != PermissionStatus::HAVE_PERMISSION_STATUS) {
                APP_LOGE("install enterprise bundle permission denied");
                return false;
            }
            continue;
        }
        if (provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE_NORMAL ||
            provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE_MDM) {
            bool result = VaildEnterpriseInstallPermission(installParam, provisionInfo);
            if (!result) {
                return false;
            }
            continue;
        }
        if (installBundleStatus != PermissionStatus::HAVE_PERMISSION_STATUS) {
            APP_LOGE("install permission denied");
            return false;
        }
    }
    return true;
}

bool BundleInstallChecker::VaildEnterpriseInstallPermission(const InstallParam &installParam,
    const Security::Verify::ProvisionInfo &provisionInfo)
{
    if (installParam.isSelfUpdate) {
        if (provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE_MDM) {
            APP_LOGI("Mdm self update");
            return true;
        }
        APP_LOGE("Self update not MDM");
        return false;
    }
    bool isCallByShell = installParam.isCallByShell;
    PermissionStatus installEtpNormalBundleStatus = installParam.installEtpNormalBundlePermissionStatus;
    PermissionStatus installEtpMdmBundleStatus = installParam.installEtpMdmBundlePermissionStatus;
    if (isCallByShell && provisionInfo.type != Security::Verify::ProvisionType::DEBUG) {
        APP_LOGE("enterprise normal/mdm bundle can not be installed by shell");
        return false;
    }
    if (!isCallByShell &&
        provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE_NORMAL &&
        installEtpNormalBundleStatus != PermissionStatus::HAVE_PERMISSION_STATUS &&
        installEtpMdmBundleStatus != PermissionStatus::HAVE_PERMISSION_STATUS) {
        APP_LOGE("install enterprise normal bundle permission denied");
        return false;
    }
    if (!isCallByShell &&
        provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE_MDM &&
        installEtpMdmBundleStatus != PermissionStatus::HAVE_PERMISSION_STATUS) {
        APP_LOGE("install enterprise mdm bundle permission denied");
        return false;
    }
    return true;
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
        Security::Verify::ProvisionInfo provisionInfo = hapVerifyRes[i].GetProvisionInfo();
        bool isSystemApp = provisionInfo.bundleInfo.appFeature == Constants::HOS_SYSTEM_APP;
        if (isSystemApp) {
            newInfo.SetAppType(Constants::AppType::SYSTEM_APP);
        } else {
            newInfo.SetAppType(Constants::AppType::THIRD_PARTY_APP);
        }
        newInfo.SetIsPreInstallApp(checkParam.isPreInstallApp);
        result = ParseBundleInfo(bundlePaths[i], newInfo, packInfo);
        if (result != ERR_OK) {
            APP_LOGE("bundle parse failed %{public}d", result);
            return result;
        }
        newInfo.SetOrganization(provisionInfo.organization);
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
        // modify fingerprint to appId
        newInfo.SetProvisionId(provisionInfo.appId);
        FetchPrivilegeCapabilityFromPreConfig(
            newInfo.GetBundleName(), newInfo.GetAppId(), appPrivilegeCapability);
        // allow appIdentifier
        FetchPrivilegeCapabilityFromPreConfig(
            newInfo.GetBundleName(), provisionInfo.bundleInfo.appIdentifier, appPrivilegeCapability);
        // process bundleInfo by appPrivilegeCapability
        result = ProcessBundleInfoByPrivilegeCapability(appPrivilegeCapability, newInfo);
        if (result != ERR_OK) {
            return result;
        }
        CollectProvisionInfo(provisionInfo, appPrivilegeCapability, newInfo);
#ifdef USE_PRE_BUNDLE_PROFILE
        GetPrivilegeCapability(checkParam, newInfo);
#endif
        if ((provisionInfo.distributionType == Security::Verify::AppDistType::CROWDTESTING) ||
            (checkParam.specifiedDistributionType == Constants::APP_DISTRIBUTION_TYPE_CROWDTESTING)) {
            newInfo.SetAppCrowdtestDeadline((checkParam.crowdtestDeadline >= 0) ? checkParam.crowdtestDeadline :
                Constants::INHERIT_CROWDTEST_DEADLINE);
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

ErrCode BundleInstallChecker::CheckHspInstallCondition(
    std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes)
{
    ErrCode result = ERR_OK;
    if ((result = CheckDeveloperMode(hapVerifyRes)) != ERR_OK) {
        APP_LOGE("install failed due to debug mode");
        return result;
    }
    if ((result = CheckAllowEnterpriseBundle(hapVerifyRes)) != ERR_OK) {
        APP_LOGE("install failed due to non-enterprise device");
        return result;
    }
    return ERR_OK;
}

ErrCode BundleInstallChecker::CheckInstallPermission(const InstallCheckParam &checkParam,
    const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes)
{
    if ((checkParam.installBundlePermissionStatus != PermissionStatus::NOT_VERIFIED_PERMISSION_STATUS ||
        checkParam.installEnterpriseBundlePermissionStatus != PermissionStatus::NOT_VERIFIED_PERMISSION_STATUS ||
        checkParam.installEtpNormalBundlePermissionStatus != PermissionStatus::NOT_VERIFIED_PERMISSION_STATUS ||
        checkParam.installEtpMdmBundlePermissionStatus != PermissionStatus::NOT_VERIFIED_PERMISSION_STATUS) &&
        !VaildInstallPermissionForShare(checkParam, hapVerifyRes)) {
        // need vaild permission
        APP_LOGE("install permission denied");
        return ERR_APPEXECFWK_INSTALL_PERMISSION_DENIED;
    }
    return ERR_OK;
}

bool BundleInstallChecker::VaildInstallPermissionForShare(const InstallCheckParam &checkParam,
    const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes)
{
    PermissionStatus installBundleStatus = checkParam.installBundlePermissionStatus;
    PermissionStatus installEnterpriseBundleStatus = checkParam.installEnterpriseBundlePermissionStatus;
    PermissionStatus installEtpMdmBundleStatus = checkParam.installEtpMdmBundlePermissionStatus;
    bool isCallByShell = checkParam.isCallByShell;
    if (!isCallByShell && installBundleStatus == PermissionStatus::HAVE_PERMISSION_STATUS &&
        installEnterpriseBundleStatus == PermissionStatus::HAVE_PERMISSION_STATUS &&
        installEtpMdmBundleStatus == PermissionStatus::HAVE_PERMISSION_STATUS) {
        return true;
    }
    for (uint32_t i = 0; i < hapVerifyRes.size(); ++i) {
        Security::Verify::ProvisionInfo provisionInfo = hapVerifyRes[i].GetProvisionInfo();
        if (provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE) {
            if (isCallByShell && provisionInfo.type != Security::Verify::ProvisionType::DEBUG) {
                APP_LOGE("enterprise bundle can not be installed by shell");
                return false;
            }
            if (!isCallByShell && installEnterpriseBundleStatus != PermissionStatus::HAVE_PERMISSION_STATUS) {
                APP_LOGE("install enterprise bundle permission denied");
                return false;
            }
            continue;
        }
        if (provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE_NORMAL ||
            provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE_MDM) {
            bool result = VaildEnterpriseInstallPermissionForShare(checkParam, provisionInfo);
            if (!result) {
                return false;
            }
            continue;
        }
        if (installBundleStatus != PermissionStatus::HAVE_PERMISSION_STATUS) {
            APP_LOGE("install permission denied");
            return false;
        }
    }
    return true;
}

bool BundleInstallChecker::VaildEnterpriseInstallPermissionForShare(const InstallCheckParam &checkParam,
    const Security::Verify::ProvisionInfo &provisionInfo)
{
    bool isCallByShell = checkParam.isCallByShell;
    PermissionStatus installEtpNormalBundleStatus = checkParam.installEtpNormalBundlePermissionStatus;
    PermissionStatus installEtpMdmBundleStatus = checkParam.installEtpMdmBundlePermissionStatus;
    if (isCallByShell && provisionInfo.type != Security::Verify::ProvisionType::DEBUG) {
        APP_LOGE("enterprise normal/mdm bundle can not be installed by shell");
        return false;
    }
    if (!isCallByShell &&
        provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE_NORMAL &&
        installEtpNormalBundleStatus != PermissionStatus::HAVE_PERMISSION_STATUS &&
        installEtpMdmBundleStatus != PermissionStatus::HAVE_PERMISSION_STATUS) {
        APP_LOGE("install enterprise normal bundle permission denied");
        return false;
    }
    if (!isCallByShell &&
        provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE_MDM &&
        installEtpMdmBundleStatus != PermissionStatus::HAVE_PERMISSION_STATUS) {
        APP_LOGE("install enterprise mdm bundle permission denied");
        return false;
    }
    return true;
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
        APP_LOGD("current module:%{public}s, dependencies = %{public}s", moduleInfo.moduleName.c_str(),
            GetJsonStrFromInfo(moduleInfo.dependencies).c_str());
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
                    SetCheckResultMsg(
                        moduleInfo.moduleName + "'s dependent module: " + dependency.moduleName + " does not exist.");
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
        APP_LOGD("Cross-app dependencies, check dependency with shared bundle installer.");
        return false;
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
    APP_LOGD("FindModuleInInstalledPackage the moduleName is %{public}s, the bundleName is %{public}s",
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
    newInfo.AddOldAppId(newInfo.GetAppId());
    newInfo.SetAppIdentifier(provisionInfo.bundleInfo.appIdentifier);
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
    if (!BMSEventHandler::GetPreInstallCapability(preBundleConfigInfo)) {
        APP_LOGD("bundleName: %{public}s not exist in pre install capability list", newInfo.GetBundleName().c_str());
        return;
    }

    if (!MatchSignature(preBundleConfigInfo.appSignature, newInfo.GetCertificateFingerprint()) &&
        !MatchSignature(preBundleConfigInfo.appSignature, newInfo.GetAppId()) &&
        !MatchSignature(preBundleConfigInfo.appSignature, newInfo.GetAppIdentifier()) &&
        !MatchOldSignatures(newInfo.GetBundleName(), preBundleConfigInfo.appSignature)) {
        APP_LOGE("bundleName:%{public}s signature not match the capability list", newInfo.GetBundleName().c_str());
        return;
    }

    newInfo.SetKeepAlive(preBundleConfigInfo.keepAlive);
    newInfo.SetSingleton(preBundleConfigInfo.singleton);
    newInfo.SetRunningResourcesApply(preBundleConfigInfo.runningResourcesApply);
    newInfo.SetAssociatedWakeUp(preBundleConfigInfo.associatedWakeUp);
    newInfo.SetAllowCommonEvent(preBundleConfigInfo.allowCommonEvent);
    newInfo.SetResourcesApply(preBundleConfigInfo.resourcesApply);
    newInfo.SetAllowAppRunWhenDeviceFirstLocked(preBundleConfigInfo.allowAppRunWhenDeviceFirstLocked);
}

void BundleInstallChecker::SetPackInstallationFree(BundlePackInfo &bundlePackInfo,
    const InnerBundleInfo &innerBundleInfo) const
{
    if (innerBundleInfo.GetIsNewVersion()) {
        if (innerBundleInfo.GetApplicationBundleType() != BundleType::ATOMIC_SERVICE) {
            for (auto &item : bundlePackInfo.summary.modules) {
                item.distro.installationFree = false;
            }
            return;
        }
        for (auto &item : bundlePackInfo.summary.modules) {
            item.distro.installationFree = true;
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

    const auto extensions = info.GetInnerExtensionInfos();
    for (const auto &item : extensions) {
        if (item.second.type == ExtensionAbilityType::UNSPECIFIED &&
            !BMSEventHandler::CheckExtensionTypeInConfig(item.second.extensionTypeName)) {
            APP_LOGW("Parse error, There is no corresponding type in the configuration");
        }
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
    APP_LOGI("start");
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
    APP_LOGI("end");
}

ErrCode BundleInstallChecker::CheckSystemSize(
    const std::string &bundlePath,
    const Constants::AppType appType) const
{
    if ((appType == Constants::AppType::SYSTEM_APP) &&
        (BundleUtil::CheckSystemSize(bundlePath, APP_INSTALL_PATH))) {
        return ERR_OK;
    }

    if ((appType == Constants::AppType::THIRD_SYSTEM_APP) &&
        (BundleUtil::CheckSystemSize(bundlePath, APP_INSTALL_PATH))) {
        return ERR_OK;
    }

    if ((appType == Constants::AppType::THIRD_PARTY_APP) &&
        (BundleUtil::CheckSystemSize(bundlePath, APP_INSTALL_PATH))) {
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
    uint32_t versionCode = (infos.begin()->second).GetVersionCode();
    uint32_t minCompatibleVersionCode = (infos.begin()->second).GetMinCompatibleVersionCode();
    uint32_t target = (infos.begin()->second).GetTargetVersion();
    std::string releaseType = (infos.begin()->second).GetReleaseType();
    uint32_t compatible = (infos.begin()->second).GetCompatibleVersion();
    bool singleton = (infos.begin()->second).IsSingleton();
    Constants::AppType appType = (infos.begin()->second).GetAppType();
    bool isStage = (infos.begin()->second).GetIsNewVersion();
    const std::string targetBundleName = (infos.begin()->second).GetTargetBundleName();
    int32_t targetPriority = (infos.begin()->second).GetTargetPriority();
    BundleType bundleType = (infos.begin()->second).GetApplicationBundleType();
    bool isHmService = (infos.begin()->second).GetEntryInstallationFree();
    bool debug = (infos.begin()->second).GetBaseApplicationInfo().debug;
    bool hasEntry = (infos.begin()->second).HasEntry();
    bool isSameDebugType = true;
    bool entryDebug = hasEntry ? debug : false;

    for (const auto &info : infos) {
        // check bundleName
        if (bundleName != info.second.GetBundleName()) {
            return ERR_APPEXECFWK_INSTALL_BUNDLENAME_NOT_SAME;
        }
        // check version
        if (bundleType != BundleType::SHARED) {
            if (versionCode != info.second.GetVersionCode()) {
                return ERR_APPEXECFWK_INSTALL_VERSIONCODE_NOT_SAME;
            }
            if (minCompatibleVersionCode != info.second.GetMinCompatibleVersionCode()) {
                return ERR_APPEXECFWK_INSTALL_MINCOMPATIBLE_VERSIONCODE_NOT_SAME;
            }
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
        if (targetBundleName != info.second.GetTargetBundleName()) {
            return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_TARGET_BUNDLE_NAME_NOT_SAME;
        }
        if (targetPriority != info.second.GetTargetPriority()) {
            return ERR_BUNDLEMANAGER_OVERLAY_INSTALLATION_FAILED_TARGET_PRIORITY_NOT_SAME;
        }
        if (bundleType != info.second.GetApplicationBundleType()) {
            return ERR_APPEXECFWK_BUNDLE_TYPE_NOT_SAME;
        }
        if (isHmService != info.second.GetEntryInstallationFree()) {
            APP_LOGE("application and hm service are not allowed installed simultaneously.");
            return ERR_APPEXECFWK_INSTALL_TYPE_ERROR;
        }
        if (debug != info.second.GetBaseApplicationInfo().debug) {
            isSameDebugType = false;
        }
        if (!hasEntry) {
            hasEntry = info.second.HasEntry();
            entryDebug = info.second.GetBaseApplicationInfo().debug;
        }
    }

    if (hasEntry && !entryDebug && (debug || !isSameDebugType)) {
        return ERR_APPEXECFWK_INSTALL_DEBUG_NOT_SAME;
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
    const std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    std::set<std::string> moduleSet;
    for (const auto &info : infos) {
        std::vector<std::string> moduleVec = info.second.GetDistroModuleName();
        if (moduleVec.empty()) {
            APP_LOGE("moduleName vector is empty");
            return ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
        }
        if (moduleSet.count(moduleVec[0])) {
            APP_LOGE("the moduleName: %{public}s is not unique in the haps", moduleVec[0].c_str());
            SetCheckResultMsg("the moduleName: " + moduleVec[0] + " is not unique in the haps");
            return ERR_APPEXECFWK_INSTALL_NOT_UNIQUE_DISTRO_MODULE_NAME;
        }
        moduleSet.insert(moduleVec[0]);
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
        APP_LOGD("bundleName: %{public}s is not exist in pre install capability list", bundleName.c_str());
        return;
    }
    if (!MatchSignature(configInfo.appSignature, appSignature)) {
        if (!MatchOldSignatures(bundleName, configInfo.appSignature)) {
            APP_LOGE("bundleName: %{public}s signature verify failed in capability list", bundleName.c_str());
            return;
        }
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

    appPrivilegeCapability.allowMissionNotCleared = GetPrivilegeCapabilityValue(configInfo.existInJsonFile,
        ALLOW_MISSION_NOT_CLEARED,
        configInfo.allowMissionNotCleared, appPrivilegeCapability.allowMissionNotCleared);

    appPrivilegeCapability.formVisibleNotify = GetPrivilegeCapabilityValue(configInfo.existInJsonFile,
        ALLOW_FORM_VISIBLE_NOTIFY,
        configInfo.formVisibleNotify, appPrivilegeCapability.formVisibleNotify);

    appPrivilegeCapability.userDataClearable = GetPrivilegeCapabilityValue(configInfo.existInJsonFile,
        ALLOW_APP_DATA_NOT_CLEARED,
        configInfo.userDataClearable, appPrivilegeCapability.userDataClearable);

    appPrivilegeCapability.appShareLibrary = GetPrivilegeCapabilityValue(configInfo.existInJsonFile,
        ALLOW_APP_SHARE_LIBRARY,
        configInfo.appShareLibrary, appPrivilegeCapability.appShareLibrary);
    appPrivilegeCapability.allowEnableNotification = GetPrivilegeCapabilityValue(configInfo.existInJsonFile,
        ALLOW_ENABLE_NOTIFICATION,
        configInfo.allowEnableNotification, appPrivilegeCapability.allowEnableNotification);
    APP_LOGD("AppPrivilegeCapability %{public}s", appPrivilegeCapability.ToString().c_str());
#endif
}

bool BundleInstallChecker::MatchOldSignatures(const std::string &bundleName,
    const std::vector<std::string> &appSignatures)
{
    std::vector<std::string> oldAppIds;
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (!dataMgr->GetOldAppIds(bundleName, oldAppIds)) {
        APP_LOGE("Get OldAppIds failed.");
        return false;
    }
    for (const auto &signature : appSignatures) {
        if (std::find(oldAppIds.begin(), oldAppIds.end(), signature) != oldAppIds.end()) {
            return true;
        }
    }

    return false;
}

bool BundleInstallChecker::MatchSignature(
    const std::vector<std::string> &appSignatures, const std::string &signature)
{
    if (appSignatures.empty() || signature.empty()) {
        APP_LOGW("appSignature of signature is empty");
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
    applicationInfo.allowEnableNotification = appPrivilegeCapability.allowEnableNotification;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    BundleInfo bundleInfo = innerBundleInfo.GetBaseBundleInfo();
    // process allow app share library
    if (applicationInfo.bundleType == BundleType::SHARED && !appPrivilegeCapability.appShareLibrary) {
        APP_LOGE("not allow app share library");
        return ERR_APPEXECFWK_INSTALL_SHARE_APP_LIBRARY_NOT_ALLOWED;
    }
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
        if (!appPrivilegeCapability.allowMissionNotCleared) {
            iter->second.unclearableMission = false;
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
        if (appPrivilegeCapability.allowMultiProcess) {
            APP_LOGD("bundleName: %{public}s support allowMultiProcess", iter->second.bundleName.c_str());
            auto hapModuleInfo = innerBundleInfo.GetInnerModuleInfoByModuleName(iter->second.moduleName);
            if (hapModuleInfo && !hapModuleInfo->process.empty()) {
                iter->second.process = hapModuleInfo->process;
            }
        }
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

bool BundleInstallChecker::CheckSupportAppTypes(
    const std::unordered_map<std::string, InnerBundleInfo> &infos, const std::string &supportAppTypes) const
{
    APP_LOGD("CheckSupportAppTypes begin, supportAppTypes: %{public}s", supportAppTypes.c_str());
    std::vector<std::string> appTypesVec;
    OHOS::SplitStr(supportAppTypes, SUPPORT_APP_TYPES_SEPARATOR, appTypesVec);
    if (find(appTypesVec.begin(), appTypesVec.end(), DEVICE_TYPE_OF_DEFAULT) != appTypesVec.end() &&
        find(appTypesVec.begin(), appTypesVec.end(), DEVICE_TYPE_OF_PHONE) == appTypesVec.end()) {
        appTypesVec.emplace_back(DEVICE_TYPE_OF_PHONE);
    }
    sort(appTypesVec.begin(), appTypesVec.end());
    for (const auto &info : infos) {
        std::vector<std::string> devVec = info.second.GetDeviceType(info.second.GetCurrentModulePackage());
        if (find(devVec.begin(), devVec.end(), DEVICE_TYPE_OF_DEFAULT) != devVec.end() &&
            find(devVec.begin(), devVec.end(), DEVICE_TYPE_OF_PHONE) == devVec.end()) {
            devVec.emplace_back(DEVICE_TYPE_OF_PHONE);
        }
        sort(devVec.begin(), devVec.end());
        std::vector<std::string> intersectionVec;
        set_intersection(appTypesVec.begin(), appTypesVec.end(),
            devVec.begin(), devVec.end(), back_inserter(intersectionVec));
        if (intersectionVec.empty()) {
            APP_LOGW("check supportAppTypes failed");
            return false;
        }
    }
    return true;
}

ErrCode BundleInstallChecker::CheckDeviceType(std::unordered_map<std::string, InnerBundleInfo> &infos) const
{
    std::string supportAppTypes = OHOS::system::GetParameter(SUPPORT_APP_TYPES, "");
    if (!supportAppTypes.empty() && CheckSupportAppTypes(infos, supportAppTypes)) {
        return ERR_OK;
    }
    std::string deviceType = GetDeviceType();
    APP_LOGD("deviceType is %{public}s", deviceType.c_str());
    for (const auto &info : infos) {
        std::vector<std::string> devVec = info.second.GetDeviceType(info.second.GetCurrentModulePackage());
        if (devVec.empty()) {
            APP_LOGW("deviceTypes is empty");
            continue;
        }

        if ((deviceType == DEVICE_TYPE_OF_PHONE) &&
            (find(devVec.begin(), devVec.end(), DEVICE_TYPE_OF_DEFAULT) != devVec.end())) {
            APP_LOGW("current deviceType is phone and bundle is matched with default");
            continue;
        }

        if ((deviceType == DEVICE_TYPE_OF_DEFAULT) &&
            (find(devVec.begin(), devVec.end(), DEVICE_TYPE_OF_PHONE) != devVec.end())) {
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

AppProvisionInfo BundleInstallChecker::ConvertToAppProvisionInfo(
    const Security::Verify::ProvisionInfo &provisionInfo) const
{
    AppProvisionInfo appProvisionInfo;
    appProvisionInfo.versionCode = provisionInfo.versionCode;
    appProvisionInfo.versionName = provisionInfo.versionName;
    if (provisionInfo.type == Security::Verify::ProvisionType::DEBUG) {
        appProvisionInfo.type = Constants::APP_PROVISION_TYPE_DEBUG;
        appProvisionInfo.certificate = provisionInfo.bundleInfo.developmentCertificate;
    } else {
        appProvisionInfo.type = Constants::APP_PROVISION_TYPE_RELEASE;
        appProvisionInfo.certificate = provisionInfo.bundleInfo.distributionCertificate;
    }
    appProvisionInfo.appDistributionType = GetAppDistributionType(provisionInfo.distributionType);
    appProvisionInfo.apl = provisionInfo.bundleInfo.apl.empty() ? APL_NORMAL : provisionInfo.bundleInfo.apl;
    appProvisionInfo.developerId = provisionInfo.bundleInfo.developerId;
    appProvisionInfo.issuer = provisionInfo.issuer;
    appProvisionInfo.uuid = provisionInfo.uuid;
    appProvisionInfo.validity.notBefore = provisionInfo.validity.notBefore;
    appProvisionInfo.validity.notAfter = provisionInfo.validity.notAfter;
    appProvisionInfo.appIdentifier = provisionInfo.bundleInfo.appIdentifier;
    appProvisionInfo.appServiceCapabilities = provisionInfo.appServiceCapabilities;
    appProvisionInfo.organization = provisionInfo.organization;
    return appProvisionInfo;
}

std::string GetBundleNameFromUri(const std::string &uri)
{
    std::size_t firstSlashPos = uri.find(DOUBLE_SLASH);
    if (firstSlashPos == std::string::npos) {
        APP_LOGE("dataproxy uri is invalid");
        return Constants::EMPTY_STRING;
    }

    std::size_t secondSlashPos = uri.find(SLASH, firstSlashPos + SLAH_OFFSET);
    if (secondSlashPos == std::string::npos) {
        APP_LOGE("dataproxy uri is invalid");
        return Constants::EMPTY_STRING;
    }

    std::string bundleName = uri.substr(firstSlashPos + SLAH_OFFSET, secondSlashPos - firstSlashPos - SLAH_OFFSET);
    return bundleName;
}

bool BundleInstallChecker::CheckProxyPermissionLevel(const std::string &permissionName) const
{
    // no permission name, only for self usage
    if (permissionName.empty()) {
        return true;
    }
    PermissionDef permissionDef;
    ErrCode ret = BundlePermissionMgr::GetPermissionDef(permissionName, permissionDef);
    if (ret != ERR_OK) {
        APP_LOGE("getPermissionDef failed");
        return false;
    }
    if (permissionDef.availableLevel < Security::AccessToken::ATokenAplEnum::APL_SYSTEM_BASIC) {
        APP_LOGE("permission %{public}s level too low", permissionName.c_str());
        return false;
    }
    return true;
}

ErrCode BundleInstallChecker::CheckProxyDatas(const InnerBundleInfo &innerBundleInfo) const
{
    auto bundleName = innerBundleInfo.GetBundleName();
    auto moduleInfos = innerBundleInfo.GetInnerModuleInfos();
    if (moduleInfos.empty()) {
        return ERR_OK;
    }
    for (const auto &moduleInfo : moduleInfos) {
        for (const auto &proxyData : moduleInfo.second.proxyDatas) {
            auto name = GetBundleNameFromUri(proxyData.uri);
            if (bundleName != name) {
                APP_LOGE("bundleName from uri %{public}s different from origin bundleName %{public}s",
                    name.c_str(), bundleName.c_str());
                return ERR_APPEXECFWK_INSTALL_CHECK_PROXY_DATA_URI_FAILED;
            }
            if (innerBundleInfo.IsSystemApp()) {
                continue;
            }
            if (!CheckProxyPermissionLevel(proxyData.requiredReadPermission)
                    || !CheckProxyPermissionLevel(proxyData.requiredWritePermission)) {
                return ERR_APPEXECFWK_INSTALL_CHECK_PROXY_DATA_PERMISSION_FAILED;
            }
        }
    }
    return ERR_OK;
}

bool CheckSupportIsolation(const char *szIsolationModeThresholdMb, const std::string &isolationMode)
{
    if ((std::strcmp(szIsolationModeThresholdMb, VALUE_TRUE.c_str()) == 0) ||
        (std::strcmp(szIsolationModeThresholdMb, VALUE_TRUE_BOOL.c_str()) == 0)) {
        if (isolationMode == NONISOLATION_ONLY) {
            APP_LOGE("check isolation mode failed.");
            return false;
        }
    } else {
        if (isolationMode == ISOLATION_ONLY) {
            APP_LOGE("check isolation mode failed.");
            return false;
        }
    }
    return true;
}

ErrCode BundleInstallChecker::CheckIsolationMode(const std::unordered_map<std::string, InnerBundleInfo> &infos) const
{
    for (const auto &info : infos) {
        auto moduleInfos = info.second.GetInnerModuleInfos();
        for (const auto &moduleInfo : moduleInfos) {
            std::string isolationMode = moduleInfo.second.isolationMode;
            char szIsolationModeThresholdMb[THRESHOLD_VAL_LEN] = {0};
            int32_t ret = GetParameter(SUPPORT_ISOLATION_MODE.c_str(), "",
                szIsolationModeThresholdMb, THRESHOLD_VAL_LEN);
            if (ret <= 0) {
                APP_LOGW("GetParameter failed");
            }
            if (!CheckSupportIsolation(szIsolationModeThresholdMb, isolationMode)) {
                APP_LOGE("check isolation mode failed.");
                return ERR_APPEXECFWK_INSTALL_ISOLATION_MODE_FAILED;
            }
        }
    }
    return ERR_OK;
}

ErrCode BundleInstallChecker::CheckSignatureFileDir(const std::string &signatureFileDir) const
{
    if (!BundleUtil::CheckFileName(signatureFileDir)) {
        APP_LOGE("code signature file dir is invalid");
        return ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID;
    }
    if (!BundleUtil::CheckFileType(signatureFileDir, Constants::CODE_SIGNATURE_FILE_SUFFIX)) {
        APP_LOGE("signatureFileDir is not suffixed with .sig");
        return ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID;
    }
    // signatureFileDir not support relevant dir
    if (signatureFileDir.find(Constants::RELATIVE_PATH) != std::string::npos) {
        APP_LOGE("signatureFileDir is invalid");
        return ERR_BUNDLEMANAGER_INSTALL_CODE_SIGNATURE_FILE_IS_INVALID;
    }
    return ERR_OK;
}

ErrCode BundleInstallChecker::CheckDeveloperMode(
    const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes) const
{
    if (system::GetBoolParameter(Constants::DEVELOPERMODE_STATE, true)) {
        return ERR_OK;
    }
    for (uint32_t i = 0; i < hapVerifyRes.size(); ++i) {
        Security::Verify::ProvisionInfo provisionInfo = hapVerifyRes[i].GetProvisionInfo();
        if (provisionInfo.type == Security::Verify::ProvisionType::DEBUG) {
            APP_LOGE("debug bundle can only be installed in developer mode");
            return ERR_APPEXECFWK_INSTALL_DEBUG_BUNDLE_NOT_ALLOWED;
        }
    }
    return ERR_OK;
}

ErrCode BundleInstallChecker::CheckAllowEnterpriseBundle(
    const std::vector<Security::Verify::HapVerifyResult> &hapVerifyRes) const
{
    if (system::GetBoolParameter(Constants::ALLOW_ENTERPRISE_BUNDLE, false) ||
        system::GetBoolParameter(Constants::IS_ENTERPRISE_DEVICE, false) ||
        system::GetBoolParameter(Constants::DEVELOPERMODE_STATE, false)) {
        return ERR_OK;
    }
    for (uint32_t i = 0; i < hapVerifyRes.size(); ++i) {
        Security::Verify::ProvisionInfo provisionInfo = hapVerifyRes[i].GetProvisionInfo();
        if (provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE_NORMAL ||
            provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE_MDM) {
            APP_LOGE("enterprise normal/mdm bundle cannot be installed on non-enterprise device");
            return ERR_APPEXECFWK_INSTALL_ENTERPRISE_BUNDLE_NOT_ALLOWED;
        }
    }
    return ERR_OK;
}

bool BundleInstallChecker::CheckEnterpriseBundle(Security::Verify::HapVerifyResult &hapVerifyRes) const
{
    Security::Verify::ProvisionInfo provisionInfo = hapVerifyRes.GetProvisionInfo();
    if (provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE_NORMAL ||
        provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE_MDM ||
        provisionInfo.distributionType == Security::Verify::AppDistType::ENTERPRISE) {
        return true;
    }
    return false;
}

std::string BundleInstallChecker::GetCheckResultMsg() const
{
    return checkResultMsg_;
}

void BundleInstallChecker::SetCheckResultMsg(const std::string checkResultMsg)
{
    checkResultMsg_ = checkResultMsg;
}
}  // namespace AppExecFwk
}  // namespace OHOS