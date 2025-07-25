/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_BUNDLE_INFO_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_BUNDLE_INFO_H

#include "nocopyable.h"

#include "ability_info.h"
#include "access_token.h"
#include "aot/aot_args.h"
#include "bundle_constants.h"
#include "bundle_info.h"
#include "bundle_service_constants.h"
#include "common_event_info.h"
#include "common_profile.h"
#include "data_group_info.h"
#include "data/inner_ability_info.h"
#include "data/inner_extension_info.h"
#include "distributed_bundle_info.h"
#include "dynamic_icon_info.h"
#include "extension_ability_info.h"
#include "form_info.h"
#include "hap_module_info.h"
#include "inner_app_quick_fix.h"
#include "inner_bundle_clone_info.h"
#include "inner_bundle_user_info.h"
#include "ipc/check_encryption_param.h"
#include "json_util.h"
#include "plugin/plugin_bundle_info.h"
#include "preinstalled_application_info.h"
#include "quick_fix/app_quick_fix.h"
#include "quick_fix/hqf_info.h"
#include "shared/base_shared_bundle_info.h"
#include "shared/shared_bundle_info.h"
#include "shortcut_info.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
struct Distro {
    bool deliveryWithInstall = false;
    bool installationFree = false;
    std::string moduleName;
    std::string moduleType;
};

struct DefinePermission {
    bool provisionEnable = true;
    bool distributedSceneEnable = false;
    bool isKernelEffect = false;
    bool hasValue = false;
    uint32_t labelId = 0;
    uint32_t descriptionId = 0;
    std::string name;
    std::string grantMode = Profile::DEFINEPERMISSION_GRANT_MODE_SYSTEM_GRANT;
    std::string availableLevel = Profile::DEFINEPERMISSION_AVAILABLE_LEVEL_DEFAULT_VALUE;
    std::string label;
    std::string description;
    std::string availableType;
};

struct InnerModuleInfo {
    bool isEntry = false;
    bool installationFree = false;
    bool isModuleJson = false;
    bool isStageBasedModel = false;
    bool isLibIsolated = false;
    bool compressNativeLibs = true;
    bool isEncrypted = false;
    bool asanEnabled = false;
    bool gwpAsanEnabled = false;
    bool tsanEnabled = false;
    bool needDelete = false;
    bool debug = false;
    bool resizeable = false;
    uint8_t boolSet = 0;
    uint32_t innerModuleInfoFlag = 0;
    uint32_t labelId = 0;
    uint32_t descriptionId = 0;
    uint32_t iconId = 0;
    uint32_t versionCode = 0;
    int32_t upgradeFlag = 0;
    int32_t targetPriority;
    BundleType bundleType = BundleType::SHARED;
    AOTCompileStatus aotCompileStatus = AOTCompileStatus::NOT_COMPILED;
    ModuleColorMode colorMode = ModuleColorMode::AUTO;
    std::string name;
    std::string modulePackage;
    std::string moduleName;
    std::string modulePath;
    std::string moduleDataDir;
    std::string moduleResPath;
    std::string moduleHnpsPath;
    std::string label;
    std::string hapPath;
    std::string description;
    std::string icon;
    std::string mainAbility; // config.json : mainAbility; module.json : mainElement
    std::string entryAbilityKey; // skills contains "action.system.home" and "entity.system.home"
    std::string srcPath;
    std::string hashValue;
    std::string pages;
    std::string systemTheme;
    std::string process;
    std::string srcEntrance;
    std::string uiSyntax;
    std::string virtualMachine;
    std::string compileMode;
    std::string nativeLibraryPath;
    std::string cpuAbi;
    std::string targetModuleName;
    std::string versionName;
    std::string buildHash;
    std::string isolationMode;
    std::string fileContextMenu;
    std::string routerMap;
    std::string packageName;
    std::string appStartup;
    std::string formExtensionModule;
    std::string formWidgetModule;
    std::string crossAppSharedConfig;
    std::string abilitySrcEntryDelegator;
    std::string abilityStageSrcEntryDelegator;
    std::string moduleArkTSMode = Constants::ARKTS_MODE_DYNAMIC;
    std::string arkTSMode = Constants::ARKTS_MODE_DYNAMIC;
    Distro distro;
    // all user's value of isRemovable
    // key:userId
    // value:isRemovable true or flase
    std::vector<std::string> reqCapabilities;
    std::vector<std::string> abilityKeys;
    std::vector<std::string> skillKeys;
    std::vector<std::string> deviceTypes;
    std::map<std::string, std::vector<std::string>> requiredDeviceFeatures;
    std::vector<std::string> extensionKeys;
    std::vector<std::string> extensionSkillKeys;
    std::vector<std::string> nativeLibraryFileNames;
    std::vector<std::string> querySchemes;
    std::vector<std::string> preloads;
    std::vector<HnpPackage> hnpPackages;
    // new version fields
    std::vector<DefinePermission> definePermissions;
    std::vector<RequestPermission> requestPermissions;
    std::vector<Metadata> metadata;
    std::vector<Dependency> dependencies;
    std::vector<OverlayModuleInfo> overlayModuleInfo;
    std::vector<ProxyData> proxyDatas;
    std::vector<AppEnvironment> appEnvironments;
    std::map<std::string, bool> isRemovable;
    MetaData metaData;
};

struct ExtendResourceInfo {
    uint32_t iconId = 0;
    std::string moduleName;
    std::string filePath;
};

enum InstallExceptionStatus : uint8_t {
    INSTALL_START = 1,
    INSTALL_FINISH,
    UPDATING_EXISTED_START,
    UPDATING_NEW_START,
    UPDATING_FINISH,
    UNINSTALL_BUNDLE_START,
    UNINSTALL_PACKAGE_START,
    UNKNOWN_STATUS,
};

enum class GetInnerModuleInfoFlag : uint8_t {
    GET_INNER_MODULE_INFO_WITH_HWASANENABLED = 1,
    GET_INNER_MODULE_INFO_WITH_UBSANENABLED = 2,
};

enum InnerModuleInfoBoolFlag : uint8_t {
    HAS_INTENT = 0,
    HAS_CLOUD_KIT_CONFIG = 1,
};

struct InstallMark {
    int32_t status = InstallExceptionStatus::UNKNOWN_STATUS;
    std::string bundleName;
    std::string packageName;
};
class InnerBundleInfo {
public:
    enum class BundleStatus : uint8_t {
        ENABLED = 1,
        DISABLED,
    };

    InnerBundleInfo();
    InnerBundleInfo &operator=(const InnerBundleInfo &info);
    ~InnerBundleInfo();
    /**
     * @brief Transform the InnerBundleInfo object to json.
     * @param jsonObject Indicates the obtained json object.
     * @return
     */
    void ToJson(nlohmann::json &jsonObject) const;
    /**
     * @brief Transform the json object to InnerBundleInfo object.
     * @param jsonObject Indicates the obtained json object.
     * @return Returns 0 if the json object parsed successfully; returns error code otherwise.
     */
    int32_t FromJson(const nlohmann::json &jsonObject);
    /**
     * @brief Add module info to old InnerBundleInfo object.
     * @param newInfo Indicates the new InnerBundleInfo object.
     * @return Returns true if the module successfully added; returns false otherwise.
     */
    bool AddModuleInfo(const InnerBundleInfo &newInfo);
    /**
     * @brief Update module info to old InnerBundleInfo object.
     * @param newInfo Indicates the new InnerBundleInfo object.
     * @return
     */
    void UpdateModuleInfo(const InnerBundleInfo &newInfo);
    /**
     * @brief Remove module info from InnerBundleInfo object.
     * @param modulePackage Indicates the module package to be remove.
     * @return
     */
    void RemoveModuleInfo(const std::string &modulePackage);
    /**
     * @brief Find hap module info by module package.
     * @param modulePackage Indicates the module package.
     * @param userId Indicates the user ID.
     * @return Returns the HapModuleInfo object if find it; returns null otherwise.
     */
    std::optional<HapModuleInfo> FindHapModuleInfo(
        const std::string &modulePackage, int32_t userId = Constants::UNSPECIFIED_USERID, int32_t appIndex = 0) const;
    /**
     * @brief Get module hashValue.
     * @param modulePackage Indicates the module package.
     * @param hapModuleInfo Indicates the hapModuleInfo.
     * @return
     */
    void GetModuleWithHashValue(
        int32_t flags, const std::string &modulePackage, HapModuleInfo &hapModuleInfo) const;
    /**
     * @brief Find abilityInfo by bundle name and ability name.
     * @param moduleName Indicates the module name
     * @param abilityName Indicates the ability name.
     * @param userId Indicates the user ID.
     * @return Returns the AbilityInfo object if find it; returns null otherwise.
     */
    std::optional<AbilityInfo> FindAbilityInfo(
        const std::string &moduleName,
        const std::string &abilityName,
        int32_t userId = Constants::UNSPECIFIED_USERID) const;
    /**
     * @brief Find abilityInfo by bundle name and ability name.
     * @param moduleName Indicates the module name
     * @param abilityName Indicates the ability name.
     * @return Returns the AbilityInfo object if find it; returns null otherwise.
     */
    std::optional<AbilityInfo> FindAbilityInfoV9(
        const std::string &moduleName, const std::string &abilityName) const;
    /**
     * @brief Find abilityInfo by bundle name module name and ability name.
     * @param moduleName Indicates the module name
     * @param abilityName Indicates the ability name.
     * @return Returns ERR_OK if abilityInfo find successfully obtained; returns other ErrCode otherwise.
     */
    ErrCode FindAbilityInfo(
        const std::string &moduleName, const std::string &abilityName, AbilityInfo &info) const;
    /**
     * @brief Find abilityInfo of list by bundle name.
     * @param bundleName Indicates the bundle name.
     * @param userId Indicates the user ID.
     * @return Returns the AbilityInfo of list if find it; returns null otherwise.
     */
    std::optional<std::vector<AbilityInfo>> FindAbilityInfos(
        int32_t userId = Constants::UNSPECIFIED_USERID) const;
    std::optional<AbilityInfo> FindAbilityInfo(const std::string continueType,
        int32_t userId = Constants::UNSPECIFIED_USERID) const;
    /**
     * @brief Find extensionInfo by bundle name and extension name.
     * @param moduleName Indicates the module name.
     * @param extensionName Indicates the extension name
     * @return Returns the ExtensionAbilityInfo object if find it; returns null otherwise.
     */
    std::optional<ExtensionAbilityInfo> FindExtensionInfo(
        const std::string &moduleName, const std::string &extensionName) const;
    /**
     * @brief Transform the InnerBundleInfo object to string.
     * @return Returns the string object
     */
    std::string ToString() const;
    /**
     * @brief Add InnerAbility infos to old InnerBundleInfo object.
     * @param abilityInfos Indicates the InnerAbilityInfo object to be add.
     * @return
     */
    void AddModuleAbilityInfo(const std::map<std::string, InnerAbilityInfo> &innerAbilityInfos)
    {
        for (const auto &item : innerAbilityInfos) {
            baseAbilityInfos_.try_emplace(item.first, item.second);
        }
    }

    void AddModuleExtensionInfos(const std::map<std::string, InnerExtensionInfo> &extensionInfos)
    {
        for (const auto &extensionInfo : extensionInfos) {
            baseExtensionInfos_.try_emplace(extensionInfo.first, extensionInfo.second);
        }
    }
    /**
     * @brief Add skill infos to old InnerBundleInfo object.
     * @param skillInfos Indicates the Skill object to be add.
     * @return
     */
    void AddModuleSkillInfo(const std::map<std::string, std::vector<Skill>> &skillInfos)
    {
        for (const auto &skills : skillInfos) {
            skillInfos_.try_emplace(skills.first, skills.second);
        }
    }
    void AddModuleExtensionSkillInfos(const std::map<std::string, std::vector<Skill>> &extensionSkillInfos)
    {
        for (const auto &skills : extensionSkillInfos) {
            extensionSkillInfos_.try_emplace(skills.first, skills.second);
        }
    }
    /**
     * @brief Add form infos to old InnerBundleInfo object.
     * @param formInfos Indicates the Forms object to be add.
     * @return
     */
    void AddModuleFormInfo(const std::map<std::string, std::vector<FormInfo>> &formInfos)
    {
        for (const auto &forms : formInfos) {
            formInfos_.try_emplace(forms.first, forms.second);
        }
    }
    /**
     * @brief Add common events to old InnerBundleInfo object.
     * @param commonEvents Indicates the Common Event object to be add.
     * @return
     */
    void AddModuleCommonEvent(const std::map<std::string, CommonEventInfo> &commonEvents)
    {
        for (const auto &commonEvent : commonEvents) {
            commonEvents_.try_emplace(commonEvent.first, commonEvent.second);
        }
    }
    /**
     * @brief Add shortcut infos to old InnerBundleInfo object.
     * @param shortcutInfos Indicates the Shortcut object to be add.
     * @return
     */
    void AddModuleShortcutInfo(const std::map<std::string, ShortcutInfo> &shortcutInfos)
    {
        for (const auto &shortcut : shortcutInfos) {
            shortcutInfos_.try_emplace(shortcut.first, shortcut.second);
        }
    }
    /**
     * @brief Add innerModuleInfos to old InnerBundleInfo object.
     * @param innerModuleInfos Indicates the InnerModuleInfo object to be add.
     * @return
     */
    void AddInnerModuleInfo(const std::map<std::string, InnerModuleInfo> &innerModuleInfos)
    {
        for (const auto &info : innerModuleInfos) {
            innerModuleInfos_.try_emplace(info.first, info.second);
        }
    }
    /**
     * @brief Get application name.
     * @return Return application name
     */
    std::string GetApplicationName() const
    {
        return baseApplicationInfo_->name;
    }
    /**
     * @brief Set bundle status.
     * @param status Indicates the BundleStatus object to set.
     * @return
     */
    void SetBundleStatus(const BundleStatus &status)
    {
        bundleStatus_ = status;
    }
    /**
     * @brief Get bundle status.
     * @return Return the BundleStatus object
     */
    BundleStatus GetBundleStatus() const
    {
        return bundleStatus_;
    }
    /**
     * @brief Set bundle install time.
     * @param time Indicates the install time to set.
     * @param userId Indicates the user ID.
     * @return
     */
    void SetBundleInstallTime(
        const int64_t time, int32_t userId = Constants::UNSPECIFIED_USERID);
    /**
     * @brief Get bundle install time.
     * @param userId Indicates the user ID.
     * @return Return the bundle install time.
     */
    int64_t GetBundleInstallTime(int32_t userId = Constants::UNSPECIFIED_USERID) const
    {
        InnerBundleUserInfo innerBundleUserInfo;
        if (!GetInnerBundleUserInfo(userId, innerBundleUserInfo)) {
            APP_LOGE("can not find userId %{public}d when GetBundleInstallTime", userId);
            return -1;
        }
        return innerBundleUserInfo.installTime;
    }
    /**
     * @brief Set bundle update time.
     * @param time Indicates the update time to set.
     * @param userId Indicates the user ID.
     * @return
     */
    void SetBundleUpdateTime(const int64_t time, int32_t userId = Constants::UNSPECIFIED_USERID);
    /**
     * @brief Get bundle update time.
     * @param userId Indicates the user ID.
     * @return Return the bundle update time.
     */
    int64_t GetBundleUpdateTime(int32_t userId = Constants::UNSPECIFIED_USERID) const
    {
        InnerBundleUserInfo innerBundleUserInfo;
        if (!GetInnerBundleUserInfo(userId, innerBundleUserInfo)) {
            APP_LOGE("can not find userId %{public}d when GetBundleUpdateTime", userId);
            return -1;
        }
        return innerBundleUserInfo.updateTime;
    }
    /**
     * @brief Set bundle first install time.
     * @param time Indicates the first install time to set.
     * @param userId Indicates the user ID.
     * @return
     */
    void SetFirstInstallTime(const int64_t time, int32_t userId);
    /**
     * @brief Get bundle name.
     * @return Return bundle name
     */
    const std::string GetBundleName() const
    {
        return baseApplicationInfo_->bundleName;
    }
    /**
     * @brief Get baseBundleInfo.
     * @return Return the BundleInfo object.
     */
    BundleInfo GetBaseBundleInfo() const
    {
        return *baseBundleInfo_;
    }
    /**
     * @brief Set baseBundleInfo.
     * @param bundleInfo Indicates the BundleInfo object.
     */
    void SetBaseBundleInfo(const BundleInfo &bundleInfo)
    {
        *baseBundleInfo_ = bundleInfo;
    }
    /**
     * @brief Update baseBundleInfo.
     * @param bundleInfo Indicates the new BundleInfo object.
     * @return
     */
    void UpdateBaseBundleInfo(const BundleInfo &bundleInfo, bool isEntry);
    /**
     * @brief Get baseApplicationInfo.
     * @return Return the ApplicationInfo object.
     */
    ApplicationInfo GetBaseApplicationInfo() const
    {
        return *baseApplicationInfo_;
    }
    /**
     * @brief Set baseApplicationInfo.
     * @param applicationInfo Indicates the ApplicationInfo object.
     */
    void SetBaseApplicationInfo(const ApplicationInfo &applicationInfo)
    {
        *baseApplicationInfo_ = applicationInfo;
    }
    /**
     * @brief Update baseApplicationInfo.
     * @param applicationInfo Indicates the ApplicationInfo object.
     * @param isEntry Indicates the isEntry.
     */
    void UpdateBaseApplicationInfo(const InnerBundleInfo &newInfo);
    /**
     * @brief Get application enabled.
     * @param userId Indicates the user ID.
     * @return Return whether the application is enabled.
     */
    bool GetApplicationEnabled(int32_t userId = Constants::UNSPECIFIED_USERID) const
    {
        InnerBundleUserInfo innerBundleUserInfo;
        if (!GetInnerBundleUserInfo(userId, innerBundleUserInfo)) {
            APP_LOGD("can not find userId %{public}d when GetApplicationEnabled", userId);
            return false;
        }
        PrintSetEnabledInfo(innerBundleUserInfo.bundleUserInfo.enabled, userId, 0, innerBundleUserInfo.bundleName,
            innerBundleUserInfo.bundleUserInfo.setEnabledCaller);
        return innerBundleUserInfo.bundleUserInfo.enabled;
    }

    ErrCode GetApplicationEnabledV9(int32_t userId, bool &isEnabled,
        int32_t appIndex = 0) const;
    /**
     * @brief Set application enabled.
     * @param userId Indicates the user ID.
     * @return Returns ERR_OK if the SetApplicationEnabled is successfully; returns error code otherwise.
     */
    ErrCode SetApplicationEnabled(bool enabled, const std::string &caller,
        int32_t userId = Constants::UNSPECIFIED_USERID);
    ErrCode SetCloneApplicationEnabled(bool enabled, int32_t appIndex, const std::string &caller, int32_t userId);
    ErrCode SetCloneAbilityEnabled(const std::string &moduleName, const std::string &abilityName,
        bool isEnabled, int32_t userId, int32_t appIndex);
    /**
     * @brief Get application code path.
     * @return Return the string object.
     */
    const std::string GetAppCodePath() const
    {
        return baseApplicationInfo_->codePath;
    }
    /**
     * @brief Set application code path.
     * @param codePath Indicates the code path to be set.
     */
    void SetAppCodePath(const std::string codePath)
    {
        baseApplicationInfo_->codePath = codePath;
    }
    /**
     * @brief Insert innerModuleInfos.
     * @param modulePackage Indicates the modulePackage object as key.
     * @param innerModuleInfo Indicates the InnerModuleInfo object as value.
     */
    void InsertInnerModuleInfo(const std::string &modulePackage, const InnerModuleInfo &innerModuleInfo)
    {
        innerModuleInfos_.try_emplace(modulePackage, innerModuleInfo);
    }

      /**
     * @brief replace innerModuleInfos.
     * @param modulePackage Indicates the modulePackage object as key.
     * @param innerModuleInfo Indicates the InnerModuleInfo object as value.
     */
    void ReplaceInnerModuleInfo(const std::string &modulePackage, const InnerModuleInfo &innerModuleInfo)
    {
        innerModuleInfos_[modulePackage] = innerModuleInfo;
    }
    /**
     * @brief Insert InnerAbilityInfo.
     * @param key bundleName.moduleName.abilityName
     * @param innerAbilityInfo value.
     */
    void InsertAbilitiesInfo(const std::string &key, const InnerAbilityInfo &innerAbilityInfo)
    {
        baseAbilityInfos_.emplace(key, innerAbilityInfo);
    }
    /**
     * @brief Insert InnerExtensionInfo.
     * @param key bundleName.moduleName.extensionName
     * @param extensionInfo value.
     */
    void InsertExtensionInfo(const std::string &key, const InnerExtensionInfo &extensionInfo)
    {
        baseExtensionInfos_.emplace(key, extensionInfo);
    }
    /**
     * @brief Insert ability skillInfos.
     * @param key bundleName.moduleName.abilityName
     * @param skills ability skills.
     */
    void InsertSkillInfo(const std::string &key, const std::vector<Skill> &skills)
    {
        skillInfos_.emplace(key, skills);
    }
    /**
     * @brief Insert extension skillInfos.
     * @param key bundleName.moduleName.extensionName
     * @param skills extension skills.
     */
    void InsertExtensionSkillInfo(const std::string &key, const std::vector<Skill> &skills)
    {
        extensionSkillInfos_.emplace(key, skills);
    }
    /**
     * @brief Find AbilityInfo object by Uri.
     * @param abilityUri Indicates the ability uri.
     * @param userId Indicates the user ID.
     * @return Returns the AbilityInfo object if find it; returns null otherwise.
     */
    std::optional<AbilityInfo> FindAbilityInfoByUri(const std::string &abilityUri) const
    {
        APP_LOGD("Uri is %{public}s", abilityUri.c_str());
        for (const auto &ability : baseAbilityInfos_) {
            auto abilityInfo = ability.second;
            if (abilityInfo.uri.size() < strlen(ServiceConstants::DATA_ABILITY_URI_PREFIX)) {
                continue;
            }

            auto configUri = abilityInfo.uri.substr(strlen(ServiceConstants::DATA_ABILITY_URI_PREFIX));
            APP_LOGD("configUri is %{public}s", configUri.c_str());
            if (configUri == abilityUri) {
                return InnerAbilityInfo::ConvertToAbilityInfo(abilityInfo);
            }
        }
        return std::nullopt;
    }

    bool FindExtensionAbilityInfoByUri(const std::string &uri, ExtensionAbilityInfo &extensionAbilityInfo) const
    {
        for (const auto &item : baseExtensionInfos_) {
            if (uri == item.second.uri) {
                extensionAbilityInfo = InnerExtensionInfo::ConvertToExtensionInfo(item.second);
                APP_LOGD("find target extension, bundleName : %{public}s, moduleName : %{public}s, name : %{public}s",
                    extensionAbilityInfo.bundleName.c_str(), extensionAbilityInfo.moduleName.c_str(),
                    extensionAbilityInfo.name.c_str());
                return true;
            }
        }
        return false;
    }

    /**
     * @brief Find AbilityInfo object by Uri.
     * @param abilityUri Indicates the ability uri.
     * @param userId Indicates the user ID.
     * @return Returns the AbilityInfo object if find it; returns null otherwise.
     */
    void FindAbilityInfosByUri(const std::string &abilityUri,
        std::vector<AbilityInfo> &abilityInfos,  int32_t userId = Constants::UNSPECIFIED_USERID)
    {
        APP_LOGI("Uri is %{public}s", abilityUri.c_str());
        for (auto &item : baseAbilityInfos_) {
            if (item.second.uri.size() < strlen(ServiceConstants::DATA_ABILITY_URI_PREFIX)) {
                continue;
            }

            auto configUri = item.second.uri.substr(strlen(ServiceConstants::DATA_ABILITY_URI_PREFIX));
            APP_LOGI("configUri is %{public}s", configUri.c_str());
            if (configUri == abilityUri) {
                AbilityInfo abilityInfo = InnerAbilityInfo::ConvertToAbilityInfo(item.second);
                GetApplicationInfo(
                    ApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION, userId, abilityInfo.applicationInfo);
                abilityInfos.emplace_back(abilityInfo);
            }
        }
        return;
    }
    /**
     * @brief Get all ability names in application.
     * @return Returns ability names.
     */
    auto GetAbilityNames() const
    {
        std::vector<std::string> abilityNames;
        for (auto &ability : baseAbilityInfos_) {
            abilityNames.emplace_back(ability.second.name);
        }
        return abilityNames;
    }

    bool GetCloudFileSyncEnabled() const
    {
        return baseApplicationInfo_->cloudFileSyncEnabled;
    }

    void SetCloudFileSyncEnabled(bool cloudFileSyncEnabled)
    {
        baseApplicationInfo_->cloudFileSyncEnabled = cloudFileSyncEnabled;
    }

    bool GetCloudStructuredDataSyncEnabled() const
    {
        return baseApplicationInfo_->cloudStructuredDataSyncEnabled;
    }

    void SetCloudStructuredDataSyncEnabled(bool cloudStructuredDataSyncEnabled)
    {
        baseApplicationInfo_->cloudStructuredDataSyncEnabled = cloudStructuredDataSyncEnabled;
    }

    /**
     * @brief Get version code in application.
     * @return Returns version code.
     */
    uint32_t GetVersionCode() const
    {
        return baseBundleInfo_->versionCode;
    }
    /**
     * @brief Get version name in application.
     * @return Returns version name.
     */
    std::string GetVersionName() const
    {
        return baseBundleInfo_->versionName;
    }
    /**
     * @brief Get vendor in application.
     * @return Returns vendor.
     */
    std::string GetVendor() const
    {
        return baseBundleInfo_->vendor;
    }
    /**
     * @brief Get comparible version in application.
     * @return Returns comparible version.
     */
    uint32_t GetCompatibleVersion() const
    {
        return baseBundleInfo_->compatibleVersion;
    }
    /**
     * @brief Get target version in application.
     * @return Returns target version.
     */
    uint32_t GetTargetVersion() const
    {
        return baseBundleInfo_->targetVersion;
    }
    /**
     * @brief Get release type in application.
     * @return Returns release type.
     */
    std::string GetReleaseType() const
    {
        return baseBundleInfo_->releaseType;
    }
    /**
     * @brief Get minCompatibleVersionCode in base bundleInfo.
     * @return Returns release type.
     */
    uint32_t GetMinCompatibleVersionCode() const
    {
        return baseBundleInfo_->minCompatibleVersionCode;
    }
    /**
     * @brief Get install mark in application.
     * @return Returns install mark.
     */
    void SetInstallMark(const std::string &bundleName, const std::string &packageName,
        const InstallExceptionStatus &status)
    {
        mark_.bundleName = bundleName;
        mark_.packageName = packageName;
        mark_.status = status;
    }
    /**
     * @brief Get install mark in application.
     * @return Returns install mark.
     */
    InstallMark GetInstallMark() const
    {
        return mark_;
    }
    /**
     * @brief Get application data dir.
     * @return Return the string object.
     */
    std::string GetAppDataDir() const
    {
        return baseApplicationInfo_->dataDir;
    }
    /**
     * @brief Set application data dir.
     * @param dataDir Indicates the data Dir to be set.
     */
    void SetAppDataDir(std::string dataDir)
    {
        baseApplicationInfo_->dataDir = dataDir;
    }
    /**
     * @brief Set application data base dir.
     * @param dataBaseDir Indicates the data base Dir to be set.
     */
    void SetAppDataBaseDir(std::string dataBaseDir)
    {
        baseApplicationInfo_->dataBaseDir = dataBaseDir;
    }
    /**
     * @brief Set application cache dir.
     * @param cacheDir Indicates the cache Dir to be set.
     */
    void SetAppCacheDir(std::string cacheDir)
    {
        baseApplicationInfo_->cacheDir = cacheDir;
    }

    int32_t GetUid(int32_t userId = Constants::UNSPECIFIED_USERID, int32_t appIndex = 0) const
    {
        InnerBundleUserInfo innerBundleUserInfo;
        if (!GetInnerBundleUserInfo(userId, innerBundleUserInfo)) {
            return Constants::INVALID_UID;
        }
        if (appIndex != 0) {
            auto iter = innerBundleUserInfo.cloneInfos.find(std::to_string(appIndex));
            if (iter != innerBundleUserInfo.cloneInfos.end()) {
                return iter->second.uid;
            }
            return Constants::INVALID_UID;
        }

        return innerBundleUserInfo.uid;
    }
    /**
     * @brief Get application gid.
     * @param userId Indicates the user ID.
     * @return Returns the gid.
     */
    int GetGid(int32_t userId = Constants::UNSPECIFIED_USERID) const
    {
        InnerBundleUserInfo innerBundleUserInfo;
        if (!GetInnerBundleUserInfo(userId, innerBundleUserInfo)) {
            return ServiceConstants::INVALID_GID;
        }

        if (innerBundleUserInfo.gids.empty()) {
            return ServiceConstants::INVALID_GID;
        }

        return innerBundleUserInfo.gids[0];
    }
    /**
     * @brief Get application AppType.
     * @return Returns the AppType.
     */
    Constants::AppType GetAppType() const
    {
        return appType_;
    }
    /**
     * @brief Set application AppType.
     * @param gid Indicates the AppType to be set.
     */
    void SetAppType(Constants::AppType appType)
    {
        appType_ = appType;
        if (appType_ == Constants::AppType::SYSTEM_APP) {
            baseApplicationInfo_->isSystemApp = true;
        } else {
            baseApplicationInfo_->isSystemApp = false;
        }
    }
    /**
     * @brief Get application user id.
     * @return Returns the user id.
     */
    int GetUserId() const
    {
        return userId_;
    }
    /**
     * @brief Set application user id.
     * @param gid Indicates the user id to be set.
     */
    void SetUserId(int userId)
    {
        userId_ = userId;
    }

    const std::unordered_set<int32_t> GetUsers() const
    {
        std::unordered_set<int32_t> userIds;
        for (const auto &userInfoItem : innerBundleUserInfos_) {
            userIds.insert(userInfoItem.second.bundleUserInfo.userId);
        }
        return userIds;
    }

    bool GetAllowMultiProcess() const
    {
        return baseApplicationInfo_->allowMultiProcess;
    }

    void SetAllowMultiProcess(bool allowMultiProcess)
    {
        baseApplicationInfo_->allowMultiProcess = allowMultiProcess;
    }

    // only used in install progress with newInfo
    std::string GetCurrentModulePackage() const
    {
        return currentPackage_;
    }
    void SetCurrentModulePackage(const std::string &modulePackage)
    {
        currentPackage_ = modulePackage;
    }
    void AddModuleSrcDir(const std::string &moduleSrcDir)
    {
        if (innerModuleInfos_.count(currentPackage_) == 1) {
            innerModuleInfos_.at(currentPackage_).modulePath = moduleSrcDir;
        }
    }
    void AddModuleDataDir(const std::string &moduleDataDir)
    {
        if (innerModuleInfos_.count(currentPackage_) == 1) {
            innerModuleInfos_.at(currentPackage_).moduleDataDir = moduleDataDir;
        }
    }

    void AddModuleResPath(const std::string &moduleSrcDir)
    {
        if (innerModuleInfos_.count(currentPackage_) == 1) {
            std::string moduleResPath;
            if (isNewVersion_) {
                moduleResPath = moduleSrcDir + ServiceConstants::PATH_SEPARATOR + ServiceConstants::RESOURCES_INDEX;
            } else {
                moduleResPath = moduleSrcDir + ServiceConstants::PATH_SEPARATOR + ServiceConstants::ASSETS_DIR +
                    ServiceConstants::PATH_SEPARATOR +innerModuleInfos_.at(currentPackage_).distro.moduleName +
                    ServiceConstants::PATH_SEPARATOR + ServiceConstants::RESOURCES_INDEX;
            }

            innerModuleInfos_.at(currentPackage_).moduleResPath = moduleResPath;
            for (auto &abilityInfo : baseAbilityInfos_) {
                abilityInfo.second.resourcePath = moduleResPath;
            }
            for (auto &extensionInfo : baseExtensionInfos_) {
                extensionInfo.second.resourcePath = moduleResPath;
            }
        }
    }

    void AddModuleHnpsPath(const std::string &moduleSrcDir)
    {
        if (innerModuleInfos_.count(currentPackage_) == 1) {
            std::string moduleHnpsPath = moduleSrcDir +  ServiceConstants::PATH_SEPARATOR +
                ServiceConstants::HNPS_FILE_PATH;
            innerModuleInfos_.at(currentPackage_).moduleHnpsPath = moduleHnpsPath;
        }
    }

    void SetModuleHapPath(const std::string &hapPath);

    const std::string GetModuleHapPath(const std::string &modulePackage) const
    {
        if (innerModuleInfos_.find(modulePackage) != innerModuleInfos_.end()) {
            return innerModuleInfos_.at(modulePackage).hapPath;
        }

        return Constants::EMPTY_STRING;
    }

    const std::string GetModuleName(const std::string &modulePackage) const
    {
        if (innerModuleInfos_.find(modulePackage) != innerModuleInfos_.end()) {
            return innerModuleInfos_.at(modulePackage).moduleName;
        }

        return Constants::EMPTY_STRING;
    }

    const std::string GetCurModuleName() const;
    bool IsBundleCrossAppSharedConfig() const;

    std::vector<DefinePermission> GetDefinePermissions() const
    {
        std::vector<DefinePermission> definePermissions;
        if (innerModuleInfos_.count(currentPackage_) == 1) {
            definePermissions = innerModuleInfos_.at(currentPackage_).definePermissions;
        }
        return definePermissions;
    }

    std::vector<RequestPermission> GetRequestPermissions() const
    {
        std::vector<RequestPermission> requestPermissions;
        if (innerModuleInfos_.count(currentPackage_) == 1) {
            requestPermissions = innerModuleInfos_.at(currentPackage_).requestPermissions;
        }
        return requestPermissions;
    }

    std::vector<DefinePermission> GetAllDefinePermissions() const;

    std::vector<RequestPermission> GetAllRequestPermissions() const;

    bool FindModule(std::string modulePackage) const
    {
        return (innerModuleInfos_.find(modulePackage) != innerModuleInfos_.end());
    }

    bool IsEntryModule(std::string modulePackage) const
    {
        if (FindModule(modulePackage)) {
            return innerModuleInfos_.at(modulePackage).isEntry;
        }
        return false;
    }

    std::string GetEntryModuleName() const;

    bool GetIsKeepAlive() const
    {
        return baseBundleInfo_->isKeepAlive;
    }

    void SetIsFreeInstallApp(bool isFreeInstall)
    {
        baseApplicationInfo_->isFreeInstallApp = isFreeInstall;
    }

    bool GetIsFreeInstallApp() const
    {
        return baseApplicationInfo_->isFreeInstallApp;
    }

    std::string GetMainAbility() const;

    void GetMainAbilityInfo(AbilityInfo &abilityInfo) const;

    std::string GetModuleDir(std::string modulePackage) const
    {
        if (innerModuleInfos_.find(modulePackage) != innerModuleInfos_.end()) {
            return innerModuleInfos_.at(modulePackage).modulePath;
        }
        return Constants::EMPTY_STRING;
    }

    std::string GetModuleDataDir(std::string modulePackage) const
    {
        if (innerModuleInfos_.find(modulePackage) != innerModuleInfos_.end()) {
            return innerModuleInfos_.at(modulePackage).moduleDataDir;
        }
        return Constants::EMPTY_STRING;
    }

    bool IsDisabled() const
    {
        return (bundleStatus_ == BundleStatus::DISABLED);
    }

    bool IsEnabled() const
    {
        return (bundleStatus_ == BundleStatus::ENABLED);
    }

    bool IsOnlyModule(const std::string &modulePackage)
    {
        if ((innerModuleInfos_.size() == 1) && (innerModuleInfos_.count(modulePackage) == 1)) {
            return true;
        }
        return false;
    }

    void SetProvisionId(const std::string &provisionId)
    {
        baseBundleInfo_->appId = baseBundleInfo_->name + Constants::FILE_UNDERLINE + provisionId;
    }

    std::string GetProvisionId() const
    {
        if (!baseBundleInfo_->appId.empty()) {
            return baseBundleInfo_->appId.substr(baseBundleInfo_->name.size() + 1);
        }
        return "";
    }

    std::string GetAppId() const
    {
        return baseBundleInfo_->appId;
    }

    void SetAppFeature(const std::string &appFeature)
    {
        appFeature_ = appFeature;
    }

    std::string GetAppFeature() const
    {
        return appFeature_;
    }

    void SetAppPrivilegeLevel(const std::string &appPrivilegeLevel)
    {
        if (appPrivilegeLevel.empty()) {
            return;
        }
        baseApplicationInfo_->appPrivilegeLevel = appPrivilegeLevel;
    }

    std::string GetAppPrivilegeLevel() const
    {
        return baseApplicationInfo_->appPrivilegeLevel;
    }

    bool HasEntry() const;

    bool IsHsp() const;

    /**
     * @brief Insert formInfo.
     * @param keyName Indicates object as key.
     * @param formInfos Indicates the formInfo object as value.
     */
    void InsertFormInfos(const std::string &keyName, const std::vector<FormInfo> &formInfos)
    {
        formInfos_.emplace(keyName, formInfos);
    }
    /**
     * @brief Insert commonEvent.
     * @param keyName Indicates object as key.
     * @param commonEvents Indicates the common event object as value.
     */
    void InsertCommonEvents(const std::string &keyName, const CommonEventInfo &commonEvents)
    {
        commonEvents_.emplace(keyName, commonEvents);
    }
    /**
     * @brief Insert shortcutInfos.
     * @param keyName Indicates object as key.
     * @param shortcutInfos Indicates the shortcutInfos object as value.
     */
    void InsertShortcutInfos(const std::string &keyName, const ShortcutInfo &shortcutInfos)
    {
        shortcutInfos_.emplace(keyName, shortcutInfos);
    }
    // use for new Info in updating progress
    void RestoreFromOldInfo(const InnerBundleInfo &oldInfo)
    {
        SetAppCodePath(oldInfo.GetAppCodePath());
    }
    void RestoreModuleInfo(const InnerBundleInfo &oldInfo)
    {
        if (oldInfo.FindModule(currentPackage_)) {
            innerModuleInfos_.at(currentPackage_).moduleDataDir = oldInfo.GetModuleDataDir(currentPackage_);
        }
    }

    void SetModuleHashValue(const std::string &hashValue)
    {
        if (innerModuleInfos_.count(currentPackage_) == 1) {
            innerModuleInfos_.at(currentPackage_).hashValue = hashValue;
        }
    }

    void SetModuleCpuAbi(const std::string &cpuAbi)
    {
        if (innerModuleInfos_.count(currentPackage_) == 1) {
            innerModuleInfos_.at(currentPackage_).cpuAbi = cpuAbi;
        }
    }

    void SetModuleNativeLibraryPath(const std::string &nativeLibraryPath)
    {
        if (innerModuleInfos_.count(currentPackage_) == 1) {
            innerModuleInfos_.at(currentPackage_).nativeLibraryPath = nativeLibraryPath;
        }
    }

    /**
     * @brief Set ability enabled.
     * @param moduleName Indicates the moduleName.
     * @param abilityName Indicates the abilityName.
     * @param isEnabled Indicates the ability enabled.
     * @param userId Indicates the user id.
     * @return Returns ERR_OK if the setAbilityEnabled is successfully; returns error code otherwise.
     */
    ErrCode SetAbilityEnabled(
        const std::string &moduleName,
        const std::string &abilityName,
        bool isEnabled,
        int32_t userId);
    /**
     * @brief Set the Application Need Recover object
     * @param moduleName Indicates the module name of the application.
     * @param upgradeFlag Indicates the module is need update or not.
     * @return Return ERR_OK if set data successfully.
     */
    ErrCode SetModuleUpgradeFlag(std::string moduleName, int32_t upgradeFlag);

    /**
     * @brief Get the Application Need Recover object
     * @param moduleName Indicates the module name of the application.
     * @return upgradeFlag type,NOT_UPGRADE means not need to be upgraded,SINGLE_UPGRADE means
     *         single module need to be upgraded,RELATION_UPGRADE means relation module need to be upgraded.
     */
    int32_t GetModuleUpgradeFlag(std::string moduleName) const;

    void GetApplicationInfo(int32_t flags, int32_t userId, ApplicationInfo &appInfo, int32_t appIndex = 0) const;
    ErrCode GetApplicationInfoV9(int32_t flags, int32_t userId, ApplicationInfo &appInfo, int32_t appIndex = 0) const;
    bool GetBundleInfo(int32_t flags, BundleInfo &bundleInfo, int32_t userId = Constants::UNSPECIFIED_USERID,
        int32_t appIndex = 0) const;
    ErrCode GetBundleInfoV9(int32_t flags,
        BundleInfo &bundleInfo, int32_t userId = Constants::UNSPECIFIED_USERID, int32_t appIndex = 0) const;
    bool CheckSpecialMetaData(const std::string &metaData) const;
    /**
     * @brief Obtains the FormInfo objects provided by all applications on the device.
     * @param moduleName Indicates the module name of the application.
     * @param formInfos List of FormInfo objects if obtained;
     */
    void GetFormsInfoByModule(const std::string &moduleName, std::vector<FormInfo> &formInfos) const;
    /**
     * @brief Obtains the FormInfo objects provided by a specified application on the device.
     * @param formInfos List of FormInfo objects if obtained;
     */
    void GetFormsInfoByApp(std::vector<FormInfo> &formInfos) const;
    /**
     * @brief Obtains the ShortcutInfo objects provided by a specified application on the device.
     * @param shortcutInfos List of ShortcutInfo objects if obtained.
     */
    void GetShortcutInfos(std::vector<ShortcutInfo> &shortcutInfos) const;
    /**
     * @brief Obtains the common event objects provided by a specified application on the device.
     * @param commonEvents List of common event objects if obtained.
     */
    void GetCommonEvents(const std::string &eventKey, std::vector<CommonEventInfo> &commonEvents) const;


    std::optional<InnerModuleInfo> GetInnerModuleInfoByModuleName(const std::string &moduleName) const;
    std::optional<std::vector<HnpPackage>> GetInnerModuleInfoHnpInfo(const std::string &moduleName) const;
    std::string GetInnerModuleInfoHnpPath(const std::string &moduleName) const;
    void GetModuleNames(std::vector<std::string> &moduleNames) const;

    void AddExtendResourceInfos(std::vector<ExtendResourceInfo> extendResourceInfos)
    {
        for (const auto &extendResourceInfo : extendResourceInfos) {
            extendResourceInfos_[extendResourceInfo.moduleName] = extendResourceInfo;
        }
    }

    void RemoveExtendResourceInfo(const std::string &moduleName)
    {
        auto iter = extendResourceInfos_.find(moduleName);
        if (iter != extendResourceInfos_.end()) {
            extendResourceInfos_.erase(iter);
        }
    }

    void RemoveExtendResourceInfos(const std::vector<std::string> &moduleNames)
    {
        for (const auto &moduleName : moduleNames) {
            RemoveExtendResourceInfo(moduleName);
        }
    }

    const std::map<std::string, ExtendResourceInfo> &GetExtendResourceInfos() const
    {
        return extendResourceInfos_;
    }

    const std::string GetCurDynamicIconModule() const;

    void SetCurDynamicIconModule(const std::string &curDynamicIconModule);

    const std::string GetCurDynamicIconModule(const int32_t userId, const int32_t appIndex) const;

    bool SetCurDynamicIconModule(const std::string &curDynamicIconModule,
        const int32_t userId, const int32_t appIndex);

    bool IsDynamicIconModuleExist() const;

    uint32_t GetIconId() const
    {
        return baseApplicationInfo_->iconId;
    }

    void SetIconId(uint32_t iconId)
    {
        baseApplicationInfo_->iconId = iconId;
    }

    const std::map<std::string, InnerModuleInfo> &GetInnerModuleInfos() const
    {
        return innerModuleInfos_;
    }
    /**
     * @brief Fetch all innerModuleInfos, can be modify.
     */
    std::map<std::string, InnerModuleInfo> &FetchInnerModuleInfos()
    {
        return innerModuleInfos_;
    }
    /**
     * @brief Fetch all abilityInfos, can be modify.
     */
    std::map<std::string, InnerAbilityInfo> &FetchAbilityInfos()
    {
        return baseAbilityInfos_;
    }
    /**
     * @brief Obtains all abilityInfos.
     */
    const std::map<std::string, InnerAbilityInfo> &GetInnerAbilityInfos() const
    {
        return baseAbilityInfos_;
    }
    /**
     * @brief Obtains all skillInfos.
     */
    const std::map<std::string, std::vector<Skill>> &GetInnerSkillInfos() const
    {
        return skillInfos_;
    }
    /**
     * @brief Fetch all extensionAbilityInfos, can be modify.
     */
    std::map<std::string, InnerExtensionInfo> &FetchInnerExtensionInfos()
    {
        return baseExtensionInfos_;
    }
    /**
     * @brief Obtains all innerExtensionInfos.
     */
    const std::map<std::string, InnerExtensionInfo> &GetInnerExtensionInfos() const
    {
        return baseExtensionInfos_;
    }
    /**
     * @brief Obtains all extensionSkillInfos.
     */
    const std::map<std::string, std::vector<Skill>> &GetExtensionSkillInfos() const
    {
        return  extensionSkillInfos_;
    }
    /**
     * @brief Get the bundle is whether removable.
     * @return Return whether the bundle is removable.
     */
    bool IsRemovable() const
    {
        return baseApplicationInfo_->removable;
    }
    void SetIsPreInstallApp(bool isPreInstallApp)
    {
        baseBundleInfo_->isPreInstallApp = isPreInstallApp;
    }
    bool IsPreInstallApp() const
    {
        return baseBundleInfo_->isPreInstallApp;
    }
    /**
     * @brief Get whether the bundle is a system app.
     * @return Return whether the bundle is a system app.
     */
    bool IsSystemApp() const
    {
        return baseApplicationInfo_->isSystemApp;
    }
    /**
     * @brief Get all InnerBundleUserInfo.
     * @return Return about all userinfo under the app.
     */
    const std::map<std::string, InnerBundleUserInfo>& GetInnerBundleUserInfos() const
    {
        return innerBundleUserInfos_;
    }
    /**
     * @brief Reset bundle state.
     * @param userId Indicates the userId to set.
     */
    void ResetBundleState(int32_t userId);
    /**
     * @brief Set userId to remove userinfo.
     * @param userId Indicates the userId to set.
     */
    void RemoveInnerBundleUserInfo(int32_t userId);
    /**
     * @brief Set userId to add userinfo.
     * @param userId Indicates the userInfo to set.
     */
    void AddInnerBundleUserInfo(const InnerBundleUserInfo& userInfo);
    /**
     * @brief Set userId to add userinfo.
     * @param userId Indicates the userInfo to set.
     * @param userInfo Indicates the userInfo to get.
     * @return Return whether the user information is obtained successfully.
     */
    bool GetInnerBundleUserInfo(int32_t userId, InnerBundleUserInfo& userInfo) const;
    /**
     * @brief  Check whether the user exists.
     * @param userId Indicates the userInfo to set.
     * @return Return whether the user exists..
     */
    bool HasInnerBundleUserInfo(int32_t userId) const;
    /**
     * @brief  Check whether onlyCreateBundleUser.
     * @return Return onlyCreateBundleUser.
     */
    bool IsOnlyCreateBundleUser() const
    {
        return onlyCreateBundleUser_;
    }
    /**
     * @brief Set onlyCreateBundleUser.
     * @param onlyCreateBundleUser Indicates the onlyCreateBundleUser.
     */
    void SetOnlyCreateBundleUser(bool onlyCreateBundleUser)
    {
        onlyCreateBundleUser_ = onlyCreateBundleUser;
    }
    /**
     * @brief Check whether isSingleton.
     * @return Return isSingleton.
     */
    bool IsSingleton() const
    {
        return baseApplicationInfo_->singleton;
    }
    /**
     * @brief Get response userId.
     * @param userId Indicates the request userId..
     * @return Return response userId.
     */
    int32_t GetResponseUserId(int32_t requestUserId) const;

    std::vector<std::string> GetModuleNameVec() const
    {
        std::vector<std::string> moduleVec;
        for (const auto &it : innerModuleInfos_) {
            moduleVec.emplace_back(it.first);
        }
        return moduleVec;
    }

    uint32_t GetAccessTokenId(const int32_t userId) const
    {
        InnerBundleUserInfo userInfo;
        if (GetInnerBundleUserInfo(userId, userInfo)) {
            return userInfo.accessTokenId;
        }
        return 0;
    }

    void SetAccessTokenId(uint32_t accessToken, const int32_t userId);

    uint64_t GetAccessTokenIdEx(const int32_t userId) const
    {
        InnerBundleUserInfo userInfo;
        if (GetInnerBundleUserInfo(userId, userInfo)) {
            return userInfo.accessTokenIdEx;
        }
        return 0;
    }

    void SetAccessTokenIdEx(const Security::AccessToken::AccessTokenIDEx accessTokenIdEx, const int32_t userId);

    void SetAccessTokenIdExWithAppIndex(
        const Security::AccessToken::AccessTokenIDEx accessTokenIdEx,
        const int32_t userId, const int32_t appIndex);

    void SetIsNewVersion(bool flag)
    {
        isNewVersion_ = flag;
    }

    bool GetIsNewVersion() const
    {
        return isNewVersion_;
    }

    bool GetAsanEnabled() const
    {
        return baseApplicationInfo_->asanEnabled;
    }

    void SetAsanEnabled(bool asanEnabled)
    {
        baseApplicationInfo_->asanEnabled = asanEnabled;
    }

    void SetAllowedAcls(const std::vector<std::string> &allowedAcls)
    {
        allowedAcls_.clear();
        for (const auto &acl : allowedAcls) {
            if (!acl.empty()) {
                allowedAcls_.emplace_back(acl);
            }
        }
    }

    std::vector<std::string> GetAllowedAcls() const
    {
        return allowedAcls_;
    }

    bool IsU1Enable() const
    {
        auto iter = std::find(allowedAcls_.begin(), allowedAcls_.end(),
            std::string(Constants::PERMISSION_U1_ENABLED));
        if (iter != allowedAcls_.end()) {
            return true;
        }
        return false;
    }

    /**
     * @brief ability is enabled.
     * @param abilityInfo Indicates the abilityInfo.
     * @param userId Indicates the user Id.
     * @return Return set ability enabled result.
     */
    bool IsAbilityEnabled(const AbilityInfo &abilityInfo, int32_t userId,
        int32_t appIndex = 0) const;
    ErrCode IsAbilityEnabledV9(const AbilityInfo &abilityInfo,
        int32_t userId, bool &isEnable, int32_t appIndex = 0) const;

    bool IsAccessible() const
    {
        return baseApplicationInfo_->accessible;
    }

    bool GetDependentModuleNames(const std::string &moduleName, std::vector<std::string> &dependentModuleNames) const;

    bool GetAllDependentModuleNames(const std::string &moduleName,
        std::vector<std::string> &dependentModuleNames) const;

    bool IsBundleRemovable() const;
    /**
     * @brief Which modules can be removed.
     * @param moduleToDelete Indicates the modules.
     * @return Return get module isRemoved result
     */
    bool GetRemovableModules(std::vector<std::string> &moduleToDelete) const;
    /**
     * @brief Get freeInstall module.
     * @param freeInstallModule Indicates the modules.
     * @return Return get freeInstall module result
     */
    bool GetFreeInstallModules(std::vector<std::string> &freeInstallModule) const;
    /**
     * @brief Whether module of userId is exist.
     * @param moduleName Indicates the moduleName.
     * @param userId Indicates the userId.
     * @return Return get module exist result.
     */
    bool IsUserExistModule(const std::string &moduleName, int32_t userId) const;
    /**
     * @brief whether userId's module should be removed.
     * @param moduleName Indicates the moduleName.
     * @param userId Indicates the userId.
     * @param isRemovable Indicates the module whether is removable.
     * @return Return get module isRemoved result.
     */
    ErrCode IsModuleRemovable(const std::string &moduleName, int32_t userId, bool &isRemovable) const;
    /**
     * @brief Add module removable info
     * @param info Indicates the innerModuleInfo of module.
     * @param stringUserId Indicates the string userId add to isRemovable map.
     * @param isEnable Indicates the value of enable module is removed.
     * @return Return add module isRemovable info result.
     */
    bool AddModuleRemovableInfo(InnerModuleInfo &info, const std::string &stringUserId, bool isEnable) const;
    /**
     * @brief Set userId's module value of isRemoved.
     * @param moduleName Indicates the moduleName.
     * @param isEnable Indicates the module isRemovable is enable.
     * @param userId Indicates the userId.
     * @return Return set module isRemoved result.
     */
    bool SetModuleRemovable(const std::string &moduleName, bool isEnable, int32_t userId);
    /**
     * @brief Delete userId isRemoved info from module.
     * @param moduleName Indicates the moduleName.
     * @param userId Indicates the userId.
     * @return
     */
    void DeleteModuleRemovable(const std::string &moduleName, int32_t userId);
    /**
     * @brief Delete removable info.
     * @param info Indicates the innerModuleInfo of module.
     * @param stringUserId Indicates the string userId of isRemovable map.
     * @return
     */
    void DeleteModuleRemovableInfo(InnerModuleInfo &info, const std::string &stringUserId);

    /**
     * @brief Set atomic service resizeable.
     * @param moduleName Indicates the moduleName.
     * @param resizeable Indicates the atomic service resizeable.
     * @return Return set atomic service resizeable result.
     */
    bool SetInnerModuleAtomicResizeable(const std::string &moduleName, bool resizeable);

    void SetEntryInstallationFree(bool installationFree)
    {
        baseBundleInfo_->entryInstallationFree = installationFree;
        if (installationFree) {
            baseApplicationInfo_->needAppDetail = false;
            baseApplicationInfo_->appDetailAbilityLibraryPath = Constants::EMPTY_STRING;
        }
    }

    bool GetEntryInstallationFree() const
    {
        return baseBundleInfo_->entryInstallationFree;
    }

    void SetBundlePackInfo(const BundlePackInfo &bundlePackInfo)
    {
        *bundlePackInfo_ = bundlePackInfo;
    }

    BundlePackInfo GetBundlePackInfo() const
    {
        return *bundlePackInfo_;
    }

    void SetAppIndex(int32_t appIndex)
    {
        appIndex_ = appIndex;
    }

    int32_t GetAppIndex() const
    {
        return appIndex_;
    }

    void SetIsSandbox(bool isSandbox)
    {
        isSandboxApp_ = isSandbox;
    }

    bool GetIsSandbox() const
    {
        return isSandboxApp_;
    }

    void CleanInnerBundleUserInfos()
    {
        innerBundleUserInfos_.clear();
    }

    std::string GetCertificateFingerprint() const
    {
        return baseApplicationInfo_->fingerprint;
    }

    void SetCertificateFingerprint(const std::string &fingerprint)
    {
        baseApplicationInfo_->fingerprint = fingerprint;
    }

    const std::string &GetNativeLibraryPath() const
    {
        return baseApplicationInfo_->nativeLibraryPath;
    }

    void SetNativeLibraryPath(const std::string &nativeLibraryPath)
    {
        baseApplicationInfo_->nativeLibraryPath = nativeLibraryPath;
    }

    const std::string &GetArkNativeFileAbi() const
    {
        return baseApplicationInfo_->arkNativeFileAbi;
    }

    void SetArkNativeFileAbi(const std::string &arkNativeFileAbi)
    {
        baseApplicationInfo_->arkNativeFileAbi = arkNativeFileAbi;
    }

    const std::string &GetArkNativeFilePath() const
    {
        return baseApplicationInfo_->arkNativeFilePath;
    }

    void SetArkNativeFilePath(const std::string &arkNativeFilePath)
    {
        baseApplicationInfo_->arkNativeFilePath = arkNativeFilePath;
    }

    void SetAllowAppRunWhenDeviceFirstLocked(bool allowAppRunWhenDeviceFirstLocked)
    {
        baseApplicationInfo_->allowAppRunWhenDeviceFirstLocked = allowAppRunWhenDeviceFirstLocked;
    }

    void SetAllowEnableNotification(bool allowEnableNotification)
    {
        baseApplicationInfo_->allowEnableNotification = allowEnableNotification;
    }

    const std::string &GetCpuAbi() const
    {
        return baseApplicationInfo_->cpuAbi;
    }

    void SetCpuAbi(const std::string &cpuAbi)
    {
        baseApplicationInfo_->cpuAbi = cpuAbi;
    }

    void SetRemovable(bool removable)
    {
        baseApplicationInfo_->removable = removable;
    }

    void SetKeepAlive(bool keepAlive)
    {
        baseApplicationInfo_->keepAlive = keepAlive;
        baseBundleInfo_->isKeepAlive = keepAlive;
    }

    void SetSingleton(bool singleton)
    {
        baseApplicationInfo_->singleton = singleton;
        baseBundleInfo_->singleton = singleton;
    }

    void SetRunningResourcesApply(bool runningResourcesApply)
    {
        baseApplicationInfo_->runningResourcesApply = runningResourcesApply;
    }

    void SetAssociatedWakeUp(bool associatedWakeUp)
    {
        baseApplicationInfo_->associatedWakeUp = associatedWakeUp;
    }

    void SetUserDataClearable(bool userDataClearable)
    {
        baseApplicationInfo_->userDataClearable = userDataClearable;
    }

    void SetHideDesktopIcon(bool hideDesktopIcon)
    {
        baseApplicationInfo_->hideDesktopIcon = hideDesktopIcon;
        if (hideDesktopIcon) {
            baseApplicationInfo_->needAppDetail = false;
            baseApplicationInfo_->appDetailAbilityLibraryPath = Constants::EMPTY_STRING;
        }
    }

    void SetFormVisibleNotify(bool formVisibleNotify)
    {
        baseApplicationInfo_->formVisibleNotify = formVisibleNotify;
    }

    void SetAllowCommonEvent(const std::vector<std::string> &allowCommonEvent)
    {
        baseApplicationInfo_->allowCommonEvent.clear();
        for (const auto &event : allowCommonEvent) {
            baseApplicationInfo_->allowCommonEvent.emplace_back(event);
        }
    }

    std::vector<OverlayBundleInfo> GetOverlayBundleInfo() const
    {
        return overlayBundleInfo_;
    }

    void AddOverlayBundleInfo(const OverlayBundleInfo &overlayBundleInfo)
    {
        auto iterator = std::find_if(overlayBundleInfo_.begin(), overlayBundleInfo_.end(),
            [&overlayBundleInfo](const auto &overlayInfo) {
                return overlayInfo.bundleName == overlayBundleInfo.bundleName;
        });
        if (iterator != overlayBundleInfo_.end()) {
            overlayBundleInfo_.erase(iterator);
        }
        overlayBundleInfo_.emplace_back(overlayBundleInfo);
    }

    void RemoveOverLayBundleInfo(const std::string &bundleName)
    {
        auto iterator = std::find_if(overlayBundleInfo_.begin(), overlayBundleInfo_.end(),
            [&bundleName](const auto &overlayInfo) {
                return overlayInfo.bundleName == bundleName;
        });
        if (iterator != overlayBundleInfo_.end()) {
            overlayBundleInfo_.erase(iterator);
        }
    }

    void CleanOverLayBundleInfo()
    {
        overlayBundleInfo_.clear();
    }

    std::string GetTargetBundleName() const
    {
        return baseApplicationInfo_->targetBundleName;
    }

    void SetTargetBundleName(const std::string &targetBundleName)
    {
        baseApplicationInfo_->targetBundleName = targetBundleName;
    }

    int32_t GetTargetPriority() const
    {
        return baseApplicationInfo_->targetPriority;
    }

    void SetTargetPriority(int32_t priority)
    {
        baseApplicationInfo_->targetPriority = priority;
    }

    int32_t GetOverlayState() const
    {
        return baseApplicationInfo_->overlayState;
    }

    void SetOverlayState(int32_t state)
    {
        baseApplicationInfo_->overlayState = state;
    }

    int32_t GetOverlayType() const
    {
        return overlayType_;
    }

    void SetOverlayType(int32_t type)
    {
        overlayType_ = type;
    }

    void AddOverlayModuleInfo(const OverlayModuleInfo &overlayModuleInfo)
    {
        auto iterator = innerModuleInfos_.find(overlayModuleInfo.targetModuleName);
        if (iterator == innerModuleInfos_.end()) {
            return;
        }
        auto innerModuleInfo = iterator->second;
        auto overlayModuleInfoIt = std::find_if(innerModuleInfo.overlayModuleInfo.begin(),
            innerModuleInfo.overlayModuleInfo.end(), [&overlayModuleInfo](const auto &overlayInfo) {
            return (overlayInfo.moduleName == overlayModuleInfo.moduleName) &&
                (overlayInfo.bundleName == overlayModuleInfo.bundleName);
        });
        if (overlayModuleInfoIt != innerModuleInfo.overlayModuleInfo.end()) {
            innerModuleInfo.overlayModuleInfo.erase(overlayModuleInfoIt);
        }
        innerModuleInfo.overlayModuleInfo.emplace_back(overlayModuleInfo);
        innerModuleInfos_.erase(iterator);
        innerModuleInfos_.try_emplace(overlayModuleInfo.targetModuleName, innerModuleInfo);
    }

    void RemoveOverlayModuleInfo(const std::string &targetModuleName, const std::string &bundleName,
        const std::string &moduleName)
    {
        auto iterator = innerModuleInfos_.find(targetModuleName);
        if (iterator == innerModuleInfos_.end()) {
            return;
        }
        auto innerModuleInfo = iterator->second;
        auto overlayModuleInfoIt = std::find_if(innerModuleInfo.overlayModuleInfo.begin(),
            innerModuleInfo.overlayModuleInfo.end(), [&moduleName, &bundleName](const auto &overlayInfo) {
            return (overlayInfo.moduleName == moduleName) && (overlayInfo.bundleName == bundleName);
        });
        if (overlayModuleInfoIt == innerModuleInfo.overlayModuleInfo.end()) {
            return;
        }
        innerModuleInfo.overlayModuleInfo.erase(overlayModuleInfoIt);
        innerModuleInfos_.erase(iterator);
        innerModuleInfos_.try_emplace(targetModuleName, innerModuleInfo);
    }

    void RemoveAllOverlayModuleInfo(const std::string &bundleName)
    {
        for (auto &innerModuleInfo : innerModuleInfos_) {
            innerModuleInfo.second.overlayModuleInfo.erase(std::remove_if(
                innerModuleInfo.second.overlayModuleInfo.begin(), innerModuleInfo.second.overlayModuleInfo.end(),
                [&bundleName](const auto &overlayInfo) {
                    return overlayInfo.bundleName == bundleName;
                }), innerModuleInfo.second.overlayModuleInfo.end());
        }
    }

    void CleanAllOverlayModuleInfo()
    {
        for (auto &innerModuleInfo : innerModuleInfos_) {
            innerModuleInfo.second.overlayModuleInfo.clear();
        }
    }

    bool isOverlayModule(const std::string &moduleName) const
    {
        if (innerModuleInfos_.find(moduleName) == innerModuleInfos_.end()) {
            return true;
        }
        return !innerModuleInfos_.at(moduleName).targetModuleName.empty();
    }

    bool isExistedOverlayModule() const
    {
        for (const auto &innerModuleInfo : innerModuleInfos_) {
            if (!innerModuleInfo.second.targetModuleName.empty()) {
                return true;
            }
        }
        return false;
    }

    void KeepOldOverlayConnection(InnerBundleInfo &info)
    {
        auto &newInnerModuleInfos = info.FetchInnerModuleInfos();
        for (const auto &innerModuleInfo : innerModuleInfos_) {
            if ((!innerModuleInfo.second.overlayModuleInfo.empty()) &&
                (newInnerModuleInfos.find(innerModuleInfo.second.moduleName) != newInnerModuleInfos.end())) {
                newInnerModuleInfos[innerModuleInfo.second.moduleName].overlayModuleInfo =
                    innerModuleInfo.second.overlayModuleInfo;
                return;
            }
        }
    }

    void SetAsanLogPath(const std::string& asanLogPath)
    {
        baseApplicationInfo_->asanLogPath = asanLogPath;
    }

    std::string GetAsanLogPath() const
    {
        return baseApplicationInfo_->asanLogPath;
    }

    void SetApplicationBundleType(BundleType type)
    {
        baseApplicationInfo_->bundleType = type;
    }

    BundleType GetApplicationBundleType() const
    {
        return baseApplicationInfo_->bundleType;
    }

    bool SetInnerModuleAtomicPreload(const std::string &moduleName, const std::vector<std::string> &preloads)
    {
        if (innerModuleInfos_.find(moduleName) == innerModuleInfos_.end()) {
            APP_LOGE("innerBundleInfo does not contain the module");
            return false;
        }
        innerModuleInfos_.at(moduleName).preloads = preloads;
        return true;
    }

    void SetAppProvisionMetadata(const std::vector<Metadata> &metadatas)
    {
        provisionMetadatas_ = metadatas;
    }

    std::vector<Metadata> GetAppProvisionMetadata() const
    {
        return provisionMetadatas_;
    }

    const std::map<std::string, std::vector<InnerModuleInfo>> &GetInnerSharedModuleInfos() const
    {
        return innerSharedModuleInfos_;
    }

    std::vector<Dependency> GetDependencies() const
    {
        std::vector<Dependency> dependenciesList;
        for (auto it = innerModuleInfos_.begin(); it != innerModuleInfos_.end(); it++) {
            for (const auto &item : it->second.dependencies) {
                dependenciesList.emplace_back(item);
            }
        }
        return dependenciesList;
    }

    std::vector<std::string> GetAllHspModuleNamesForVersion(uint32_t versionCode) const
    {
        std::vector<std::string> hspModuleNames;
        for (const auto &[moduleName, modules] : innerSharedModuleInfos_) {
            for (const auto &item : modules) {
                if (item.versionCode == versionCode) {
                    hspModuleNames.emplace_back(moduleName);
                }
            }
        }
        return hspModuleNames;
    }

    void AddAllowedAcls(const std::vector<std::string> &allowedAcls);
    bool GetModuleBuildHash(const std::string &moduleName, std::string &buildHash) const
    {
        if (innerModuleInfos_.find(moduleName) == innerModuleInfos_.end()) {
            APP_LOGE("innerBundleInfo does not contain the module");
            return false;
        }
        buildHash = innerModuleInfos_.at(moduleName).buildHash;
        return true;
    }

    const std::unordered_map<std::string, std::vector<DataGroupInfo>> GetDataGroupInfos() const
    {
        return dataGroupInfos_;
    }

    void DeleteDataGroupInfo(const std::string &dataGroupId)
    {
        if (dataGroupInfos_.find(dataGroupId) == dataGroupInfos_.end()) {
            return;
        }
        dataGroupInfos_.erase(dataGroupId);
    }

    void AddDataGroupInfo(const std::string &dataGroupId, const DataGroupInfo &info);

    void RemoveGroupInfos(int32_t userId, const std::string &dataGroupId)
    {
        auto iter = dataGroupInfos_.find(dataGroupId);
        if (iter == dataGroupInfos_.end()) {
            return;
        }
        for (auto dataGroupIter = iter->second.begin(); dataGroupIter != iter->second.end(); dataGroupIter++) {
            if (dataGroupIter->userId == userId) {
                iter->second.erase(dataGroupIter);
                return;
            }
        }
    }

    void UpdateDataGroupInfos(const std::unordered_map<std::string, std::vector<DataGroupInfo>> &dataGroupInfos)
    {
        std::set<int32_t> userIdList;
        for (auto item = dataGroupInfos.begin(); item != dataGroupInfos.end(); item++) {
            for (const DataGroupInfo &info : item->second) {
                userIdList.insert(info.userId);
            }
        }

        std::vector<std::string> deletedGroupIds;
        for (auto &item : dataGroupInfos_) {
            if (dataGroupInfos.find(item.first) == dataGroupInfos.end()) {
                for (int32_t userId : userIdList) {
                    RemoveGroupInfos(userId, item.first);
                }
            }
            if (item.second.empty()) {
                deletedGroupIds.emplace_back(item.first);
            }
        }
        for (std::string groupId : deletedGroupIds) {
            dataGroupInfos_.erase(groupId);
        }
        for (auto item = dataGroupInfos.begin(); item != dataGroupInfos.end(); item++) {
            std::string dataGroupId = item->first;
            for (const DataGroupInfo &info : item->second) {
                AddDataGroupInfo(dataGroupId, info);
            }
        }
    }

    void SetApplicationReservedFlag(uint32_t flag)
    {
        baseApplicationInfo_->applicationReservedFlag |= flag;
    }

    void ClearApplicationReservedFlag(uint32_t flag)
    {
        baseApplicationInfo_->applicationReservedFlag &= ~flag;
    }

    uint32_t GetApplicationReservedFlag() const
    {
        return baseApplicationInfo_->applicationReservedFlag;
    }

    void SetGwpAsanEnabled(bool gwpAsanEnabled)
    {
        baseApplicationInfo_->gwpAsanEnabled = gwpAsanEnabled;
    }

    bool GetGwpAsanEnabled() const
    {
        return baseApplicationInfo_->gwpAsanEnabled;
    }

    bool GetTsanEnabled() const
    {
        return baseApplicationInfo_->tsanEnabled;
    }

    void SetTsanEnabled(bool tsanEnabled)
    {
        baseApplicationInfo_->tsanEnabled = tsanEnabled;
    }

    bool GetHwasanEnabled() const
    {
        return baseApplicationInfo_->hwasanEnabled;
    }

    void SetHwasanEnabled(bool hwasanEnabled)
    {
        baseApplicationInfo_->hwasanEnabled = hwasanEnabled;
    }

    bool GetUbsanEnabled() const
    {
        return baseApplicationInfo_->ubsanEnabled;
    }

    void SetUbsanEnabled(bool ubsanEnabled)
    {
        baseApplicationInfo_->ubsanEnabled = ubsanEnabled;
    }

    std::vector<ApplicationEnvironment> GetAppEnvironments() const
    {
        return baseApplicationInfo_->appEnvironments;
    }

    void SetAppEnvironments(std::vector<ApplicationEnvironment> appEnvironments)
    {
        baseApplicationInfo_->appEnvironments = appEnvironments;
    }

    std::vector<std::string> GetAssetAccessGroups() const
    {
        return baseApplicationInfo_->assetAccessGroups;
    }

    std::string GetDeveloperId() const
    {
        return developerId_;
    }

    int32_t GetMaxChildProcess() const
    {
        return baseApplicationInfo_->maxChildProcess;
    }

    void SetMaxChildProcess(int32_t maxChildProcess)
    {
        baseApplicationInfo_->maxChildProcess = maxChildProcess;
    }

    void SetOrganization(const std::string &organization)
    {
        baseApplicationInfo_->organization = organization;
    }

    int32_t GetMultiAppMaxCount() const
    {
        return baseApplicationInfo_->multiAppMode.maxCount;
    }

    MultiAppModeType GetMultiAppModeType() const
    {
        return baseApplicationInfo_->multiAppMode.multiAppModeType;
    }

    void SetInstallSource(const std::string &installSource)
    {
        baseApplicationInfo_->installSource = installSource;
    }

    bool IsInstalledForAllUser() const
    {
        return baseApplicationInfo_->installedForAllUser;
    }

    void SetInstalledForAllUser(bool installedForAllUser) const
    {
        // only update from false to true
        if (baseApplicationInfo_->installedForAllUser && !installedForAllUser) {
            APP_LOGI("origin value is true, return");
            return;
        }
        baseApplicationInfo_->installedForAllUser = installedForAllUser;
    }

    std::unordered_map<std::string, PluginBundleInfo> GetAllPluginBundleInfo() const
    {
        APP_LOGI("pluginBundleInfos size: %{public}zu", pluginBundleInfos_.size());
        return pluginBundleInfos_;
    }

    bool GetPluginBundleInfos(const int32_t userId,
        std::unordered_map<std::string, PluginBundleInfo> &pluginBundleInfos) const;
    void SetApplicationFlags(ApplicationInfoFlag flag);

    void UpdateExtensionSandboxInfo(const std::vector<std::string> &typeList);
    std::vector<std::string> GetAllExtensionDirsInSpecifiedModule(const std::string &moduleName) const;
    std::vector<std::string> GetAllExtensionDirs() const;
    void UpdateExtensionDataGroupInfo(const std::string &key, const std::vector<std::string> &dataGroupIds);
    void SetAppDistributionType(const std::string &appDistributionType);

    std::string GetAppDistributionType() const;

    void SetAppProvisionType(const std::string &appProvisionType);

    std::string GetAppProvisionType() const;

    void SetAppCrowdtestDeadline(int64_t crowdtestDeadline);

    int64_t GetAppCrowdtestDeadline() const;

    std::vector<std::string> GetDistroModuleName() const;

    std::string GetModuleNameByPackage(const std::string &packageName) const;

    std::string GetModuleTypeByPackage(const std::string &packageName) const;

    AppQuickFix GetAppQuickFix() const;

    void SetAppQuickFix(const AppQuickFix &appQuickFix);

    std::vector<HqfInfo> GetQuickFixHqfInfos() const;

    void SetQuickFixHqfInfos(const std::vector<HqfInfo> &hqfInfos);

    void UpdatePrivilegeCapability(const ApplicationInfo &applicationInfo);
    void UpdateRemovable(bool isPreInstall, bool removable);
    bool FetchNativeSoAttrs(
        const std::string &requestPackage, std::string &cpuAbi, std::string &nativeLibraryPath) const;
    void UpdateNativeLibAttrs(const ApplicationInfo &applicationInfo);
    void UpdateArkNativeAttrs(const ApplicationInfo &applicationInfo);
    bool IsLibIsolated(const std::string &moduleName) const;
    std::vector<std::string> GetDeviceType(const std::string &packageName) const;
    std::map<std::string, std::vector<std::string>> GetRequiredDeviceFeatures(const std::string &packageName) const;
    int64_t GetLastInstallationTime() const;
    void UpdateAppDetailAbilityAttrs();
    bool IsHideDesktopIcon() const;
    void AddApplyQuickFixFrequency();
    int32_t GetApplyQuickFixFrequency() const;
    void ResetApplyQuickFixFrequency();

    bool GetOverlayModuleState(const std::string &moduleName, int32_t userId, int32_t &state) const;

    void SetOverlayModuleState(const std::string &moduleName, int32_t state, int32_t userId);

    void SetOverlayModuleState(const std::string &moduleName, int32_t state);

    void ClearOverlayModuleStates(const std::string &moduleName);

    void SetInnerModuleNeedDelete(const std::string &moduleName, const bool needDelete);

    bool GetInnerModuleNeedDelete(const std::string &moduleName);

    bool GetBaseSharedBundleInfo(const std::string &moduleName, uint32_t versionCode,
        BaseSharedBundleInfo &baseSharedBundleInfo) const;
    bool GetMaxVerBaseSharedBundleInfo(const std::string &moduleName,
        BaseSharedBundleInfo &baseSharedBundleInfo) const;
    void InsertInnerSharedModuleInfo(const std::string &moduleName, const InnerModuleInfo &innerModuleInfo);
    void SetSharedModuleNativeLibraryPath(const std::string &nativeLibraryPath);
    bool GetSharedBundleInfo(SharedBundleInfo &sharedBundleInfo) const;
    bool GetSharedDependencies(const std::string &moduleName, std::vector<Dependency> &dependencies) const;
    bool GetAllSharedDependencies(const std::string &moduleName, std::vector<Dependency> &dependencies) const;
    std::vector<uint32_t> GetAllHspVersion() const;
    void DeleteHspModuleByVersion(int32_t versionCode);
    bool GetSharedBundleInfo(int32_t flags, BundleInfo &bundleInfo) const;
    ErrCode GetProxyDataInfos(const std::string &moduleName, std::vector<ProxyData> &proxyDatas) const;
    void GetAllProxyDataInfos(std::vector<ProxyData> &proxyDatas) const;
    bool IsCompressNativeLibs(const std::string &moduleName) const;
    void SetNativeLibraryFileNames(const std::string &moduleName, const std::vector<std::string> &fileNames);
    void UpdateSharedModuleInfo();
    AOTCompileStatus GetAOTCompileStatus(const std::string &moduleName) const;
    void SetAOTCompileStatus(const std::string &moduleName, AOTCompileStatus aotCompileStatus);
    void ResetAOTFlags();
    ErrCode ResetAOTCompileStatus(const std::string &moduleName);
    void GetInternalDependentHspInfo(const std::string &moduleName, std::vector<HspInfo> &hspInfoVector) const;
    ErrCode SetExtName(const std::string &moduleName, const std::string &abilityName, const std::string extName);
    ErrCode SetMimeType(const std::string &moduleName, const std::string &abilityName, const std::string mimeType);
    ErrCode DelExtName(const std::string &moduleName, const std::string &abilityName, const std::string extName);
    ErrCode DelMimeType(const std::string &moduleName, const std::string &abilityName, const std::string extName);
    void SetResourcesApply(const std::vector<int32_t> &resourcesApply);
    void SetAppIdentifier(const std::string &appIdentifier);
    std::string GetAppIdentifier() const;
    void SetCertificate(const std::string &certificate);
    std::string GetCertificate() const;
    void AddOldAppId(const std::string &appId);
    std::vector<std::string> GetOldAppIds() const;
    void SetMoudleIsEncrpted(const std::string &packageName, bool isEncrypted);
    bool IsEncryptedMoudle(const std::string &packageName) const;
    void GetAllEncryptedModuleNames(std::vector<std::string> &moduleNames) const;
    bool IsContainEncryptedModule() const;
    void UpdateDebug(const InnerBundleInfo &newInfo);
    bool GetDebugFromModules(const std::map<std::string, InnerModuleInfo> &innerModuleInfos);
    ErrCode GetAppServiceHspInfo(BundleInfo &bundleInfo) const;
    std::vector<std::string> GetQuerySchemes() const;
    void UpdateOdid(const std::string &developerId, const std::string &odid);
    void UpdateOdidByBundleInfo(const InnerBundleInfo &info);
    void GetDeveloperidAndOdid(std::string &developerId, std::string &odid) const;
    void GetOdid(std::string &odid) const;
    bool IsAsanEnabled() const;
    bool IsGwpAsanEnabled() const;
    bool IsTsanEnabled() const;
    bool NeedCreateEl5Dir() const;
    bool GetUninstallState() const;
    void SetUninstallState(const bool &uninstallState);
    bool IsNeedSendNotify() const;
    void SetNeedSendNotify(const bool needStatus);
    void UpdateMultiAppMode(const InnerBundleInfo &newInfo);
    void UpdateReleaseType(const InnerBundleInfo &newInfo);
    ErrCode AddCloneBundle(const InnerBundleCloneInfo &attr);
    ErrCode RemoveCloneBundle(const int32_t userId, const int32_t appIndex);
    ErrCode GetAvailableCloneAppIndex(const int32_t userId, int32_t &appIndex);
    ErrCode IsCloneAppIndexExisted(const int32_t userId, const int32_t appIndex, bool &res);
    void SetkeyId(const int32_t userId, const std::string &keyId, const int32_t appIndex = 0);
    bool GetApplicationInfoAdaptBundleClone(const InnerBundleUserInfo &innerBundleUserInfo, int32_t appIndex,
        ApplicationInfo &appInfo) const;
    bool GetBundleInfoAdaptBundleClone(const InnerBundleUserInfo &innerBundleUserInfo, int32_t appIndex,
        BundleInfo &bundleInfo) const;
    ErrCode VerifyAndAckCloneAppIndex(int32_t userId, int32_t &appIndex);
    void AdaptMainLauncherResourceInfo(ApplicationInfo &applicationInfo) const;
    bool IsHwasanEnabled() const;
    bool IsUbsanEnabled() const;
    ErrCode UpdateAppEncryptedStatus(const std::string &bundleName, bool isExisted, int32_t appIndex);
    std::set<int32_t> GetCloneBundleAppIndexes() const;
    static uint8_t GetSanitizerFlag(GetInnerModuleInfoFlag flag);
    void InnerProcessShortcut(const Shortcut &oldShortcut, ShortcutInfo &shortcutInfo) const;
    void HandleOTACodeEncryption(std::vector<std::string> &withoutKeyBundles,
        std::vector<std::string> &withKeyBundles) const;
    void CheckHapEncryption(const CheckEncryptionParam &checkEncryptionParam,
        const InnerModuleInfo &moduleInfo) const;
    void CheckSoEncryption(const CheckEncryptionParam &checkEncryptionParam, const std::string &requestPackage,
        const InnerModuleInfo &moduleInfo) const;
    std::string GetModuleArkTSMode(const std::string &moduleName) const;

    void SetMultiAppMode(MultiAppModeData multiAppMode)
    {
        baseApplicationInfo_->multiAppMode = multiAppMode;
    }

    void SetDFXParamStatus();
    int32_t GetApplicationFlags() const
    {
        return baseApplicationInfo_->applicationFlags;
    }
    bool ConvertPluginBundleInfo(const std::string &bundleName, PluginBundleInfo &pluginBundleInfo) const;
    bool AddPluginBundleInfo(const PluginBundleInfo &pluginBundleInfo, const int32_t userId);
    bool RemovePluginBundleInfo(const std::string &pluginBundleName, const int32_t userId);
    bool HasMultiUserPlugin(const std::string &pluginBundleName) const;
    bool UpdatePluginBundleInfo(const PluginBundleInfo &pluginBundleInfo);
    bool RemovePluginFromUserInfo(const std::string &pluginBundleName, const int32_t userId);
    void GetAllDynamicIconInfo(const int32_t userId, std::vector<DynamicIconInfo> &dynamicIconInfos) const;
    std::string GetApplicationArkTSMode() const;
    void UpdateHasCloudkitConfig();
    int32_t GetModuleSize() const;

private:
    bool IsExistLauncherAbility() const;
    void GetBundleWithAbilities(
        int32_t flags, BundleInfo &bundleInfo, int32_t appIndex, int32_t userId = Constants::UNSPECIFIED_USERID) const;
    void GetBundleWithExtension(
        int32_t flags, BundleInfo &bundleInfo, int32_t appIndex, int32_t userId = Constants::UNSPECIFIED_USERID) const;
    void BuildDefaultUserInfo();
    void RemoveDuplicateName(std::vector<std::string> &name) const;
    void GetBundleWithReqPermissionsV9(
        int32_t flags, int32_t userId, BundleInfo &bundleInfo, int32_t appIndex = 0) const;
    void ProcessBundleFlags(
        int32_t flags, int32_t userId, BundleInfo &bundleInfo, int32_t appIndex = 0) const;
    void ProcessBundleWithHapModuleInfoFlag(
        int32_t flags, BundleInfo &bundleInfo, int32_t userId, int32_t appIndex = 0) const;
    void GetBundleWithAbilitiesV9(
        int32_t flags, HapModuleInfo &hapModuleInfo, int32_t userId, int32_t appIndex = 0) const;
    void GetBundleWithExtensionAbilitiesV9(int32_t flags, HapModuleInfo &hapModuleInfo, int32_t appIndex = 0) const;
    IsolationMode GetIsolationMode(const std::string &isolationMode) const;
    void UpdateIsCompressNativeLibs();
    void InnerProcessRequestPermissions(
        const std::unordered_map<std::string, std::string> &moduleNameMap,
        std::vector<RequestPermission> &requestPermissions) const;
    bool ShouldReplacePermission(const RequestPermission &oldPermission, const RequestPermission &newPermission,
        const std::unordered_map<std::string, std::string> &moduleNameTypeMap) const;
    void PrintSetEnabledInfo(bool isEnabled, int32_t userId, int32_t appIndex,
        const std::string &bundleName, const std::string &caller) const;
    void GetPreInstallApplicationFlags(ApplicationInfo &appInfo) const;

    bool isSandboxApp_ = false;
    // Auxiliary property, which is used when the application
    // has been installed when the user is created.
    bool onlyCreateBundleUser_ = false;
    // new version fields
    bool isNewVersion_ = false;

    // use to control uninstalling
    bool uninstallState_ = true;

    // need to send a notification when uninstallState_ change
    bool isNeedSendNotify_ = false;
    BundleStatus bundleStatus_ = BundleStatus::ENABLED;
    int32_t appIndex_ = Constants::INITIAL_APP_INDEX;
    // apply quick fix frequency
    int32_t applyQuickFixFrequency_ = 0;
    int32_t overlayType_ = NON_OVERLAY_TYPE;
    // using for get
    Constants::AppType appType_ = Constants::AppType::THIRD_PARTY_APP;
    int userId_ = Constants::DEFAULT_USERID;
    std::string appFeature_;

    // only using for install or update progress, doesn't need to save to database
    std::string currentPackage_;
    // curDynamicIconModule only in ExtendResourceInfos
    std::string curDynamicIconModule_;

    // for odid
    std::string developerId_;
    std::string odid_;
    std::shared_ptr<ApplicationInfo> baseApplicationInfo_;
    std::shared_ptr<BundleInfo> baseBundleInfo_;  // applicationInfo and abilityInfo empty

    std::shared_ptr<BundlePackInfo> bundlePackInfo_;
    InstallMark mark_;
    std::vector<std::string> allowedAcls_;

    // quick fix hqf info
    std::vector<HqfInfo> hqfInfos_;

    // overlay bundleInfo
    std::vector<OverlayBundleInfo> overlayBundleInfo_;

    // provision metadata
    std::vector<Metadata> provisionMetadatas_;

    std::map<std::string, InnerModuleInfo> innerModuleInfos_;

    std::map<std::string, std::vector<FormInfo>> formInfos_;
    std::map<std::string, CommonEventInfo> commonEvents_;
    std::map<std::string, ShortcutInfo> shortcutInfos_;

    std::map<std::string, InnerAbilityInfo> baseAbilityInfos_;
    std::map<std::string, std::vector<Skill>> skillInfos_;

    std::map<std::string, InnerBundleUserInfo> innerBundleUserInfos_;
    std::map<std::string, InnerExtensionInfo> baseExtensionInfos_;
    std::map<std::string, std::vector<Skill>> extensionSkillInfos_;

    // shared module info
    std::map<std::string, std::vector<InnerModuleInfo>> innerSharedModuleInfos_ ;

    // key:moduleName value:ExtendResourceInfo
    std::map<std::string, ExtendResourceInfo> extendResourceInfos_;

    // data group info
    std::unordered_map<std::string, std::vector<DataGroupInfo>> dataGroupInfos_;

    // pluginBundleName -> pluginBundleInfo
    std::unordered_map<std::string, PluginBundleInfo> pluginBundleInfos_;
};

void from_json(const nlohmann::json &jsonObject, InnerModuleInfo &info);
void from_json(const nlohmann::json &jsonObject, Distro &distro);
void from_json(const nlohmann::json &jsonObject, InstallMark &installMark);
void from_json(const nlohmann::json &jsonObject, DefinePermission &definePermission);
void from_json(const nlohmann::json &jsonObject, Dependency &dependency);
void from_json(const nlohmann::json &jsonObject, OverlayBundleInfo &overlayBundleInfo);
void from_json(const nlohmann::json &jsonObject, ExtendResourceInfo &extendResourceInfo);
void to_json(nlohmann::json &jsonObject, const ExtendResourceInfo &extendResourceInfo);
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_BUNDLE_INFO_H
