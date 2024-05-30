/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "aot/aot_args.h"
#include "bundle_service_constants.h"
#include "inner_app_quick_fix.h"
#include "inner_bundle_clone_info.h"
#include "inner_bundle_user_info.h"
#include "inner_common_info.h"
#include "preinstalled_application_info.h"
#include "property.h"
#include "quick_fix/app_quick_fix.h"
#include "quick_fix/hqf_info.h"
#include "shared/base_shared_bundle_info.h"
#include "shared/shared_bundle_info.h"

namespace OHOS {
namespace AppExecFwk {
struct ExtendResourceInfo {
    std::string moduleName;
    int32_t iconId;
    std::string filePath;
};

class InnerBundleInfo {
public:
    enum class BundleStatus {
        ENABLED = 1,
        DISABLED,
    };

    InnerBundleInfo();
    InnerBundleInfo &operator=(const InnerBundleInfo &info);
    ~InnerBundleInfo();

    void ToJson(nlohmann::json &jsonObject) const;
    int32_t FromJson(const nlohmann::json &jsonObject);
    bool AddModuleInfo(const InnerBundleInfo &newInfo);
    void UpdateModuleInfo(const InnerBundleInfo &newInfo);
    void RemoveModuleInfo(const std::string &modulePackage);
    std::optional<HapModuleInfo> FindHapModuleInfo(
        const std::string &modulePackage, int32_t userId = Constants::UNSPECIFIED_USERID, int32_t appIndex = 0) const;
    void GetModuleWithHashValue(
        int32_t flags, const std::string &modulePackage, HapModuleInfo &hapModuleInfo) const;
    std::optional<AbilityInfo> FindAbilityInfo(
        const std::string &moduleName,
        const std::string &abilityName,
        int32_t userId = Constants::UNSPECIFIED_USERID) const;
    std::optional<AbilityInfo> FindAbilityInfoV9(
        const std::string &moduleName, const std::string &abilityName) const;
    ErrCode FindAbilityInfo(
        const std::string &moduleName, const std::string &abilityName, AbilityInfo &info) const;
    std::optional<std::vector<AbilityInfo>> FindAbilityInfos(
        int32_t userId = Constants::UNSPECIFIED_USERID) const;
    std::optional<AbilityInfo> FindAbilityInfo(const std::string continueType,
        int32_t userId = Constants::UNSPECIFIED_USERID) const;
    std::optional<ExtensionAbilityInfo> FindExtensionInfo(
        const std::string &moduleName, const std::string &extensionName) const;
    std::optional<std::vector<ExtensionAbilityInfo>> FindExtensionInfos() const;
    std::string ToString() const;
    void AddModuleAbilityInfo(const std::map<std::string, AbilityInfo> &abilityInfos)
    {
        for (const auto &ability : abilityInfos) {
            baseAbilityInfos_.try_emplace(ability.first, ability.second);
        }
    }

    void AddModuleExtensionInfos(const std::map<std::string, ExtensionAbilityInfo> &extensionInfos)
    {
        for (const auto &extensionInfo : extensionInfos) {
            baseExtensionInfos_.try_emplace(extensionInfo.first, extensionInfo.second);
        }
    }

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

    void AddModuleFormInfo(const std::map<std::string, std::vector<FormInfo>> &formInfos)
    {
        for (const auto &forms : formInfos) {
            formInfos_.try_emplace(forms.first, forms.second);
        }
    }

    void AddModuleCommonEvent(const std::map<std::string, CommonEventInfo> &commonEvents)
    {
        for (const auto &commonEvent : commonEvents) {
            commonEvents_.try_emplace(commonEvent.first, commonEvent.second);
        }
    }

    void AddModuleShortcutInfo(const std::map<std::string, ShortcutInfo> &shortcutInfos)
    {
        for (const auto &shortcut : shortcutInfos) {
            shortcutInfos_.try_emplace(shortcut.first, shortcut.second);
        }
    }

    void AddInnerModuleInfo(const std::map<std::string, InnerModuleInfo> &innerModuleInfos)
    {
        for (const auto &info : innerModuleInfos) {
            innerModuleInfos_.try_emplace(info.first, info.second);
        }
    }

    void SetBundleInstallTime(
        const int64_t time, int32_t userId = Constants::UNSPECIFIED_USERID);

    int64_t GetBundleInstallTime(int32_t userId = Constants::UNSPECIFIED_USERID) const
    {
        InnerBundleUserInfo innerBundleUserInfo;
        if (!GetInnerBundleUserInfo(userId, innerBundleUserInfo)) {
            APP_LOGE("can not find userId %{public}d when GetBundleInstallTime", userId);
            return -1;
        }
        return innerBundleUserInfo.installTime;
    }

    void SetBundleUpdateTime(const int64_t time, int32_t userId = Constants::UNSPECIFIED_USERID);

    int64_t GetBundleUpdateTime(int32_t userId = Constants::UNSPECIFIED_USERID) const
    {
        InnerBundleUserInfo innerBundleUserInfo;
        if (!GetInnerBundleUserInfo(userId, innerBundleUserInfo)) {
            APP_LOGE("can not find userId %{public}d when GetBundleUpdateTime", userId);
            return -1;
        }
        return innerBundleUserInfo.updateTime;
    }

    BundleInfo GetBaseBundleInfo() const
    {
        return *baseBundleInfo_;
    }

    void SetBaseBundleInfo(const BundleInfo &bundleInfo)
    {
        *baseBundleInfo_ = bundleInfo;
    }

    void UpdateBaseBundleInfo(const BundleInfo &bundleInfo, bool isEntry);

    ApplicationInfo GetBaseApplicationInfo() const
    {
        return *baseApplicationInfo_;
    }

    void SetBaseApplicationInfo(const ApplicationInfo &applicationInfo)
    {
        *baseApplicationInfo_ = applicationInfo;
    }

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

    void UpdateBaseApplicationInfo(const ApplicationInfo &applicationInfo, bool isEntry);

    bool GetApplicationEnabled(int32_t userId = Constants::UNSPECIFIED_USERID) const
    {
        InnerBundleUserInfo innerBundleUserInfo;
        if (!GetInnerBundleUserInfo(userId, innerBundleUserInfo)) {
            APP_LOGD("can not find userId %{public}d when GetApplicationEnabled", userId);
            return false;
        }

        return innerBundleUserInfo.bundleUserInfo.enabled;
    }

    ErrCode GetApplicationEnabledV9(int32_t userId, bool &isEnabled,
        int32_t appIndex = 0) const;

    ErrCode SetApplicationEnabled(bool enabled, int32_t userId = Constants::UNSPECIFIED_USERID);
    ErrCode SetCloneApplicationEnabled(bool enabled, int32_t appIndex, int32_t userId);

    void InsertInnerModuleInfo(const std::string &modulePackage, const InnerModuleInfo &innerModuleInfo)
    {
        innerModuleInfos_.try_emplace(modulePackage, innerModuleInfo);
    }

    void InsertAbilitiesInfo(const std::string &key, const AbilityInfo &abilityInfo)
    {
        baseAbilityInfos_.emplace(key, abilityInfo);
    }

    void InsertExtensionInfo(const std::string &key, const ExtensionAbilityInfo &extensionInfo)
    {
        baseExtensionInfos_.emplace(key, extensionInfo);
    }

    void InsertSkillInfo(const std::string &key, const std::vector<Skill> &skills)
    {
        skillInfos_.emplace(key, skills);
    }

    void InsertExtensionSkillInfo(const std::string &key, const std::vector<Skill> &skills)
    {
        extensionSkillInfos_.emplace(key, skills);
    }

    std::optional<AbilityInfo> FindAbilityInfoByUri(const std::string &abilityUri) const;
    bool FindExtensionAbilityInfoByUri(
        const std::string &uri, ExtensionAbilityInfo &extensionAbilityInfo) const;
    void FindAbilityInfosByUri(const std::string &abilityUri,
        std::vector<AbilityInfo> &abilityInfos,  int32_t userId = Constants::UNSPECIFIED_USERID);

    auto GetAbilityNames() const
    {
        std::vector<std::string> abilityNames;
        for (auto &ability : baseAbilityInfos_) {
            abilityNames.emplace_back(ability.second.name);
        }
        return abilityNames;
    }

    BMS_DEFINE_PROPERTY_MEMBER_FILED_GET(ApplicationName, baseApplicationInfo_, name, std::string);
    BMS_DEFINE_PROPERTY(BundleStatus, bundleStatus_, BundleStatus);
    BMS_DEFINE_PROPERTY_MEMBER_FILED_GET(BundleName, baseApplicationInfo_, bundleName, std::string);
    BMS_DEFINE_PROPERTY_MEMBER_FILED(AppCodePath, baseApplicationInfo_, codePath, std::string);
    BMS_DEFINE_PROPERTY_MEMBER_FILED_GET(VersionCode, baseBundleInfo_, versionCode, uint32_t);
    BMS_DEFINE_PROPERTY_MEMBER_FILED_GET(VersionName, baseBundleInfo_, versionName, std::string);
    BMS_DEFINE_PROPERTY_MEMBER_FILED_GET(Vendor, baseBundleInfo_, vendor, std::string);
    BMS_DEFINE_PROPERTY_MEMBER_FILED_GET(CompatibleVersion, baseBundleInfo_, compatibleVersion, uint32_t);
    BMS_DEFINE_PROPERTY_MEMBER_FILED_GET(TargetVersion, baseBundleInfo_, targetVersion, uint32_t);
    BMS_DEFINE_PROPERTY_MEMBER_FILED_GET(ReleaseType, baseBundleInfo_, releaseType, std::string);
    BMS_DEFINE_PROPERTY_MEMBER_FILED_GET(
        MinCompatibleVersionCode, baseBundleInfo_, minCompatibleVersionCode, uint32_t);
    BMS_DEFINE_PROPERTY_GET(InstallMark, mark_, InstallMark);
    BMS_DEFINE_PROPERTY_MEMBER_FILED(AppDataDir, baseApplicationInfo_, dataDir, std::string);
    BMS_DEFINE_PROPERTY_MEMBER_FILED_SET(AppDataBaseDir, baseApplicationInfo_, dataBaseDir, std::string);
    BMS_DEFINE_PROPERTY_MEMBER_FILED_SET(AppCacheDir, baseApplicationInfo_, cacheDir, std::string);
    BMS_DEFINE_PROPERTY_GET(AppType, appType_, Constants::AppType);
    BMS_DEFINE_PROPERTY(UserId, userId_, int);
    BMS_DEFINE_PROPERTY(CurrentModulePackage, currentPackage_, std::string);
    BMS_DEFINE_PROPERTY_MEMBER_FILED_GET(IsKeepAlive, baseBundleInfo_, isKeepAlive, bool);
    BMS_DEFINE_PROPERTY_MEMBER_FILED(IsFreeInstallApp, baseApplicationInfo_, isFreeInstallApp, bool);
    BMS_DEFINE_PROPERTY_MEMBER_FILED_GET(AppId, baseBundleInfo_, appId, std::string);
    BMS_DEFINE_PROPERTY(AppFeature, appFeature_, std::string);
    BMS_DEFINE_PROPERTY_MEMBER_FILED_GET(
        AppPrivilegeLevel, baseApplicationInfo_, appPrivilegeLevel, std::string);
    BMS_DEFINE_PROPERTY_MEMBER_FILED(IsPreInstallApp, baseBundleInfo_, isPreInstallApp, bool);
    BMS_DEFINE_PROPERTY(OnlyCreateBundleUser, onlyCreateBundleUser_, bool);
    BMS_DEFINE_PROPERTY(IsNewVersion, isNewVersion_, bool);
    BMS_DEFINE_PROPERTY_MEMBER_FILED(AsanEnabled, baseApplicationInfo_, asanEnabled, bool);
    BMS_DEFINE_PROPERTY_GET(AllowedAcls, allowedAcls_, std::vector<std::string>);
    BMS_DEFINE_PROPERTY(AppIndex, appIndex_, int32_t);
    BMS_DEFINE_PROPERTY(IsSandbox, isSandboxApp_, bool);
    BMS_DEFINE_PROPERTY_MEMBER_FILED(
        CertificateFingerprint, baseApplicationInfo_, fingerprint, std::string);
    BMS_DEFINE_PROPERTY_MEMBER_FILED(
        NativeLibraryPath, baseApplicationInfo_, nativeLibraryPath, std::string);
    BMS_DEFINE_PROPERTY_MEMBER_FILED(
        ArkNativeFileAbi, baseApplicationInfo_, arkNativeFileAbi, std::string);
    BMS_DEFINE_PROPERTY_MEMBER_FILED(
        ArkNativeFilePath, baseApplicationInfo_, arkNativeFilePath, std::string);
    BMS_DEFINE_PROPERTY_MEMBER_FILED(CpuAbi, baseApplicationInfo_, cpuAbi, std::string);
    BMS_DEFINE_PROPERTY_MEMBER_FILED(Removable, baseApplicationInfo_, removable, bool);
    BMS_DEFINE_PROPERTY_MEMBER_FILED_SET(
        RunningResourcesApply, baseApplicationInfo_, runningResourcesApply, bool);
    BMS_DEFINE_PROPERTY_MEMBER_FILED_SET(AssociatedWakeUp, baseApplicationInfo_, associatedWakeUp, bool);
    BMS_DEFINE_PROPERTY_MEMBER_FILED_SET(UserDataClearable, baseApplicationInfo_, userDataClearable, bool);
    BMS_DEFINE_PROPERTY_MEMBER_FILED_SET(FormVisibleNotify, baseApplicationInfo_, formVisibleNotify, bool);
    BMS_DEFINE_PROPERTY_GET(OverlayBundleInfo, overlayBundleInfo_, std::vector<OverlayBundleInfo>);
    BMS_DEFINE_PROPERTY_MEMBER_FILED(TargetBundleName, baseApplicationInfo_, targetBundleName, std::string);
    BMS_DEFINE_PROPERTY_MEMBER_FILED(TargetPriority, baseApplicationInfo_, targetPriority, int32_t);
    BMS_DEFINE_PROPERTY_MEMBER_FILED(OverlayState, baseApplicationInfo_, overlayState, int32_t);
    BMS_DEFINE_PROPERTY(OverlayType, overlayType_, int32_t);
    BMS_DEFINE_PROPERTY_MEMBER_FILED(AsanLogPath, baseApplicationInfo_, asanLogPath, std::string);
    BMS_DEFINE_PROPERTY_MEMBER_FILED(ApplicationBundleType, baseApplicationInfo_, bundleType, BundleType);
    BMS_DEFINE_PROPERTY(AppProvisionMetadata, provisionMetadatas_, std::vector<Metadata>);
    BMS_DEFINE_PROPERTY_MEMBER_FILED(GwpAsanEnabled, baseApplicationInfo_, gwpAsanEnabled, bool);
    BMS_DEFINE_PROPERTY_MEMBER_FILED(
        ApplicationReservedFlag, baseApplicationInfo_, applicationReservedFlag, uint32_t);
    BMS_DEFINE_PROPERTY_MEMBER_FILED(
        AllowAppRunWhenDeviceFirstLocked, baseApplicationInfo_, allowAppRunWhenDeviceFirstLocked, bool);
    BMS_DEFINE_PROPERTY_MEMBER_FILED(TsanEnabled, baseApplicationInfo_, tsanEnabled, bool);
    BMS_DEFINE_PROPERTY(CurDynamicIconModule, curDynamicIconModule_, std::string);
    BMS_DEFINE_PROPERTY_MEMBER_FILED(IconId, baseApplicationInfo_, iconId, int32_t);
    BMS_DEFINE_PROPERTY_MEMBER_FILED(
        AppEnvironments, baseApplicationInfo_, appEnvironments, std::vector<ApplicationEnvironment>);
    BMS_DEFINE_PROPERTY_MEMBER_FILED(
        MaxChildProcess, baseApplicationInfo_, maxChildProcess, int32_t);

    void SetInstallMark(const std::string &bundleName, const std::string &packageName,
        const InstallExceptionStatus &status)
    {
        mark_.bundleName = bundleName;
        mark_.packageName = packageName;
        mark_.status = status;
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

    int32_t GetGid(int32_t userId = Constants::UNSPECIFIED_USERID) const
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

    void SetAppType(Constants::AppType appType)
    {
        appType_ = appType;
        if (appType_ == Constants::AppType::SYSTEM_APP) {
            baseApplicationInfo_->isSystemApp = true;
        } else {
            baseApplicationInfo_->isSystemApp = false;
        }
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
    const std::string &GetModuleHapPath(const std::string &modulePackage) const
    {
        if (innerModuleInfos_.find(modulePackage) != innerModuleInfos_.end()) {
            return innerModuleInfos_.at(modulePackage).hapPath;
        }

        return Constants::EMPTY_STRING;
    }

    const std::string &GetModuleName(const std::string &modulePackage) const
    {
        if (innerModuleInfos_.find(modulePackage) != innerModuleInfos_.end()) {
            return innerModuleInfos_.at(modulePackage).moduleName;
        }

        return Constants::EMPTY_STRING;
    }

    const std::string &GetCurModuleName() const;

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

    void SetAppPrivilegeLevel(const std::string &appPrivilegeLevel)
    {
        if (appPrivilegeLevel.empty()) {
            return;
        }
        baseApplicationInfo_->appPrivilegeLevel = appPrivilegeLevel;
    }

    bool HasEntry() const;

    void InsertFormInfos(const std::string &keyName, const std::vector<FormInfo> &formInfos)
    {
        formInfos_.emplace(keyName, formInfos);
    }

    void InsertCommonEvents(const std::string &keyName, const CommonEventInfo &commonEvents)
    {
        commonEvents_.emplace(keyName, commonEvents);
    }

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

    ErrCode SetAbilityEnabled(
        const std::string &moduleName,
        const std::string &abilityName,
        bool isEnabled,
        int32_t userId);
    ErrCode SetCloneAbilityEnabled(const std::string &moduleName, const std::string &abilityName,
        bool isEnabled, int32_t userId, int32_t appIndex);
    ErrCode SetModuleUpgradeFlag(std::string moduleName, int32_t upgradeFlag);
    int32_t GetModuleUpgradeFlag(std::string moduleName) const;
    void GetApplicationInfo(int32_t flags, int32_t userId, ApplicationInfo &appInfo, int32_t appIndex = 0) const;
    ErrCode GetApplicationInfoV9(int32_t flags, int32_t userId, ApplicationInfo &appInfo, int32_t appIndex = 0) const;
    bool GetBundleInfo(int32_t flags, BundleInfo &bundleInfo, int32_t userId = Constants::UNSPECIFIED_USERID,
        int32_t appIndex = 0) const;
    ErrCode GetBundleInfoV9(int32_t flags,
        BundleInfo &bundleInfo, int32_t userId = Constants::UNSPECIFIED_USERID, int32_t appIndex = 0) const;
    bool CheckSpecialMetaData(const std::string &metaData) const;
    void GetFormsInfoByModule(const std::string &moduleName, std::vector<FormInfo> &formInfos) const;
    void GetFormsInfoByApp(std::vector<FormInfo> &formInfos) const;
    void GetShortcutInfos(std::vector<ShortcutInfo> &shortcutInfos) const;
    void GetCommonEvents(const std::string &eventKey, std::vector<CommonEventInfo> &commonEvents) const;
    std::optional<InnerModuleInfo> GetInnerModuleInfoByModuleName(const std::string &moduleName) const;
    std::optional<std::vector<HnpPackage>> GetInnerModuleInfoHnpInfo(const std::string &moduleName) const;
    std::string GetInnerModuleInfoHnpPath(const std::string &moduleName) const;
    void GetModuleNames(std::vector<std::string> &moduleNames) const;
    const std::map<std::string, InnerModuleInfo> &GetInnerModuleInfos() const
    {
        return innerModuleInfos_;
    }

    std::map<std::string, InnerModuleInfo> &FetchInnerModuleInfos()
    {
        return innerModuleInfos_;
    }

    std::map<std::string, AbilityInfo> &FetchAbilityInfos()
    {
        return baseAbilityInfos_;
    }

    const std::map<std::string, AbilityInfo> &GetInnerAbilityInfos() const
    {
        return baseAbilityInfos_;
    }

    const std::map<std::string, std::vector<Skill>> &GetInnerSkillInfos() const
    {
        return skillInfos_;
    }

    std::map<std::string, ExtensionAbilityInfo> &FetchInnerExtensionInfos()
    {
        return baseExtensionInfos_;
    }

    const std::map<std::string, ExtensionAbilityInfo> &GetInnerExtensionInfos() const
    {
        return baseExtensionInfos_;
    }

    const std::map<std::string, std::vector<Skill>> &GetExtensionSkillInfos() const
    {
        return  extensionSkillInfos_;
    }

    bool IsSystemApp() const
    {
        return baseApplicationInfo_->isSystemApp;
    }

    const std::map<std::string, InnerBundleUserInfo>& GetInnerBundleUserInfos() const
    {
        return innerBundleUserInfos_;
    }

    void ResetBundleState(int32_t userId);
    void RemoveInnerBundleUserInfo(int32_t userId);
    void AddInnerBundleUserInfo(const InnerBundleUserInfo& userInfo);
    bool GetInnerBundleUserInfo(int32_t userId, InnerBundleUserInfo& userInfo) const;
    bool HasInnerBundleUserInfo(int32_t userId) const;
    int32_t GetResponseUserId(int32_t requestUserId) const;
    bool IsSingleton() const
    {
        return baseApplicationInfo_->singleton;
    }

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

    void SetAccessTokenIdEx(
        const Security::AccessToken::AccessTokenIDEx accessTokenIdEx, const int32_t userId);

    void SetAllowedAcls(const std::vector<std::string> &allowedAcls)
    {
        allowedAcls_.clear();
        for (const auto &acl : allowedAcls) {
            if (!acl.empty()) {
                allowedAcls_.emplace_back(acl);
            }
        }
    }

    bool IsAbilityEnabled(const AbilityInfo &abilityInfo, int32_t userId,
        int32_t appIndex = 0) const;
    ErrCode IsAbilityEnabledV9(const AbilityInfo &abilityInfo,
        int32_t userId, bool &isEnable, int32_t appIndex = 0) const;

    bool GetDependentModuleNames(const std::string &moduleName, std::vector<std::string> &dependentModuleNames) const;
    bool GetAllDependentModuleNames(const std::string &moduleName,
        std::vector<std::string> &dependentModuleNames) const;
    bool IsBundleRemovable() const;
    bool GetRemovableModules(std::vector<std::string> &moduleToDelete) const;
    bool GetFreeInstallModules(std::vector<std::string> &freeInstallModule) const;
    bool IsUserExistModule(const std::string &moduleName, int32_t userId) const;
    ErrCode IsModuleRemovable(const std::string &moduleName, int32_t userId, bool &isRemovable) const;
    bool AddModuleRemovableInfo(InnerModuleInfo &info, const std::string &stringUserId, bool isEnable) const;
    bool SetModuleRemovable(const std::string &moduleName, bool isEnable, int32_t userId);
    void DeleteModuleRemovable(const std::string &moduleName, int32_t userId);
    void DeleteModuleRemovableInfo(InnerModuleInfo &info, const std::string &stringUserId);
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

    void CleanInnerBundleUserInfos()
    {
        innerBundleUserInfos_.clear();
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

    void SetHideDesktopIcon(bool hideDesktopIcon)
    {
        baseApplicationInfo_->hideDesktopIcon = hideDesktopIcon;
        if (hideDesktopIcon) {
            baseApplicationInfo_->needAppDetail = false;
            baseApplicationInfo_->appDetailAbilityLibraryPath = Constants::EMPTY_STRING;
        }
    }

    void SetAllowCommonEvent(const std::vector<std::string> &allowCommonEvent)
    {
        baseApplicationInfo_->allowCommonEvent.clear();
        for (const auto &event : allowCommonEvent) {
            baseApplicationInfo_->allowCommonEvent.emplace_back(event);
        }
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

    void AddOverlayModuleInfo(const OverlayModuleInfo &overlayModuleInfo);
    void RemoveOverlayModuleInfo(const std::string &targetModuleName,
        const std::string &bundleName, const std::string &moduleName);
    void RemoveAllOverlayModuleInfo(const std::string &bundleName);
    void CleanAllOverlayModuleInfo();
    bool isOverlayModule(const std::string &moduleName) const;
    bool isExistedOverlayModule() const;
    void KeepOldOverlayConnection(InnerBundleInfo &info);

    bool SetInnerModuleAtomicPreload(const std::string &moduleName, const std::vector<std::string> &preloads)
    {
        if (innerModuleInfos_.find(moduleName) == innerModuleInfos_.end()) {
            APP_LOGE("innerBundleInfo does not contain the module.");
            return false;
        }
        innerModuleInfos_.at(moduleName).preloads = preloads;
        return true;
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
            APP_LOGE("innerBundleInfo does not contain the module.");
            return false;
        }
        buildHash = innerModuleInfos_.at(moduleName).buildHash;
        return true;
    }

    const std::unordered_map<std::string, std::vector<DataGroupInfo>> GetDataGroupInfos() const
    {
        return dataGroupInfos_;
    }


    void SetOrganization(const std::string &organization)
    {
        baseApplicationInfo_->organization = organization;
    }

    void AddDataGroupInfo(const std::string &dataGroupId, const DataGroupInfo &info);
    void RemoveGroupInfos(int32_t userId, const std::string &dataGroupId);
    void UpdateDataGroupInfos(
        const std::unordered_map<std::string, std::vector<DataGroupInfo>> &dataGroupInfos);

    void ClearApplicationReservedFlag(uint32_t flag)
    {
        baseApplicationInfo_->applicationReservedFlag &= ~flag;
    }

    int32_t GetMultiAppMaxCount() const
    {
        return baseApplicationInfo_->multiAppMode.maxCount;
    }

    MultiAppModeType GetMultiAppModeType() const
    {
        return baseApplicationInfo_->multiAppMode.multiAppModeType;
    }

    std::set<std::string> GetAllExtensionDirsInSpecifiedModule(
        const std::string &moduleName, int32_t userId) const;
    std::set<std::string> GetAllExtensionDirs(int32_t userId) const;
    void UpdateExtensionDirInfo(const std::string &key,
        int32_t userId, const std::string &sandBoxPath, const std::vector<std::string>& dataGroupIds);
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
    void AddOldAppId(const std::string &appId);
    std::vector<std::string> GetOldAppIds() const;
    void SetMoudleIsEncrpted(const std::string &packageName, bool isEncrypted);
    bool IsEncryptedMoudle(const std::string &packageName) const;
    bool IsContainEncryptedModule() const;
    void UpdateDebug(bool debug, bool isEntry);
    ErrCode GetAppServiceHspInfo(BundleInfo &bundleInfo) const;
    std::vector<std::string> GetQuerySchemes() const;
    void UpdateOdid(const std::string &developerId, const std::string &odid);
    void UpdateOdidByBundleInfo(const InnerBundleInfo &info);
    void GetDeveloperidAndOdid(std::string &developerId, std::string &odid) const;
    bool IsAsanEnabled() const;
    bool IsGwpAsanEnabled() const;
    bool GetUninstallState() const;
    void SetUninstallState(const bool &uninstallState);
    void UpdateMultiAppMode(const InnerBundleInfo &newInfo);
    ErrCode AddCloneBundle(const InnerBundleCloneInfo &attr);
    ErrCode RemoveCloneBundle(const int32_t userId, const int32_t appIndex);
    ErrCode GetAvailableCloneAppIndex(const int32_t userId, int32_t &appIndex);
    ErrCode IsCloneAppIndexExisted(const int32_t userId, const int32_t appIndex, bool &res);
    bool GetApplicationInfoAdaptBundleClone(const InnerBundleUserInfo &innerBundleUserInfo, int32_t appIndex,
        ApplicationInfo &appInfo) const;
    bool GetBundleInfoAdaptBundleClone(const InnerBundleUserInfo &innerBundleUserInfo, int32_t appIndex,
        BundleInfo &bundleInfo) const;
    ErrCode VerifyAndAckCloneAppIndex(int32_t userId, int32_t &appIndex);
    void SetkeyId(const int32_t userId, const std::string &keyId);
private:
    bool IsExistLauncherAbility() const;
    void GetBundleWithAbilities(
        int32_t flags, BundleInfo &bundleInfo, int32_t userId = Constants::UNSPECIFIED_USERID) const;
    void GetBundleWithExtension(
        int32_t flags, BundleInfo &bundleInfo, int32_t userId = Constants::UNSPECIFIED_USERID) const;
    void RemoveDuplicateName(std::vector<std::string> &name) const;
    void GetBundleWithReqPermissionsV9(
        int32_t flags, int32_t userId, BundleInfo &bundleInfo, int32_t appIndex = 0) const;
    void ProcessBundleFlags(
        int32_t flags, int32_t userId, BundleInfo &bundleInfo, int32_t appIndex = 0) const;
    void ProcessBundleWithHapModuleInfoFlag(
        int32_t flags, BundleInfo &bundleInfo, int32_t userId, int32_t appIndex = 0) const;
    void GetBundleWithAbilitiesV9(
        int32_t flags, HapModuleInfo &hapModuleInfo, int32_t userId, int32_t appIndex = 0) const;
    void GetBundleWithExtensionAbilitiesV9(int32_t flags, HapModuleInfo &hapModuleInfo) const;
    IsolationMode GetIsolationMode(const std::string &isolationMode) const;
    void UpdateIsCompressNativeLibs();
    void InnerProcessShortcut(const Shortcut &oldShortcut, ShortcutInfo &shortcutInfo) const;

    // using for get
    Constants::AppType appType_ = Constants::AppType::THIRD_PARTY_APP;
    int userId_ = Constants::DEFAULT_USERID;
    BundleStatus bundleStatus_ = BundleStatus::ENABLED;
    std::shared_ptr<ApplicationInfo> baseApplicationInfo_;
    std::shared_ptr<BundleInfo> baseBundleInfo_;  // applicationInfo and abilityInfo empty
    std::string appFeature_;
    std::vector<std::string> allowedAcls_;
    InstallMark mark_;
    int32_t appIndex_ = Constants::INITIAL_APP_INDEX;
    bool isSandboxApp_ = false;

    // only using for install or update progress, doesn't need to save to database
    std::string currentPackage_;
    // Auxiliary property, which is used when the application
    // has been installed when the user is created.
    bool onlyCreateBundleUser_ = false;

    std::map<std::string, InnerModuleInfo> innerModuleInfos_;
    std::map<std::string, std::vector<FormInfo>> formInfos_;
    std::map<std::string, CommonEventInfo> commonEvents_;
    std::map<std::string, ShortcutInfo> shortcutInfos_;
    std::map<std::string, AbilityInfo> baseAbilityInfos_;
    std::map<std::string, std::vector<Skill>> skillInfos_;
    std::map<std::string, InnerBundleUserInfo> innerBundleUserInfos_;
    std::shared_ptr<BundlePackInfo> bundlePackInfo_;
    // new version fields
    bool isNewVersion_ = false;
    std::map<std::string, ExtensionAbilityInfo> baseExtensionInfos_;
    std::map<std::string, std::vector<Skill>> extensionSkillInfos_;

    // quick fix hqf info
    std::vector<HqfInfo> hqfInfos_;
    // apply quick fix frequency
    int32_t applyQuickFixFrequency_ = 0;

    // overlay bundleInfo
    std::vector<OverlayBundleInfo> overlayBundleInfo_;
    int32_t overlayType_ = NON_OVERLAY_TYPE;

    // provision metadata
    std::vector<Metadata> provisionMetadatas_;

    // shared module info
    std::map<std::string, std::vector<InnerModuleInfo>> innerSharedModuleInfos_ ;

    // data group info
    std::unordered_map<std::string, std::vector<DataGroupInfo>> dataGroupInfos_;

    // key:moduleName value:ExtendResourceInfo
    std::map<std::string, ExtendResourceInfo> extendResourceInfos_;
    // curDynamicIconModule only in ExtendResourceInfos
    std::string curDynamicIconModule_;

    // for odid
    std::string developerId_;
    std::string odid_;

    // use to control uninstalling
    bool uninstallState_ = true;
};

void from_json(const nlohmann::json &jsonObject, ExtendResourceInfo &extendResourceInfo);
void to_json(nlohmann::json &jsonObject, const ExtendResourceInfo &extendResourceInfo);
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_BUNDLE_INFO_H
