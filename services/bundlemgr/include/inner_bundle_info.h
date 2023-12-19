/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "inner_app_quick_fix.h"
#include "inner_bundle_user_info.h"
#include "inner_common_info.h"
#include "quick_fix/app_quick_fix.h"
#include "quick_fix/hqf_info.h"
#include "shared/base_shared_bundle_info.h"
#include "shared/shared_bundle_info.h"

namespace OHOS {
namespace AppExecFwk {
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
        const std::string &modulePackage, int32_t userId = Constants::UNSPECIFIED_USERID) const;
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

    std::string GetApplicationName() const
    {
        return baseApplicationInfo_->name;
    }

    void SetBundleStatus(const BundleStatus &status)
    {
        bundleStatus_ = status;
    }

    BundleStatus GetBundleStatus() const
    {
        return bundleStatus_;
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

    const std::string GetBundleName() const
    {
        return baseApplicationInfo_->bundleName;
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

    ErrCode GetApplicationEnabledV9(int32_t userId, bool &isEnabled) const
    {
        InnerBundleUserInfo innerBundleUserInfo;
        if (!GetInnerBundleUserInfo(userId, innerBundleUserInfo)) {
            APP_LOGD("can not find bundleUserInfo in userId: %{public}d when GetApplicationEnabled", userId);
            return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
        }
        isEnabled = innerBundleUserInfo.bundleUserInfo.enabled;
        return ERR_OK;
    }

    ErrCode SetApplicationEnabled(bool enabled, int32_t userId = Constants::UNSPECIFIED_USERID);

    const std::string GetAppCodePath() const
    {
        return baseApplicationInfo_->codePath;
    }

    void SetAppCodePath(const std::string codePath)
    {
        baseApplicationInfo_->codePath = codePath;
    }

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

    std::optional<AbilityInfo> FindAbilityInfoByUri(const std::string &abilityUri) const
    {
        APP_LOGD("Uri is %{public}s", abilityUri.c_str());
        for (const auto &ability : baseAbilityInfos_) {
            auto abilityInfo = ability.second;
            if (abilityInfo.uri.size() < strlen(Constants::DATA_ABILITY_URI_PREFIX)) {
                continue;
            }

            auto configUri = abilityInfo.uri.substr(strlen(Constants::DATA_ABILITY_URI_PREFIX));
            APP_LOGD("configUri is %{public}s", configUri.c_str());
            if (configUri == abilityUri) {
                return abilityInfo;
            }
        }
        return std::nullopt;
    }

    bool FindExtensionAbilityInfoByUri(const std::string &uri, ExtensionAbilityInfo &extensionAbilityInfo) const
    {
        for (const auto &item : baseExtensionInfos_) {
            if (uri == item.second.uri) {
                extensionAbilityInfo = item.second;
                APP_LOGD("find target extension, bundleName : %{public}s, moduleName : %{public}s, name : %{public}s",
                    extensionAbilityInfo.bundleName.c_str(), extensionAbilityInfo.moduleName.c_str(),
                    extensionAbilityInfo.name.c_str());
                return true;
            }
        }
        return false;
    }

    void FindAbilityInfosByUri(const std::string &abilityUri,
        std::vector<AbilityInfo> &abilityInfos,  int32_t userId = Constants::UNSPECIFIED_USERID)
    {
        APP_LOGI("Uri is %{public}s", abilityUri.c_str());
        for (auto &ability : baseAbilityInfos_) {
            auto abilityInfo = ability.second;
            if (abilityInfo.uri.size() < strlen(Constants::DATA_ABILITY_URI_PREFIX)) {
                continue;
            }

            auto configUri = abilityInfo.uri.substr(strlen(Constants::DATA_ABILITY_URI_PREFIX));
            APP_LOGI("configUri is %{public}s", configUri.c_str());
            if (configUri == abilityUri) {
                GetApplicationInfo(
                    ApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION, userId, abilityInfo.applicationInfo);
                abilityInfos.emplace_back(abilityInfo);
            }
        }
        return;
    }

    auto GetAbilityNames() const
    {
        std::vector<std::string> abilityNames;
        for (auto &ability : baseAbilityInfos_) {
            abilityNames.emplace_back(ability.second.name);
        }
        return abilityNames;
    }

    uint32_t GetVersionCode() const
    {
        return baseBundleInfo_->versionCode;
    }

    std::string GetVersionName() const
    {
        return baseBundleInfo_->versionName;
    }

    std::string GetVendor() const
    {
        return baseBundleInfo_->vendor;
    }

    uint32_t GetCompatibleVersion() const
    {
        return baseBundleInfo_->compatibleVersion;
    }

    uint32_t GetTargetVersion() const
    {
        return baseBundleInfo_->targetVersion;
    }

    std::string GetReleaseType() const
    {
        return baseBundleInfo_->releaseType;
    }

    uint32_t GetMinCompatibleVersionCode() const
    {
        return baseBundleInfo_->minCompatibleVersionCode;
    }

    void SetInstallMark(const std::string &bundleName, const std::string &packageName,
        const InstallExceptionStatus &status)
    {
        mark_.bundleName = bundleName;
        mark_.packageName = packageName;
        mark_.status = status;
    }

    InstallMark GetInstallMark() const
    {
        return mark_;
    }

    std::string GetAppDataDir() const
    {
        return baseApplicationInfo_->dataDir;
    }

    void SetAppDataDir(std::string dataDir)
    {
        baseApplicationInfo_->dataDir = dataDir;
    }

    void SetAppDataBaseDir(std::string dataBaseDir)
    {
        baseApplicationInfo_->dataBaseDir = dataBaseDir;
    }

    void SetAppCacheDir(std::string cacheDir)
    {
        baseApplicationInfo_->cacheDir = cacheDir;
    }

    void SetUid(int uid) {}

    int GetUid(int32_t userId = Constants::UNSPECIFIED_USERID) const
    {
        InnerBundleUserInfo innerBundleUserInfo;
        if (!GetInnerBundleUserInfo(userId, innerBundleUserInfo)) {
            return Constants::INVALID_UID;
        }

        return innerBundleUserInfo.uid;
    }

    int GetGid(int32_t userId = Constants::UNSPECIFIED_USERID) const
    {
        InnerBundleUserInfo innerBundleUserInfo;
        if (!GetInnerBundleUserInfo(userId, innerBundleUserInfo)) {
            return Constants::INVALID_GID;
        }

        if (innerBundleUserInfo.gids.empty()) {
            return Constants::INVALID_GID;
        }

        return innerBundleUserInfo.gids[0];
    }

    void SetGid(int gid) {}

    Constants::AppType GetAppType() const
    {
        return appType_;
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

    int GetUserId() const
    {
        return userId_;
    }

    void SetUserId(int userId)
    {
        userId_ = userId;
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
                moduleResPath = moduleSrcDir + Constants::PATH_SEPARATOR + Constants::RESOURCES_INDEX;
            } else {
                moduleResPath = moduleSrcDir + Constants::PATH_SEPARATOR + Constants::ASSETS_DIR +
                    Constants::PATH_SEPARATOR +innerModuleInfos_.at(currentPackage_).distro.moduleName +
                    Constants::PATH_SEPARATOR + Constants::RESOURCES_INDEX;
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
        SetUid(oldInfo.GetUid());
        SetGid(oldInfo.GetGid());
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
    ErrCode SetModuleUpgradeFlag(std::string moduleName, int32_t upgradeFlag);
    int32_t GetModuleUpgradeFlag(std::string moduleName) const;
    void GetApplicationInfo(int32_t flags, int32_t userId, ApplicationInfo &appInfo) const;
    ErrCode GetApplicationInfoV9(int32_t flags, int32_t userId, ApplicationInfo &appInfo) const;
    bool GetBundleInfo(int32_t flags, BundleInfo &bundleInfo, int32_t userId = Constants::UNSPECIFIED_USERID) const;
    ErrCode GetBundleInfoV9(int32_t flags,
        BundleInfo &bundleInfo, int32_t userId = Constants::UNSPECIFIED_USERID) const;
    bool CheckSpecialMetaData(const std::string &metaData) const;
    void GetFormsInfoByModule(const std::string &moduleName, std::vector<FormInfo> &formInfos) const;
    void GetFormsInfoByApp(std::vector<FormInfo> &formInfos) const;
    void GetShortcutInfos(std::vector<ShortcutInfo> &shortcutInfos) const;
    void GetCommonEvents(const std::string &eventKey, std::vector<CommonEventInfo> &commonEvents) const;
    std::optional<InnerModuleInfo> GetInnerModuleInfoByModuleName(const std::string &moduleName) const;
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
    bool IsOnlyCreateBundleUser() const
    {
        return onlyCreateBundleUser_;
    }

    void SetOnlyCreateBundleUser(bool onlyCreateBundleUser)
    {
        onlyCreateBundleUser_ = onlyCreateBundleUser;
    }

    bool IsSingleton() const
    {
        return baseApplicationInfo_->singleton;
    }

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

    bool IsAbilityEnabled(const AbilityInfo &abilityInfo, int32_t userId) const;
    ErrCode IsAbilityEnabledV9(const AbilityInfo &abilityInfo, int32_t userId, bool &isEnable) const;
    bool IsAccessible() const
    {
        return baseApplicationInfo_->accessible;
    }

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
            APP_LOGE("innerBundleInfo does not contain the module.");
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

    void AddDataGroupInfo(const std::string &dataGroupId, const DataGroupInfo &info)
    {
        APP_LOGD("AddDataGroupInfo, dataGroupId: %{public}s, dataGroupInfo: %{public}s",
            dataGroupId.c_str(), info.ToString().c_str());
        auto dataGroupInfosItem = dataGroupInfos_.find(dataGroupId);
        if (dataGroupInfosItem == dataGroupInfos_.end()) {
            APP_LOGD("AddDataGroupInfo add new dataGroupInfo for dataGroupId: %{public}s", dataGroupId.c_str());
            dataGroupInfos_[dataGroupId] = std::vector<DataGroupInfo> { info };
            return;
        }

        int32_t userId = info.userId;
        auto iter = std::find_if(std::begin(dataGroupInfos_[dataGroupId]), std::end(dataGroupInfos_[dataGroupId]),
            [userId](const DataGroupInfo &dataGroupinfo) { return dataGroupinfo.userId == userId; });
        if (iter != std::end(dataGroupInfos_[dataGroupId])) {
            return;
        }

        APP_LOGD("AddDataGroupInfo add new dataGroupInfo for user: %{public}d", info.userId);
        dataGroupInfos_[dataGroupId].emplace_back(info);
    }

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

    void SetGwpAsanEnabled(bool gwpAsanEnabled)
    {
        baseApplicationInfo_->gwpAsanEnabled = gwpAsanEnabled;
    }

    bool GetGwpAsanEnabled() const
    {
        return baseApplicationInfo_->gwpAsanEnabled;
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

private:
    bool IsExistLauncherAbility() const;
    void GetBundleWithAbilities(
        int32_t flags, BundleInfo &bundleInfo, int32_t userId = Constants::UNSPECIFIED_USERID) const;
    void GetBundleWithExtension(
        int32_t flags, BundleInfo &bundleInfo, int32_t userId = Constants::UNSPECIFIED_USERID) const;
    void RemoveDuplicateName(std::vector<std::string> &name) const;
    void GetBundleWithReqPermissionsV9(int32_t flags, int32_t userId, BundleInfo &bundleInfo) const;
    void ProcessBundleFlags(int32_t flags, int32_t userId, BundleInfo &bundleInfo) const;
    void ProcessBundleWithHapModuleInfoFlag(int32_t flags, BundleInfo &bundleInfo, int32_t userId) const;
    void GetBundleWithAbilitiesV9(int32_t flags, HapModuleInfo &hapModuleInfo, int32_t userId) const;
    void GetBundleWithExtensionAbilitiesV9(int32_t flags, HapModuleInfo &hapModuleInfo) const;
    IsolationMode GetIsolationMode(const std::string &isolationMode) const;
    void UpdateIsCompressNativeLibs();
    void InnerProcessShortcut(const Shortcut &oldShortcut, ShortcutInfo &shortcutInfo) const;

    // using for get
    Constants::AppType appType_ = Constants::AppType::THIRD_PARTY_APP;
    int uid_ = Constants::INVALID_UID;
    int gid_ = Constants::INVALID_GID;
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
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_BUNDLE_INFO_H
