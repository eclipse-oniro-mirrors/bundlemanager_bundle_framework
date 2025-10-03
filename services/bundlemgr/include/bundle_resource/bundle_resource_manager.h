/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_MANAGER_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_MANAGER_H

#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "ability_info.h"
#include "bundle_constants.h"
#include "bundle_resource_change_type.h"
#include "bundle_resource_icon_rdb.h"
#include "bundle_resource_rdb.h"
#include "bundle_system_state.h"
#include "inner_bundle_info.h"
#include "launcher_ability_info.h"
#include "resource_info.h"
#include "resource_manager.h"
#include "singleton.h"
#include "single_delayed_task_mgr.h"
#include "uninstall_bundle_resource_rdb.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
class BundleResourceManager : public DelayedSingleton<BundleResourceManager> {
public:
    BundleResourceManager();

    ~BundleResourceManager();
    /**
     * delete resource info
     */
    bool DeleteResourceInfo(const std::string &key);
    /**
     * delete all resource info
     */
    bool DeleteAllResourceInfo();

    bool GetAllResourceName(std::vector<std::string> &keyNames);

    bool GetBundleResourceInfo(const std::string &bundleName, const uint32_t flags,
        BundleResourceInfo &bundleResourceInfo, const int32_t appIndex = 0);

    bool GetLauncherAbilityResourceInfo(const std::string &bundleName, const uint32_t flags,
        std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfo, const int32_t appIndex = 0);

    bool GetAllBundleResourceInfo(const uint32_t flags, std::vector<BundleResourceInfo> &bundleResourceInfos);

    bool GetAllLauncherAbilityResourceInfo(const uint32_t flags,
        std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos);

    bool IsLauncherAbility(const LauncherAbilityResourceInfo &resourceInfo, std::vector<AbilityInfo> &abilityInfos);

    bool GetLauncherAbilityInfos(const std::string &bundleName, std::vector<AbilityInfo> &abilityInfos);

    bool FilterLauncherAbilityResourceInfoWithFlag(const uint32_t flags,
        const std::string &bundleName, std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos);

    void GetTargetBundleName(const std::string &bundleName, std::string &targetBundleName);

    bool DeleteNotExistResourceInfo();

    bool GetExtensionAbilityResourceInfo(const std::string &bundleName,
        const ExtensionAbilityType extensionAbilityType, const uint32_t flags,
        std::vector<LauncherAbilityResourceInfo> &extensionAbilityResourceInfo, const int32_t appIndex = 0);

    bool AddResourceInfoByBundleNameWhenInstall(const std::string &bundleName, const int32_t userId,
        const bool isBundleFirstInstall = true);

    bool AddResourceInfoByBundleNameWhenUpdate(const std::string &bundleName, const int32_t userId);

    bool AddResourceInfoByBundleNameWhenCreateUser(const std::string &bundleName, const int32_t userId);

    bool DeleteBundleResourceInfo(const std::string &bundleName, const int32_t userId, const bool isExistInOtherUser);

    bool AddDynamicIconResource(
        const std::string &bundleName, const int32_t userId, const int32_t appIndex, ResourceInfo &resourceInfo);

    bool DeleteDynamicIconResource(const std::string &bundleName, const int32_t userId, const int32_t appIndex);

    bool AddAllResourceInfo(const int32_t userId, const uint32_t type);

    bool AddResourceInfosWhenSystemThemeChanged(
        std::map<std::string, std::vector<ResourceInfo>> &resourceInfosMap,
        const int32_t userId, const uint32_t tempTaskNumber);

    bool AddResourceInfosWhenSystemLanguageChanged(
        std::map<std::string, std::vector<ResourceInfo>> &resourceInfosMap,
        const int32_t userId, const uint32_t tempTaskNumber);

    bool AddCloneBundleResourceInfoWhenInstall(const std::string &bundleName, const int32_t userId,
        const int32_t appIndex, const bool isExistInOtherUser);

    bool DeleteCloneBundleResourceInfoWhenUninstall(const std::string &bundleName, const int32_t userId,
        const int32_t appIndex, const bool isExistInOtherUser);

    void SetIsOnlineThemeWhenBoot();

    // for ota, need process all user
    bool ProcessThemeAndDynamicIconWhenOta(const std::set<std::string> &updateBundleNames);

    bool AddUninstallBundleResource(const std::string &bundleName, const int32_t userId, const int32_t appIndex);

    bool DeleteUninstallBundleResource(const std::string &bundleName, const int32_t userId, const int32_t appIndex);

private:
    void ProcessResourceInfoWhenParseFailed(ResourceInfo &resourceInfo);

    void GetDefaultIcon(ResourceInfo &resourceInfo);

    uint32_t CheckResourceFlags(const uint32_t flags);

    void SendBundleResourcesChangedEvent(const int32_t userId, const uint32_t type);

    void InnerProcessResourceInfoBySystemLanguageChanged(
        std::map<std::string, std::vector<ResourceInfo>> &resourceInfosMap);

    void InnerProcessResourceInfoBySystemThemeChanged(
        std::map<std::string, std::vector<ResourceInfo>> &resourceInfosMap, const int32_t userId);

    void DeleteNotExistResourceInfo(const std::map<std::string, std::vector<ResourceInfo>> &resourceInfosMap,
        const std::vector<std::string> &existResourceNames);

    bool GetBundleResourceInfoForCloneBundle(const std::string &bundleName,
        const int32_t appIndex, const uint32_t type, std::vector<ResourceInfo> &resourceInfos);

    bool ProcessCloneBundleResourceInfo(const std::string &bundleName, const int32_t appIndex);

    void DeleteNotExistResourceInfo(const std::string &bundleName,
        const int32_t appIndex, const std::vector<ResourceInfo> &resourceInfos);

    void ProcessResourceInfoNoNeedToParseOtherIcon(std::vector<ResourceInfo> &resourceInfos);

    bool ProcessCloneBundleResourceInfoWhenSystemThemeChanged(
        const std::string &bundleName, const int32_t userId, const int32_t appIndex);

    bool ProcessCloneBundleResourceInfoWhenSystemLanguageChanged(
        const std::string &bundleName, const int32_t userId, const int32_t appIndex);

    void DeleteNotExistThemeResource(const std::map<std::string, std::vector<ResourceInfo>> &resourceInfosMap,
        const std::set<std::string> &oldResourceNames, const int32_t userId);

    bool IsNeedProcessResourceIconInfo(const uint32_t resourceFlags);

    bool InnerProcessThemeIconWhenOta(const std::string &bundleName, const std::set<int32_t> userIds,
        const bool hasBundleUpdated = false);

    bool InnerProcessDynamicIconWhenOta(const std::string &bundleName);

    int32_t GetUserId();

    void SetIsOnlineTheme(const int32_t userId);

    void PrepareSysRes();

    bool IsNeedInterrupted(const uint32_t tempTaskNumber, const BundleResourceChangeType type);

    std::atomic_uint currentTaskNum_ = 0;
    std::atomic_uint currentChangeType_ = 0;
    std::mutex mutex_;
    std::shared_ptr<BundleResourceRdb> bundleResourceRdb_;
    std::shared_ptr<BundleResourceIconRdb> bundleResourceIconRdb_;
    std::shared_ptr<UninstallBundleResourceRdb> uninstallBundleResourceRdb_;
    std::shared_ptr<SingleDelayedTaskMgr> delayedTaskMgr_ = nullptr;
    static std::mutex g_sysResMutex;
    static std::shared_ptr<Global::Resource::ResourceManager> g_resMgr;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_MANAGER_H
