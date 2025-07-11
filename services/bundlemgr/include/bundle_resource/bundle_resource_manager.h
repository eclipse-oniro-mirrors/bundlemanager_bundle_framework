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
#include "bundle_resource_rdb.h"
#include "bundle_system_state.h"
#include "inner_bundle_info.h"
#include "launcher_ability_info.h"
#include "resource_info.h"
#include "resource_manager.h"
#include "singleton.h"
#include "single_delayed_task_mgr.h"
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
     * add all resource info in system, used when system configuration changed, like:
     * language, colorMode, theme, and so on
     */
    bool AddAllResourceInfo(const int32_t userId, const uint32_t type,
        const int32_t oldUserId = Constants::INVALID_USERID);
    /**
     * delete all resource info
     */
    bool DeleteAllResourceInfo();
    /**
     * add bundle resource info by bundleName, used when bundle state changed, like:
     * enable or disable
     */
    bool AddResourceInfoByBundleName(const std::string &bundleName, const int32_t userId);
    /**
     * add launcher ability resource info by abilityName, used when ability state changed, like:
     * enable or disable
     */
    bool AddResourceInfoByAbility(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, const int32_t userId);

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

    bool SaveResourceInfos(std::vector<ResourceInfo> &resourceInfos);

    void GetTargetBundleName(const std::string &bundleName, std::string &targetBundleName);

    bool UpdateBundleIcon(const std::string &bundleName, ResourceInfo &resourceInfo);

    bool AddCloneBundleResourceInfo(const std::string &bundleName, const int32_t appIndex,
        const int32_t userId = Constants::UNSPECIFIED_USERID);

    bool DeleteCloneBundleResourceInfo(const std::string &bundleName, const int32_t appIndex);

    bool DeleteNotExistResourceInfo();

    bool AddResourceInfoByBundleName(const std::string &bundleName, const int32_t userId, const int32_t appIndex);
	
    bool GetExtensionAbilityResourceInfo(const std::string &bundleName,
        const ExtensionAbilityType extensionAbilityType, const uint32_t flags,
        std::vector<LauncherAbilityResourceInfo> &extensionAbilityResourceInfo, const int32_t appIndex = 0);

    bool GetResourceInfoForRequestUser(const std::string &bundleName, const int32_t userId, const uint32_t flags,
        const int32_t appIndex, std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfo);
    
    bool ConvertLauncherAbilityResourceInfo(const ResourceInfo &resourceInfo, const uint32_t flags,
        LauncherAbilityResourceInfo &launcherAbilityResourceInfo);

private:
    bool AddResourceInfo(const int32_t userId, ResourceInfo &resourceInfo);

    bool AddResourceInfos(const int32_t userId, std::vector<ResourceInfo> &resourceInfos);

    bool AddResourceInfosByMap(std::map<std::string, std::vector<ResourceInfo>> &resourceInfosMap,
        const uint32_t tempTaskNumber, const uint32_t type, const int32_t userId, const int32_t oldUserId);

    void InnerProcessResourceInfoByResourceUpdateType(
        std::map<std::string, std::vector<ResourceInfo>> &resourceInfosMap, const uint32_t type,
        const int32_t userId, const int32_t oldUserId);

    void ProcessResourceInfoWhenParseFailed(ResourceInfo &resourceInfo);

    void ProcessResourceInfo(const std::vector<ResourceInfo> &resourceInfos, ResourceInfo &resourceInfo);

    void GetDefaultIcon(ResourceInfo &resourceInfo);

    uint32_t CheckResourceFlags(const uint32_t flags);

    void SendBundleResourcesChangedEvent(const int32_t userId, const uint32_t type);

    void InnerProcessResourceInfoBySystemLanguageChanged(
        std::map<std::string, std::vector<ResourceInfo>> &resourceInfosMap);

    void InnerProcessResourceInfoBySystemThemeChanged(
        std::map<std::string, std::vector<ResourceInfo>> &resourceInfosMap,
        const int32_t userId);

    void InnerProcessResourceInfoByUserIdChanged(
        std::map<std::string, std::vector<ResourceInfo>> &resourceInfosMap,
        const int32_t userId, const int32_t oldUserId);

    void DeleteNotExistResourceInfo(const std::map<std::string, std::vector<ResourceInfo>> &resourceInfosMap,
        const std::vector<std::string> &existResourceNames);

    bool InnerProcessWhetherThemeExist(const std::string &bundleName, const int32_t userId);

    bool GetBundleResourceInfoForCloneBundle(const std::string &bundleName,
        const int32_t appIndex, std::vector<ResourceInfo> &resourceInfos);

    bool UpdateCloneBundleResourceInfo(const std::string &bundleName, const int32_t appIndex, const uint32_t type);

    bool UpdateCloneBundleResourceInfo(const std::string &bundleName, const int32_t userId,
        const int32_t appIndex, const uint32_t type);

    void DeleteNotExistResourceInfo(const std::string &bundleName,
        const int32_t appIndex, const std::vector<ResourceInfo> &resourceInfos);

    void ProcessResourceInfoNoNeedToParseOtherIcon(std::vector<ResourceInfo> &resourceInfos);

    bool ProcessUpdateCloneBundleResourceInfo(const std::string &bundleName);

    void BundleResourceConvertToResourceInfo(const BundleResourceInfo &bundleResourceInfo, ResourceInfo &resourceInfo);

    void LauncherAbilityResourceConvertToResourceInfo(
        const LauncherAbilityResourceInfo &launcherAbilityResourceInfo, ResourceInfo &resourceInfo);

    void PrepareSysRes();

    bool CheckAllAddResourceInfo(const int32_t userId);

    std::atomic<bool> isInterrupted_ = false;
    std::atomic_uint currentTaskNum_ = 0;
    std::mutex mutex_;
    std::shared_ptr<BundleResourceRdb> bundleResourceRdb_;
    std::shared_ptr<SingleDelayedTaskMgr> delayedTaskMgr_ = nullptr;
    static std::mutex g_sysResMutex;
    static std::shared_ptr<Global::Resource::ResourceManager> g_resMgr;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_MANAGER_H
