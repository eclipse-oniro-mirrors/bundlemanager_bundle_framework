/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_HELPER_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_HELPER_H

#include <string>
#include <vector>

#include "bundle_constants.h"
#include "bundle_resource_info.h"
#include "inner_bundle_info.h"
#include "launcher_ability_resource_info.h"

namespace OHOS {
namespace AppExecFwk {
enum class ADD_RESOURCE_TYPE {
    INSTALL_BUNDLE = 1,
    UPDATE_BUNDLE = 2,
    CREATE_USER = 3
};

class BundleResourceHelper {
public:
    // parse system config and init BundleSystemState, like language and colorMode
    static void BundleSystemStateInit();

    // Register observer to monitor system state changes
    static void RegisterConfigurationObserver();

    // Register subscriber to monitor userId changes
    static void RegisterCommonEventSubscriber();

    static void AddResourceInfoByBundleName(const std::string &bundleName,
        const int32_t userId, const ADD_RESOURCE_TYPE type, const bool isBundleFirstInstall = true);

    static bool DeleteBundleResourceInfo(const std::string &bundleName,
        const int32_t userId, const bool isExistInOtherUser);

    static bool DeleteAllResourceInfo();

    static void GetAllBundleResourceName(std::vector<std::string> &resourceNames);

    static std::string ParseBundleName(const std::string &keyName);

    static void SetIsOnlineThemeWhenBoot();

    static void SetOverlayEnabled(const std::string &bundleName, const std::string &moduleName, bool isEnabled,
        int32_t userId);

    static bool AddCloneBundleResourceInfo(const std::string &bundleName,
        const int32_t userId, const int32_t appIndex, const bool isExistInOtherUser);

    static bool DeleteCloneBundleResourceInfo(const std::string &bundleName, const int32_t userId,
        const int32_t appIndex, const bool isExistInOtherUser);

    static bool ProcessThemeAndDynamicIconWhenOta(const std::set<std::string> updateBundleNames);

    static void DeleteNotExistResourceInfo();

    static bool GetBundleResourceInfo(const std::string &bundleName, const uint32_t flags,
        BundleResourceInfo &bundleResourceInfo, const int32_t appIndex = 0);
        
    static bool GetLauncherAbilityResourceInfo(const std::string &bundleName, const uint32_t flags,
        std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfo, const int32_t appIndex = 0);

    static void ProcessBundleResourceChange();

    static void AddUninstallBundleResource(const std::string &bundleName, const int32_t userId,
        const int32_t appIndex);

    static void DeleteUninstallBundleResource(const std::string &bundleName, const int32_t userId,
        const int32_t appIndex);
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_HELPER_H
