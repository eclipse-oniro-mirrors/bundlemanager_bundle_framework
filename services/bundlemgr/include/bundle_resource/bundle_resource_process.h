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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_PROCESS_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_PROCESS_H

#include "ability_info.h"
#include "inner_bundle_info.h"
#include "resource_info.h"

#include <map>
#include <string>
#include <vector>

namespace OHOS {
namespace AppExecFwk {
class BundleResourceProcess {
public:
    // get LauncherAbilityResourceInfo and BundleResourceInfo by bundleName
    static bool GetResourceInfoByBundleName(const std::string &bundleName, const int32_t userId,
        std::vector<ResourceInfo> &resourceInfo);
    // get LauncherAbilityResourceInfo by abilityName
    static bool GetLauncherResourceInfoByAbilityName(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, const int32_t userId,
        ResourceInfo &resourceInfo);
    // get all LauncherAbilityResourceInfo and BundleResourceInfo
    static bool GetAllResourceInfo(const int32_t userId,
        std::map<std::string, std::vector<ResourceInfo>> &resourceInfosMap);
    // get LauncherAbilityResourceInfo when colorMode changed
    static bool GetResourceInfoByColorModeChanged(const std::vector<std::string> &resourceNames,
        const int32_t userId, std::vector<ResourceInfo> &resourceInfos);

    static void GetTargetBundleName(const std::string &bundleName, std::string &targetBundleName);

private:
    // used for show in settings
    static bool GetBundleResourceInfo(const InnerBundleInfo &innerBundleInfo, const int32_t userId,
        ResourceInfo &resourceInfo);
    // get launcher ability resource
    static bool GetLauncherAbilityResourceInfos(const InnerBundleInfo &innerBundleInfo, const int32_t userId,
        std::vector<ResourceInfo> &resourceInfos);
    // get all ability resource
    static bool GetAbilityResourceInfos(const InnerBundleInfo &innerBundleInfo, const int32_t userId,
        std::vector<ResourceInfo> &resourceInfos);

    static ResourceInfo ConvertToLauncherAbilityResourceInfo(const AbilityInfo &ability);

    static ResourceInfo ConvertToBundleResourceInfo(const InnerBundleInfo &innerBundleInfo);

    static bool InnerGetResourceInfo(const InnerBundleInfo &innerBundleInfo, const int32_t userId,
        std::vector<ResourceInfo> &resourceInfos);

    static bool OnGetResourceInfo(const InnerBundleInfo &innerBundleInfo, const int32_t userId,
        std::vector<ResourceInfo> &resourceInfos);

    static bool CheckIsNeedProcessAbilityResource(const InnerBundleInfo &innerBundleInfo);

    static bool GetOverlayModuleHapPaths(const InnerBundleInfo &innerBundleInfo, const std::string &moduleName,
        int32_t userId, std::vector<std::string> &overlayHapPaths);

    static void ChangeDynamicIcon(
        std::vector<ResourceInfo> &resourceInfos, const ResourceInfo &resourceInfo);

    static bool GetDynamicIcon(
        const InnerBundleInfo &innerBundleInfo, ResourceInfo &resourceInfo);

    static bool GetExternalOverlayHapState(const std::string &bundleName,
        const std::string &moduleName, const int32_t userId, int32_t &state);
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_PROCESS_H
