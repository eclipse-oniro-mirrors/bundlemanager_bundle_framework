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

#include <string>
#include <vector>

namespace OHOS {
namespace AppExecFwk {
class BundleResourceProcess {
public:
    // used for show in desktop
    static bool GetLauncherAbilityResourceInfo(const InnerBundleInfo &innerBundleInfo, const int32_t userId,
        std::vector<ResourceInfo> &resourceInfo);
    // used for show in settings
    static bool GetBundleResourceInfo(const InnerBundleInfo &innerBundleInfo, const int32_t userId,
        ResourceInfo &resourceInfo);
    // get LauncherAbilityResourceInfo and BundleResourceInfo
    static bool GetResourceInfo(const InnerBundleInfo &innerBundleInfo, const int32_t userId,
        std::vector<ResourceInfo> &resourceInfo);
    // get LauncherAbilityResourceInfo and BundleResourceInfo by bundleName
    static bool GetResourceInfoByBundleName(const std::string &bundleName, const int32_t userId,
        std::vector<ResourceInfo> &resourceInfo);
    // get LauncherAbilityResourceInfo by abilityName
    static bool GetResourceInfoByAbilityName(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, const int32_t userId,
        ResourceInfo &resourceInfo);
    // get all LauncherAbilityResourceInfo and BundleResourceInfo
    static bool GetAllResourceInfo(const int32_t userId, std::vector<ResourceInfo> &resourceInfos);
    // get LauncherAbilityResourceInfo when colorMode changed
    static bool GetResourceInfoByColorModeChanged(const std::vector<std::string> &resourceNames,
        std::vector<ResourceInfo> &resourceInfos);

private:
    static bool IsBundleExist(const InnerBundleInfo &innerBundleInfo, const int32_t userId);

    static int64_t GetUpdateTime(const InnerBundleInfo &innerBundleInfo,  const int32_t userId);

    static ResourceInfo ConvertToLauncherAbilityResourceInfo(const AbilityInfo &ability);

    static ResourceInfo ConvertToBundleResourceInfo(const InnerBundleInfo &innerBundleInfo,
        const int32_t userId);

    static bool InnerGetResourceInfo(const InnerBundleInfo &innerBundleInfo,  const int32_t userId,
        std::vector<ResourceInfo> &resourceInfos);

    static bool GetDefaultIconResource(int32_t &iconId, std::string &hapPath);
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_PROCESS_H
