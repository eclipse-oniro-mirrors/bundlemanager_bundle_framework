/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_THEME_PROCESS_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_THEME_PROCESS_H

#include <vector>

#include "bundle_resource_info.h"
#include "launcher_ability_resource_info.h"

namespace OHOS {
namespace AppExecFwk {
class BundleResourceThemeProcess : public std::enable_shared_from_this<BundleResourceThemeProcess> {
public:
    BundleResourceThemeProcess() {};
    ~BundleResourceThemeProcess() {};

    static bool IsBundleThemeExist(const std::string &bundleName, const int32_t userId);

    static bool IsAbilityThemeExist(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, const int32_t userId);

    static bool IsThemeExistInFlagA(const std::string &bundleName, const int32_t userId);

    static bool IsThemeExistInFlagB(const std::string &bundleName, const int32_t userId);

    static void ProcessSpecialBundleResource(const std::vector<LauncherAbilityResourceInfo> &resourceIconInfos,
        BundleResourceInfo &bundleResourceInfo);
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_THEME_PROCESS_H