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
#include "inner_bundle_info.h"

namespace OHOS {
namespace AppExecFwk {
class BundleResourceHelper {
public:
    // parse system config and init BundleSystemState, like language and colorMode
    static void BundleSystemStateInit();

    // Register observer to monitor system state changes
    static void RegisterConfigurationObserver();

    // Register subscriber to monitor userId changes
    static void RegisterCommonEventSubscriber();

    static void AddResourceInfoByBundleName(const std::string &bundleName,
        const int32_t userId);

    static bool DeleteResourceInfo(const std::string &key, const int32_t userId = Constants::UNSPECIFIED_USERID);

    static bool DeleteAllResourceInfo();

    static void SetApplicationEnabled(const std::string &bundleName, bool enabled, const int32_t userId,
        int32_t appIndex = 0);

    static void SetAbilityEnabled(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, bool enabled, const int32_t userId, int32_t appIndex = 0);

    static void GetAllBundleResourceName(std::vector<std::string> &resourceNames);

    static void SetOverlayEnabled(const std::string &bundleName, const std::string &moduleName, bool isEnabled,
        int32_t userId);

    static bool AddCloneBundleResourceInfo(const std::string &bundleName,
        const int32_t appIndex, const int32_t userId = Constants::UNSPECIFIED_USERID);

    static bool DeleteCloneBundleResourceInfo(const std::string &bundleName, const int32_t appIndex,
        const int32_t userId = Constants::UNSPECIFIED_USERID);
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_HELPER_H
