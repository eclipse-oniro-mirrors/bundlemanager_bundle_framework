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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_CALLBACK_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_CALLBACK_H

#include <string>

namespace OHOS {
namespace AppExecFwk {
class BundleResourceCallback {
public:
    BundleResourceCallback() = default;

    ~BundleResourceCallback() = default;

    // for userId switched
    bool OnUserIdSwitched(const int32_t userId);

    // for colorMode changed
    bool OnSystemColorModeChanged(const std::string &colorMode);

    // for system language changed
    bool OnSystemLanguageChange(const std::string &language);

    // for bundle enable or disable
    bool OnBundleStatusChanged(const std::string &bundleName, bool enabled, const int32_t userId, int32_t appIndex = 0);

    // for ability enable or disable
    bool OnAbilityStatusChanged(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, bool enabled, const int32_t userId);

    // for application theme changed
    bool OnApplicationThemeChanged(const std::string &theme);

    // for overlay
    bool OnOverlayStatusChanged(const std::string &bundleName, bool isEnabled, int32_t userId);
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_CALLBACK_H
