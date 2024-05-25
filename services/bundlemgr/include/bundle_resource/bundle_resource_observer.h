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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_OBSERVER_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_OBSERVER_H

#include <string>

#ifdef ABILITY_RUNTIME_ENABLE
#include "configuration_observer_stub.h"
#endif

namespace OHOS {
namespace AppExecFwk {
#ifdef ABILITY_RUNTIME_ENABLE
class BundleResourceObserver : public ConfigurationObserverStub {
public:
    BundleResourceObserver();

    virtual ~BundleResourceObserver() override;

    void OnConfigurationUpdated(const AppExecFwk::Configuration& configuration) override;

private:
    static void OnSystemColorModeChanged(const std::string &colorMode, const uint32_t type);

    static void OnSystemLanguageChange(const std::string &language, const uint32_t type);

    static void OnApplicationThemeChanged(const std::string &theme, const uint32_t type);
};
#endif
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_RESOURCE_OBSERVER_H
