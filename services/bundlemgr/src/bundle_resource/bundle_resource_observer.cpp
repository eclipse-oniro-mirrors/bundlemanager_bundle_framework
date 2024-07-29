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

#include "bundle_resource_observer.h"

#include <thread>

#include "app_log_wrapper.h"
#include "bundle_resource_callback.h"
#include "bundle_system_state.h"

#ifdef ABILITY_RUNTIME_ENABLE
#include "configuration.h"
#endif

namespace OHOS {
namespace AppExecFwk {
#ifdef ABILITY_RUNTIME_ENABLE
BundleResourceObserver::BundleResourceObserver()
{}

BundleResourceObserver::~BundleResourceObserver()
{}

void BundleResourceObserver::OnConfigurationUpdated(const AppExecFwk::Configuration& configuration)
{
    APP_LOGI("called");
    std::string colorMode = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_COLORMODE);
    if (!colorMode.empty() && (colorMode != BundleSystemState::GetInstance().GetSystemColorMode())) {
        APP_LOGI("OnSystemColorModeChanged colorMode:%{public}s", colorMode.c_str());
        OnSystemColorModeChanged(colorMode, static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_COLOR_MODE_CHANGE));
    }
    uint32_t type = 0;
    std::string language = configuration.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE);
    if (!language.empty() && (language != BundleSystemState::GetInstance().GetSystemLanguage())) {
        APP_LOGI("language change %{public}s", language.c_str());
        type = (type == 0) ? static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_LANGUE_CHANGE) :
            (type | static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_LANGUE_CHANGE));
        std::thread systemLanguageChangedThread(OnSystemLanguageChange, language, type);
        systemLanguageChangedThread.detach();
    }
    std::string theme = configuration.GetItem(AAFwk::GlobalConfigurationKey::THEME);
    if (!theme.empty()) {
        APP_LOGI("theme change %{public}s", theme.c_str());
        type = (type == 0) ? static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_THEME_CHANGE) :
            (type | static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_THEME_CHANGE));
        std::thread applicationThemeChangedThread(OnApplicationThemeChanged, theme, type);
        applicationThemeChangedThread.detach();
    }
    APP_LOGI("end change type %{public}u", type);
}

void BundleResourceObserver::OnSystemColorModeChanged(const std::string &colorMode, const uint32_t type)
{
    BundleResourceCallback callback;
    callback.OnSystemColorModeChanged(colorMode, type);
}

void BundleResourceObserver::OnSystemLanguageChange(const std::string &language, const uint32_t type)
{
    BundleResourceCallback callback;
    callback.OnSystemLanguageChange(language, type);
}

void BundleResourceObserver::OnApplicationThemeChanged(const std::string &theme, const uint32_t type)
{
    BundleResourceCallback callback;
    callback.OnApplicationThemeChanged(theme, type);
}
#endif
} // AppExecFwk
} // OHOS
