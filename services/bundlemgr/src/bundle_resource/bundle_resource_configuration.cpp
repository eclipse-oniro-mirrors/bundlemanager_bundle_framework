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

#include "bundle_resource_configuration.h"

#include "app_log_wrapper.h"
#include "bundle_system_state.h"
#include "bundle_util.h"
#ifdef GLOBAL_I18_ENABLE
#include "locale_config.h"
#include "locale_info.h"
#endif
#include <unordered_map>

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string RESOURCE_LIGHT = "light";
const std::string RESOURCE_DARK = "dark";
static const std::unordered_map<std::string, Global::Resource::ColorMode> BUNDLE_COLOR_MODE = {
    {RESOURCE_LIGHT, Global::Resource::ColorMode::LIGHT},
    {RESOURCE_DARK, Global::Resource::ColorMode::DARK},
};

Global::Resource::ColorMode ConvertColorMode(const std::string &colorMode)
{
    if (BUNDLE_COLOR_MODE.find(colorMode) != BUNDLE_COLOR_MODE.end()) {
        return BUNDLE_COLOR_MODE.at(colorMode);
    }
    return Global::Resource::ColorMode::COLOR_MODE_NOT_SET;
}
}

bool BundleResourceConfiguration::InitResourceGlobalConfig(
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager)
{
    return InitResourceGlobalConfig("", resourceManager);
}

bool BundleResourceConfiguration::InitResourceGlobalConfig(
    const std::string &hapPath,
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager)
{
    if (resourceManager == nullptr) {
        APP_LOGE("resourceManager is nullptr");
        return false;
    }
    std::unique_ptr<Global::Resource::ResConfig> resConfig(Global::Resource::CreateResConfig());
    if (resConfig == nullptr) {
        APP_LOGE("resConfig is nullptr");
        return false;
    }

#ifdef GLOBAL_I18_ENABLE
    std::map<std::string, std::string> configs;
    OHOS::Global::I18n::LocaleInfo locale(Global::I18n::LocaleConfig::GetSystemLocale(), configs);
    resConfig->SetLocaleInfo(locale.GetLanguage().c_str(), locale.GetScript().c_str(), locale.GetRegion().c_str());
#endif
    std::string colorMode = BundleSystemState::GetInstance().GetSystemColorMode();
    resConfig->SetColorMode(ConvertColorMode(colorMode));
    resConfig->SetScreenDensityDpi(Global::Resource::ScreenDensity::SCREEN_DENSITY_XXXLDPI);

    Global::Resource::RState ret = resourceManager->UpdateResConfig(*resConfig);
    if (ret != Global::Resource::RState::SUCCESS) {
        APP_LOGE("UpdateResConfig failed with errcode %{public}d", static_cast<int32_t>(ret));
        return false;
    }
    if (!hapPath.empty() && !resourceManager->AddResource(hapPath.c_str(),
        Global::Resource::SELECT_STRING | Global::Resource::SELECT_MEDIA)) {
        APP_LOGE("AddResource failed, hapPath: %{private}s", hapPath.c_str());
        return false;
    }
    return true;
}

bool BundleResourceConfiguration::InitResourceGlobalConfig(const std::string &hapPath,
    const std::vector<std::string> &overlayHaps,
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager)
{
    if (resourceManager == nullptr) {
        APP_LOGE("resourceManager is nullptr");
        return false;
    }
    std::unique_ptr<Global::Resource::ResConfig> resConfig(Global::Resource::CreateResConfig());
    if (resConfig == nullptr) {
        APP_LOGE("resConfig is nullptr");
        return false;
    }

#ifdef GLOBAL_I18_ENABLE
    std::map<std::string, std::string> configs;
    OHOS::Global::I18n::LocaleInfo locale(Global::I18n::LocaleConfig::GetSystemLocale(), configs);
    resConfig->SetLocaleInfo(locale.GetLanguage().c_str(), locale.GetScript().c_str(), locale.GetRegion().c_str());
#endif
    std::string colorMode = BundleSystemState::GetInstance().GetSystemColorMode();
    resConfig->SetColorMode(ConvertColorMode(colorMode));
    resConfig->SetScreenDensityDpi(Global::Resource::ScreenDensity::SCREEN_DENSITY_XXXLDPI);

    Global::Resource::RState ret = resourceManager->UpdateResConfig(*resConfig);
    if (ret != Global::Resource::RState::SUCCESS) {
        APP_LOGE("UpdateResConfig failed with errcode %{public}d", static_cast<int32_t>(ret));
        return false;
    }
    // adapt overlay
    if (overlayHaps.empty()) {
        if (!resourceManager->AddResource(hapPath.c_str(),
            Global::Resource::SELECT_STRING | Global::Resource::SELECT_MEDIA)) {
            APP_LOGW("AddResource failed, hapPath: %{public}s", hapPath.c_str());
        }
    } else {
        if (!resourceManager->AddResource(hapPath, overlayHaps)) {
            APP_LOGW("AddResource overlay failed, hapPath: %{public}s", hapPath.c_str());
        }
    }
    return true;
}
} // AppExecFwk
} // OHOS
