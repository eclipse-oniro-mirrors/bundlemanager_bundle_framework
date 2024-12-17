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
#ifdef GLOBAL_I18_ENABLE
#include "locale_config.h"
#include "locale_info.h"
#endif

namespace OHOS {
namespace AppExecFwk {
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
    resConfig->SetScreenDensityDpi(Global::Resource::ScreenDensity::SCREEN_DENSITY_XXXLDPI);

    Global::Resource::RState ret = resourceManager->UpdateResConfig(*resConfig);
    if (ret != Global::Resource::RState::SUCCESS) {
        APP_LOGE("UpdateResConfig failed %{public}d", static_cast<int32_t>(ret));
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
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager,
    bool needParseIcon, bool needParseLabel)
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
    resConfig->SetScreenDensityDpi(Global::Resource::ScreenDensity::SCREEN_DENSITY_XXXLDPI);

    Global::Resource::RState ret = resourceManager->UpdateResConfig(*resConfig);
    if (ret != Global::Resource::RState::SUCCESS) {
        APP_LOGE("UpdateResConfig failed %{public}d", static_cast<int32_t>(ret));
        return false;
    }
    // adapt overlay
    APP_LOGI_NOFUNC("AddResource start");
    if (overlayHaps.empty()) {
        uint32_t selectType = needParseIcon ? Global::Resource::SELECT_MEDIA : 0;
        selectType = needParseLabel ? (selectType | Global::Resource::SELECT_STRING) : selectType;
        if (!resourceManager->AddResource(hapPath.c_str(), selectType)) {
            APP_LOGW("AddResource failed, hapPath: %{public}s", hapPath.c_str());
        }
    } else {
        if (!resourceManager->AddResource(hapPath, overlayHaps)) {
            APP_LOGW("AddResource overlay failed, hapPath: %{public}s", hapPath.c_str());
        }
    }
    APP_LOGI_NOFUNC("AddResource end");
    return true;
}
} // AppExecFwk
} // OHOS
