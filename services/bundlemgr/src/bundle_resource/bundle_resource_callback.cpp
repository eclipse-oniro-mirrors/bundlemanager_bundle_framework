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

#include "bundle_resource_callback.h"

#include <string>

#include "account_helper.h"
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_resource_manager.h"
#include "bundle_resource_param.h"
#include "bundle_system_state.h"
#include "resource_info.h"

namespace OHOS {
namespace AppExecFwk {
void BundleResourceCallback::OnUserIdSwitched(const int32_t userId)
{
    APP_LOGI("start");
    if (userId != Constants::DEFAULT_USERID && userId != Constants::START_USERID) {
        int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
        if ((currentUserId <= 0) && (currentUserId != userId)) {
            APP_LOGE("userId: %{public}d, currentUserId :%{public}d not same", userId, currentUserId);
            return;
        }
    }
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("switch userId : %{public}d failed, manager is nullptr", userId);
        return;
    }
    if (!manager->DeleteAllResourceInfo()) {
        APP_LOGE("DeleteAllResourceInfo userId : %{public}d failed.", userId);
    }
    if (!manager->AddAllResourceInfo(userId)) {
        APP_LOGE("AddAllResourceInfo userId : %{public}d failed.", userId);
    }
}

void BundleResourceCallback::OnSystemColorModeChanged(const std::string &colorMode)
{
    APP_LOGI("start, colorMode: %{public}s", colorMode.c_str());
    if (colorMode == BundleSystemState::GetInstance().GetSystemColorMode()) {
        APP_LOGD("colorMode: %{public}s no change", colorMode.c_str());
        return;
    }
    BundleSystemState::GetInstance().SetSystemColorMode(colorMode);
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("manager is nullptr");
        return;
    }
    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    if (currentUserId <= 0) {
        currentUserId = Constants::START_USERID;
    }

    if (!manager->AddResourceInfoByColorModeChanged(currentUserId)) {
        APP_LOGE("add colorMode : %{public}s failed, currentUserId :%{public}d", colorMode.c_str(), currentUserId);
    }
}

void BundleResourceCallback::OnSystemLanguageChange(const std::string &language)
{
    APP_LOGI("start, current language is %{public}s", language.c_str());
    if (language == BundleSystemState::GetInstance().GetSystemLanguage()) {
        APP_LOGD("current language is %{public}s no change", language.c_str());
        return;
    }
    BundleSystemState::GetInstance().SetSystemLanguage(language);
    // need delete all and reload all
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("manager is nullptr");
        return;
    }

    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    if (currentUserId <= 0) {
        currentUserId = Constants::START_USERID;
    }

    if (!manager->DeleteAllResourceInfo()) {
        APP_LOGE("DeleteAllResourceInfo currentUserId : %{public}d failed.", currentUserId);
    }
    if (!manager->AddAllResourceInfo(currentUserId)) {
        APP_LOGE("AddAllResourceInfo currentUserId : %{public}d failed.", currentUserId);
    }
}

void BundleResourceCallback::OnBundleStatusChanged(
    const std::string &bundleName,
    bool enabled,
    const int32_t userId)
{
    APP_LOGI("start, bundleName: %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return;
    }
    if (userId != Constants::DEFAULT_USERID && userId != Constants::START_USERID) {
        int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
        if ((currentUserId <= 0) && (currentUserId != userId)) {
            APP_LOGE("userId: %{public}d, currentUserId :%{public}d", userId, currentUserId);
            return;
        }
    }
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("manager is nullptr");
        return;
    }

    if (enabled) {
        if (!manager->AddResourceInfoByBundleName(bundleName, userId)) {
            APP_LOGE("add bundleName : %{public}s resource failed.", bundleName.c_str());
        }
    } else {
        if (!manager->DeleteResourceInfo(bundleName)) {
            APP_LOGE("delete bundleName : %{public}s resource failed.", bundleName.c_str());
        }
    }
}

void BundleResourceCallback::OnAbilityStatusChanged(const std::string &bundleName,const std::string &moduleName,
    const std::string &abilityName, bool enabled, const int32_t userId)
{
    APP_LOGI("start, bundleName: %{public}s, moduleName:%{public}s, abilityName:%{public}s",
        bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
    if (bundleName.empty() || moduleName.empty() || abilityName.empty()) {
        APP_LOGE("bundleName or moduleName or abilityName is empty");
        return;
    }

    if (userId != Constants::DEFAULT_USERID && userId != Constants::START_USERID) {
        int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
        if ((currentUserId <= 0) && (currentUserId != userId)) {
            APP_LOGE("wtt userId: %{public}d, currentUserId :%{public}d not same", userId, currentUserId);
            return;
        }
    }

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("manager is nullptr");
        return;
    }

    if (enabled) {
        if (!manager->AddResourceInfoByAbility(bundleName, moduleName, abilityName, userId)) {
            APP_LOGE("add bundleName : %{public}s resource failed.", bundleName.c_str());
        }
    } else {
        ResourceInfo info;
        info.bundleName_ = bundleName;
        info.moduleName_ = moduleName;
        info.abilityName_ = abilityName;
        if (!manager->DeleteResourceInfo(info.GetKey())) {
            APP_LOGE("delete key : %{public}s resource failed.", info.GetKey().c_str());
        }
    }
}
} // AppExecFwk
} // OHOS
