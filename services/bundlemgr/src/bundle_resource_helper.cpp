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

#include "bundle_resource_helper.h"

#include "app_log_wrapper.h"
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
#include "account_helper.h"
#include "bundle_resource_callback.h"
#include "bundle_resource_manager.h"
#include "bundle_resource_param.h"
#include "bundle_resource_parser.h"
#include "bundle_resource_register.h"
#include "bundle_system_state.h"
#include "resource_manager.h"
#endif


namespace OHOS {
namespace AppExecFwk {
namespace {
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
void ConvertToResourceInfo(
    const std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos,
    const std::string &icon, std::vector<ResourceInfo> &resourceInfos)
{
    for (const auto &launcherAbilityResourceInfo : launcherAbilityResourceInfos) {
        ResourceInfo resourceInfo;
        resourceInfo.bundleName_ = launcherAbilityResourceInfo.bundleName;
        resourceInfo.abilityName_ = launcherAbilityResourceInfo.abilityName;
        resourceInfo.moduleName_ = launcherAbilityResourceInfo.moduleName;
        resourceInfo.label_ = launcherAbilityResourceInfo.label;
        resourceInfo.icon_ = icon;
        resourceInfos.emplace_back(resourceInfo);
    }
}

void ConvertToResourceInfo(
    const BundleResourceInfo &bundleResourceInfo,
    const std::string &icon, std::vector<ResourceInfo> &resourceInfos)
{
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = bundleResourceInfo.bundleName;
    resourceInfo.label_ = bundleResourceInfo.label;
    resourceInfo.icon_ = icon;
    resourceInfos.emplace_back(resourceInfo);
}
#endif
}
void BundleResourceHelper::BundleSystemStateInit()
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    APP_LOGI("system state init start");
    // init language and colorMode
    BundleSystemState::GetInstance().SetSystemLanguage(BundleResourceParam::GetSystemLanguage());
    BundleSystemState::GetInstance().SetSystemColorMode(BundleResourceParam::GetSystemColorMode());
    // init resource manager
    if (Global::Resource::GetSystemResourceManagerNoSandBox() == nullptr) {
        APP_LOGE("init no sand box resource manager failed");
    }
#endif
}

void BundleResourceHelper::RegisterConfigurationObserver()
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    BundleResourceRegister::RegisterConfigurationObserver();
#endif
}

void BundleResourceHelper::RegisterCommonEventSubscriber()
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    BundleResourceRegister::RegisterCommonEventSubscriber();
#endif
}

void BundleResourceHelper::AddResourceInfoByBundleName(const std::string &bundleName,
    const int32_t userId)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    APP_LOGD("start");
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("failed, manager is nullptr");
        return;
    }
    // need delete current resource info
    if (!manager->DeleteResourceInfo(bundleName)) {
        APP_LOGW("failed, bundleName:%{public}s", bundleName.c_str());
    }
    int32_t currentUserId = userId;
    // 0 and 100 exist
    if ((userId != Constants::DEFAULT_USERID) && (userId != Constants::START_USERID)) {
        currentUserId = AccountHelper::GetCurrentActiveUserId();
        if (currentUserId <= 0) {
            // invalid userId
            currentUserId = userId;
        }
    }
    // add new resource info
    if (!manager->AddResourceInfoByBundleName(bundleName, currentUserId)) {
        APP_LOGW("failed, bundleName:%{public}s", bundleName.c_str());
    }
#endif
}

bool BundleResourceHelper::DeleteResourceInfo(const std::string &key, const int32_t userId)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    APP_LOGD("start");
    if (userId != Constants::UNSPECIFIED_USERID) {
        int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
        if ((currentUserId > 0) && (userId != currentUserId)) {
            APP_LOGW("currentUserId: %{public}d, userId: %{public}d is not same", currentUserId, userId);
            return false;
        }
    }

    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("failed, manager is nullptr");
        return false;
    }

    if (!manager->DeleteResourceInfo(key)) {
        APP_LOGE("failed, key:%{public}s", key.c_str());
        return false;
    }

    return true;
#else
    return false;
#endif
}

void BundleResourceHelper::SetApplicationEnabled(const std::string &bundleName,
    bool enabled, const int32_t userId)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    APP_LOGD("bundleName: %{public}s, enable: %{public}d, userId: %{public}d", bundleName.c_str(), enabled, userId);
    BundleResourceCallback callback;
    callback.OnBundleStatusChanged(bundleName, enabled, userId);
#endif
}

void BundleResourceHelper::SetAbilityEnabled(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, bool enabled, const int32_t userId)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    APP_LOGD("bundleName: %{public}s, abilityName: %{public}s, enable: %{public}d, userId: %{public}d",
        bundleName.c_str(), abilityName.c_str(), enabled, userId);
    BundleResourceCallback callback;
    callback.OnAbilityStatusChanged(bundleName, moduleName, abilityName, enabled, userId);
#endif
}

void BundleResourceHelper::GetAllBundleResourceName(std::vector<std::string> &resourceNames)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    APP_LOGI("start");
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("failed, manager is nullptr");
        return;
    }
    if (!manager->GetAllResourceName(resourceNames)) {
        APP_LOGE("failed");
    }
#endif
}

void BundleResourceHelper::SetOverlayEnabled(const std::string &bundleName, const std::string &moduleName,
    bool isEnabled, int32_t userId)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    APP_LOGD("bundleName: %{public}s, moduleName: %{public}s,isEnabled: %{public}d, userId: %{public}d",
        bundleName.c_str(), moduleName.c_str(), isEnabled, userId);
    BundleResourceCallback callback;
    callback.OnOverlayStatusChanged(bundleName, isEnabled, userId);
#endif
}

bool BundleResourceHelper::ParseIconResourceByPath(
    const std::string &filePath, const int32_t iconId, std::string &icon)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    BundleResourceParser bundleResourceParser;
    ResourceInfo info;
    info.iconId_ = iconId;
    return bundleResourceParser.ParseIconResourceByPath(filePath, iconId, icon);
#else
    return false;
#endif
}

bool BundleResourceHelper::ResetBunldleResourceIcon(const std::string &bundleName)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    APP_LOGI("ResetBunldleResourceIcon %{public}s", bundleName.c_str());
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("failed, manager is nullptr");
        return false;
    }

    // Delete dynamic icon resource
    if (!manager->DeleteResourceInfo(bundleName)) {
        APP_LOGE("DeleteResourceInfo failed, bundleName:%{public}s", bundleName.c_str());
        return false;
    }

    // Reset default icon
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    if (!manager->GetLauncherAbilityResourceInfo(bundleName,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), launcherAbilityResourceInfos)) {
        APP_LOGD("No default icon, bundleName:%{public}s", bundleName.c_str());
    }

    return true;
#else
    return false;
#endif
}

bool BundleResourceHelper::UpdateBundleIcon(const std::string &bundleName, const std::string &icon)
{
    if (bundleName.empty() || icon.empty()) {
        APP_LOGE("param is empty");
        return false;
    }

#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("failed, manager is nullptr");
        return false;
    }

    std::vector<ResourceInfo> resourceInfos;
    BundleResourceInfo bundleResourceInfo;
    if (!manager->GetBundleResourceInfo(bundleName,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL),
        bundleResourceInfo)) {
        APP_LOGW("GetBundleResourceInfo failed, bundleName:%{public}s", bundleName.c_str());
    } else {
        ConvertToResourceInfo(bundleResourceInfo, icon, resourceInfos);
    }

    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    if (!manager->GetLauncherAbilityResourceInfo(bundleName,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL),
        launcherAbilityResourceInfos)) {
        APP_LOGW("GetLauncherAbilityResourceInfo failed, bundleName:%{public}s",
            bundleName.c_str());
    } else {
        ConvertToResourceInfo(launcherAbilityResourceInfos, icon, resourceInfos);
    }

    if (resourceInfos.empty()) {
        APP_LOGI("%{public}s does not have default icon, build new resourceInfo",
            bundleName.c_str());
        ResourceInfo resourceInfo;
        resourceInfo.bundleName_ = bundleName;
        resourceInfo.label_ = bundleName;
        resourceInfo.icon_ = icon;
        resourceInfos.emplace_back(resourceInfo);
    }

    APP_LOGI("UpdateBundleIcon %{public}s, size: %{public}zu",
        bundleName.c_str(), resourceInfos.size());
    return manager->SaveResourceInfos(resourceInfos);
#else
    return false;
#endif
}
} // AppExecFwk
} // OHOS
