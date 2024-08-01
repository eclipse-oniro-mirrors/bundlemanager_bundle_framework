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
void BundleResourceHelper::BundleSystemStateInit()
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    APP_LOGI("system state init start");
    // init language and colorMode
    BundleSystemState::GetInstance().SetSystemLanguage(BundleResourceParam::GetSystemLanguage());
    BundleSystemState::GetInstance().SetSystemColorMode(BundleResourceParam::GetSystemColorMode());
    APP_LOGI("current system state: %{public}s", BundleSystemState::GetInstance().ToString().c_str());
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
    APP_LOGI_NOFUNC("-n %{public}s -u %{public}d add resource start", bundleName.c_str(), userId);
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("failed, manager is nullptr");
        return;
    }
    // add new resource info
    if (!manager->AddResourceInfoByBundleName(bundleName, userId)) {
        APP_LOGW("failed, bundleName:%{public}s", bundleName.c_str());
    }
    APP_LOGI_NOFUNC("-n %{public}s -u %{public}d add resource end", bundleName.c_str(), userId);
#endif
}

bool BundleResourceHelper::DeleteResourceInfo(const std::string &key, const int32_t userId)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    APP_LOGI("start delete key %{public}s userId:%{public}d", key.c_str(), userId);
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

std::string BundleResourceHelper::ParseBundleName(const std::string &keyName)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    ResourceInfo info;
    info.ParseKey(keyName);
    return info.bundleName_;
#else
    return keyName;
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

bool BundleResourceHelper::DeleteAllResourceInfo()
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("failed, manager is nullptr");
        return false;
    }
    if (!manager->DeleteAllResourceInfo()) {
        APP_LOGE("delete all bundle resource failed");
        return false;
    }
    return true;
#else
    return false;
#endif
}

bool BundleResourceHelper::AddCloneBundleResourceInfo(const std::string &bundleName,
    const int32_t appIndex, const int32_t userId)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    APP_LOGI("start add clone bundle:%{public}s appIndex:%{public}d userId:%{public}d",
        bundleName.c_str(), appIndex, userId);
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("failed, manager is nullptr");
        return false;
    }
    if (!manager->AddCloneBundleResourceInfo(bundleName, appIndex)) {
        APP_LOGE("add clone bundle resource failed, bundleName:%{public}s, appIndex:%{public}d",
            bundleName.c_str(), appIndex);
        return false;
    }
    APP_LOGI("end add clone bundle:%{public}s appIndex:%{public}d userId:%{public}d",
        bundleName.c_str(), appIndex, userId);
    return true;
#else
    APP_LOGI("bundle resource is not support");
    return true;
#endif
}

bool BundleResourceHelper::DeleteCloneBundleResourceInfo(const std::string &bundleName,
    const int32_t appIndex, const int32_t userId)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    APP_LOGI("start delete clone bundle:%{public}s appIndex:%{public}d userId:%{public}d",
        bundleName.c_str(), appIndex, userId);
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("failed, manager is nullptr");
        return false;
    }

    if (!manager->DeleteCloneBundleResourceInfo(bundleName, appIndex)) {
        APP_LOGE("failed, key:%{public}s appIndex:%{public}d", bundleName.c_str(), appIndex);
        return false;
    }

    return true;
#else
    return false;
#endif
}

void BundleResourceHelper::DeleteNotExistResourceInfo()
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    APP_LOGI_NOFUNC("start delete not exist resource");
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("failed, manager is nullptr");
        return;
    }

    if (!manager->DeleteNotExistResourceInfo()) {
        APP_LOGE("delete not exist resource failed");
        return;
    }
#endif
}
} // AppExecFwk
} // OHOS
