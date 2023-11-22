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

#include "bundle_resource_manager.h"

#include "app_log_wrapper.h"
#include "bundle_common_event_mgr.h"
#include "bundle_resource_parser.h"
#include "bundle_resource_process.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* GLOBAL_RESOURCE_BUNDLE_NAME = "ohos.global.systemres";
}
BundleResourceManager::BundleResourceManager()
{
    bundleResourceRdb_ = std::make_shared<BundleResourceRdb>();
}

BundleResourceManager::~BundleResourceManager()
{
}

bool BundleResourceManager::AddResourceInfo(const InnerBundleInfo &innerBundleInfo,
    const int32_t userId, std::string hapPath)
{
    std::vector<ResourceInfo> resourceInfos;
    if (!BundleResourceProcess::GetResourceInfo(innerBundleInfo, userId, resourceInfos)) {
        APP_LOGE("bundleName: %{public}s failed to GetResourceInfo", innerBundleInfo.GetBundleName().c_str());
        return false;
    }

    if (!hapPath.empty()) {
        for (auto &info : resourceInfos) {
            info.hapPath_ = hapPath;
        }
    }
    return AddResourceInfos(resourceInfos);
}

bool BundleResourceManager::AddResourceInfoByBundleName(const std::string &bundleName, const int32_t userId)
{
    std::vector<ResourceInfo> resourceInfos;
    if (!BundleResourceProcess::GetResourceInfoByBundleName(bundleName, userId, resourceInfos)) {
        APP_LOGE("bundleName: %{public}s GetResourceInfoByBundleName failed", bundleName.c_str());
        return false;
    }
    return AddResourceInfos(resourceInfos);
}

bool BundleResourceManager::AddResourceInfoByAbility(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, const int32_t userId)
{
    ResourceInfo resourceInfo;
    if (!BundleResourceProcess::GetResourceInfoByAbilityName(bundleName, moduleName, abilityName,
        userId, resourceInfo)) {
        APP_LOGE("bundleName: %{public}s, moduleName: %{public}s, abilityName: %{public}s failed",
            bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
        return false;
    }
    return AddResourceInfo(resourceInfo);
}

bool BundleResourceManager::AddAllResourceInfo(const int32_t userId)
{
    std::vector<ResourceInfo> resourceInfos;
    if (!BundleResourceProcess::GetAllResourceInfo(userId, resourceInfos)) {
        APP_LOGE("GetAllResourceInfo failed, userId:%{public}d", userId);
        return false;
    }
    auto ret = AddResourceInfos(resourceInfos);
    SendBundleResourcesUpdateEvent(userId);
    return ret;
}

bool BundleResourceManager::DeleteAllResourceInfo()
{
    return bundleResourceRdb_->DeleteAllResourceInfo();
}

bool BundleResourceManager::AddResourceInfo(ResourceInfo &resourceInfo)
{
    // need to parse label and icon
    BundleResourceParser parser;
    if (!parser.ParseResourceInfo(resourceInfo)) {
        APP_LOGW("key: %{public}s ParseResourceInfo failed", resourceInfo.GetKey().c_str());
        ProcessResourceInfoWhenParseFailed(resourceInfo);
    }
    return bundleResourceRdb_->AddResourceInfo(resourceInfo);
}

bool BundleResourceManager::AddResourceInfos(std::vector<ResourceInfo> &resourceInfos)
{
    if (resourceInfos.empty()) {
        APP_LOGE("resourceInfos is empty.");
        return false;
    }
    // need to parse label and icon
    BundleResourceParser parser;
    if (!parser.ParseResourceInfos(resourceInfos)) {
        APP_LOGW("Parse ResourceInfos failed, need to modify label and icon");
        for (auto &resourceInfo : resourceInfos) {
            ProcessResourceInfoWhenParseFailed(resourceInfo);
        }
    }
    return bundleResourceRdb_->AddResourceInfos(resourceInfos);
}

bool BundleResourceManager::DeleteResourceInfo(const std::string &key)
{
    return bundleResourceRdb_->DeleteResourceInfo(key);
}

bool BundleResourceManager::GetAllResourceName(std::vector<std::string> &keyNames)
{
    return bundleResourceRdb_->GetAllResourceName(keyNames);
}

bool BundleResourceManager::AddResourceInfoByColorModeChanged(const int32_t userId)
{
    std::vector<ResourceInfo> resourceInfos;
    // to judge whether the current colorMode exists in the database
    bool isExist = bundleResourceRdb_->IsCurrentColorModeExist();
    if (isExist) {
        // exist then update new install bundles
        std::vector<std::string> names;
        if (!bundleResourceRdb_->GetAllResourceName(names)) {
            APP_LOGE("GetAllResourceName failed");
            return false;
        }
        if (!BundleResourceProcess::GetResourceInfoByColorModeChanged(names, resourceInfos)) {
            APP_LOGE("GetResourceInfoByColorModeChanged failed");
            return false;
        }
        if (resourceInfos.empty()) {
            APP_LOGI("no need to add resource");
            SendBundleResourcesUpdateEvent(userId);
            return true;
        }
    } else {
        // not exist then update all resource info
        if (!BundleResourceProcess::GetAllResourceInfo(userId, resourceInfos)) {
            APP_LOGE("GetAllResourceInfo failed, userId:%{public}d", userId);
            return false;
        }
    }
    auto ret = AddResourceInfos(resourceInfos);
    SendBundleResourcesUpdateEvent(userId);
    return ret;
}

bool BundleResourceManager::GetBundleResourceInfo(const std::string &bundleName, const uint32_t flags,
    BundleResourceInfo &bundleResourceInfo)
{
    APP_LOGD("start, bundleName:%{public}s", bundleName.c_str());
    uint32_t resourceFlags = CheckResourceFlags(flags);
    return bundleResourceRdb_->GetBundleResourceInfo(bundleName, resourceFlags, bundleResourceInfo);
}

bool BundleResourceManager::GetLauncherAbilityResourceInfo(const std::string &bundleName, const uint32_t flags,
    std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfo)
{
    APP_LOGD("start, bundleName:%{public}s", bundleName.c_str());
    uint32_t resourceFlags = CheckResourceFlags(flags);
    return bundleResourceRdb_->GetLauncherAbilityResourceInfo(bundleName, resourceFlags, launcherAbilityResourceInfo);
}

bool BundleResourceManager::GetAllBundleResourceInfo(const uint32_t flags,
    std::vector<BundleResourceInfo> &bundleResourceInfos)
{
    APP_LOGD("start");
    uint32_t resourceFlags = CheckResourceFlags(flags);
    return bundleResourceRdb_->GetAllBundleResourceInfo(resourceFlags, bundleResourceInfos);
}

bool BundleResourceManager::GetAllLauncherAbilityResourceInfo(const uint32_t flags,
    std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos)
{
    APP_LOGD("start");
    uint32_t resourceFlags = CheckResourceFlags(flags);
    return bundleResourceRdb_->GetAllLauncherAbilityResourceInfo(resourceFlags, launcherAbilityResourceInfos);
}

uint32_t BundleResourceManager::CheckResourceFlags(const uint32_t flags)
{
    APP_LOGD("flags:%{public}u", flags);
    if (((flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL)) ||
        ((flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL)) ||
        ((flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON))) {
        return flags;
    }
    APP_LOGD("illegal flags");
    return flags | static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
}

void BundleResourceManager::ProcessResourceInfoWhenParseFailed(ResourceInfo &resourceInfo)
{
    if (resourceInfo.label_.empty()) {
        resourceInfo.label_ = resourceInfo.bundleName_;
    }
    if (resourceInfo.icon_.empty()) {
        resourceInfo.icon_ = GetDefaultIcon();
    }
}

std::string BundleResourceManager::GetDefaultIcon()
{
    BundleResourceInfo bundleResourceInfo;
    if (!GetBundleResourceInfo(GLOBAL_RESOURCE_BUNDLE_NAME,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON),
        bundleResourceInfo)) {
        APP_LOGE("get default icon failed");
        return std::string();
    }
    return bundleResourceInfo.icon;
}

void BundleResourceManager::SendBundleResourcesUpdateEvent(int32_t userId)
{
    APP_LOGD("send bundleResource event");
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    commonEventMgr->NotifyBundleResourcesUpdate(userId);
}
} // AppExecFwk
} // OHOS
