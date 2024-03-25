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

#include <thread>
#include <unistd.h>

#include "account_helper.h"
#include "app_log_wrapper.h"
#include "bundle_common_event_mgr.h"
#include "bundle_promise.h"
#include "bundle_memory_guard.h"
#include "bundle_resource_parser.h"
#include "bundle_resource_process.h"
#include "thread_pool.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* GLOBAL_RESOURCE_BUNDLE_NAME = "ohos.global.systemres";
constexpr int32_t MAX_TASK_NUMBER = 10;
const std::string THREAD_POOL_NAME = "BundleResourceThreadPool";
constexpr int32_t CHECK_INTERVAL = 50; // 50ms
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
    APP_LOGD("start, bundleName:%{public}s", bundleName.c_str());
    std::vector<ResourceInfo> resourceInfos;
    if (!BundleResourceProcess::GetResourceInfoByBundleName(bundleName, userId, resourceInfos)) {
        APP_LOGE("bundleName: %{public}s GetResourceInfoByBundleName failed", bundleName.c_str());
        return false;
    }
    if (!AddResourceInfos(resourceInfos)) {
        APP_LOGE("error, bundleName:%{public}s", bundleName.c_str());
        return false;
    }
    APP_LOGD("success, bundleName:%{public}s", bundleName.c_str());
    return true;
}

bool BundleResourceManager::AddResourceInfoByAbility(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, const int32_t userId)
{
    APP_LOGD("start, bundleName:%{public}s", bundleName.c_str());
    ResourceInfo resourceInfo;
    if (!BundleResourceProcess::GetLauncherResourceInfoByAbilityName(bundleName, moduleName, abilityName,
        userId, resourceInfo)) {
        APP_LOGE("bundleName: %{public}s, moduleName: %{public}s, abilityName: %{public}s failed",
            bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
        return false;
    }
    if (!AddResourceInfo(resourceInfo)) {
        APP_LOGE("error, bundleName: %{public}s, moduleName: %{public}s, abilityName: %{public}s failed",
            bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
        return false;
    }
    APP_LOGD("success, bundleName: %{public}s, moduleName: %{public}s, abilityName: %{public}s failed",
        bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
    return true;
}

bool BundleResourceManager::AddAllResourceInfo(const int32_t userId)
{
    std::map<std::string, std::vector<ResourceInfo>> resourceInfosMap;
    if (!BundleResourceProcess::GetAllResourceInfo(userId, resourceInfosMap)) {
        APP_LOGE("GetAllResourceInfo failed, userId:%{public}d", userId);
        return false;
    }

    if (!AddResourceInfos(resourceInfosMap)) {
        APP_LOGE("failed, userId:%{public}d", userId);
        return false;
    }
    SendBundleResourcesChangedEvent(userId);
    return true;
}

bool BundleResourceManager::DeleteAllResourceInfo()
{
    return bundleResourceRdb_->DeleteAllResourceInfo();
}

bool BundleResourceManager::AddResourceInfo(ResourceInfo &resourceInfo)
{
    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    if ((currentUserId <= 0)) {
        currentUserId = Constants::START_USERID;
    }
    // need to parse label and icon
    BundleResourceParser parser;
    if (!parser.ParseResourceInfo(currentUserId, resourceInfo)) {
        APP_LOGW("key: %{public}s ParseResourceInfo failed", resourceInfo.GetKey().c_str());
        BundleResourceInfo bundleResourceInfo;
        if (GetBundleResourceInfo(resourceInfo.bundleName_,
            static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL), bundleResourceInfo)) {
            // default ability label and icon
            resourceInfo.label_ = resourceInfo.label_.empty() ? bundleResourceInfo.label : resourceInfo.label_;
            resourceInfo.icon_ = resourceInfo.icon_.empty() ? bundleResourceInfo.icon : resourceInfo.icon_;
        }
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
    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    if ((currentUserId <= 0)) {
        currentUserId = Constants::START_USERID;
    }
    // need to parse label and icon
    BundleResourceParser parser;
    if (!parser.ParseResourceInfos(currentUserId, resourceInfos)) {
        APP_LOGW("Parse ResourceInfos failed, need to modify label and icon");
        for (auto &resourceInfo : resourceInfos) {
            ProcessResourceInfoWhenParseFailed(resourceInfo);
        }
    }
    return bundleResourceRdb_->AddResourceInfos(resourceInfos);
}

bool BundleResourceManager::AddResourceInfos(std::map<std::string, std::vector<ResourceInfo>> &resourceInfosMap)
{
    if (resourceInfosMap.empty()) {
        APP_LOGE("resourceInfosMap is empty.");
        return false;
    }
    std::lock_guard<std::mutex> guard(mutex_);
    APP_LOGI("bundle resource hold mutex");
    std::shared_ptr<ThreadPool> threadPool = std::make_shared<ThreadPool>(THREAD_POOL_NAME);
    if (threadPool == nullptr) {
        APP_LOGE("threadPool is nullptr");
        return false;
    }
    threadPool->Start(std::thread::hardware_concurrency());
    threadPool->SetMaxTaskNum(MAX_TASK_NUMBER);
    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    if ((currentUserId <= 0)) {
        currentUserId = Constants::START_USERID;
    }
    for (const auto &item : resourceInfosMap) {
        std::string bundleName = item.first;
        auto task = [currentUserId, bundleName, &resourceInfosMap]() {
            // need to parse label and icon
            if (resourceInfosMap.find(bundleName) != resourceInfosMap.end()) {
                BundleResourceParser parser;
                parser.ParseResourceInfos(currentUserId, resourceInfosMap[bundleName]);
            }
        };
        threadPool->AddTask(task);
    }
    while (threadPool->GetCurTaskNum() > 0) {
        APP_LOGI("sleep");
        std::this_thread::sleep_for(std::chrono::milliseconds(CHECK_INTERVAL));
    }
    threadPool->Stop();
    APP_LOGI("All tasks has executed end");
    bool isExistDefaultIcon = (resourceInfosMap.find(GLOBAL_RESOURCE_BUNDLE_NAME) != resourceInfosMap.end());
    std::vector<ResourceInfo> resourceInfos;
    for (auto &item : resourceInfosMap) {
        for (auto &resourceInfo : item.second) {
            if (resourceInfo.label_.empty() || resourceInfo.icon_.empty()) {
                ProcessResourceInfo(isExistDefaultIcon ? resourceInfosMap[GLOBAL_RESOURCE_BUNDLE_NAME] :
                    std::vector<ResourceInfo>(), resourceInfo);
            }
            resourceInfos.emplace_back(resourceInfo);
        }
    }
    APP_LOGI("resource info size:%{public}zu", resourceInfos.size());
    return bundleResourceRdb_->AddResourceInfos(resourceInfos);
}

void BundleResourceManager::ProcessResourceInfo(
    const std::vector<ResourceInfo> &resourceInfos, ResourceInfo &resourceInfo)
{
    if (resourceInfo.label_.empty()) {
        resourceInfo.label_ = resourceInfo.bundleName_;
    }
    if (resourceInfo.icon_.empty()) {
        if (!resourceInfos.empty() && !resourceInfos[0].icon_.empty()) {
            resourceInfo.icon_ = resourceInfos[0].icon_;
            resourceInfo.foreground_ = resourceInfos[0].foreground_;
            resourceInfo.background_ = resourceInfos[0].background_;
        } else {
            ProcessResourceInfoWhenParseFailed(resourceInfo);
        }
    }
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
    std::map<std::string, std::vector<ResourceInfo>> resourceInfosMap;
    // to judge whether the current colorMode exists in the database
    bool isExist = bundleResourceRdb_->IsCurrentColorModeExist();
    if (isExist) {
        // exist then update new install bundles
        std::vector<std::string> names;
        if (!bundleResourceRdb_->GetAllResourceName(names)) {
            APP_LOGE("GetAllResourceName failed");
            return false;
        }
        std::vector<ResourceInfo> resourceInfos;
        if (!BundleResourceProcess::GetResourceInfoByColorModeChanged(names, resourceInfos)) {
            APP_LOGE("GetResourceInfoByColorModeChanged failed");
            return false;
        }
        if (resourceInfos.empty()) {
            APP_LOGI("no need to add resource");
            SendBundleResourcesChangedEvent(userId);
            return true;
        }
        for (const auto &info : resourceInfos) {
            resourceInfosMap[info.bundleName_].emplace_back(info);
        }
    } else {
        // not exist then update all resource info
        if (!BundleResourceProcess::GetAllResourceInfo(userId, resourceInfosMap)) {
            APP_LOGE("GetAllResourceInfo failed, userId:%{public}d", userId);
            return false;
        }
    }
    if (!AddResourceInfos(resourceInfosMap)) {
        APP_LOGE("add resource infos failed, userId:%{public}d", userId);
        return false;
    }
    SendBundleResourcesChangedEvent(userId);
    return true;
}

bool BundleResourceManager::GetBundleResourceInfo(const std::string &bundleName, const uint32_t flags,
    BundleResourceInfo &bundleResourceInfo)
{
    APP_LOGD("start, bundleName:%{public}s", bundleName.c_str());
    uint32_t resourceFlags = CheckResourceFlags(flags);
    if (bundleResourceRdb_->GetBundleResourceInfo(bundleName, resourceFlags, bundleResourceInfo)) {
        APP_LOGD("success, bundleName:%{public}s", bundleName.c_str());
        return true;
    }
    APP_LOGW("bundleName:%{public}s not exist in resource rdb, need add again ", bundleName.c_str());
    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    if (currentUserId <= 0) {
        // invalid userId
        currentUserId = Constants::START_USERID;
    }
    if (!AddResourceInfoByBundleName(bundleName, currentUserId)) {
        APP_LOGW("bundleName:%{public}s add failed", bundleName.c_str());
    }
    return bundleResourceRdb_->GetBundleResourceInfo(bundleName, resourceFlags, bundleResourceInfo);
}

bool BundleResourceManager::GetLauncherAbilityResourceInfo(const std::string &bundleName, const uint32_t flags,
    std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfo)
{
    APP_LOGD("start, bundleName:%{public}s", bundleName.c_str());
    uint32_t resourceFlags = CheckResourceFlags(flags);
    if (bundleResourceRdb_->GetLauncherAbilityResourceInfo(bundleName, resourceFlags, launcherAbilityResourceInfo)) {
        APP_LOGD("success, bundleName:%{public}s", bundleName.c_str());
        return true;
    }
    APP_LOGW("bundleName:%{public}s not exist in resource rdb, need add again ", bundleName.c_str());
    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    if (currentUserId <= 0) {
        // invalid userId
        currentUserId = Constants::START_USERID;
    }
    if (!AddResourceInfoByBundleName(bundleName, currentUserId)) {
        APP_LOGW("bundleName:%{public}s add failed", bundleName.c_str());
    }
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
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON)) ||
        ((flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR))) {
        return flags;
    }
    APP_LOGD("illegal flags");
    return flags | static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
}

void BundleResourceManager::ProcessResourceInfoWhenParseFailed(ResourceInfo &resourceInfo)
{
    APP_LOGI("start, bundleName:%{public}s", resourceInfo.bundleName_.c_str());
    if (resourceInfo.label_.empty()) {
        resourceInfo.label_ = resourceInfo.bundleName_;
    }
    if (resourceInfo.bundleName_ == GLOBAL_RESOURCE_BUNDLE_NAME) {
        APP_LOGE("bundleName: %{public}s default resource parse failed", resourceInfo.bundleName_.c_str());
        return;
    }
    if (resourceInfo.icon_.empty()) {
        GetDefaultIcon(resourceInfo);
    }
}

bool BundleResourceManager::SaveResourceInfos(std::vector<ResourceInfo> &resourceInfos)
{
    if (resourceInfos.empty()) {
        APP_LOGE("resourceInfos is empty.");
        return false;
    }
    return bundleResourceRdb_->AddResourceInfos(resourceInfos);
}

bool BundleResourceManager::ParseIconResourceByPath(
    const std::string &filePath, const int32_t iconId, std::string &icon)
{
    BundleResourceParser parser;
    return parser.ParseIconResourceByPath(filePath, iconId, icon);
}

void BundleResourceManager::GetDefaultIcon(ResourceInfo &resourceInfo)
{
    BundleResourceInfo bundleResourceInfo;
    if (!GetBundleResourceInfo(GLOBAL_RESOURCE_BUNDLE_NAME,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON) |
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR),
        bundleResourceInfo)) {
        APP_LOGE("get default icon failed");
        return;
    }
    resourceInfo.icon_ = bundleResourceInfo.icon;
    resourceInfo.foreground_ = bundleResourceInfo.foreground;
    resourceInfo.background_ = bundleResourceInfo.background;
}

void BundleResourceManager::SendBundleResourcesChangedEvent(int32_t userId)
{
    APP_LOGD("send bundleResource event");
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    commonEventMgr->NotifyBundleResourcesChanged(userId);
}

void BundleResourceManager::GetTargetBundleName(const std::string &bundleName, std::string &targetBundleName)
{
    APP_LOGD("start");
    BundleResourceProcess::GetTargetBundleName(bundleName, targetBundleName);
}
} // AppExecFwk
} // OHOS
