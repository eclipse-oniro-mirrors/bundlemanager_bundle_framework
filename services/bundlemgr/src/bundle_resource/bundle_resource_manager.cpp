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
#include "event_report.h"
#include "thread_pool.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* GLOBAL_RESOURCE_BUNDLE_NAME = "ohos.global.systemres";
constexpr int32_t MAX_TASK_NUMBER = 3;
const std::string THREAD_POOL_NAME = "BundleResourceThreadPool";
constexpr int32_t CHECK_INTERVAL = 50; // 50ms
constexpr const char* FOUNDATION_PROCESS_NAME = "foundation";
constexpr int32_t SCENE_ID_UPDATE_RESOURCE = 1 << 1;
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
    if (!resourceInfos.empty() && !resourceInfos[0].appIndexes_.empty()) {
        if (!AddCloneBundleResourceInfo(resourceInfos[0].bundleName_, resourceInfos[0].appIndexes_)) {
            APP_LOGW("bundleName:%{public}s add clone resource failed", bundleName.c_str());
        }
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

bool BundleResourceManager::AddAllResourceInfo(const int32_t userId, const uint32_t type)
{
    EventReport::SendCpuSceneEvent(FOUNDATION_PROCESS_NAME, SCENE_ID_UPDATE_RESOURCE);
    ++currentTaskNum_;
    uint32_t tempTaskNum = currentTaskNum_;
    std::lock_guard<std::mutex> guard(mutex_);
    APP_LOGI("bundle resource hold mutex");
    std::map<std::string, std::vector<ResourceInfo>> resourceInfosMap;
    if (!BundleResourceProcess::GetAllResourceInfo(userId, resourceInfosMap)) {
        APP_LOGE("GetAllResourceInfo failed, userId:%{public}d", userId);
        return false;
    }

    if (!AddResourceInfos(resourceInfosMap, true, tempTaskNum)) {
        APP_LOGE("add all resource info failed, userId:%{public}d", userId);
        return false;
    }
    // process clone bundle resource info
    for (const auto &item : resourceInfosMap) {
        if (!item.second.empty() && !item.second[0].appIndexes_.empty()) {
            APP_LOGI("start process bundle:%{public}s clone resource info", item.first.c_str());
            if (!AddCloneBundleResourceInfo(item.first, item.second[0].appIndexes_)) {
                APP_LOGW("bundleName:%{public}s add clone resource failed", item.second[0].bundleName_.c_str());
            }
        }
    }
    SendBundleResourcesChangedEvent(userId, type);
    APP_LOGI("add all resource end");
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
            resourceInfo.foreground_ = resourceInfo.foreground_.empty() ? bundleResourceInfo.foreground :
                resourceInfo.foreground_;
            resourceInfo.background_ = resourceInfo.background_.empty() ? bundleResourceInfo.background :
                resourceInfo.background_;
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

bool BundleResourceManager::AddResourceInfos(
    std::map<std::string, std::vector<ResourceInfo>> &resourceInfosMap,
    bool needDeleteAllResourceInfo,
    uint32_t tempTaskNumber)
{
    if (resourceInfosMap.empty()) {
        APP_LOGE("resourceInfosMap is empty.");
        return false;
    }
    if (tempTaskNumber != currentTaskNum_) {
        APP_LOGI("need stop current task, new first");
        return false;
    }
    std::shared_ptr<ThreadPool> threadPool = std::make_shared<ThreadPool>(THREAD_POOL_NAME);
    if (threadPool == nullptr) {
        APP_LOGE("threadPool is nullptr");
        return false;
    }
    threadPool->Start(MAX_TASK_NUMBER);
    threadPool->SetMaxTaskNum(MAX_TASK_NUMBER);
    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    if ((currentUserId <= 0)) {
        currentUserId = Constants::START_USERID;
    }
    // first delete all resource info, then add new resource
    if (needDeleteAllResourceInfo && !bundleResourceRdb_->DeleteAllResourceInfo()) {
        APP_LOGE("delete all bundle resource info failed, then add new resource info");
    }

    // parse default icon resource
    bool isExistDefaultIcon = (resourceInfosMap.find(GLOBAL_RESOURCE_BUNDLE_NAME) != resourceInfosMap.end());
    if (isExistDefaultIcon) {
        BundleResourceParser parser;
        parser.ParseResourceInfos(currentUserId, resourceInfosMap[GLOBAL_RESOURCE_BUNDLE_NAME]);
        bundleResourceRdb_->AddResourceInfos(resourceInfosMap[GLOBAL_RESOURCE_BUNDLE_NAME]);
    }

    for (const auto &item : resourceInfosMap) {
        if (tempTaskNumber != currentTaskNum_) {
            APP_LOGI("need stop current task, new first");
            threadPool->Stop();
            return false;
        }
        std::string bundleName = item.first;
        if (bundleName == GLOBAL_RESOURCE_BUNDLE_NAME) {
            continue;
        }
        auto task = [currentUserId, bundleName, isExistDefaultIcon, &resourceInfosMap, this]() {
            if (resourceInfosMap.find(bundleName) == resourceInfosMap.end()) {
                APP_LOGE("bundleName: %{public}s not exist", bundleName.c_str());
                return;
            }
            std::vector<ResourceInfo> resourceInfos = resourceInfosMap[bundleName];
            BundleResourceParser parser;
            parser.ParseResourceInfos(currentUserId, resourceInfos);
            InnerProcessResourceInfos(resourceInfosMap, isExistDefaultIcon, resourceInfos);
            bundleResourceRdb_->AddResourceInfos(resourceInfos);
        };
        threadPool->AddTask(task);
    }
    while (threadPool->GetCurTaskNum() > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(CHECK_INTERVAL));
    }
    threadPool->Stop();
    APP_LOGI("All tasks has executed end, resource info size:%{public}zu", resourceInfosMap.size());
    return true;
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

bool BundleResourceManager::AddResourceInfoByColorModeChanged(const int32_t userId, const uint32_t type)
{
    ++currentTaskNum_;
    uint32_t tempTaskNum = currentTaskNum_;
    std::lock_guard<std::mutex> guard(mutex_);
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
            SendBundleResourcesChangedEvent(userId, type);
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
    if (!AddResourceInfos(resourceInfosMap, false, tempTaskNum)) {
        APP_LOGE("add resource infos failed, userId:%{public}d", userId);
        return false;
    }
    // process clone bundle resource info
    for (const auto &item : resourceInfosMap) {
        if (!item.second.empty() && !item.second[0].appIndexes_.empty()) {
            APP_LOGI("start process bundle:%{public}s clone resource info", item.first.c_str());
            if (!AddCloneBundleResourceInfo(item.first, item.second[0].appIndexes_)) {
                APP_LOGW("bundle:%{public}s add clone resource failed", item.first.c_str());
            }
        }
    }
    SendBundleResourcesChangedEvent(userId, type);
    return true;
}

bool BundleResourceManager::GetBundleResourceInfo(const std::string &bundleName, const uint32_t flags,
    BundleResourceInfo &bundleResourceInfo, int32_t appIndex)
{
    APP_LOGD("start, bundleName:%{public}s", bundleName.c_str());
    uint32_t resourceFlags = CheckResourceFlags(flags);
    if (bundleResourceRdb_->GetBundleResourceInfo(bundleName, resourceFlags, bundleResourceInfo, appIndex)) {
        APP_LOGD("success, bundleName:%{public}s", bundleName.c_str());
        return true;
    }
    APP_LOGE("bundleName:%{public}s not exist in resource rdb", bundleName.c_str());
    return false;
}

bool BundleResourceManager::GetLauncherAbilityResourceInfo(const std::string &bundleName, const uint32_t flags,
    std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfo, const int32_t appIndex)
{
    APP_LOGD("start, bundleName:%{public}s", bundleName.c_str());
    uint32_t resourceFlags = CheckResourceFlags(flags);
    if (bundleResourceRdb_->GetLauncherAbilityResourceInfo(bundleName, resourceFlags,
        launcherAbilityResourceInfo, appIndex)) {
        APP_LOGD("success, bundleName:%{public}s", bundleName.c_str());
        return true;
    }
    APP_LOGE("bundleName:%{public}s not exist in resource rdb", bundleName.c_str());
    return false;
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

void BundleResourceManager::SendBundleResourcesChangedEvent(const int32_t userId, const uint32_t type)
{
    APP_LOGI("send bundleResource event, userId:%{public}d type:%{public}u", userId, type);
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    commonEventMgr->NotifyBundleResourcesChanged(userId, type);
}

void BundleResourceManager::GetTargetBundleName(const std::string &bundleName, std::string &targetBundleName)
{
    APP_LOGD("start");
    BundleResourceProcess::GetTargetBundleName(bundleName, targetBundleName);
}

bool BundleResourceManager::UpdateBundleIcon(const std::string &bundleName, ResourceInfo &resourceInfo)
{
    APP_LOGI("bundleName:%{public}s update icon", bundleName.c_str());
    std::vector<ResourceInfo> resourceInfos;
    BundleResourceInfo bundleResourceInfo;
    if (!GetBundleResourceInfo(bundleName,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL),
        bundleResourceInfo)) {
        APP_LOGW("GetBundleResourceInfo failed, bundleName:%{public}s", bundleName.c_str());
    } else {
        resourceInfo.bundleName_ = bundleResourceInfo.bundleName;
        resourceInfo.moduleName_ = Constants::EMPTY_STRING;
        resourceInfo.abilityName_ = Constants::EMPTY_STRING;
        resourceInfo.label_ = bundleResourceInfo.label;
        resourceInfos.emplace_back(resourceInfo);
    }

    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    if (!GetLauncherAbilityResourceInfo(bundleName,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL),
        launcherAbilityResourceInfos)) {
        APP_LOGW("GetLauncherAbilityResourceInfo failed, bundleName:%{public}s",
            bundleName.c_str());
    } else {
        for (const auto &launcherAbilityResourceInfo : launcherAbilityResourceInfos) {
            resourceInfo.bundleName_ = launcherAbilityResourceInfo.bundleName;
            resourceInfo.abilityName_ = launcherAbilityResourceInfo.abilityName;
            resourceInfo.moduleName_ = launcherAbilityResourceInfo.moduleName;
            resourceInfo.label_ = launcherAbilityResourceInfo.label;
            resourceInfos.emplace_back(resourceInfo);
        }
    }
    if (resourceInfos.empty()) {
        APP_LOGI("%{public}s does not have default icon, build new resourceInfo",
            bundleName.c_str());
        resourceInfo.bundleName_ = bundleName;
        resourceInfo.moduleName_ = Constants::EMPTY_STRING;
        resourceInfo.abilityName_ = Constants::EMPTY_STRING;
        resourceInfo.label_ = bundleName;
        resourceInfos.emplace_back(resourceInfo);
    }

    APP_LOGI("UpdateBundleIcon %{public}s, size: %{public}zu", bundleName.c_str(), resourceInfos.size());
    return SaveResourceInfos(resourceInfos);
}

void BundleResourceManager::InnerProcessResourceInfos(
    const std::map<std::string, std::vector<ResourceInfo>> &resourceInfosMap,
    bool isExistDefaultIcon,
    std::vector<ResourceInfo> &resourceInfos)
{
    for (auto &resourceInfo : resourceInfos) {
        if (resourceInfo.label_.empty() || resourceInfo.icon_.empty()) {
            ProcessResourceInfo(isExistDefaultIcon ? resourceInfosMap.at(GLOBAL_RESOURCE_BUNDLE_NAME) :
                std::vector<ResourceInfo>(), resourceInfo);
        }
    }
}

bool BundleResourceManager::AddCloneBundleResourceInfo(
    const std::string &bundleName,
    const int32_t appIndex)
{
    APP_LOGD("start add clone bundle resource info, bundleName:%{public}s appIndex:%{public}d",
        bundleName.c_str(), appIndex);
    // 1. get main bundle resource info
    std::vector<ResourceInfo> resourceInfos;
    if (!GetBundleResourceInfoForCloneBundle(bundleName, appIndex, resourceInfos)) {
        APP_LOGE("add clone bundle resource failed, bundleName:%{public}s appIndex:%{public}d",
            bundleName.c_str(), appIndex);
        return false;
    }
    // 2. need to process base icon and badge icon
    // BundleResourceParser
    BundleResourceParser parser;
    if (parser.ParserCloneResourceInfo(appIndex, resourceInfos)) {
        APP_LOGE("bundleName:%{public}s appIndex:%{public}d parse clone resource failed",
            bundleName.c_str(), appIndex);
    }
    // 3. need delete old clone resource info
    if (!DeleteCloneBundleResourceInfo(bundleName, appIndex)) {
        APP_LOGW("delete bundleName:%{public}s appIndex:%{public}d resource failed", bundleName.c_str(), appIndex);
    }
    // 4. save clone bundle resource info
    if (!bundleResourceRdb_->AddResourceInfos(resourceInfos)) {
        APP_LOGE("add resource failed, bundleName:%{public}s appIndex:%{public}d", bundleName.c_str(), appIndex);
        return false;
    }
    APP_LOGD("end, add clone bundle resource succeed");
    return true;
}

bool BundleResourceManager::DeleteCloneBundleResourceInfo(const std::string &bundleName,
    const int32_t appIndex)
{
    APP_LOGD("start delete clone bundle resource info, bundleName:%{public}s appIndex:%{public}d",
        bundleName.c_str(), appIndex);
    ResourceInfo info;
    info.bundleName_ = bundleName;
    info.appIndex_ = appIndex;
    return bundleResourceRdb_->DeleteResourceInfo(info.GetKey());
}

bool BundleResourceManager::AddCloneBundleResourceInfo(
    const std::string &bundleName,
    const std::vector<int32_t> appIndexes)
{
    APP_LOGD("start add clone resource info, bundleName:%{public}s", bundleName.c_str());
    bool result = true;
    for (const auto index : appIndexes) {
        result = AddCloneBundleResourceInfo(bundleName, index);
        if (!result) {
            APP_LOGW("bundleName:%{public}s appIndex:%{public}d add clone bundle resource failed", bundleName.c_str(),
                index);
        }
    }
    return result;
}

bool BundleResourceManager::GetBundleResourceInfoForCloneBundle(const std::string &bundleName,
    const int32_t appIndex, std::vector<ResourceInfo> &resourceInfos)
{
    // 1. get main bundle resource info
    BundleResourceInfo bundleResourceInfo;
    uint32_t flags = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL) |
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR);
    if (!bundleResourceRdb_->GetBundleResourceInfo(bundleName, flags, bundleResourceInfo)) {
        APP_LOGE("get bundle resource failed, bundleName:%{public}s appIndex:%{public}d", bundleName.c_str(), appIndex);
        return false;
    }
    bundleResourceInfo.appIndex = appIndex;
    ResourceInfo bundleResource;
    bundleResource.ConvertFromBundleResourceInfo(bundleResourceInfo);
    resourceInfos.emplace_back(bundleResource);
    // 2. get main launcher ability resource info
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    if (!bundleResourceRdb_->GetLauncherAbilityResourceInfo(bundleName, flags, launcherAbilityResourceInfos)) {
        APP_LOGW("get ability resource failed, bundleName:%{public}s appIndex:%{public}d",
            bundleName.c_str(), appIndex);
    }
    for (auto &launcherAbility : launcherAbilityResourceInfos) {
        launcherAbility.appIndex = appIndex;
        ResourceInfo launcherResource;
        launcherResource.ConvertFromLauncherAbilityResourceInfo(launcherAbility);
        resourceInfos.emplace_back(launcherResource);
    }
    APP_LOGI("bundleName:%{public}s appIndex:%{public}d add resource size:%{public}zu", bundleName.c_str(), appIndex,
        resourceInfos.size());
    return true;
}
} // AppExecFwk
} // OHOS
