/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "bms_extension_client.h"
#include "bundle_common_event_mgr.h"
#include "bundle_util.h"
#include "bundle_resource_parser.h"
#include "bundle_resource_process.h"
#include "bundle_mgr_service.h"
#include "event_report.h"
#include "hitrace_meter.h"
#include "thread_pool.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* GLOBAL_RESOURCE_BUNDLE_NAME = "ohos.global.systemres";
constexpr int8_t MAX_TASK_NUMBER = 2;
constexpr const char* THREAD_POOL_NAME = "BundleResourceThreadPool";
constexpr int8_t CHECK_INTERVAL = 30; // 30ms
constexpr const char* FOUNDATION_PROCESS_NAME = "foundation";
constexpr int8_t SCENE_ID_UPDATE_RESOURCE = 1 << 1;
constexpr const char* SYSTEM_THEME_PATH = "/data/service/el1/public/themes/";
constexpr const char* THEME_ICONS_A = "/a/app/icons/";
constexpr const char* THEME_ICONS_B = "/b/app/icons/";
constexpr const char* INNER_UNDER_LINE = "_";
constexpr const char* THEME_ICONS_A_FLAG = "/a/app/flag";
constexpr const char* THEME_ICONS_B_FLAG = "/b/app/flag";
constexpr const char* TASK_NAME = "ReleaseResourceTask";
constexpr uint64_t DELAY_TIME_MILLI_SECONDS = 3 * 60 * 1000; // 3mins
using Want = OHOS::AAFwk::Want;
}
std::mutex BundleResourceManager::g_sysResMutex;
std::shared_ptr<Global::Resource::ResourceManager> BundleResourceManager::g_resMgr = nullptr;

BundleResourceManager::BundleResourceManager()
{
    bundleResourceRdb_ = std::make_shared<BundleResourceRdb>();
    delayedTaskMgr_ = std::make_shared<SingleDelayedTaskMgr>(TASK_NAME, DELAY_TIME_MILLI_SECONDS);
}

BundleResourceManager::~BundleResourceManager()
{
}

bool BundleResourceManager::AddResourceInfoByBundleName(const std::string &bundleName, const int32_t userId)
{
    APP_LOGD("start, bundleName:%{public}s", bundleName.c_str());
    std::vector<ResourceInfo> resourceInfos;
    if (!BundleResourceProcess::GetResourceInfoByBundleName(bundleName, userId, resourceInfos)) {
        APP_LOGE("bundleName %{public}s GetResourceInfoByBundleName failed", bundleName.c_str());
        return false;
    }
    DeleteNotExistResourceInfo(bundleName, 0, resourceInfos);
    PrepareSysRes();

    if (!AddResourceInfos(userId, resourceInfos)) {
        APP_LOGE("error, bundleName:%{public}s", bundleName.c_str());
        return false;
    }
    if (!resourceInfos.empty() && !resourceInfos[0].appIndexes_.empty()) {
        for (const int32_t appIndex : resourceInfos[0].appIndexes_) {
            DeleteNotExistResourceInfo(bundleName, appIndex, resourceInfos);
            // trigger parse dynamic icon
            if (!AddCloneBundleResourceInfo(resourceInfos[0].bundleName_, appIndex, userId)) {
                APP_LOGW("-n %{public}s -i %{public}d add clone resource failed", bundleName.c_str(), appIndex);
            }
        }
    }
    APP_LOGD("success, bundleName:%{public}s", bundleName.c_str());
    return true;
}

bool BundleResourceManager::AddResourceInfoByBundleName(
    const std::string &bundleName, const int32_t userId, const int32_t appIndex)
{
    APP_LOGD("start bundleName%{public}s userId %{public}d appIndex %{public}d", bundleName.c_str(), userId, appIndex);
    std::vector<ResourceInfo> resourceInfos;
    if (!BundleResourceProcess::GetResourceInfoByBundleName(bundleName, userId, resourceInfos, appIndex) ||
        resourceInfos.empty()) {
        APP_LOGE("get resource bundleName %{public}s userId %{public}d appIndex %{public}d failed",
            bundleName.c_str(), userId, appIndex);
        return false;
    }
    DeleteNotExistResourceInfo(bundleName, appIndex, resourceInfos);
    PrepareSysRes();
    // need to parse label and icon
    BundleResourceParser parser;
    if (!parser.ParseResourceInfos(userId, resourceInfos)) {
        APP_LOGW_NOFUNC("key:%{public}s Parse failed, need to modify label and icon",
            resourceInfos[0].GetKey().c_str());
        ProcessResourceInfoWhenParseFailed(resourceInfos[0]);
    }
    if (appIndex != 0) {
        for (auto &info : resourceInfos) {
            info.label_ = info.label_.empty() ? info.label_ : (info.label_ + std::to_string(appIndex));
            info.appIndex_ = appIndex;
        }
        // process clone bundle
        if (!parser.ParserCloneResourceInfo(appIndex, resourceInfos)) {
            APP_LOGW_NOFUNC("key:%{public}s Parse clone failed may loss badge", resourceInfos[0].GetKey().c_str());
        }
    }
    return bundleResourceRdb_->AddResourceInfos(resourceInfos);
}

void BundleResourceManager::DeleteNotExistResourceInfo(
    const std::string &bundleName, const int32_t appIndex, const std::vector<ResourceInfo> &resourceInfos)
{
    // get current rdb resource
    std::vector<std::string> existResourceName;
    if (bundleResourceRdb_->GetResourceNameByBundleName(bundleName, appIndex, existResourceName) &&
        !existResourceName.empty()) {
        for (const auto &key : existResourceName) {
            auto it = std::find_if(resourceInfos.begin(), resourceInfos.end(),
                [&key](const ResourceInfo &info) {
                return info.GetKey() == key;
            });
            if (it == resourceInfos.end()) {
                bundleResourceRdb_->DeleteResourceInfo(key);
            }
        }
    }
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
    PrepareSysRes();
    if (!AddResourceInfo(userId, resourceInfo)) {
        APP_LOGE("error, bundleName %{public}s, moduleName %{public}s, abilityName %{public}s failed",
            bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
        return false;
    }
    APP_LOGD("success, bundleName: %{public}s, moduleName: %{public}s, abilityName: %{public}s failed",
        bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
    return true;
}

bool BundleResourceManager::AddAllResourceInfo(const int32_t userId, const uint32_t type, const int32_t oldUserId)
{
    EventReport::SendCpuSceneEvent(FOUNDATION_PROCESS_NAME, SCENE_ID_UPDATE_RESOURCE);
    ++currentTaskNum_;
    uint32_t tempTaskNum = currentTaskNum_;
    std::lock_guard<std::mutex> guard(mutex_);
    APP_LOGI("bundle resource hold mutex");
    std::map<std::string, std::vector<ResourceInfo>> resourceInfosMap;
    if (!BundleResourceProcess::GetAllResourceInfo(userId, resourceInfosMap)) {
        APP_LOGE("GetAllResourceInfo failed userId %{public}d", userId);
        return false;
    }
    if (tempTaskNum != currentTaskNum_) {
        APP_LOGI("need stop current task, new first");
        return false;
    }
    PrepareSysRes();
    if (!AddResourceInfosByMap(resourceInfosMap, tempTaskNum, type, userId, oldUserId)) {
        APP_LOGE("add all resource info failed, userId:%{public}d", userId);
        return false;
    }
    // process clone bundle resource info
    for (const auto &item : resourceInfosMap) {
        if (!item.second.empty() && !item.second[0].appIndexes_.empty()) {
            APP_LOGI("start process bundle:%{public}s clone resource info", item.first.c_str());
            for (const int32_t appIndex : item.second[0].appIndexes_) {
                UpdateCloneBundleResourceInfo(item.first, userId, appIndex, type);
            }
        }
    }
    SendBundleResourcesChangedEvent(userId, type);
    std::string systemState;
    if (bundleResourceRdb_->GetCurrentSystemState(systemState)) {
        APP_LOGI_NOFUNC("current resource rdb system state:%{public}s", systemState.c_str());
    }
    APP_LOGI_NOFUNC("add all resource end");
    return true;
}

bool BundleResourceManager::DeleteAllResourceInfo()
{
    return bundleResourceRdb_->DeleteAllResourceInfo();
}

bool BundleResourceManager::AddResourceInfo(const int32_t userId, ResourceInfo &resourceInfo)
{
    // need to parse label and icon
    BundleResourceParser parser;
    if (!parser.ParseResourceInfo(userId, resourceInfo)) {
        APP_LOGW("key %{public}s ParseResourceInfo failed", resourceInfo.GetKey().c_str());
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

bool BundleResourceManager::AddResourceInfos(const int32_t userId, std::vector<ResourceInfo> &resourceInfos)
{
    if (resourceInfos.empty()) {
        APP_LOGE("resourceInfos is empty");
        return false;
    }
    // need to parse label and icon
    BundleResourceParser parser;
    if (!parser.ParseResourceInfos(userId, resourceInfos)) {
        APP_LOGW_NOFUNC("key:%{public}s Parse failed, need to modify label and icon",
            resourceInfos[0].GetKey().c_str());
        ProcessResourceInfoWhenParseFailed(resourceInfos[0]);
    }
    return bundleResourceRdb_->AddResourceInfos(resourceInfos);
}

void BundleResourceManager::InnerProcessResourceInfoByResourceUpdateType(
    std::map<std::string, std::vector<ResourceInfo>> &resourceInfosMap,
    const uint32_t type, const int32_t userId, const int32_t oldUserId)
{
    APP_LOGI("current resource update, code:%{public}u", type);
    switch (type) {
        case static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_LANGUE_CHANGE) : {
            InnerProcessResourceInfoBySystemLanguageChanged(resourceInfosMap);
            break;
        }
        case static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_THEME_CHANGE) : {
            InnerProcessResourceInfoBySystemThemeChanged(resourceInfosMap, userId);
            break;
        }
        case static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_USER_ID_CHANGE) : {
            InnerProcessResourceInfoByUserIdChanged(resourceInfosMap, userId, oldUserId);
            break;
        }
        default: {
            break;
        }
    }
}

void BundleResourceManager::InnerProcessResourceInfoBySystemLanguageChanged(
    std::map<std::string, std::vector<ResourceInfo>> &resourceInfosMap)
{
    for (auto iter = resourceInfosMap.begin(); iter != resourceInfosMap.end(); ++iter) {
        for (auto &resourceInfo : iter->second) {
            resourceInfo.iconNeedParse_ = false;
        }
    }
}

void BundleResourceManager::InnerProcessResourceInfoBySystemThemeChanged(
    std::map<std::string, std::vector<ResourceInfo>> &resourceInfosMap,
    const int32_t userId)
{
    // judge whether the bundle theme exists
    for (auto iter = resourceInfosMap.begin(); iter != resourceInfosMap.end();) {
        if (!BundleUtil::IsExistDirNoLog(SYSTEM_THEME_PATH + std::to_string(userId) + THEME_ICONS_A + iter->first) &&
            !BundleUtil::IsExistDirNoLog(SYSTEM_THEME_PATH + std::to_string(userId) + THEME_ICONS_B + iter->first)) {
            iter = resourceInfosMap.erase(iter);
        } else {
            ++iter;
        }
    }
    // process labelNeedParse_
    for (auto iter = resourceInfosMap.begin(); iter != resourceInfosMap.end(); ++iter) {
        ProcessResourceInfoNoNeedToParseOtherIcon(iter->second);
    }
}

void BundleResourceManager::InnerProcessResourceInfoByUserIdChanged(
    std::map<std::string, std::vector<ResourceInfo>> &resourceInfosMap,
    const int32_t userId, const int32_t oldUserId)
{
    APP_LOGI("start process switch oldUserId:%{public}d to userId:%{public}d", oldUserId, userId);
    for (auto iter = resourceInfosMap.begin(); iter != resourceInfosMap.end();) {
        // first, check oldUserId whether exist theme, if exist then need parse again
        bool isOldUserExistTheme = InnerProcessWhetherThemeExist(iter->first, oldUserId);
        bool isNewUserExistTheme = InnerProcessWhetherThemeExist(iter->first, userId);
        if (!isOldUserExistTheme && !isNewUserExistTheme && iter->second[0].appIndexes_.empty()) {
            APP_LOGD("bundleName:%{public}s not exist theme", iter->first.c_str());
            iter = resourceInfosMap.erase(iter);
            continue;
        }
        APP_LOGI("bundleName:%{public}s oldUser:%{public}d or newUser:%{public}d exist theme",
            iter->first.c_str(), oldUserId, userId);
        if (isNewUserExistTheme) {
            ProcessResourceInfoNoNeedToParseOtherIcon(iter->second);
        } else {
            for (auto &resource : iter->second) {
                resource.labelNeedParse_ = false;
                resource.label_ = Constants::EMPTY_STRING;
            }
        }
        ++iter;
    }
}

void BundleResourceManager::DeleteNotExistResourceInfo(
    const std::map<std::string, std::vector<ResourceInfo>> &resourceInfosMap,
    const std::vector<std::string> &existResourceNames)
{
    // delete not exist resource
    for (const auto &name : existResourceNames) {
        if (resourceInfosMap.find(name) == resourceInfosMap.end()) {
            ResourceInfo resourceInfo;
            resourceInfo.ParseKey(name);
            // main bundle not exist
            if (resourceInfo.appIndex_ == 0) {
                DeleteResourceInfo(name);
                continue;
            }
            auto iter = resourceInfosMap.find(resourceInfo.bundleName_);
            // main bundle not exist
            if ((iter == resourceInfosMap.end()) || (iter->second.empty())) {
                DeleteResourceInfo(name);
                continue;
            }
            // clone bundle appIndex not exist
            if (std::find(iter->second[0].appIndexes_.begin(), iter->second[0].appIndexes_.end(),
                resourceInfo.appIndex_) == iter->second[0].appIndexes_.end()) {
                DeleteResourceInfo(name);
            }
        }
    }
}

bool BundleResourceManager::InnerProcessWhetherThemeExist(const std::string &bundleName, const int32_t userId)
{
    if (BundleUtil::IsExistFileNoLog(SYSTEM_THEME_PATH + std::to_string(userId) + THEME_ICONS_A_FLAG)) {
        return BundleUtil::IsExistDirNoLog(SYSTEM_THEME_PATH + std::to_string(userId) + THEME_ICONS_A + bundleName);
    }
    return BundleUtil::IsExistDirNoLog(SYSTEM_THEME_PATH + std::to_string(userId) + THEME_ICONS_B + bundleName);
}

bool BundleResourceManager::AddResourceInfosByMap(
    std::map<std::string, std::vector<ResourceInfo>> &resourceInfosMap,
    const uint32_t tempTaskNumber,
    const uint32_t type,
    const int32_t userId,
    const int32_t oldUserId)
{
    if (resourceInfosMap.empty()) {
        APP_LOGE("resourceInfosMap is empty");
        return false;
    }
    InnerProcessResourceInfoByResourceUpdateType(resourceInfosMap, type, userId, oldUserId);
    if (resourceInfosMap.empty()) {
        APP_LOGI("resourceInfosMap is empty, no need to parse");
        return true;
    }
    std::shared_ptr<ThreadPool> threadPool = std::make_shared<ThreadPool>(THREAD_POOL_NAME);
    threadPool->Start(MAX_TASK_NUMBER);
    threadPool->SetMaxTaskNum(MAX_TASK_NUMBER);

    for (const auto &item : resourceInfosMap) {
        if (tempTaskNumber != currentTaskNum_) {
            APP_LOGI("need stop current task, new first");
            threadPool->Stop();
            return false;
        }
        std::string bundleName = item.first;
        auto task = [userId, bundleName, &resourceInfosMap, this]() {
            if (resourceInfosMap.find(bundleName) == resourceInfosMap.end()) {
                APP_LOGE("bundleName %{public}s not exist", bundleName.c_str());
                return;
            }
            std::vector<ResourceInfo> resourceInfos = resourceInfosMap[bundleName];
            BundleResourceParser parser;
            parser.ParseResourceInfos(userId, resourceInfos);
            bundleResourceRdb_->UpdateResourceForSystemStateChanged(resourceInfos);
        };
        threadPool->AddTask(task);
    }
    while (threadPool->GetCurTaskNum() > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(CHECK_INTERVAL));
    }
    threadPool->Stop();
    APP_LOGI("all task end resource size %{public}zu", resourceInfosMap.size());
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

bool BundleResourceManager::GetBundleResourceInfo(const std::string &bundleName, const uint32_t flags,
    BundleResourceInfo &bundleResourceInfo, int32_t appIndex)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("start, bundleName:%{public}s", bundleName.c_str());
    uint32_t resourceFlags = CheckResourceFlags(flags);
    if (bundleResourceRdb_->GetBundleResourceInfo(bundleName, resourceFlags, bundleResourceInfo, appIndex)) {
        APP_LOGD("success, bundleName:%{public}s", bundleName.c_str());
        return true;
    }
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ErrCode ret = bmsExtensionClient->GetBundleResourceInfo(bundleName, resourceFlags, bundleResourceInfo, appIndex);
    if (ret == ERR_OK) {
        APP_LOGD("success, bundleName:%{public}s", bundleName.c_str());
        return true;
    }
    APP_LOGE_NOFUNC("%{public}s not exist in resource rdb", bundleName.c_str());
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
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ErrCode ret = bmsExtensionClient->GetLauncherAbilityResourceInfo(bundleName, resourceFlags,
        launcherAbilityResourceInfo, appIndex);
    if (ret == ERR_OK) {
        APP_LOGD("success, bundleName:%{public}s", bundleName.c_str());
        return true;
    }
    APP_LOGE_NOFUNC("%{public}s not exist in resource rdb", bundleName.c_str());
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

bool BundleResourceManager::FilterLauncherAbilityResourceInfoWithFlag(const uint32_t flags,
    const std::string &bundleName, std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos)
{
    if ((flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ONLY_WITH_MAIN_ABILITY)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ONLY_WITH_MAIN_ABILITY)) {
        std::vector<AbilityInfo> abilityInfos;
        if (!GetLauncherAbilityInfos(bundleName, abilityInfos)) {
            launcherAbilityResourceInfos.clear();
            APP_LOGE("GetLauncherAbilityInfos failed");
            return false;
        }
        launcherAbilityResourceInfos.erase(
            std::remove_if(launcherAbilityResourceInfos.begin(), launcherAbilityResourceInfos.end(),
                [this, &abilityInfos](const LauncherAbilityResourceInfo& resource) {
                    return !this->IsLauncherAbility(resource, abilityInfos);
                }),
            launcherAbilityResourceInfos.end()
        );
    }
    return true;
}

bool BundleResourceManager::GetLauncherAbilityInfos(const std::string &bundleName,
    std::vector<AbilityInfo> &abilityInfos)
{
    int32_t userId = Constants::UNSPECIFIED_USERID;
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return false;
    }
    Want want;
    want.SetAction(Want::ACTION_HOME);
    want.AddEntity(Want::ENTITY_HOME);
    if (!bundleName.empty()) {
        ElementName elementName;
        elementName.SetBundleName(bundleName);
        want.SetElement(elementName);
    }
    ErrCode ret = dataMgr->QueryLauncherAbilityInfos(want, userId, abilityInfos);
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ErrCode ans = bmsExtensionClient->QueryLauncherAbility(want, userId, abilityInfos);
    if (ret != ERR_OK && ans != ERR_OK) {
        APP_LOGE("GetLauncherAbilityInfos failed, ret:%{public}d, ans:%{public}d", ret, ans);
        return false;
    }
    return true;
}

bool BundleResourceManager::IsLauncherAbility(const LauncherAbilityResourceInfo &resourceInfo,
    std::vector<AbilityInfo> &abilityInfos)
{
    for (const auto& abilityInfo : abilityInfos) {
        if (resourceInfo.bundleName == abilityInfo.bundleName &&
            resourceInfo.moduleName == abilityInfo.moduleName &&
            resourceInfo.abilityName == abilityInfo.name) {
            return true;
        }
    }
    return false;
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
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR)) ||
        ((flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ONLY_WITH_MAIN_ABILITY)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ONLY_WITH_MAIN_ABILITY))) {
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
        APP_LOGE("%{public}s default resource parse failed", resourceInfo.bundleName_.c_str());
        return;
    }
    if (resourceInfo.icon_.empty()) {
        GetDefaultIcon(resourceInfo);
    }
}

bool BundleResourceManager::SaveResourceInfos(std::vector<ResourceInfo> &resourceInfos)
{
    if (resourceInfos.empty()) {
        APP_LOGE("resourceInfos is empty");
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
    int32_t appIndex = resourceInfo.appIndex_;
    APP_LOGI("bundleName:%{public}s appIndex %{public}d update icon", bundleName.c_str(), appIndex);
    if (appIndex == Constants::UNSPECIFIED_USERID) {
        resourceInfo.appIndex_ = 0;
    }
    std::vector<ResourceInfo> resourceInfos;
    BundleResourceInfo bundleResourceInfo;
    if (!GetBundleResourceInfo(bundleName,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL), bundleResourceInfo)) {
        APP_LOGW("bundle %{public}s index %{public}d get resource failed", bundleName.c_str(), resourceInfo.appIndex_);
    } else {
        BundleResourceConvertToResourceInfo(bundleResourceInfo, resourceInfo);
        resourceInfos.emplace_back(resourceInfo);
    }

    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    if (!GetLauncherAbilityResourceInfo(bundleName,
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL), launcherAbilityResourceInfos)) {
        APP_LOGW("bundle %{public}s index %{public}d get resource failed", bundleName.c_str(), resourceInfo.appIndex_);
    } else {
        for (const auto &launcherAbilityResourceInfo : launcherAbilityResourceInfos) {
            LauncherAbilityResourceConvertToResourceInfo(launcherAbilityResourceInfo, resourceInfo);
            resourceInfos.emplace_back(resourceInfo);
        }
    }
    if (resourceInfos.empty()) {
        APP_LOGW("%{public}s no default icon, need build new", bundleName.c_str());
        resourceInfo.bundleName_ = bundleName;
        resourceInfo.label_ = bundleName;
        resourceInfos.emplace_back(resourceInfo);
    }

    APP_LOGI("bundle %{public}s size %{public}zu index %{public}d", bundleName.c_str(), resourceInfos.size(), appIndex);
    if (resourceInfo.appIndex_ != 0) {
        // need to process base icon and badge icon
        BundleResourceParser parser;
        if (!parser.ParserCloneResourceInfo(resourceInfo.appIndex_, resourceInfos)) {
            APP_LOGW("%{public}s appIndex:%{public}d parse clone resource failed", bundleName.c_str(), appIndex);
        }
    }
    if (!SaveResourceInfos(resourceInfos)) {
        APP_LOGE("save %{public}s resource info failed", bundleName.c_str());
        return false;
    }
    if (appIndex == Constants::UNSPECIFIED_USERID) {
        return ProcessUpdateCloneBundleResourceInfo(bundleName);
    }
    return true;
}

bool BundleResourceManager::AddCloneBundleResourceInfo(
    const std::string &bundleName, const int32_t appIndex, const int32_t userId)
{
    APP_LOGD("start add clone bundle resource info, bundleName:%{public}s appIndex:%{public}d",
        bundleName.c_str(), appIndex);
    if (userId != Constants::UNSPECIFIED_USERID) {
        return UpdateCloneBundleResourceInfo(bundleName, userId, appIndex,
            static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_USER_ID_CHANGE));
    }
    // 1. get main bundle resource info
    std::vector<ResourceInfo> resourceInfos;
    if (!GetBundleResourceInfoForCloneBundle(bundleName, appIndex, resourceInfos)) {
        APP_LOGE("add clone resource failed %{public}s appIndex:%{public}d",
            bundleName.c_str(), appIndex);
        return false;
    }
    // 2. need to process base icon and badge icon
    // BundleResourceParser
    BundleResourceParser parser;
    if (!parser.ParserCloneResourceInfo(appIndex, resourceInfos)) {
        APP_LOGE("%{public}s appIndex:%{public}d parse clone resource failed", bundleName.c_str(), appIndex);
    }
    // 3. save clone bundle resource info
    if (!bundleResourceRdb_->AddResourceInfos(resourceInfos)) {
        APP_LOGE("add resource failed %{public}s appIndex:%{public}d", bundleName.c_str(), appIndex);
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

bool BundleResourceManager::GetBundleResourceInfoForCloneBundle(const std::string &bundleName,
    const int32_t appIndex, std::vector<ResourceInfo> &resourceInfos)
{
    // 1. get main bundle resource info
    BundleResourceInfo bundleResourceInfo;
    uint32_t flags = static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL) |
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR);
    if (!bundleResourceRdb_->GetBundleResourceInfo(bundleName, flags, bundleResourceInfo)) {
        APP_LOGE("get resource failed %{public}s appIndex:%{public}d", bundleName.c_str(), appIndex);
        return false;
    }
    bundleResourceInfo.appIndex = appIndex;
    ResourceInfo bundleResource;
    bundleResource.ConvertFromBundleResourceInfo(bundleResourceInfo);
    resourceInfos.emplace_back(bundleResource);
    // 2. get main launcher ability resource info
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    if (!bundleResourceRdb_->GetLauncherAbilityResourceInfo(bundleName, flags, launcherAbilityResourceInfos)) {
        APP_LOGW("get ability resource failed %{public}s appIndex:%{public}d",
            bundleName.c_str(), appIndex);
    }
    for (auto &launcherAbility : launcherAbilityResourceInfos) {
        launcherAbility.appIndex = appIndex;
        ResourceInfo launcherResource;
        launcherResource.ConvertFromLauncherAbilityResourceInfo(launcherAbility);
        resourceInfos.emplace_back(launcherResource);
    }
    // 3. get extension ability resource info
    std::vector<LauncherAbilityResourceInfo> extensionAbilityResourceInfos;
    bundleResourceRdb_->GetAllExtensionAbilityResourceInfo(bundleName, flags, extensionAbilityResourceInfos);
    for (auto &extensionAbility : extensionAbilityResourceInfos) {
        extensionAbility.appIndex = appIndex;
        ResourceInfo extensionResource;
        extensionResource.ConvertFromLauncherAbilityResourceInfo(extensionAbility);
        resourceInfos.emplace_back(extensionResource);
    }
    APP_LOGI("%{public}s appIndex:%{public}d add resource size:%{public}zu", bundleName.c_str(), appIndex,
        resourceInfos.size());
    return true;
}

bool BundleResourceManager::UpdateCloneBundleResourceInfo(
    const std::string &bundleName,
    const int32_t appIndex,
    const uint32_t type)
{
    APP_LOGD("start update clone bundle resource info, bundleName:%{public}s appIndex:%{public}d",
        bundleName.c_str(), appIndex);
    // 1. get main bundle resource info
    std::vector<ResourceInfo> resourceInfos;
    if (!GetBundleResourceInfoForCloneBundle(bundleName, appIndex, resourceInfos)) {
        APP_LOGE("add clone bundle resource failed, bundleName:%{public}s appIndex:%{public}d",
            bundleName.c_str(), appIndex);
        return false;
    }
    // 2. need to process base icon and badge icon when userId or theme changed
    if (((type & static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_THEME_CHANGE)) ==
        static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_THEME_CHANGE)) ||
        ((type & static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_USER_ID_CHANGE)) ==
        static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_USER_ID_CHANGE))) {
        BundleResourceParser parser;
        if (!parser.ParserCloneResourceInfo(appIndex, resourceInfos)) {
            APP_LOGE("bundleName:%{public}s appIndex:%{public}d parse clone resource failed",
                bundleName.c_str(), appIndex);
        }
    } else {
        for (auto &resourceInfo : resourceInfos) {
            resourceInfo.icon_ = Constants::EMPTY_STRING;
        }
    }
    // 3. save clone bundle resource info
    if (!bundleResourceRdb_->UpdateResourceForSystemStateChanged(resourceInfos)) {
        APP_LOGE("add resource failed, bundleName:%{public}s appIndex:%{public}d", bundleName.c_str(), appIndex);
        return false;
    }
    APP_LOGD("end, add clone bundle resource succeed");
    return true;
}

bool BundleResourceManager::UpdateCloneBundleResourceInfo(const std::string &bundleName, const int32_t userId,
    const int32_t appIndex, const uint32_t type)
{
    if (appIndex <= 0) {
        APP_LOGW("-n %{public}s -i %{public}d invalid", bundleName.c_str(), appIndex);
        return false;
    }
    // check theme
    bool isPreSetTheme = true;
    if (BundleResourceProcess::CheckThemeType(bundleName, userId, isPreSetTheme) && !isPreSetTheme) {
        return UpdateCloneBundleResourceInfo(bundleName, appIndex, type);
    }
    // Need to consider dynamic icons when user switching
    if (((type & static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_USER_ID_CHANGE)) !=
        static_cast<uint32_t>(BundleResourceChangeType::SYSTEM_USER_ID_CHANGE))) {
        return UpdateCloneBundleResourceInfo(bundleName, appIndex, type);
    }
    // check dynamic
    std::string mainDynamicIcon = BundleResourceProcess::GetCurDynamicIconModule(bundleName, userId, 0);
    std::string dynamicIcon = BundleResourceProcess::GetCurDynamicIconModule(bundleName, userId, appIndex);
    if (mainDynamicIcon == dynamicIcon) {
        return UpdateCloneBundleResourceInfo(bundleName, appIndex, type);
    } else if (!dynamicIcon.empty()) {
        // need to parse dynamic icon
        ExtendResourceInfo extendResourceInfo;
        if (!BundleResourceProcess::GetExtendResourceInfo(bundleName, dynamicIcon, extendResourceInfo)) {
            APP_LOGW("-n %{public}s -m %{public}s is not exist", bundleName.c_str(), dynamicIcon.c_str());
            return UpdateCloneBundleResourceInfo(bundleName, appIndex, type);
        }
        ResourceInfo resourceInfo;
        resourceInfo.bundleName_ = bundleName;
        resourceInfo.iconId_ = extendResourceInfo.iconId;
        resourceInfo.appIndex_ = appIndex;
        BundleResourceParser bundleResourceParser;
        if (!bundleResourceParser.ParseIconResourceByPath(extendResourceInfo.filePath,
            extendResourceInfo.iconId, resourceInfo) || resourceInfo.icon_.empty()) {
            APP_LOGW("-n %{public}s -m %{public}s parse resource by path failed",
                bundleName.c_str(), dynamicIcon.c_str());
            return UpdateCloneBundleResourceInfo(bundleName, appIndex, type);
        }
        return UpdateBundleIcon(bundleName, resourceInfo);
    } else {
        // need to parse hap icon
        return AddResourceInfoByBundleName(bundleName, userId, appIndex);
    }
}

bool BundleResourceManager::DeleteNotExistResourceInfo()
{
    APP_LOGD("start delete not exist resource");
    return bundleResourceRdb_->DeleteNotExistResourceInfo();
}

bool BundleResourceManager::GetExtensionAbilityResourceInfo(const std::string &bundleName,
    const ExtensionAbilityType extensionAbilityType, const uint32_t flags,
    std::vector<LauncherAbilityResourceInfo> &extensionAbilityResourceInfo, const int32_t appIndex)
{
    APP_LOGD("start, bundleName:%{public}s", bundleName.c_str());
    uint32_t resourceFlags = CheckResourceFlags(flags);
    if (bundleResourceRdb_->GetExtensionAbilityResourceInfo(bundleName, extensionAbilityType, resourceFlags,
        extensionAbilityResourceInfo, appIndex)) {
        return true;
    }
    APP_LOGE_NOFUNC("%{public}s extension ability %{public}d not exist in resource rdb", bundleName.c_str(),
        extensionAbilityType);
    return false;
}

void BundleResourceManager::ProcessResourceInfoNoNeedToParseOtherIcon(std::vector<ResourceInfo> &resourceInfos)
{
    size_t size = resourceInfos.size();
    for (size_t index = 0; index < size; ++index) {
        // theme changed no need parse label
        resourceInfos[index].labelNeedParse_ = false;
        resourceInfos[index].label_ = Constants::EMPTY_STRING;
        if ((index > 0) && ServiceConstants::ALLOW_MULTI_ICON_BUNDLE.find(resourceInfos[0].bundleName_) ==
            ServiceConstants::ALLOW_MULTI_ICON_BUNDLE.end()) {
            // only need parse once
            resourceInfos[index].iconNeedParse_ = false;
        }
    }
}

void BundleResourceManager::PrepareSysRes()
{
    {
        std::lock_guard<std::mutex> guard(g_sysResMutex);
        if (!g_resMgr) {
            g_resMgr = std::shared_ptr<Global::Resource::ResourceManager>(
                Global::Resource::CreateResourceManager());
            APP_LOGI("get system resource");
        }
    }
    auto task = [] {
        std::lock_guard<std::mutex> guard(g_sysResMutex);
        g_resMgr = nullptr;
        APP_LOGI("release system resource");
    };
    delayedTaskMgr_->ScheduleDelayedTask(task);
}

bool BundleResourceManager::ProcessUpdateCloneBundleResourceInfo(const std::string &bundleName)
{
    bool ret = true;
    auto appIndexes = BundleResourceProcess::GetAppIndexByBundleName(bundleName);
    for (const auto appIndex : appIndexes) {
        if (!AddCloneBundleResourceInfo(bundleName, appIndex)) {
            APP_LOGE("add %{public}s %{public}d clone resource info failed", bundleName.c_str(), appIndex);
            ret = false;
        }
    }
    return ret;
}

void BundleResourceManager::BundleResourceConvertToResourceInfo(
    const BundleResourceInfo &bundleResourceInfo, ResourceInfo &resourceInfo)
{
    // no need to process icon, use dynamic icon
    resourceInfo.bundleName_ = bundleResourceInfo.bundleName;
    resourceInfo.moduleName_ = Constants::EMPTY_STRING;
    resourceInfo.abilityName_ = Constants::EMPTY_STRING;
    if (bundleResourceInfo.appIndex == resourceInfo.appIndex_) {
        resourceInfo.label_ = bundleResourceInfo.label;
    } else {
        resourceInfo.label_ = bundleResourceInfo.label + std::to_string(resourceInfo.appIndex_);
    }
}

void BundleResourceManager::LauncherAbilityResourceConvertToResourceInfo(
    const LauncherAbilityResourceInfo &launcherAbilityResourceInfo, ResourceInfo &resourceInfo)
{
    // no need to process icon, use dynamic icon
    resourceInfo.bundleName_ = launcherAbilityResourceInfo.bundleName;
    resourceInfo.abilityName_ = launcherAbilityResourceInfo.abilityName;
    resourceInfo.moduleName_ = launcherAbilityResourceInfo.moduleName;
    if (launcherAbilityResourceInfo.appIndex == resourceInfo.appIndex_) {
        resourceInfo.label_ = launcherAbilityResourceInfo.label;
    } else {
        resourceInfo.label_ = launcherAbilityResourceInfo.label + std::to_string(resourceInfo.appIndex_);
    }
}
} // AppExecFwk
} // OHOS
