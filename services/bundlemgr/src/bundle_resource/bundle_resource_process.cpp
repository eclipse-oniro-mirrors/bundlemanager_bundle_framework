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

#include "bundle_resource_process.h"

#include <mutex>

#include "ability_info.h"
#include "account_helper.h"
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string INNER_UNDER_LINE = "_";
}

bool BundleResourceProcess::GetBundleResourceInfo(const InnerBundleInfo &innerBundleInfo,
    const int32_t userId,
    ResourceInfo &resourceInfo)
{
    if (innerBundleInfo.GetBundleName().empty()) {
        APP_LOGE("bundleName is empty");
        return false;
    }
    if (innerBundleInfo.GetApplicationBundleType() == BundleType::SHARED) {
        APP_LOGD("bundleName:%{public}s is shared", innerBundleInfo.GetBundleName().c_str());
        return false;
    }
    resourceInfo = ConvertToBundleResourceInfo(innerBundleInfo);

    return true;
}

bool BundleResourceProcess::GetResourceInfo(
    const InnerBundleInfo &innerBundleInfo,
    const int32_t userId,
    std::vector<ResourceInfo> &resourceInfo)
{
    if (userId != Constants::DEFAULT_USERID) {
        int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
        if ((currentUserId > 0) && (currentUserId != userId)) {
            APP_LOGW("userId not same, userId: %{public}d, currentUserId :%{public}d", userId, currentUserId);
            return false;
        }
    }

    if (!IsBundleExist(innerBundleInfo, userId)) {
        APP_LOGW("bundle %{public}s is not exist in userId: %{public}d",
            innerBundleInfo.GetBundleName().c_str(), userId);
        return false;
    }

    return InnerGetResourceInfo(innerBundleInfo, userId, resourceInfo);
}

bool BundleResourceProcess::GetAllResourceInfo(
    const int32_t userId,
    std::map<std::string, std::vector<ResourceInfo>> &resourceInfosMap)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return false;
    }
    auto userIds = dataMgr->GetAllUser();
    if (userIds.find(userId) == userIds.end()) {
        APP_LOGE("userId: %{public}d is not exist", userId);
        return false;
    }
    const std::map<std::string, InnerBundleInfo> bundleInfos = dataMgr->GetAllInnerBundleInfos();
    if (bundleInfos.empty()) {
        APP_LOGE("bundleInfos is empty");
        return false;
    }

    for (const auto &item : bundleInfos) {
        if (item.second.IsDisabled()) {
            APP_LOGD("bundle %{public}s is disabled", item.second.GetBundleName().c_str());
            continue;
        }
        if (!IsBundleExist(item.second, userId)) {
            APP_LOGD("bundle %{public}s is not exist in userId: %{public}d",
                item.second.GetBundleName().c_str(), userId);
            continue;
        }
        if (!item.second.GetApplicationEnabled(item.second.GetResponseUserId(userId))) {
            APP_LOGD("bundle %{public}s is disabled in userId: %{public}d",
                item.second.GetBundleName().c_str(), userId);
            continue;
        }
        std::vector<ResourceInfo> resourceInfos;
        if (!InnerGetResourceInfo(item.second, userId, resourceInfos)) {
            APP_LOGW("bundle %{public}s resourceInfo is empty", item.second.GetBundleName().c_str());
        } else {
            resourceInfosMap[item.second.GetBundleName()] = resourceInfos;
        }
    }
    return true;
}

bool BundleResourceProcess::GetResourceInfoByBundleName(
    const std::string &bundleName,
    const int32_t userId,
    std::vector<ResourceInfo> &resourceInfo)
{
    APP_LOGD("start, bundleName:%{public}s", bundleName.c_str());
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return false;
    }
    const std::map<std::string, InnerBundleInfo> bundleInfos = dataMgr->GetAllInnerBundleInfos();
    auto item = bundleInfos.find(bundleName);
    if (item == bundleInfos.end()) {
        APP_LOGE("bundleName %{public}s is not exist", bundleName.c_str());
        return false;
    }

    if (!IsBundleExist(item->second, userId)) {
        APP_LOGW("bundle %{public}s is not exist in userId: %{public}d",
            item->second.GetBundleName().c_str(), userId);
        return false;
    }

    if (!item->second.GetApplicationEnabled(item->second.GetResponseUserId(userId))) {
        APP_LOGW("bundle %{public}s is disabled in userId:%{public}d",
            item->second.GetBundleName().c_str(), userId);
        return false;
    }

    return InnerGetResourceInfo(item->second, userId, resourceInfo);
}

bool BundleResourceProcess::GetResourceInfoByAbilityName(
    const std::string &bundleName,
    const std::string &moduleName,
    const std::string &abilityName,
    const int32_t userId,
    ResourceInfo &resourceInfo)
{
    APP_LOGD("start, bundleName:%{public}s, moduleName:%{public}s, abilityName:%{public}s",
        bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return false;
    }
    const std::map<std::string, InnerBundleInfo> bundleInfos = dataMgr->GetAllInnerBundleInfos();
    auto item = bundleInfos.find(bundleName);
    if (item == bundleInfos.end()) {
        APP_LOGE("bundleName %{public}s is not exist", bundleName.c_str());
        return false;
    }
    if (!IsBundleExist(item->second, userId)) {
        APP_LOGW("bundle %{public}s is not exist in userId: %{public}d",
            item->second.GetBundleName().c_str(), userId);
        return false;
    }
    if (item->second.IsDisabled()) {
        APP_LOGD("bundle %{public}s is disabled", item->second.GetBundleName().c_str());
        return false;
    }
    std::vector<ResourceInfo> resourceInfos;
    if (GetAbilityResourceInfos(item->second, userId, resourceInfos)) {
        for (const auto &info : resourceInfos) {
            if ((info.moduleName_ == moduleName) && (info.abilityName_ == abilityName)) {
                resourceInfo = info;
                return true;
            }
        }
    }
    APP_LOGE("bundleName %{public}s, moduleName: %{public}s, abilityName:%{public}s is not exist",
        bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
    return false;
}

bool BundleResourceProcess::GetResourceInfoByColorModeChanged(
    const std::vector<std::string> &resourceNames,
    std::vector<ResourceInfo> &resourceInfos)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return false;
    }
    std::vector<std::string> bundleNames = dataMgr->GetAllBundleName();
    std::vector<std::string> needAddResourceBundles;
    for (const auto &bundleName : bundleNames) {
        if (std::find(resourceNames.begin(), resourceNames.end(), bundleName) == resourceNames.end()) {
            needAddResourceBundles.push_back(bundleName);
        }
    }
    if (needAddResourceBundles.empty()) {
        APP_LOGW("needAddResourceBundles is empty");
        return true;
    }

    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    if (currentUserId <= 0) {
        currentUserId = Constants::START_USERID;
    }
    for (const auto &bundleName : needAddResourceBundles) {
        if (!GetResourceInfoByBundleName(bundleName, currentUserId, resourceInfos)) {
            APP_LOGW("bundleName: %{public}s GetResourceInfoByBundleName failed.", bundleName.c_str());
        }
    }
    return true;
}

bool BundleResourceProcess::InnerGetResourceInfo(
    const InnerBundleInfo &innerBundleInfo,
    const int32_t userId,
    std::vector<ResourceInfo> &resourceInfos)
{
    std::string bundleName = innerBundleInfo.GetBundleName();
    APP_LOGD("start, bundleName:%{public}s", bundleName.c_str());
    // get bundle
    ResourceInfo bundleResourceInfo;
    if (!GetBundleResourceInfo(innerBundleInfo, userId, bundleResourceInfo)) {
        APP_LOGW("bundleName: %{public}s get bundle resource failed", bundleName.c_str());
        return false;
    }
    resourceInfos.push_back(bundleResourceInfo);

    // get ability
    std::vector<ResourceInfo> abilityResourceInfos;
    if (GetAbilityResourceInfos(innerBundleInfo, userId, abilityResourceInfos)) {
        for (const auto &info : abilityResourceInfos) {
            resourceInfos.push_back(info);
        }
    }
    APP_LOGI("end, bundleName:%{public}s, resourceInfo.size:%{public}d", bundleName.c_str(),
        static_cast<int32_t>(resourceInfos.size()));
    return !resourceInfos.empty();
}

bool BundleResourceProcess::IsBundleExist(const InnerBundleInfo &innerBundleInfo, const int32_t userId)
{
    int32_t responseUserId = innerBundleInfo.GetResponseUserId(userId);
    return responseUserId != Constants::INVALID_USERID;
}

ResourceInfo BundleResourceProcess::ConvertToLauncherAbilityResourceInfo(const AbilityInfo &info, bool hideDesktopIcon)
{
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = info.bundleName;
    resourceInfo.moduleName_ = info.moduleName;
    resourceInfo.abilityName_ = info.name;
    resourceInfo.labelId_ = info.labelId;
    resourceInfo.iconId_ = info.iconId;
    resourceInfo.hapPath_ = info.hapPath;
    resourceInfo.hideDesktopIcon_ = hideDesktopIcon;
    return resourceInfo;
}

ResourceInfo BundleResourceProcess::ConvertToBundleResourceInfo(const InnerBundleInfo &innerBundleInfo)
{
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = innerBundleInfo.GetBundleName();
    resourceInfo.labelId_ = innerBundleInfo.GetBaseApplicationInfo().labelResource.id;
    resourceInfo.iconId_ = innerBundleInfo.GetBaseApplicationInfo().iconResource.id;
    const auto &moduleName = innerBundleInfo.GetBaseApplicationInfo().labelResource.moduleName;
    const auto &moduleInfos = innerBundleInfo.GetInnerModuleInfos();
    for (const auto &iter : moduleInfos) {
        if (iter.second.moduleName == moduleName) {
            resourceInfo.hapPath_ = iter.second.hapPath;
            break;
        }
    }
    resourceInfo.moduleName_ = moduleName;
    resourceInfo.abilityName_ = std::string();
    return resourceInfo;
}

bool BundleResourceProcess::GetAbilityResourceInfos(
    const InnerBundleInfo &innerBundleInfo,
    const int32_t userId,
    std::vector<ResourceInfo> &resourceInfo)
{
    APP_LOGD("start get ability, bundleName:%{public}s", innerBundleInfo.GetBundleName().c_str());
    if (innerBundleInfo.GetBundleName().empty()) {
        APP_LOGE("bundleName is empty");
        return false;
    }
    if (innerBundleInfo.GetApplicationBundleType() == BundleType::SHARED) {
        APP_LOGW("bundleName:%{public}s is shared bundle, no ability", innerBundleInfo.GetBundleName().c_str());
        return false;
    }
    bool hideDesktopIcon = true;
    std::map<std::string, AbilityInfo> abilityInfos = innerBundleInfo.GetInnerAbilityInfos();
    std::map<std::string, std::vector<Skill>> skillInfos = innerBundleInfo.GetInnerSkillInfos();
    for (const auto &item : abilityInfos) {
        if (!innerBundleInfo.IsAbilityEnabled(item.second, innerBundleInfo.GetResponseUserId(userId))) {
            APP_LOGW("bundleName:%{public}s abilityName:%{public}s is disabled", item.second.bundleName.c_str(),
                item.second.name.c_str());
            continue;
        }
        bool needHideDeskTopIcon = hideDesktopIcon;
        auto skillsPair = skillInfos.find(item.first);
        if (skillsPair != skillInfos.end()) {
            InnerProcessLauncherAbilityResource(innerBundleInfo, skillsPair->second,
                item.second.type, needHideDeskTopIcon);
        }
        resourceInfo.emplace_back(ConvertToLauncherAbilityResourceInfo(item.second, needHideDeskTopIcon));
    }
    APP_LOGD("end get ability, size:%{public}zu, bundleName:%{public}s", resourceInfo.size(),
        innerBundleInfo.GetBundleName().c_str());
    return !resourceInfo.empty();
}

void BundleResourceProcess::InnerProcessLauncherAbilityResource(const InnerBundleInfo &innerBundleInfo,
    const std::vector<Skill> &skills, const AbilityType type, bool &needHideDeskTopIcon)
{
    OHOS::AAFwk::Want want;
    want.SetAction(Want::ACTION_HOME);
    want.AddEntity(Want::ENTITY_HOME);
    for (const Skill& skill : skills) {
        if (skill.MatchLauncher(want) && (type == AbilityType::PAGE)) {
            needHideDeskTopIcon = innerBundleInfo.GetBaseApplicationInfo().hideDesktopIcon ||
                innerBundleInfo.GetBaseBundleInfo().entryInstallationFree;
            return;
        }
    }
}
} // AppExecFwk
} // OHOS
