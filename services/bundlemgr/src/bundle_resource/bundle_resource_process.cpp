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

#include "ability_info.h"
#include "account_helper.h"
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* GLOBAL_RESOURCE_BUNDLE_NAME = "ohos.global.systemres";
const std::string INNER_UNDER_LINE = "_";
}
bool BundleResourceProcess::GetLauncherAbilityResourceInfo(const InnerBundleInfo &innerBundleInfo,
    const int32_t userId,
    std::vector<ResourceInfo> &resourceInfos)
{
    if (innerBundleInfo.GetBundleName().empty()) {
        APP_LOGE("bundleName is empty");
        return false;
    }

    if (innerBundleInfo.GetApplicationBundleType() == BundleType::SHARED) {
        APP_LOGD("bundleName:%{public}s is shared", innerBundleInfo.GetBundleName().c_str());
        return false;
    }

    if (innerBundleInfo.GetBaseApplicationInfo().hideDesktopIcon) {
        APP_LOGD("bundleName:%{public}s hide desktop icon", innerBundleInfo.GetBundleName().c_str());
        return false;
    }

    if (innerBundleInfo.GetBaseBundleInfo().entryInstallationFree) {
        APP_LOGD("bundleName:%{public}s is atomic service, hide desktop icon", innerBundleInfo.GetBundleName().c_str());
        return false;
    }

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return false;
    }
    OHOS::AAFwk::Want want;
    want.SetAction(Want::ACTION_HOME);
    want.AddEntity(Want::ENTITY_HOME);
    std::vector<AbilityInfo> abilityInfos;
    int64_t time = GetUpdateTime(innerBundleInfo, userId);
    dataMgr->GetMatchLauncherAbilityInfos(want, innerBundleInfo, abilityInfos, time, userId);

    if (abilityInfos.empty()) {
        APP_LOGE("abilityInfos is empty");
        return false;
    }

    for (const auto &info : abilityInfos) {
        if (!info.applicationInfo.enabled) {
            continue;
        }
        resourceInfos.push_back(ConvertToLauncherAbilityResourceInfo(info));
    }
    return true;
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
    resourceInfo = ConvertToBundleResourceInfo(innerBundleInfo, userId);

    return true;
}

bool BundleResourceProcess::GetResourceInfo(
    const InnerBundleInfo &innerBundleInfo,
    const int32_t userId,
    std::vector<ResourceInfo> &resourceInfo)
{
    if (userId != Constants::DEFAULT_USERID && userId != Constants::START_USERID) {
        int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
        if ((currentUserId <= 0) && (currentUserId != userId)) {
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
    std::vector<ResourceInfo> &resourceInfos)
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
        if (!InnerGetResourceInfo(item.second, userId, resourceInfos)) {
            APP_LOGW("bundle %{public}s resourceInfo is empty", item.second.GetBundleName().c_str());
        }
    }
    return true;
}

bool BundleResourceProcess::GetResourceInfoByBundleName(
    const std::string &bundleName,
    const int32_t userId,
    std::vector<ResourceInfo> &resourceInfo)
{
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

    return InnerGetResourceInfo(item->second, userId, resourceInfo);
}

bool BundleResourceProcess::GetResourceInfoByAbilityName(
    const std::string &bundleName,
    const std::string &moduleName,
    const std::string &abilityName,
    const int32_t userId,
    ResourceInfo &resourceInfo)
{
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
    if (GetLauncherAbilityResourceInfo(item->second, userId, resourceInfos)) {
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
        return false;
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
    ResourceInfo bundleResourceInfo;
    if (GetBundleResourceInfo(innerBundleInfo, userId, bundleResourceInfo)) {
        resourceInfos.push_back(bundleResourceInfo);
    }

    std::vector<ResourceInfo> launcherAbilityResourceInfos;
    if (GetLauncherAbilityResourceInfo(innerBundleInfo, userId, launcherAbilityResourceInfos)) {
        for (const auto &info : launcherAbilityResourceInfos) {
            resourceInfos.push_back(info);
        }
    }
    return !resourceInfos.empty();
}

bool BundleResourceProcess::IsBundleExist(const InnerBundleInfo &innerBundleInfo, const int32_t userId)
{
    int32_t responseUserId = innerBundleInfo.GetResponseUserId(userId);
    return responseUserId != Constants::INVALID_USERID;
    // get installTime from innerBundleUserInfo
}

int64_t BundleResourceProcess::GetUpdateTime(const InnerBundleInfo &innerBundleInfo, const int32_t userId)
{
    // get installTime from innerBundleUserInfo
    std::string userIdKey = innerBundleInfo.GetBundleName() + INNER_UNDER_LINE + std::to_string(userId);
    std::string userZeroKey = innerBundleInfo.GetBundleName() + INNER_UNDER_LINE + std::to_string(0);
    auto iter = std::find_if(innerBundleInfo.GetInnerBundleUserInfos().begin(),
        innerBundleInfo.GetInnerBundleUserInfos().end(),
        [&userIdKey, &userZeroKey](const std::pair<std::string, InnerBundleUserInfo> &infoMap) {
        return (infoMap.first == userIdKey || infoMap.first == userZeroKey);
    });
    int64_t installTime = 0;
    if (iter != innerBundleInfo.GetInnerBundleUserInfos().end()) {
        installTime = iter->second.installTime;
    }
    return installTime;
}

ResourceInfo BundleResourceProcess::ConvertToLauncherAbilityResourceInfo(const AbilityInfo &info)
{
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = info.bundleName;
    resourceInfo.moduleName_ = info.moduleName;
    resourceInfo.abilityName_ = info.name;
    resourceInfo.labelId_ = info.labelId;
    resourceInfo.label_ = info.label;
    if (resourceInfo.label_.empty()) {
        resourceInfo.label_ = info.bundleName;
    }
    resourceInfo.iconId_ = info.iconId;
    resourceInfo.hapPath_ = info.hapPath;
    resourceInfo.updateTime_ = info.installTime;
    if ((resourceInfo.abilityName_ == Constants::APP_DETAIL_ABILITY) && (resourceInfo.hapPath_.empty())) {
        if (!GetDefaultIconResource(resourceInfo.iconId_, resourceInfo.defaultIconHapPath_)) {
            APP_LOGW("GetDefaultIconResource failed bundleName:%{public}s", resourceInfo.bundleName_.c_str());
        }
    }
    return resourceInfo;
}

ResourceInfo BundleResourceProcess::ConvertToBundleResourceInfo(
    const InnerBundleInfo &innerBundleInfo,
    const int32_t userId)
{
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = innerBundleInfo.GetBundleName();
    resourceInfo.labelId_ = innerBundleInfo.GetBaseApplicationInfo().labelResource.id;
    resourceInfo.label_ = innerBundleInfo.GetBaseApplicationInfo().label;
    if ((resourceInfo.labelId_ == 0) || resourceInfo.label_.empty()) {
        resourceInfo.label_ = innerBundleInfo.GetBundleName();
    }
    resourceInfo.iconId_ = innerBundleInfo.GetBaseApplicationInfo().iconResource.id;
    resourceInfo.icon_ = innerBundleInfo.GetBaseApplicationInfo().icon;
    resourceInfo.updateTime_ = GetUpdateTime(innerBundleInfo, userId);
    if (resourceInfo.iconId_ == 0) {
        if (!GetDefaultIconResource(resourceInfo.iconId_, resourceInfo.defaultIconHapPath_)) {
            APP_LOGW("GetDefaultIconResource failed bundleName:%{public}s", resourceInfo.bundleName_.c_str());
        }
    }
    const auto &moduleName = innerBundleInfo.GetBaseApplicationInfo().labelResource.moduleName;
    const auto &moduleInfos = innerBundleInfo.GetInnerModuleInfos();
    for (const auto &iter : moduleInfos) {
        if (iter.second.moduleName == moduleName) {
            resourceInfo.hapPath_ = iter.second.hapPath;
            break;
        }
    }
    return resourceInfo;
}

bool BundleResourceProcess::GetDefaultIconResource(int32_t &iconId, std::string &hapPath)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return false;
    }
    BundleInfo info;
    if (dataMgr->GetBundleInfoV9(GLOBAL_RESOURCE_BUNDLE_NAME,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION),
        info, Constants::START_USERID) != ERR_OK) {
        APP_LOGE("GetDefaultIconResource failed to get ohos.global.systemres info");
        return false;
    }
    if (!info.hapModuleInfos.empty()) {
        iconId = info.applicationInfo.iconResource.id;
        hapPath = info.hapModuleInfos[0].hapPath;
        return true;
    }
    APP_LOGE("hapModuleInfos is empty");
    return false;
}
} // AppExecFwk
} // OHOS
