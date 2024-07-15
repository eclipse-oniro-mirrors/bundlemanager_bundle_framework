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
#include "bundle_resource_manager.h"
#include "bundle_resource_parser.h"

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
    // process overlay hap paths
    GetOverlayModuleHapPaths(innerBundleInfo, resourceInfo.moduleName_, userId, resourceInfo.overlayHapPaths_);
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
            APP_LOGW("userId:%{public}d current:%{public}d not same", userId, currentUserId);
            return false;
        }
    }

    if (!IsBundleExist(innerBundleInfo, userId)) {
        APP_LOGW("%{public}s not exist in userId %{public}d",
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
        APP_LOGE("userId %{public}d not exist", userId);
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
        std::vector<ResourceInfo> resourceInfos;
        if (!InnerGetResourceInfo(item.second, userId, resourceInfos)) {
            APP_LOGW("%{public}s resourceInfo empty", item.second.GetBundleName().c_str());
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
    InnerBundleInfo innerBundleInfo;
    if (!dataMgr->FetchInnerBundleInfo(bundleName, innerBundleInfo)) {
        APP_LOGE("bundleName %{public}s not exist", bundleName.c_str());
        return false;
    }

    if (!IsBundleExist(innerBundleInfo, userId)) {
        APP_LOGW("bundle %{public}s not exist in userId %{public}d", innerBundleInfo.GetBundleName().c_str(), userId);
        return false;
    }

    return InnerGetResourceInfo(innerBundleInfo, userId, resourceInfo);
}

bool BundleResourceProcess::GetLauncherResourceInfoByAbilityName(
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
    InnerBundleInfo innerBundleInfo;
    if (!dataMgr->FetchInnerBundleInfo(bundleName, innerBundleInfo)) {
        APP_LOGE("bundleName %{public}s not exist", bundleName.c_str());
        return false;
    }

    if (!IsBundleExist(innerBundleInfo, userId)) {
        APP_LOGW("bundle %{public}s not exist in userId %{public}d", innerBundleInfo.GetBundleName().c_str(), userId);
        return false;
    }
    if (innerBundleInfo.IsDisabled()) {
        APP_LOGD("bundle %{public}s is disabled", innerBundleInfo.GetBundleName().c_str());
        return false;
    }
    std::vector<ResourceInfo> resourceInfos;
    if (GetAbilityResourceInfos(innerBundleInfo, userId, resourceInfos)) {
        for (const auto &info : resourceInfos) {
            if ((info.moduleName_ == moduleName) && (info.abilityName_ == abilityName)) {
                resourceInfo = info;
                return true;
            }
        }
    }
    APP_LOGE("bundleName %{public}s, moduleName %{public}s, abilityName %{public}s not exist",
        bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
    return false;
}

bool BundleResourceProcess::GetResourceInfoByColorModeChanged(
    const std::vector<std::string> &resourceNames,
    const int32_t userId,
    std::vector<ResourceInfo> &resourceInfos)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return false;
    }
    const std::map<std::string, InnerBundleInfo> bundleInfos = dataMgr->GetAllInnerBundleInfos();
    std::vector<std::string> bundleNames;
    for (const auto &item : bundleInfos) {
        bundleNames.emplace_back(item.first);
        InnerBundleUserInfo innerBundleUserInfo;
        if (item.second.GetInnerBundleUserInfo(userId, innerBundleUserInfo) &&
            !innerBundleUserInfo.cloneInfos.empty()) {
            // need process clone app resource
            APP_LOGI("bundleName:%{public}s has clone info", item.first.c_str());
            for (const auto &clone : innerBundleUserInfo.cloneInfos) {
                bundleNames.emplace_back(std::to_string(clone.second.appIndex) + INNER_UNDER_LINE + item.first);
            }
        }
    }
    std::set<std::string> needAddResourceBundles;
    for (const auto &bundleName : bundleNames) {
        if (std::find(resourceNames.begin(), resourceNames.end(), bundleName) == resourceNames.end()) {
            ResourceInfo info;
            info.ParseKey(bundleName);
            needAddResourceBundles.insert(info.bundleName_);
        }
    }
    if (needAddResourceBundles.empty()) {
        APP_LOGW("needAddResourceBundles is empty");
        return true;
    }

    for (const auto &bundleName : needAddResourceBundles) {
        if (!GetResourceInfoByBundleName(bundleName, userId, resourceInfos)) {
            APP_LOGW("bundleName %{public}s GetResourceInfoByBundleName failed", bundleName.c_str());
        }
    }
    return true;
}

void BundleResourceProcess::ChangeDynamicIcon(
    std::vector<ResourceInfo> &resourceInfos, const ResourceInfo &resourceInfo)
{
    for (auto &info : resourceInfos) {
        info.icon_ = resourceInfo.icon_;
        info.foreground_ = resourceInfo.foreground_;
        info.background_ = resourceInfo.background_;
        info.iconNeedParse_ = false;
    }
}

bool BundleResourceProcess::GetDynamicIcon(
    const InnerBundleInfo &innerBundleInfo, ResourceInfo &resourceInfo)
{
    std::string curDynamicIconModule = innerBundleInfo.GetCurDynamicIconModule();
    if (curDynamicIconModule.empty()) {
        return false;
    }

    std::map<std::string, ExtendResourceInfo> extResourceInfos =
        innerBundleInfo.GetExtendResourceInfos();
    auto iter = extResourceInfos.find(curDynamicIconModule);
    if (iter == extResourceInfos.end()) {
        APP_LOGE("Module not exist %{public}s",
            curDynamicIconModule.c_str());
        return false;
    }
    auto &extendResourceInfo = iter->second;
    BundleResourceParser parser;
    if (parser.ParseIconResourceByPath(extendResourceInfo.filePath, extendResourceInfo.iconId, resourceInfo)) {
        APP_LOGE("bundleName:%{public}s parse dynamicIcon failed, iconId:%{public}d",
            innerBundleInfo.GetBundleName().c_str(), extendResourceInfo.iconId);
        return false;
    }
    return true;
}

bool BundleResourceProcess::InnerGetResourceInfo(
    const InnerBundleInfo &innerBundleInfo,
    const int32_t userId,
    std::vector<ResourceInfo> &resourceInfos)
{
    // for clone bundle
    std::vector<int32_t> appIndexes;
    InnerBundleUserInfo innerBundleUserInfo;
    if (innerBundleInfo.GetInnerBundleUserInfo(userId, innerBundleUserInfo)) {
        for (const auto &cloneInfo : innerBundleUserInfo.cloneInfos) {
            if (cloneInfo.second.enabled) {
                appIndexes.emplace_back(cloneInfo.second.appIndex);
            }
        }
    }
    if (!innerBundleInfo.GetApplicationEnabled(innerBundleInfo.GetResponseUserId(userId))) {
        if (appIndexes.empty()) {
            APP_LOGW("bundle %{public}s is disabled in userId:%{public}d, no clone info",
                innerBundleInfo.GetBundleName().c_str(), userId);
            return false;
        }
        appIndexes.emplace_back(ServiceConstants::INVALID_GID);
    }

    ResourceInfo dynamicResourceInfo;
    bool hasDynamicIcon = GetDynamicIcon(innerBundleInfo, dynamicResourceInfo);
    if (!OnGetResourceInfo(innerBundleInfo, userId, resourceInfos)) {
        if (!hasDynamicIcon) {
            APP_LOGW("bundleName: %{public}s get bundle resource failed",
                innerBundleInfo.GetBundleName().c_str());
            return false;
        }

        APP_LOGI("%{public}s no default icon, build new", innerBundleInfo.GetBundleName().c_str());
        ResourceInfo defaultResourceInfo;
        defaultResourceInfo.bundleName_ = innerBundleInfo.GetBundleName();
        defaultResourceInfo.labelNeedParse_ = false;
        defaultResourceInfo.iconNeedParse_ = false;
        defaultResourceInfo.icon_ = dynamicResourceInfo.icon_;
        defaultResourceInfo.foreground_ = dynamicResourceInfo.foreground_;
        defaultResourceInfo.background_ = dynamicResourceInfo.background_;
        resourceInfos.emplace_back(defaultResourceInfo);
    }

    if (hasDynamicIcon) {
        APP_LOGI("bundle %{public}s has dynamicIcon", innerBundleInfo.GetBundleName().c_str());
        ChangeDynamicIcon(resourceInfos, dynamicResourceInfo);
    }
    // for clone bundle
    if (!appIndexes.empty()) {
        APP_LOGI("bundleName:%{public}s contains clone bundle", innerBundleInfo.GetBundleName().c_str());
        for (auto &info : resourceInfos) {
            info.appIndexes_ = appIndexes;
        }
    }
    return true;
}

bool BundleResourceProcess::OnGetResourceInfo(
    const InnerBundleInfo &innerBundleInfo,
    const int32_t userId,
    std::vector<ResourceInfo> &resourceInfos)
{
    std::string bundleName = innerBundleInfo.GetBundleName();
    APP_LOGD("start, bundleName:%{public}s", bundleName.c_str());
    // get bundle
    ResourceInfo bundleResourceInfo;
    if (!GetBundleResourceInfo(innerBundleInfo, userId, bundleResourceInfo)) {
        APP_LOGW("%{public}s get resource failed", bundleName.c_str());
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

ResourceInfo BundleResourceProcess::ConvertToLauncherAbilityResourceInfo(const AbilityInfo &info)
{
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = info.bundleName;
    resourceInfo.moduleName_ = info.moduleName;
    resourceInfo.abilityName_ = info.name;
    resourceInfo.labelId_ = info.labelId;
    resourceInfo.iconId_ = info.iconId;
    resourceInfo.hapPath_ = info.hapPath;
    return resourceInfo;
}

ResourceInfo BundleResourceProcess::ConvertToBundleResourceInfo(const InnerBundleInfo &innerBundleInfo)
{
    ApplicationInfo appInfo = innerBundleInfo.GetBaseApplicationInfo();
    innerBundleInfo.AdaptMainLauncherResourceInfo(appInfo);
    ResourceInfo resourceInfo;
    resourceInfo.bundleName_ = innerBundleInfo.GetBundleName();
    resourceInfo.labelId_ = appInfo.labelResource.id;
    resourceInfo.iconId_ = appInfo.iconResource.id;
    const auto &moduleName = appInfo.labelResource.moduleName;
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

bool BundleResourceProcess::GetLauncherAbilityResourceInfos(
    const InnerBundleInfo &innerBundleInfo,
    const int32_t userId,
    std::vector<ResourceInfo> &resourceInfos)
{
    APP_LOGD("start get ability, bundleName:%{public}s", innerBundleInfo.GetBundleName().c_str());
    if (!CheckIsNeedProcessAbilityResource(innerBundleInfo)) {
        APP_LOGW("%{public}s no need add ability resource", innerBundleInfo.GetBundleName().c_str());
        return false;
    }

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return false;
    }
    OHOS::AAFwk::Want want;
    want.SetAction(Want::ACTION_HOME);
    want.AddEntity(Want::ENTITY_HOME);
    std::vector<AbilityInfo> abilityInfos;
    int64_t time = 0;
    dataMgr->GetMatchLauncherAbilityInfos(want, innerBundleInfo, abilityInfos, time, userId);

    if (abilityInfos.empty()) {
        APP_LOGW("%{public}s no launcher ability Info", innerBundleInfo.GetBundleName().c_str());
        return false;
    }
    for (const auto &info : abilityInfos) {
        if (!info.applicationInfo.enabled) {
            continue;
        }
        if (!innerBundleInfo.IsAbilityEnabled(info, innerBundleInfo.GetResponseUserId(userId))) {
            APP_LOGW("abilityName %{public}s disable", info.name.c_str());
            continue;
        }
        resourceInfos.push_back(ConvertToLauncherAbilityResourceInfo(info));
    }
    // process overlay hap paths
    size_t size = resourceInfos.size();
    for (size_t index = 0; index < size; ++index) {
        if ((index > 0) && (resourceInfos[index].moduleName_ == resourceInfos[index - 1].moduleName_)) {
            resourceInfos[index].overlayHapPaths_ = resourceInfos[index - 1].overlayHapPaths_;
            continue;
        }
        GetOverlayModuleHapPaths(innerBundleInfo, resourceInfos[index].moduleName_,
            userId, resourceInfos[index].overlayHapPaths_);
    }

    APP_LOGD("end get ability, size:%{public}zu, bundleName:%{public}s", resourceInfos.size(),
        innerBundleInfo.GetBundleName().c_str());
    return !resourceInfos.empty();
}

bool BundleResourceProcess::CheckIsNeedProcessAbilityResource(const InnerBundleInfo &innerBundleInfo)
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
        APP_LOGD("bundleName:%{public}s is atomic service, hide desktop icon",
            innerBundleInfo.GetBundleName().c_str());
        return false;
    }
    return true;
}

bool BundleResourceProcess::GetOverlayModuleHapPaths(
    const InnerBundleInfo &innerBundleInfo,
    const std::string &moduleName,
    int32_t userId,
    std::vector<std::string> &overlayHapPaths)
{
#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
    auto innerModuleInfo = innerBundleInfo.GetInnerModuleInfoByModuleName(moduleName);
    if (innerModuleInfo == std::nullopt) {
        APP_LOGE("moduleName %{public}s not exist", moduleName.c_str());
        return false;
    }
    if (innerModuleInfo->overlayModuleInfo.empty()) {
        APP_LOGD("moduleName:%{public}s has no overlay module", moduleName.c_str());
        return false;
    }
    std::string bundleName = innerBundleInfo.GetBundleName();
    APP_LOGI("bundleName %{public}s need add path", bundleName.c_str());
    auto overlayModuleInfos = innerModuleInfo->overlayModuleInfo;
    for (auto &info : overlayModuleInfos) {
        if (info.bundleName == bundleName) {
            innerBundleInfo.GetOverlayModuleState(info.moduleName, userId, info.state);
        } else {
            GetExternalOverlayHapState(info.bundleName, info.moduleName, userId, info.state);
        }
    }
    // sort by priority
    std::sort(overlayModuleInfos.begin(), overlayModuleInfos.end(),
        [](const OverlayModuleInfo &lhs, const OverlayModuleInfo &rhs) -> bool {
            return lhs.priority > rhs.priority;
        });
    for (const auto &info : overlayModuleInfos) {
        if (info.state == OverlayState::OVERLAY_ENABLE) {
            overlayHapPaths.emplace_back(info.hapPath);
        }
    }
    if (overlayHapPaths.empty()) {
        APP_LOGE("moduleName %{public}s overlay hap path empty", moduleName.c_str());
        return false;
    }
    return true;
#endif
    return true;
}

bool BundleResourceProcess::GetExternalOverlayHapState(const std::string &bundleName,
    const std::string &moduleName, const int32_t userId, int32_t &state)
{
#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
    APP_LOGD("bundleName:%{public}s, moduleName:%{public}s get overlay state", bundleName.c_str(), moduleName.c_str());
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return false;
    }
    InnerBundleInfo bundleInfo;
    if (!dataMgr->QueryOverlayInnerBundleInfo(bundleName, bundleInfo)) {
        return false;
    }
    if (!bundleInfo.GetOverlayModuleState(moduleName, userId, state)) {
        return false;
    }
    return true;
#endif
    return true;
}

bool BundleResourceProcess::GetAbilityResourceInfos(
    const InnerBundleInfo &innerBundleInfo,
    const int32_t userId,
    std::vector<ResourceInfo> &resourceInfos)
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
    std::map<std::string, AbilityInfo> abilityInfos = innerBundleInfo.GetInnerAbilityInfos();
    for (const auto &item : abilityInfos) {
        if (!innerBundleInfo.IsAbilityEnabled(item.second, innerBundleInfo.GetResponseUserId(userId))) {
            APP_LOGW("bundleName %{public}s abilityName %{public}s disable", item.second.bundleName.c_str(),
                item.second.name.c_str());
            continue;
        }
        resourceInfos.emplace_back(ConvertToLauncherAbilityResourceInfo(item.second));
    }
    // process overlay hap paths
    size_t size = resourceInfos.size();
    for (size_t index = 0; index < size; ++index) {
        if ((index > 0) && (resourceInfos[index].moduleName_ == resourceInfos[index - 1].moduleName_)) {
            resourceInfos[index].overlayHapPaths_ = resourceInfos[index - 1].overlayHapPaths_;
            continue;
        }
        GetOverlayModuleHapPaths(innerBundleInfo, resourceInfos[index].moduleName_,
            userId, resourceInfos[index].overlayHapPaths_);
    }

    APP_LOGD("end get ability, size:%{public}zu, bundleName:%{public}s", resourceInfos.size(),
        innerBundleInfo.GetBundleName().c_str());
    return !resourceInfos.empty();
}

void BundleResourceProcess::GetTargetBundleName(const std::string &bundleName,
    std::string &targetBundleName)
{
    targetBundleName = bundleName;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return;
    }
    InnerBundleInfo bundleInfo;
    if (!dataMgr->QueryOverlayInnerBundleInfo(bundleName, bundleInfo)) {
        return;
    }
    if (bundleInfo.GetOverlayType() == OverlayType::OVERLAY_EXTERNAL_BUNDLE) {
        targetBundleName = bundleInfo.GetTargetBundleName();
    }
}
} // AppExecFwk
} // OHOS
