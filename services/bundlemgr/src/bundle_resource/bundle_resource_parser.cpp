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

#include "bundle_resource_parser.h"

#include "app_log_wrapper.h"
#include "bundle_resource_configuration.h"
#include "bundle_system_state.h"
#include "bundle_resource_drawable.h"

namespace OHOS {
namespace AppExecFwk {
BundleResourceParser::BundleResourceParser()
{
}

BundleResourceParser::~BundleResourceParser()
{
}

bool BundleResourceParser::ParseResourceInfo(ResourceInfo &resourceInfo)
{
    return ParseResourceInfoWithSameHap(resourceInfo);
}

bool BundleResourceParser::ParseResourceInfos(std::vector<ResourceInfo> &resourceInfos)
{
    APP_LOGD("start");
    if (resourceInfos.empty()) {
        APP_LOGE("resourceInfos is empty");
        return false;
    }
    // same module need parse together
    std::map<std::string, std::shared_ptr<Global::Resource::ResourceManager>> resourceManagerMap;
    size_t size = resourceInfos.size();
    for (size_t index = 0; index < size; ++index) {
        if (!resourceInfos[index].iconNeedParse_ && !resourceInfos[index].labelNeedParse_) {
            APP_LOGI("%{public}s does not need parse",
                resourceInfos[index].bundleName_.c_str());
            continue;
        }

        auto resourceManager = resourceManagerMap[resourceInfos[index].moduleName_];
        if (resourceManager == nullptr) {
            std::unique_ptr<Global::Resource::ResConfig> resConfig(Global::Resource::CreateResConfig());
            if (resConfig == nullptr) {
                APP_LOGE("resConfig is nullptr");
                continue;
            }
            resourceManager =
                std::shared_ptr<Global::Resource::ResourceManager>(Global::Resource::CreateResourceManager(
                    resourceInfos[index].bundleName_, resourceInfos[index].moduleName_,
                    resourceInfos[index].hapPath_, resourceInfos[index].overlayHapPaths_, *resConfig));
            resourceManagerMap[resourceInfos[index].moduleName_] = resourceManager;
            if (!BundleResourceConfiguration::InitResourceGlobalConfig(
                resourceInfos[index].hapPath_, resourceInfos[index].overlayHapPaths_, resourceManager)) {
                APP_LOGW("InitResourceGlobalConfig failed, key:%{public}s", resourceInfos[index].GetKey().c_str());
            }
        }

        if (!ParseResourceInfoByResourceManager(resourceManager, resourceInfos[index])) {
            APP_LOGE("ParseResourceInfo failed, key:%{public}s", resourceInfos[index].GetKey().c_str());
            if (index > 0) {
                resourceInfos[index].label_ = resourceInfos[index].label_.empty() ? resourceInfos[0].label_ :
                    resourceInfos[index].label_;
                resourceInfos[index].icon_ = resourceInfos[index].icon_.empty() ? resourceInfos[0].icon_ :
                    resourceInfos[index].icon_;
            }
        }
    }
    if (resourceInfos[0].label_.empty() || resourceInfos[0].icon_.empty()) {
        APP_LOGE("bundleName:%{public}s moduleName:%{public}s prase resource failed",
            resourceInfos[0].bundleName_.c_str(), resourceInfos[0].moduleName_.c_str());
        return false;
    }
    APP_LOGD("end");
    return true;
}

bool BundleResourceParser::ParseResourceInfoWithSameHap(ResourceInfo &resourceInfo)
{
    if (resourceInfo.hapPath_.empty()) {
        APP_LOGE("resourceInfo.hapPath_ is empty");
        return false;
    }
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager(Global::Resource::CreateResourceManager());
    if (resourceManager == nullptr) {
        APP_LOGE("resourceManager is nullptr");
        return false;
    }
    if (!BundleResourceConfiguration::InitResourceGlobalConfig(resourceInfo.hapPath_, resourceManager)) {
        APP_LOGE("InitResourceGlobalConfig failed, key:%{public}s", resourceInfo.GetKey().c_str());
        return false;
    }
    if (!ParseResourceInfoByResourceManager(resourceManager, resourceInfo)) {
        APP_LOGE("ParseResourceInfo failed, key:%{public}s", resourceInfo.GetKey().c_str());
        return false;
    }
    return true;
}

bool BundleResourceParser::ParseLabelResourceByPath(
    const std::string &hapPath, const int32_t labelId, std::string &label)
{
    if (hapPath.empty()) {
        APP_LOGE("hapPath is empty");
        return false;
    }
    // allow label resource parse failed, then label is bundleName
    if (labelId <= 0) {
        APP_LOGW("labelId is 0");
        return true;
    }
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager(Global::Resource::CreateResourceManager());
    if (resourceManager == nullptr) {
        APP_LOGE("resourceManager is nullptr");
        return false;
    }
    if (!BundleResourceConfiguration::InitResourceGlobalConfig(hapPath, resourceManager)) {
        APP_LOGE("InitResourceGlobalConfig failed, key:%{private}s", hapPath.c_str());
        return false;
    }
    if (!ParseLabelResourceByResourceManager(resourceManager, labelId, label)) {
        APP_LOGE("ParseLabelResource failed, label: %{public}d", labelId);
        return false;
    }
    return true;
}

bool BundleResourceParser::ParseIconResourceByPath(const std::string &hapPath, const int32_t iconId, std::string &icon)
{
    if (hapPath.empty()) {
        APP_LOGE("hapPath is empty");
        return false;
    }
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager(Global::Resource::CreateResourceManager());
    if (resourceManager == nullptr) {
        APP_LOGE("resourceManager is nullptr");
        return false;
    }
    if (!BundleResourceConfiguration::InitResourceGlobalConfig(hapPath, resourceManager)) {
        APP_LOGE("InitResourceGlobalConfig failed, hapPath:%{private}s", hapPath.c_str());
        return false;
    }
    if (!ParseIconResourceByResourceManager(resourceManager, iconId, icon)) {
        APP_LOGE("failed, iconId: %{public}d", iconId);
        return false;
    }
    return true;
}

bool BundleResourceParser::ParseResourceInfoByResourceManager(
    const std::shared_ptr<Global::Resource::ResourceManager> resourceManager,
    ResourceInfo &resourceInfo)
{
    if (resourceManager == nullptr) {
        APP_LOGE("resourceManager is nullptr");
        return false;
    }
    bool ans = true;
    if (resourceInfo.labelNeedParse_ && !ParseLabelResourceByResourceManager(
        resourceManager, resourceInfo.labelId_, resourceInfo.label_)) {
        APP_LOGE("ParseLabelResource failed, key: %{public}s", resourceInfo.GetKey().c_str());
        ans = false;
    }

    if (resourceInfo.iconNeedParse_ && !ParseIconResourceByResourceManager(
        resourceManager, resourceInfo.iconId_, resourceInfo.icon_)) {
        APP_LOGE("ParseIconResource failed, key: %{public}s", resourceInfo.GetKey().c_str());
        ans = false;
    }

    return ans;
}

bool BundleResourceParser::ParseLabelResourceByResourceManager(
    const std::shared_ptr<Global::Resource::ResourceManager> resourceManager,
    const int32_t labelId, std::string &label)
{
    if (resourceManager == nullptr) {
        APP_LOGE("resourceManager is nullptr");
        return false;
    }
    if (labelId <= 0) {
        APP_LOGW("ParseLabelResource labelId is 0 or less than 0, label is bundleName");
        return false;
    }
    auto ret = resourceManager->GetStringById(static_cast<uint32_t>(labelId), label);
    if (ret != OHOS::Global::Resource::RState::SUCCESS) {
        APP_LOGE("GetStringById failed errcode: %{public}d, labelId: %{public}d",
            static_cast<int32_t>(ret), labelId);
        return false;
    }
    return true;
}

bool BundleResourceParser::ParseIconResourceByResourceManager(
    const std::shared_ptr<Global::Resource::ResourceManager> resourceManager,
    const int32_t iconId, std::string &icon)
{
    if (resourceManager == nullptr) {
        APP_LOGE("resourceManager is nullptr");
        return false;
    }
    if (iconId <= 0) {
        APP_LOGE("iconId is 0 or less than 0");
        return false;
    }
    // density 0
    BundleResourceDrawable drawable;
    if (!drawable.GetIconResourceByDrawable(iconId, 0, resourceManager, icon)) {
        APP_LOGE("parse layered-image failed iconId:%{public}d", iconId);
        return false;
    }
    return true;
}
} // AppExecFwk
} // OHOS