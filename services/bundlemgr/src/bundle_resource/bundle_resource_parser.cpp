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
    if (resourceInfo.defaultIconHapPath_.empty()) {
        return ParseResourceInfoWithSameHap(resourceInfo);
    }
    return ParseResourceInfoWithDifferentHap(resourceInfo);
}

bool BundleResourceParser::ParseResourceInfos(std::vector<ResourceInfo> &resourceInfos)
{
    if (resourceInfos.empty()) {
        APP_LOGE("resourceInfos is empty");
        return false;
    }
    for (auto &info : resourceInfos) {
        if (!ParseResourceInfo(info)) {
            APP_LOGE("ParseResource failed, key: %{public}s", info.GetKey().c_str());
            return false;
        }
    }
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

bool BundleResourceParser::ParseResourceInfoWithDifferentHap(ResourceInfo &resourceInfo)
{
    if (!ParseLabelResourceByPath(resourceInfo.hapPath_, resourceInfo.labelId_, resourceInfo.label_)) {
        APP_LOGE("bundleName: %{public}s ParseLabelResource failed", resourceInfo.bundleName_.c_str());
        return false;
    }
    if (!ParseIconResourceByPath(resourceInfo.defaultIconHapPath_, resourceInfo.iconId_, resourceInfo.icon_)) {
        APP_LOGE("bundleName: %{public}s ParseIconResource failed", resourceInfo.bundleName_.c_str());
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

    if (!ParseLabelResourceByResourceManager(resourceManager, resourceInfo.labelId_, resourceInfo.label_)) {
        APP_LOGE("ParseLabelResource failed, key: %{public}s", resourceInfo.GetKey().c_str());
        return false;
    }

    if (!ParseIconResourceByResourceManager(resourceManager, resourceInfo.iconId_, resourceInfo.icon_)) {
        APP_LOGE("ParseIconResource failed, key: %{public}s", resourceInfo.GetKey().c_str());
        return false;
    }

    return true;
}

bool BundleResourceParser::ParseLabelResourceByResourceManager(
    const std::shared_ptr<Global::Resource::ResourceManager> resourceManager,
    const int32_t labelId, std::string &label)
{
    if (resourceManager == nullptr) {
        APP_LOGE("resourceManager is nullptr");
        return false;
    }
    if (labelId == 0) {
        APP_LOGD("ParseLabelResource labelId is 0, label is bundleName");
        return true;
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
    if (iconId == 0) {
        APP_LOGE("iconId is 0");
        return false;
    }
    // density 0
    auto ret = resourceManager->GetMediaBase64DataById(static_cast<uint32_t>(iconId), icon, 0);
    if (ret != OHOS::Global::Resource::RState::SUCCESS) {
        APP_LOGE("GetMediaBase64DataById failed errcode: %{public}d, iconId:%{public}d",
            static_cast<int32_t>(ret), iconId);
        return false;
    }
    return true;
}
} // AppExecFwk
} // OHOS