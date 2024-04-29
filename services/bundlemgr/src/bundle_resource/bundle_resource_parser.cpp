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

#include <cstdlib>
#include "nlohmann/json.hpp"

#include "app_log_wrapper.h"
#include "bundle_resource_configuration.h"
#include "bundle_system_state.h"
#include "bundle_resource_drawable.h"
#include "json_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* TYPE_JSON = "json";
const char* FOREGROUND = "foreground";
const char* BACKGROUND = "background";
const char CHAR_COLON = ':';
const char* LAYERED_IMAGE = "layered-image";

struct LayeredImage {
    std::string foreground;
    std::string background;
};

void from_json(const nlohmann::json &jsonObject, LayeredImage &layeredImage)
{
    int32_t parseResult = 0;
    const auto &jsonObjectEnd = jsonObject.end();
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, FOREGROUND, layeredImage.foreground,
        JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);

    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, BACKGROUND, layeredImage.background,
        JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
}
}

BundleResourceParser::BundleResourceParser()
{
}

BundleResourceParser::~BundleResourceParser()
{
}

bool BundleResourceParser::ParseResourceInfo(const int32_t userId, ResourceInfo &resourceInfo)
{
    return ParseResourceInfoWithSameHap(userId, resourceInfo);
}

bool BundleResourceParser::ParseResourceInfos(const int32_t userId, std::vector<ResourceInfo> &resourceInfos)
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
            APP_LOGI("%{public}s does not need parse", resourceInfos[index].bundleName_.c_str());
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
                    resourceInfos[index].hapPath_, resourceInfos[index].overlayHapPaths_, *resConfig, 0, userId));
            resourceManagerMap[resourceInfos[index].moduleName_] = resourceManager;
            if (!BundleResourceConfiguration::InitResourceGlobalConfig(
                resourceInfos[index].hapPath_, resourceInfos[index].overlayHapPaths_, resourceManager)) {
                APP_LOGW("InitResourceGlobalConfig failed, key:%{public}s", resourceInfos[index].GetKey().c_str());
            }
        }

        if (!ParseResourceInfoByResourceManager(resourceManager, resourceInfos[index])) {
            APP_LOGE("ParseResourceInfo failed, key:%{public}s", resourceInfos[index].GetKey().c_str());
            if (index > 0) {
                ProcessResourceInfoWhenParseFailed(resourceInfos[0], resourceInfos[index]);
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

bool BundleResourceParser::ParseResourceInfoWithSameHap(const int32_t userId, ResourceInfo &resourceInfo)
{
    if (resourceInfo.hapPath_.empty()) {
        APP_LOGE("resourceInfo.hapPath_ is empty");
        return false;
    }
    std::unique_ptr<Global::Resource::ResConfig> resConfig(Global::Resource::CreateResConfig());
    if (resConfig == nullptr) {
        APP_LOGE("resConfig is nullptr");
        return false;
    }
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager =
        std::shared_ptr<Global::Resource::ResourceManager>(Global::Resource::CreateResourceManager(
            resourceInfo.bundleName_, resourceInfo.moduleName_,
            resourceInfo.hapPath_, resourceInfo.overlayHapPaths_, *resConfig, 0, userId));
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

bool BundleResourceParser::ParseIconResourceByPath(const std::string &hapPath, const int32_t iconId,
    ResourceInfo &resourceInfo)
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
    resourceInfo.iconId_ = iconId;
    if (!ParseIconResourceByResourceManager(resourceManager, resourceInfo)) {
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

    if (resourceInfo.iconNeedParse_ && !ParseIconResourceByResourceManager(resourceManager, resourceInfo)) {
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
    ResourceInfo &resourceInfo)
{
    if (resourceManager == nullptr) {
        APP_LOGE("resourceManager is nullptr");
        return false;
    }
    if (resourceInfo.iconId_ <= 0) {
        APP_LOGE("iconId is 0 or less than 0");
        return false;
    }
    // density 0
    BundleResourceDrawable drawable;
    if (!drawable.GetIconResourceByDrawable(resourceInfo.iconId_, 0, resourceManager, resourceInfo)) {
        APP_LOGE("key:%{public}s parse image failed iconId:%{public}d, ", resourceInfo.GetKey().c_str(),
            resourceInfo.iconId_);
        return false;
    }
    if (!resourceInfo.foreground_.empty() && !resourceInfo.background_.empty()) {
        return true;
    }
    // parse json
    std::string type;
    size_t len;
    std::unique_ptr<uint8_t[]> jsonBuf;
    Global::Resource::RState state = resourceManager->GetDrawableInfoById(resourceInfo.iconId_, type, len, jsonBuf, 0);
    if (state != Global::Resource::SUCCESS) {
        APP_LOGE("bundleName:%{public}s Failed to get drawable id:%{public}d", resourceInfo.bundleName_.c_str(),
            resourceInfo.iconId_);
        return false;
    }
    transform(type.begin(), type.end(), type.begin(), ::tolower);
    if (type == TYPE_JSON) {
        // first parse theme resource, if theme not exist, then parse normal resource
        if (ParseThemeIcon(resourceManager, 0, resourceInfo)) {
            return true;
        }
        return ParseForegroundAndBackgroundResource(resourceManager,
            std::string(reinterpret_cast<char*>(jsonBuf.get()), len), 0, resourceInfo);
    } else {
        resourceInfo.foreground_.resize(len);
        for (size_t index = 0; index < len; ++index) {
            resourceInfo.foreground_[index] = jsonBuf[index];
        }
    }
    return true;
}

bool BundleResourceParser::ParseIconIdFromJson(
    const std::string &jsonBuff, uint32_t &foregroundId, uint32_t &backgroundId)
{
    nlohmann::json jsonObject = nlohmann::json::parse(jsonBuff, nullptr, false);
    if (jsonObject.is_discarded()) {
        APP_LOGE("failed to parse jsonBuff: %{public}s.", jsonBuff.c_str());
        return false;
    }
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = 0;
    LayeredImage layerImage;
    GetValueIfFindKey<LayeredImage>(jsonObject, jsonObjectEnd, LAYERED_IMAGE, layerImage,
        JsonType::OBJECT, false, parseResult, ArrayType::NOT_ARRAY);

    if (layerImage.foreground.empty() && layerImage.background.empty()) {
        APP_LOGE("foreground and background are empty, buffer is %{public}s", jsonBuff.c_str());
        return false;
    }
    auto pos = layerImage.foreground.find(CHAR_COLON);
    if (pos != std::string::npos) {
        int32_t foregroundLength = static_cast<int32_t>(layerImage.foreground.length());
        foregroundId = atoi(layerImage.foreground.substr(pos + 1, foregroundLength - pos - 1).c_str());
    }
    pos = layerImage.background.find(CHAR_COLON);
    if (pos != std::string::npos) {
        int32_t backgroundLength = static_cast<int32_t>(layerImage.background.length());
        backgroundId = atoi(layerImage.background.substr(pos + 1,
            backgroundLength - pos - 1).c_str());
    }
    APP_LOGD("succeed, foregroundId:%{public}u, backgroundId:%{public}u", foregroundId, backgroundId);
    return true;
}

bool BundleResourceParser::GetMediaDataById(
    const std::shared_ptr<Global::Resource::ResourceManager> resourceManager,
    const uint32_t iconId, const int32_t density, std::vector<uint8_t> &data)
{
    if (resourceManager == nullptr) {
        APP_LOGE("resourceManager is nullptr");
        return false;
    }
    std::string type;
    size_t len;
    std::unique_ptr<uint8_t[]> jsonBuf;
    Global::Resource::RState state = resourceManager->GetDrawableInfoById(iconId, type, len, jsonBuf, density);
    if (state != Global::Resource::SUCCESS) {
        APP_LOGE("Failed to get drawable info from resourceManager, iconId:%{public}u", iconId);
        return false;
    }
    data.resize(len);
    for (size_t index = 0; index < len; ++index) {
        data[index] = jsonBuf[index];
    }
    return true;
}

bool BundleResourceParser::ParseForegroundAndBackgroundResource(
    const std::shared_ptr<Global::Resource::ResourceManager> resourceManager,
    const std::string &jsonBuff,
    const int32_t density,
    ResourceInfo &resourceInfo)
{
    APP_LOGD("start");
    if (resourceManager == nullptr) {
        APP_LOGE("resourceManager is nullptr");
        return false;
    }
    uint32_t foregroundId = 0;
    uint32_t backgroundId = 0;
    if (!ParseIconIdFromJson(jsonBuff, foregroundId, backgroundId)) {
        APP_LOGE("parse from json failed, iconId:%{public}d,buffer:%{public}s", resourceInfo.iconId_, jsonBuff.c_str());
        return false;
    }
    // parse foreground
    bool ans = true;
    if (!GetMediaDataById(resourceManager, foregroundId, density, resourceInfo.foreground_)) {
        APP_LOGE("parse foreground failed iconId: %{public}u", foregroundId);
        ans = false;
    }
    // parse background
    if (!GetMediaDataById(resourceManager, backgroundId, density, resourceInfo.background_)) {
        APP_LOGE("parse background failed iconId:%{public}u", backgroundId);
        ans = false;
    }
    APP_LOGD("foreground size:%{public}zu background size:%{public}zu",
        resourceInfo.foreground_.size(), resourceInfo.background_.size());
    return ans;
}

bool BundleResourceParser::ParseThemeIcon(const std::shared_ptr<Global::Resource::ResourceManager> resourceManager,
    const int32_t density,
    ResourceInfo &resourceInfo)
{
    if (resourceManager == nullptr) {
        APP_LOGE("resourceManager is nullptr");
        return false;
    }
    std::pair<std::unique_ptr<uint8_t[]>, size_t> foregroundInfo;
    std::pair<std::unique_ptr<uint8_t[]>, size_t> backgroundInfo;
    Global::Resource::RState state = resourceManager->GetThemeIcons(resourceInfo.iconId_,
        foregroundInfo, backgroundInfo, 0);
    if (state == Global::Resource::SUCCESS) {
        resourceInfo.foreground_.resize(foregroundInfo.second);
        for (size_t index = 0; index < foregroundInfo.second; ++index) {
            resourceInfo.foreground_[index] = foregroundInfo.first[index];
        }
        resourceInfo.background_.resize(backgroundInfo.second);
        for (size_t index = 0; index < backgroundInfo.second; ++index) {
            resourceInfo.background_[index] = backgroundInfo.first[index];
        }
        return true;
    }
    APP_LOGD("bundleName:%{public}s theme is not exist", resourceInfo.bundleName_.c_str());
    return false;
}

void BundleResourceParser::ProcessResourceInfoWhenParseFailed(
    const ResourceInfo &oldResourceInfo, ResourceInfo &newResourceInfo)
{
    newResourceInfo.label_ = newResourceInfo.label_.empty() ? oldResourceInfo.label_ : newResourceInfo.label_;
    newResourceInfo.icon_ = newResourceInfo.icon_.empty() ? oldResourceInfo.icon_ :newResourceInfo.icon_;

    newResourceInfo.foreground_ = newResourceInfo.foreground_.empty() ? oldResourceInfo.foreground_ :
        newResourceInfo.foreground_;
    newResourceInfo.background_ = newResourceInfo.background_.empty() ? oldResourceInfo.background_ :
        newResourceInfo.background_;
}
} // AppExecFwk
} // OHOS