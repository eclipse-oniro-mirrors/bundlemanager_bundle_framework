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

#include "bundle_resource_configuration.h"
#include "bundle_resource_image_info.h"
#include "bundle_resource_drawable.h"
#include "bundle_service_constants.h"
#include "json_util.h"

#ifdef BUNDLE_FRAMEWORK_GRAPHICS
#include "image_source.h"
#include "pixel_map.h"
#endif

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* TYPE_JSON = "json";
constexpr const char* TYPE_PNG = "png";
constexpr const char* FOREGROUND = "foreground";
constexpr const char* BACKGROUND = "background";
constexpr char CHAR_COLON = ':';
#ifdef BUNDLE_FRAMEWORK_GRAPHICS
constexpr const char* OHOS_CLONE_APP_BADGE_RESOURCE = "clone_app_badge_";
constexpr int8_t BADGE_SIZE = 62;
#endif

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

#ifdef BUNDLE_FRAMEWORK_GRAPHICS
bool GetBadgeResource(const std::string &resourceName, std::shared_ptr<Media::PixelMap> &badgePixelMap)
{
    std::shared_ptr<Global::Resource::ResourceManager> resMgr(Global::Resource::CreateResourceManager());
    if (resMgr == nullptr) {
        APP_LOGE("resMgr is nullptr");
        return false;
    }
    std::unique_ptr<Global::Resource::ResConfig> resConfig(Global::Resource::CreateResConfig());
    if (resConfig == nullptr) {
        APP_LOGE("resConfig is nullptr");
        return false;
    }
    resMgr->UpdateResConfig(*resConfig);

    std::unique_ptr<uint8_t[]> badgeResourceData;
    size_t badgeResourceDataLength = 0;
    auto ret = resMgr->GetMediaDataByName(resourceName.c_str(), badgeResourceDataLength, badgeResourceData);
    if (ret != Global::Resource::RState::SUCCESS) {
        APP_LOGE("get (%{public}s) failed, errorCode:%{public}d", resourceName.c_str(), static_cast<int32_t>(ret));
        return false;
    }

    Media::SourceOptions opts;
    uint32_t errorCode = 0;
    std::unique_ptr<Media::ImageSource> imageSource =
        Media::ImageSource::CreateImageSource(badgeResourceData.get(), badgeResourceDataLength, opts, errorCode);
    Media::DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = Media::PixelFormat::BGRA_8888;
    decodeOpts.desiredSize.width = BADGE_SIZE;
    decodeOpts.desiredSize.height = BADGE_SIZE;
    if (imageSource) {
        auto pixelMapPtr = imageSource->CreatePixelMap(decodeOpts, errorCode);
        badgePixelMap = std::shared_ptr<Media::PixelMap>(pixelMapPtr.release());
    }
    if (errorCode != 0 || (badgePixelMap == nullptr)) {
        APP_LOGE("get badge failed, errorCode:%{public}u", errorCode);
        return false;
    }
    return true;
}
#endif
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
            APP_LOGI("%{public}s no need parse", resourceInfos[index].bundleName_.c_str());
            continue;
        }
        if ((index > 0) && !IsNeedToParseResourceInfo(resourceInfos[index], resourceInfos[0])) {
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
                resourceInfos[index].hapPath_, resourceInfos[index].overlayHapPaths_, resourceManager,
                resourceInfos[index].iconNeedParse_, resourceInfos[index].labelNeedParse_)) {
                APP_LOGW("InitResourceGlobalConfig failed, key:%{public}s", resourceInfos[index].GetKey().c_str());
            }
        }

        if (!ParseResourceInfoByResourceManager(resourceManager, resourceInfos[index])) {
            APP_LOGW_NOFUNC("ParseResourceInfo fail key:%{public}s", resourceInfos[index].GetKey().c_str());
        }
    }
    if ((resourceInfos[0].labelNeedParse_ && resourceInfos[0].label_.empty()) ||
        (resourceInfos[0].iconNeedParse_ && resourceInfos[0].icon_.empty())) {
        APP_LOGE_NOFUNC("ParseResourceInfos fail -n %{public}s -m %{public}s",
            resourceInfos[0].bundleName_.c_str(), resourceInfos[0].moduleName_.c_str());
        return false;
    }
    APP_LOGD("end");
    return true;
}

bool BundleResourceParser::IsNeedToParseResourceInfo(
    const ResourceInfo &newResourceInfo, const ResourceInfo &oldResourceInfo)
{
    if (ServiceConstants::ALLOW_MULTI_ICON_BUNDLE.find(newResourceInfo.bundleName_) !=
        ServiceConstants::ALLOW_MULTI_ICON_BUNDLE.end()) {
        return true;
    }
    // same labelId and iconId no need to parse again
    if (newResourceInfo.moduleName_ == oldResourceInfo.moduleName_) {
        if ((newResourceInfo.labelId_ == oldResourceInfo.labelId_) &&
            (newResourceInfo.iconId_ == oldResourceInfo.iconId_)) {
            return false;
        }
    }
    if ((newResourceInfo.labelId_ <= 0) && (newResourceInfo.iconId_ <= 0)) {
        // no need to process icon and label
        APP_LOGW("key:%{public}s label and icon both equal 0", newResourceInfo.GetKey().c_str());
        return false;
    }
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
        APP_LOGE_NOFUNC("ParseResourceInfo fail key:%{public}s", resourceInfo.GetKey().c_str());
        return false;
    }
    return true;
}

bool BundleResourceParser::ParseLabelResourceByPath(
    const std::string &hapPath, const uint32_t labelId, std::string &label)
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
        APP_LOGE("ParseLabelResource fail label %{public}d", labelId);
        return false;
    }
    return true;
}

bool BundleResourceParser::ParseIconResourceByPath(const std::string &hapPath, const uint32_t iconId,
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
        APP_LOGE("failed, iconId %{public}d", iconId);
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
        APP_LOGE_NOFUNC("ParseLabelResource fail key %{public}s", resourceInfo.GetKey().c_str());
        ans = false;
    }

    if (resourceInfo.iconNeedParse_ && !ParseIconResourceByResourceManager(resourceManager, resourceInfo)) {
        APP_LOGE_NOFUNC("ParseIconResource fail key %{public}s", resourceInfo.GetKey().c_str());
        ans = false;
    }

    return ans;
}

bool BundleResourceParser::ParseLabelResourceByResourceManager(
    const std::shared_ptr<Global::Resource::ResourceManager> resourceManager,
    const uint32_t labelId, std::string &label)
{
    if (resourceManager == nullptr) {
        APP_LOGE("resourceManager is nullptr");
        return false;
    }
    if (labelId <= 0) {
        APP_LOGW_NOFUNC("ParseLabelResource labelId invalid label is bundleName");
        return false;
    }
    auto ret = resourceManager->GetStringById(labelId, label);
    if (ret != OHOS::Global::Resource::RState::SUCCESS) {
        APP_LOGE("GetStringById failed %{public}d, labelId %{public}d",
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
        APP_LOGE_NOFUNC("iconId is 0 or less than 0");
        return false;
    }
    // parse json
    std::string type;
    size_t len;
    std::unique_ptr<uint8_t[]> jsonBuf;
    Global::Resource::RState state = resourceManager->GetDrawableInfoById(resourceInfo.iconId_, type, len, jsonBuf, 0);
    if (state != Global::Resource::SUCCESS) {
        APP_LOGE("%{public}s failed to get id:%{public}d", resourceInfo.bundleName_.c_str(),
            resourceInfo.iconId_);
        return false;
    }
    transform(type.begin(), type.end(), type.begin(), ::tolower);
    if (type == TYPE_PNG) {
        resourceInfo.foreground_.resize(len);
        for (size_t index = 0; index < len; ++index) {
            resourceInfo.foreground_[index] = jsonBuf[index];
        }
        BundleResourceImageInfo bundleResourceImageInfo;
        // encode base64
        return bundleResourceImageInfo.ConvertToBase64(std::move(jsonBuf), len, resourceInfo.icon_);
    }
    APP_LOGI_NOFUNC("%{public}s icon is not png, parse by drawable descriptor", resourceInfo.GetKey().c_str());
    // density 0
    BundleResourceDrawable drawable;
    if (!drawable.GetIconResourceByDrawable(resourceInfo.iconId_, 0, resourceManager, resourceInfo)) {
        APP_LOGE("key:%{public}s parse failed iconId:%{public}d", resourceInfo.GetKey().c_str(), resourceInfo.iconId_);
        return false;
    }
    if (!resourceInfo.foreground_.empty()) {
        return true;
    }

    if (type == TYPE_JSON) {
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
        APP_LOGE("failed to parse jsonBuff %{public}s", jsonBuff.c_str());
        return false;
    }
    const auto &jsonObjectStart = jsonObject.begin();
    if ((jsonObjectStart == jsonObject.end()) || !jsonObjectStart.value().is_object()) {
        APP_LOGE("not object, failed to parse jsonBuff %{public}s", jsonBuff.c_str());
        return false;
    }
    LayeredImage layerImage = jsonObjectStart.value().get<LayeredImage>();
    if (layerImage.foreground.empty() && layerImage.background.empty()) {
        APP_LOGE("foreground background empty, buffer %{public}s", jsonBuff.c_str());
        return false;
    }
    auto pos = layerImage.foreground.find(CHAR_COLON);
    if (pos != std::string::npos) {
        int32_t foregroundLength = static_cast<int32_t>(layerImage.foreground.length());
        foregroundId = static_cast<uint32_t>(
            atoi(layerImage.foreground.substr(pos + 1, foregroundLength - pos - 1).c_str()));
    }
    pos = layerImage.background.find(CHAR_COLON);
    if (pos != std::string::npos) {
        int32_t backgroundLength = static_cast<int32_t>(layerImage.background.length());
        backgroundId = static_cast<uint32_t>(atoi(layerImage.background.substr(pos + 1,
            backgroundLength - pos - 1).c_str()));
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
        APP_LOGE("Failed get drawable info, iconId %{public}u", iconId);
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
    APP_LOGI_NOFUNC("key:%{public}s start parse layered-image", resourceInfo.GetKey().c_str());
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
        APP_LOGE("parse foreground failed iconId %{public}u", foregroundId);
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

bool BundleResourceParser::ParserCloneResourceInfo(
    const int32_t appIndex, std::vector<ResourceInfo> &resourceInfos)
{
#ifdef BUNDLE_FRAMEWORK_GRAPHICS
    // 1. get badge resource media
    std::string resourceName = OHOS_CLONE_APP_BADGE_RESOURCE + std::to_string(appIndex);
    APP_LOGI("parse clone info appIndex:%{public}d resourceName:%{public}s start", appIndex, resourceName.c_str());
    std::shared_ptr<Media::PixelMap> badgePixelMap;
    if (!GetBadgeResource(resourceName, badgePixelMap) || (badgePixelMap == nullptr)) {
        APP_LOGE("resourceName:%{public}s get failed", resourceName.c_str());
        return false;
    }
    bool ans = true;
    // 2. base64 to pixelMap
    for (auto &resourceInfo : resourceInfos) {
        uint32_t errorCode = 0;
        Media::SourceOptions opts;
        std::unique_ptr<Media::ImageSource> imageSource =
            Media::ImageSource::CreateImageSource(resourceInfo.icon_, opts, errorCode); // base64 to image
        Media::DecodeOptions decodeOpts;
        decodeOpts.desiredPixelFormat = Media::PixelFormat::BGRA_8888;
        std::shared_ptr<Media::PixelMap> baseIconResource;
        if (imageSource) {
            auto pixelMapPtr = imageSource->CreatePixelMap(decodeOpts, errorCode);
            baseIconResource = std::shared_ptr<Media::PixelMap>(pixelMapPtr.release());
        }
        if ((errorCode != 0) || (baseIconResource == nullptr)) {
            APP_LOGW("get base icon resource failed, key:%{public}s", resourceInfo.GetKey().c_str());
            ans = false;
            continue;
        }
        // base icon and badge icon resource
        BundleResourceDrawable drawable;
        if (!drawable.GetBadgedIconResource(baseIconResource, badgePixelMap, resourceInfo)) {
            APP_LOGE("get badge failed, key:%{public}s", resourceInfo.GetKey().c_str());
            ans = false;
        }
    }
    APP_LOGI("parse clone resource info appIndex:%{public}d end", appIndex);
    return ans;
#else
    APP_LOGI("not support pixel map");
    return false;
#endif
}
} // AppExecFwk
} // OHOS