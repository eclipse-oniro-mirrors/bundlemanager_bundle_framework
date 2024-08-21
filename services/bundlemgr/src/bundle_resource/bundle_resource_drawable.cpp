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

#include "bundle_resource_drawable.h"

#include "app_log_tag_wrapper.h"
#include "bundle_resource_image_info.h"
#include "parameter.h"

#ifdef BUNDLE_FRAMEWORK_GRAPHICS
#include "drawable_descriptor.h"
#endif

namespace OHOS {
namespace AppExecFwk {
namespace {
// bundle name
constexpr const char* COM_OHOS_CONTACTS = "com.ohos.contacts";
constexpr const char* IS_SUPPORT_TELEPHONY_VOICE = "const.telephony.voice.capable";
constexpr int8_t THRESHOLD_VAL_LEN = 10;

bool IsSupportTelephonyVoice()
{
    char retValue[THRESHOLD_VAL_LEN] = {"true"};
    int32_t ret = GetParameter(IS_SUPPORT_TELEPHONY_VOICE, "true", retValue, THRESHOLD_VAL_LEN);
    if (ret <= 0) {
        LOG_W(BMS_TAG_DEFAULT, "GetParameter const.telephony.voice.capable failed");
        return true;
    }
    if (std::strcmp(retValue, "false") == 0) {
        return false;
    }
    return true;
}
}

bool BundleResourceDrawable::GetIconResourceByDrawable(
    const uint32_t iconId,
    const int32_t density,
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager,
    ResourceInfo &resourceInfo)
{
#ifdef BUNDLE_FRAMEWORK_GRAPHICS
    if (resourceManager == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "resourceManager is nullptr");
        return false;
    }
    if ((resourceInfo.GetKey() == COM_OHOS_CONTACTS) && IsSupportTelephonyVoice()) {
        // contacts app.json use hap resource
        LOG_I(BMS_TAG_DEFAULT, "bundleName:%{public}s parse no theme icon", resourceInfo.bundleName_.c_str());
        return GetIconResourceByDrawableNoTheme(iconId, density, resourceManager, resourceInfo);
    }
    BundleResourceImageInfo info;
    OHOS::Ace::Napi::DrawableDescriptor::DrawableType drawableType;
    std::string themeMask = resourceManager->GetThemeMask();
    std::pair<std::unique_ptr<uint8_t[]>, size_t> foregroundInfo;
    std::pair<std::unique_ptr<uint8_t[]>, size_t> backgroundInfo;
    Global::Resource::RState state = resourceManager->GetThemeIcons(iconId, foregroundInfo, backgroundInfo, density,
        resourceInfo.abilityName_);
    if (state == Global::Resource::SUCCESS) {
        LOG_I(BMS_TAG_DEFAULT, "bundleName:%{public}s find theme resource", resourceInfo.bundleName_.c_str());
        auto drawableDescriptor = Ace::Napi::DrawableDescriptorFactory::Create(foregroundInfo, backgroundInfo,
            themeMask, drawableType, resourceManager);
        if ((drawableDescriptor != nullptr) && (drawableDescriptor->GetPixelMap() != nullptr)) {
            // init foreground
            resourceInfo.foreground_.resize(foregroundInfo.second);
            for (size_t index = 0; index < foregroundInfo.second; ++index) {
                resourceInfo.foreground_[index] = foregroundInfo.first[index];
            }
            // init background
            resourceInfo.background_.resize(backgroundInfo.second);
            for (size_t index = 0; index < backgroundInfo.second; ++index) {
                resourceInfo.background_[index] = backgroundInfo.first[index];
            }
            return info.ConvertToString(drawableDescriptor->GetPixelMap(), resourceInfo.icon_);
        }
        LOG_W(BMS_TAG_DEFAULT, "bundleName:%{public}s drawableDescriptor or pixelMap is nullptr, need create again",
            resourceInfo.bundleName_.c_str());
    }
    auto drawableDescriptor = Ace::Napi::DrawableDescriptorFactory::Create(
        iconId, resourceManager, state, drawableType, 0);
    if ((drawableDescriptor == nullptr) || (state != Global::Resource::SUCCESS)) {
        LOG_E(BMS_TAG_DEFAULT, "bundleName:%{public}s drawableDescriptor is nullptr, errCode:%{public}d",
            resourceInfo.bundleName_.c_str(), static_cast<int32_t>(state));
        return false;
    }
    return info.ConvertToString(drawableDescriptor->GetPixelMap(), resourceInfo.icon_);
#else
    return false;
#endif
}

bool BundleResourceDrawable::GetIconResourceByDrawableNoTheme(
    const uint32_t iconId,
    const int32_t density,
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager,
    ResourceInfo &resourceInfo)
{
#ifdef BUNDLE_FRAMEWORK_GRAPHICS
    if (resourceManager == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "resourceManager is nullptr");
        return false;
    }
    BundleResourceImageInfo info;
    OHOS::Ace::Napi::DrawableDescriptor::DrawableType drawableType;
    Global::Resource::RState state = Global::Resource::SUCCESS;
    auto drawableDescriptor = Ace::Napi::DrawableDescriptorFactory::Create(
        iconId, resourceManager, state, drawableType, density);
    if ((drawableDescriptor == nullptr) || (state != Global::Resource::SUCCESS)) {
        LOG_E(BMS_TAG_DEFAULT, "bundleName:%{public}s drawableDescriptor is nullptr, errCode:%{public}d",
            resourceInfo.bundleName_.c_str(), static_cast<int32_t>(state));
        return false;
    }
    return info.ConvertToString(drawableDescriptor->GetPixelMap(), resourceInfo.icon_);
#else
    return false;
#endif
}

#ifdef BUNDLE_FRAMEWORK_GRAPHICS
bool BundleResourceDrawable::GetBadgedIconResource(
    const std::shared_ptr<Media::PixelMap> layeredPixelMap,
    const std::shared_ptr<Media::PixelMap> badgedPixelMap,
    ResourceInfo &resourceInfo)
{
    if ((layeredPixelMap == nullptr) || (badgedPixelMap == nullptr)) {
        LOG_E(BMS_TAG_DEFAULT, "bundleName:%{public}s layered or badge pixelMap are nullptr",
            resourceInfo.bundleName_.c_str());
        return false;
    }
    Ace::Napi::LayeredDrawableDescriptor layeredDrawableDescriptor;
    std::shared_ptr<Media::PixelMap> compositePixelMap;
    if (!layeredDrawableDescriptor.GetCompositePixelMapWithBadge(layeredPixelMap, badgedPixelMap, compositePixelMap)) {
        LOG_E(BMS_TAG_DEFAULT, "bundleName:%{public}s GetCompositePixelMapWithBadge failed",
            resourceInfo.bundleName_.c_str());
        return false;
    }
    if (compositePixelMap == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "bundleName:%{public}s compositePixelMap is nullptr",
            resourceInfo.bundleName_.c_str());
        return false;
    }
    BundleResourceImageInfo info;
    return info.ConvertToString(compositePixelMap, resourceInfo.icon_);
}
#endif
} // AppExecFwk
} // OHOS
