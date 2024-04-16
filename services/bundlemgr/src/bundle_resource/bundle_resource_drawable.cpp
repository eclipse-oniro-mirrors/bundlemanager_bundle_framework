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

#ifdef BUNDLE_FRAMEWORK_GRAPHICS
#include "drawable_descriptor.h"
#endif

namespace OHOS {
namespace AppExecFwk {
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
    BundleResourceImageInfo info;
    OHOS::Ace::Napi::DrawableDescriptor::DrawableType drawableType;
    std::string themeMask = resourceManager->GetThemeMask();
    std::pair<std::unique_ptr<uint8_t[]>, size_t> foregroundInfo;
    std::pair<std::unique_ptr<uint8_t[]>, size_t> backgroundInfo;
    Global::Resource::RState state = resourceManager->GetThemeIcons(iconId, foregroundInfo, backgroundInfo, density);
    if (state == Global::Resource::SUCCESS) {
        LOG_D(BMS_TAG_DEFAULT, "bundleName:%{public}s find theme resource", resourceInfo.bundleName_.c_str());
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
        auto drawableDescriptor = Ace::Napi::DrawableDescriptorFactory::Create(foregroundInfo, backgroundInfo,
            themeMask, drawableType, resourceManager);
        if (drawableDescriptor != nullptr) {
            return info.ConvertToString(drawableDescriptor->GetPixelMap(), resourceInfo.icon_);
        }
        LOG_W(BMS_TAG_DEFAULT, "bundleName:%{public}s drawableDescriptor is nullptr, need create again",
            resourceInfo.bundleName_.c_str());
    }
    auto drawableDescriptor = Ace::Napi::DrawableDescriptorFactory::Create(
        iconId, resourceManager, state, drawableType, 0);
    if ((drawableDescriptor == nullptr) || (state != Global::Resource::SUCCESS)) {
        LOG_E(BMS_TAG_DEFAULT, "bundleName:%{public}s drawableDescriptor is nullptr",
            resourceInfo.bundleName_.c_str());
        return false;
    }
    return info.ConvertToString(drawableDescriptor->GetPixelMap(), resourceInfo.icon_);
#else
    return false;
#endif
}
} // AppExecFwk
} // OHOS
