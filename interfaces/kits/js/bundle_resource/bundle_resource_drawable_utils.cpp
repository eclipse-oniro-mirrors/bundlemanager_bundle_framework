/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "bundle_resource_drawable_utils.h"

#ifdef BUNDLE_FRAMEWORK_GRAPHICS
#include "drawable_descriptor.h"
#include "js_drawable_descriptor.h"
#include "resource_manager.h"
#endif
#include "parameters.h"
namespace OHOS {
namespace AppExecFwk {
constexpr const char* DRAWABLE_ICON_SIZE = "const.bms.drawableIconSize";
constexpr int32_t DECODE_SIZE = 0;
#ifdef BUNDLE_FRAMEWORK_GRAPHICS
std::shared_ptr<Global::Resource::ResourceManager> BundleResourceDrawableUtils::resourceManager_ = nullptr;
std::mutex BundleResourceDrawableUtils::resMutex_;

void BundleResourceDrawableUtils::InitResourceManager()
{
    std::lock_guard<std::mutex> lock(resMutex_);
    if (resourceManager_ == nullptr) {
        std::unique_ptr<Global::Resource::ResConfig> resConfig(Global::Resource::CreateResConfig());
        if (resConfig == nullptr) {
            return;
        }
        resourceManager_ =
            std::shared_ptr<Global::Resource::ResourceManager>(Global::Resource::CreateResourceManager(
                "bundleName", "moduleName", "", std::vector<std::string>(), *resConfig));
    }
}
#endif

napi_value BundleResourceDrawableUtils::ConvertToDrawableDescriptor(napi_env env,
    const std::vector<uint8_t> &foreground, const std::vector<uint8_t> &background)
{
#ifdef BUNDLE_FRAMEWORK_GRAPHICS
    if (foreground.empty() && background.empty()) {
        return nullptr;
    }
    InitResourceManager();
    size_t lenForeground = foreground.size();
    std::unique_ptr<uint8_t[]> foregroundPtr = std::make_unique<uint8_t[]>(lenForeground);
    for (size_t index = 0; index < lenForeground; ++index) {
        foregroundPtr[index] = foreground[index];
    }
    int32_t decodeSize = OHOS::system::GetIntParameter(DRAWABLE_ICON_SIZE, DECODE_SIZE);
    if (background.empty()) {
        // base-icon
        std::unique_ptr<Ace::Napi::DrawableDescriptor> drawableDescriptor =
            std::make_unique<Ace::Napi::DrawableDescriptor>(std::move(foregroundPtr), lenForeground);
        drawableDescriptor->SetDecodeSize(decodeSize, decodeSize);
        return Ace::Napi::JsDrawableDescriptor::ToNapi(env, drawableDescriptor.release(),
            Ace::Napi::DrawableDescriptor::DrawableType::BASE);
    }
    // layered-icon
    size_t lenBackground = background.size();
    std::unique_ptr<uint8_t[]> backgroundPtr = std::make_unique<uint8_t[]>(lenBackground);
    for (size_t index = 0; index < lenBackground; ++index) {
        backgroundPtr[index] = background[index];
    }
    std::unique_ptr<uint8_t[]> jsonBuf;
    std::string themeMask = (resourceManager_ == nullptr) ? "" : resourceManager_->GetThemeMask();

    std::pair<std::unique_ptr<uint8_t[]>, size_t> foregroundPair;
    foregroundPair.first = std::move(foregroundPtr);
    foregroundPair.second = lenForeground;
    std::pair<std::unique_ptr<uint8_t[]>, size_t> backgroundPair;
    backgroundPair.first = std::move(backgroundPtr);
    backgroundPair.second = lenBackground;
    std::unique_ptr<Ace::Napi::DrawableDescriptor> drawableDescriptor =
        std::make_unique<Ace::Napi::LayeredDrawableDescriptor>(std::move(jsonBuf), 0, resourceManager_, themeMask, 1,
        foregroundPair, backgroundPair);
    drawableDescriptor->SetDecodeSize(decodeSize, decodeSize);
    return Ace::Napi::JsDrawableDescriptor::ToNapi(env, drawableDescriptor.release(),
        Ace::Napi::DrawableDescriptor::DrawableType::LAYERED);
#else
    return nullptr;
#endif
}
}
}
