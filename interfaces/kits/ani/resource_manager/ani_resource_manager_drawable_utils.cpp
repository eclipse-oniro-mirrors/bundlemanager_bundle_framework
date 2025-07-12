/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "ani_resource_manager_drawable_utils.h"

#ifdef BUNDLE_FRAMEWORK_GRAPHICS
#include "app_log_wrapper.h"
#include "drawable_descriptor_ani.h"
#include "resource_manager.h"
#endif
namespace OHOS {
namespace AppExecFwk {
#ifdef BUNDLE_FRAMEWORK_GRAPHICS
std::shared_ptr<Global::Resource::ResourceManager> AniResourceManagerDrawableUtils::resourceManager_ = nullptr;
std::mutex AniResourceManagerDrawableUtils::resMutex_;

void AniResourceManagerDrawableUtils::InitResourceManager()
{
    std::lock_guard<std::mutex> lock(resMutex_);
    if (resourceManager_ == nullptr) {
        std::unique_ptr<Global::Resource::ResConfig> resConfig(Global::Resource::CreateResConfig());
        if (resConfig == nullptr) {
            APP_LOGE("resConfig is nullptr");
            return;
        }
        resourceManager_ =
            std::shared_ptr<Global::Resource::ResourceManager>(Global::Resource::CreateResourceManager(
                "bundleName", "moduleName", "", std::vector<std::string>(), *resConfig));
    }
}
#endif

ani_object AniResourceManagerDrawableUtils::ConvertDrawableDescriptor(ani_env* env,
    const std::vector<uint8_t> &foreground, const std::vector<uint8_t> &background)
{
#ifdef BUNDLE_FRAMEWORK_GRAPHICS
    if (foreground.empty() && background.empty()) {
        APP_LOGE("foreground and background empty");
        return nullptr;
    }
    InitResourceManager();
    if (resourceManager_ == nullptr) {
        APP_LOGE("resourceManager_ is nullptr");
        return nullptr;
    }

    OHOS::Ace::Ani::DrawableInfo drawableInfo;
    drawableInfo.manager = resourceManager_;
    size_t lenForeground = foreground.size();
    drawableInfo.firstBuffer.data = std::make_unique<uint8_t[]>(lenForeground);
    drawableInfo.firstBuffer.len = lenForeground;
    std::copy(foreground.data(), foreground.data() + lenForeground, drawableInfo.firstBuffer.data.get());

    if (background.empty()) {
        // base-icon
        drawableInfo.type = "none";
        return OHOS::Ace::Ani::DrawableDescriptorAni::CreateDrawableDescriptor(env, drawableInfo);
    }
    // layered-icon
    drawableInfo.type = "layered";
    size_t lenBackground = background.size();
    drawableInfo.secondBuffer.data = std::make_unique<uint8_t[]>(lenBackground);
    drawableInfo.secondBuffer.len = lenBackground;
    std::copy(background.data(), background.data() + lenBackground, drawableInfo.secondBuffer.data.get());
    return OHOS::Ace::Ani::DrawableDescriptorAni::CreateDrawableDescriptor(env, drawableInfo);
#else
    return nullptr;
#endif
}
} // AppExecFwk
} // OHOS