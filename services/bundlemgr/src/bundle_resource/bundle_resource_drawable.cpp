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
    std::string &icon)
{
#ifdef BUNDLE_FRAMEWORK_GRAPHICS
    OHOS::Ace::Napi::DrawableDescriptor::DrawableType drawableType;
    Global::Resource::RState state;
    auto drawableDescriptor = Ace::Napi::DrawableDescriptorFactory::Create(
        iconId, resourceManager, state, drawableType, 0);
    if ((drawableDescriptor == nullptr) || (state != Global::Resource::SUCCESS)) {
        return false;
    }
    BundleResourceImageInfo info;
    return info.ConvertToString(drawableDescriptor->GetPixelMap(), icon);
#else
    return false;
#endif
}
} // AppExecFwk
} // OHOS
