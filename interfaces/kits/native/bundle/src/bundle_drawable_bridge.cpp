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

#include "app_log_wrapper.h"
#include "bundle_resource_drawable_utils_native.h"
#include "native/node/native_drawable_descriptor.h"

extern "C" {
ArkUI_DrawableDescriptor* BundleNDKCreateDrawableDescriptor(
    const uint8_t* foreground, size_t foregroundLen,
    const uint8_t* background, size_t backgroundLen)
{
    std::vector<uint8_t> foregroundVec(foreground, foreground + foregroundLen);
    std::vector<uint8_t> backgroundVec(background, background + backgroundLen);

    auto nDrawableDescriptor = OHOS::AppExecFwk::BundleResourceDrawableUtilsNative::ConvertToDrawableDescriptor(
        foregroundVec, backgroundVec);
    if (nDrawableDescriptor == nullptr) {
        APP_LOGE_NOFUNC("failed to ConvertToDrawableDescriptor");
        return nullptr;
    }

    ArkUI_DrawableDescriptor* descriptor = OH_ArkUI_CreateFromNapiDrawable(nDrawableDescriptor.get());
    if (descriptor == nullptr) {
        APP_LOGE_NOFUNC("failed to OH_ArkUI_CreateFromNapiDrawable");
        return nullptr;
    }

    return descriptor;
}

void BundleNDKDisposeDrawableDescriptor(ArkUI_DrawableDescriptor* descriptor)
{
    if (descriptor != nullptr) {
        OH_ArkUI_DrawableDescriptor_Dispose(descriptor);
    }
}
} // extern "C"
