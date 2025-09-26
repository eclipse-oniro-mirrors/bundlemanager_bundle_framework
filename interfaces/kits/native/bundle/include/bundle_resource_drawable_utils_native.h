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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INTERFACE_KITS_JS_BUNDLE_RESOURCE_DRAWABLE_UTILS_NATIVE_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INTERFACE_KITS_JS_BUNDLE_RESOURCE_DRAWABLE_UTILS_NATIVE_H

#include <memory>

#include "native/drawable_descriptor.h"
#include "native/node/native_drawable_descriptor.h"

#ifdef BUNDLE_FRAMEWORK_GRAPHICS
#include <mutex>

#include "drawable_descriptor.h"
#include "resource_manager.h"
#endif

namespace OHOS {
namespace AppExecFwk {
class BundleResourceDrawableUtilsNative {
public:
    static std::unique_ptr<Ace::Napi::DrawableDescriptor> ConvertToDrawableDescriptor(
        const std::vector<uint8_t> &foreground, const std::vector<uint8_t> &background);

private:
#ifdef BUNDLE_FRAMEWORK_GRAPHICS
    static void InitResourceManager();

    static std::shared_ptr<Global::Resource::ResourceManager> resourceManager_;
    static std::mutex resMutex_;
#endif
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INTERFACE_KITS_JS_BUNDLE_RESOURCE_DRAWABLE_UTILS_NATIVE_H