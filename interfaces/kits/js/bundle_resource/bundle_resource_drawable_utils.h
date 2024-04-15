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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INTERFACE_KITS_JS_BUNDLE_RESOURCE_DRAWABLE_UTILS_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INTERFACE_KITS_JS_BUNDLE_RESOURCE_DRAWABLE_UTILS_H

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

#ifdef BUNDLE_FRAMEWORK_GRAPHICS
#include <mutex>
#include "resource_manager.h"
#endif

namespace OHOS {
namespace AppExecFwk {
class BundleResourceDrawableUtils {
public:
    static napi_value ConvertToDrawableDescriptor(napi_env env,
        const std::vector<uint8_t> &foreground, const std::vector<uint8_t> &background);

private:
#ifdef BUNDLE_FRAMEWORK_GRAPHICS
    static void InitResourceManager();

    static std::shared_ptr<Global::Resource::ResourceManager> resourceManager_;
    static std::mutex resMutex_;
#endif
};
}
}
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INTERFACE_KITS_JS_BUNDLE_RESOURCE_DRAWABLE_UTILS_H
