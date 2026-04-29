/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_DRAWABLE_MANAGER_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_DRAWABLE_MANAGER_H

#include <cstdint>
#include <dlfcn.h>
#include <memory>
#include <mutex>

#include "ability_resource_info.h"
#include "delayed_task_runner.h"

namespace OHOS {
namespace AppExecFwk {
class DrawableManager {
public:
    static DrawableManager& GetInstance();

    using CreateDrawableDescriptorFunc = ArkUI_DrawableDescriptor* (*)(const uint8_t*, size_t, const uint8_t*, size_t);
    using DisposeDrawableDescriptorFunc = void (*)(ArkUI_DrawableDescriptor*);

    ArkUI_DrawableDescriptor* CreateDrawableDescriptor(
        const uint8_t* foreground, size_t foregroundLen,
        const uint8_t* background, size_t backgroundLen);

    void DisposeDrawableDescriptor(ArkUI_DrawableDescriptor* descriptor);

private:
    DrawableManager();

    bool LoadLibraryNoLock();
    void UnloadLibrary();
    void ScheduleUnload();

    void* handle_ = nullptr;
    CreateDrawableDescriptorFunc createFunc_ = nullptr;
    DisposeDrawableDescriptorFunc disposeFunc_ = nullptr;
    std::mutex mutex_;
    std::shared_ptr<DelayedTaskRunner> unloadRunner_;

    static constexpr uint32_t UNLOAD_DELAY_MS = 3 * 60 * 1000;
    static constexpr const char* LIB_NAME = "/system/lib/libbundle_ndk_drawable.z.so";
    static constexpr const char* LIB64_NAME = "/system/lib64/libbundle_ndk_drawable.z.so";
    static constexpr const char* CREATE_FUNC_NAME = "BundleNDKCreateDrawableDescriptor";
    static constexpr const char* DISPOSE_FUNC_NAME = "BundleNDKDisposeDrawableDescriptor";
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_DRAWABLE_MANAGER_H
