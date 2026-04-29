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

#include "drawable_manager.h"

#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {

DrawableManager::DrawableManager()
    : unloadRunner_(std::make_shared<DelayedTaskRunner>(UNLOAD_DELAY_MS))
{}

DrawableManager& DrawableManager::GetInstance()
{
    static DrawableManager instance;
    return instance;
}

bool DrawableManager::LoadLibraryNoLock()
{
    if (handle_ != nullptr) {
        return true;
    }

    handle_ = dlopen(LIB64_NAME, RTLD_NOW | RTLD_LOCAL);
    if (handle_ == nullptr) {
        APP_LOGW_NOFUNC("Failed to load %{public}s: %{public}s", LIB64_NAME, dlerror());
        handle_ = dlopen(LIB_NAME, RTLD_NOW | RTLD_LOCAL);
    }
    if (handle_ == nullptr) {
        APP_LOGW_NOFUNC("Failed to load %{public}s: %{public}s", LIB_NAME, dlerror());
        return false;
    }

    createFunc_ = reinterpret_cast<CreateDrawableDescriptorFunc>(dlsym(handle_, CREATE_FUNC_NAME));
    if (createFunc_ == nullptr) {
        APP_LOGW_NOFUNC("Failed to get symbol %{public}s: %{public}s", CREATE_FUNC_NAME, dlerror());
        dlclose(handle_);
        handle_ = nullptr;
        return false;
    }

    disposeFunc_ = reinterpret_cast<DisposeDrawableDescriptorFunc>(dlsym(handle_, DISPOSE_FUNC_NAME));
    if (disposeFunc_ == nullptr) {
        APP_LOGW_NOFUNC("Failed to get symbol %{public}s: %{public}s", DISPOSE_FUNC_NAME, dlerror());
        dlclose(handle_);
        handle_ = nullptr;
        createFunc_ = nullptr;
        return false;
    }

    APP_LOGI_NOFUNC("Loaded %{public}s", LIB_NAME);
    return true;
}

void DrawableManager::UnloadLibrary()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (handle_ == nullptr) {
        return;
    }
    dlclose(handle_);
    handle_ = nullptr;
    createFunc_ = nullptr;
    disposeFunc_ = nullptr;
    APP_LOGI_NOFUNC("Unloaded %{public}s", LIB_NAME);
}

void DrawableManager::ScheduleUnload()
{
    unloadRunner_->ScheduleDelayedTask([this]() { UnloadLibrary(); });
}

ArkUI_DrawableDescriptor* DrawableManager::CreateDrawableDescriptor(
    const uint8_t* foreground, size_t foregroundLen,
    const uint8_t* background, size_t backgroundLen)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!LoadLibraryNoLock()) {
        return nullptr;
    }
    ArkUI_DrawableDescriptor* descriptor = createFunc_(foreground, foregroundLen, background, backgroundLen);
    ScheduleUnload();
    return descriptor;
}

void DrawableManager::DisposeDrawableDescriptor(ArkUI_DrawableDescriptor* descriptor)
{
    if (descriptor == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!LoadLibraryNoLock()) {
        return;
    }
    disposeFunc_(descriptor);
    ScheduleUnload();
}

} // namespace AppExecFwk
} // namespace OHOS
