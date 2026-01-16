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

#include "exception_util.h"

#include <dlfcn.h>

#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr uint32_t UNLOAD_DELAY_MS = 3 * 60 * 1000;
constexpr const char* UNLOAD_TASK_NAME = "ExceptionUtilUnloadTask";
constexpr const char* LIB_NAME = "libbms_exception_wrapper.z.so";
constexpr const char* SAFE_DUMP_FUNC_NAME = "BundleMgrSafeDump";
} // namespace

ExceptionUtil& ExceptionUtil::GetInstance()
{
    static ExceptionUtil instance;
    return instance;
}

ExceptionUtil::ExceptionUtil()
{
    delayedTaskMgr_ = std::make_shared<SingleDelayedTaskMgr>(UNLOAD_TASK_NAME, UNLOAD_DELAY_MS);
}

bool ExceptionUtil::LoadLibraryNoLock()
{
    if (handle_ != nullptr) {
        return true;
    }

    handle_ = dlopen(LIB_NAME, RTLD_NOW | RTLD_LOCAL);
    if (handle_ == nullptr) {
        APP_LOGE_NOFUNC("Failed to load %{public}s: %{public}s", LIB_NAME, dlerror());
        return false;
    }

    safeDumpFunc_ = reinterpret_cast<SafeDumpFunc>(dlsym(handle_, SAFE_DUMP_FUNC_NAME));
    if (safeDumpFunc_ == nullptr) {
        APP_LOGE_NOFUNC("Failed to get symbol %{public}s: %{public}s", SAFE_DUMP_FUNC_NAME, dlerror());
        dlclose(handle_);
        handle_ = nullptr;
        return false;
    }

    APP_LOGI_NOFUNC("Loaded %{public}s", LIB_NAME);
    return true;
}

void ExceptionUtil::UnloadLibrary()
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    if (handle_ == nullptr) {
        return;
    }
    dlclose(handle_);
    handle_ = nullptr;
    safeDumpFunc_ = nullptr;
    APP_LOGI_NOFUNC("Unloaded %{public}s", LIB_NAME);
}

void ExceptionUtil::ScheduleUnload()
{
    auto unloadTask = [this]() {
        UnloadLibrary();
    };
    delayedTaskMgr_->ScheduleDelayedTask(unloadTask);
}

bool ExceptionUtil::SafeDump(const nlohmann::json& jsonObject, std::string& result, int32_t indent)
{
    // Fast path: library already loaded, use shared read lock
    {
        std::shared_lock<std::shared_mutex> readLock(mutex_);
        if (handle_ != nullptr && safeDumpFunc_ != nullptr) {
            bool ret = safeDumpFunc_(jsonObject, result, indent);
            ScheduleUnload();
            return ret;
        }
    }

    // Slow path: need to load library, use exclusive write lock
    {
        std::unique_lock<std::shared_mutex> writeLock(mutex_);
        if (!LoadLibraryNoLock() || safeDumpFunc_ == nullptr) {
            return false;
        }
        bool ret = safeDumpFunc_(jsonObject, result, indent);
        ScheduleUnload();
        return ret;
    }
}
} // namespace AppExecFwk
} // namespace OHOS
