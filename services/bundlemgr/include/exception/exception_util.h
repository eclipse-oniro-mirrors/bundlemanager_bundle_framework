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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_EXCEPTION_UTIL_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_EXCEPTION_UTIL_H

#include <cstdint>
#include <shared_mutex>
#include <string>

#include "nlohmann/json.hpp"
#include "single_delayed_task_mgr.h"

namespace OHOS {
namespace AppExecFwk {
class ExceptionUtil {
public:
    static ExceptionUtil& GetInstance();

    /**
     * @brief Safely dump json object to string with exception handling.
     *        Thread-safe with read-write lock, auto unload after 3 minutes of inactivity.
     * @param jsonObject The json object to dump.
     * @param result Output parameter for the dumped string.
     * @param indent The indent for output, default -1.
     * @return Returns true if dump succeeds, false otherwise.
     */
    bool SafeDump(const nlohmann::json& jsonObject, std::string& result, int32_t indent = -1);

private:
    ExceptionUtil();
    ~ExceptionUtil() = default;
    ExceptionUtil(const ExceptionUtil&) = delete;
    ExceptionUtil& operator=(const ExceptionUtil&) = delete;
    ExceptionUtil(ExceptionUtil&&) = delete;
    ExceptionUtil& operator=(ExceptionUtil&&) = delete;

    bool LoadLibraryNoLock();
    void UnloadLibrary();
    void ScheduleUnload();

    using SafeDumpFunc = bool (*)(const nlohmann::json&, std::string&, int32_t);

    mutable std::shared_mutex mutex_;
    void* handle_ = nullptr;
    SafeDumpFunc safeDumpFunc_ = nullptr;
    std::shared_ptr<SingleDelayedTaskMgr> delayedTaskMgr_ = nullptr;
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_EXCEPTION_UTIL_H
