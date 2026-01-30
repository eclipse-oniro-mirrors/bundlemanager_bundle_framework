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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_CRITICAL_MANAGER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_CRITICAL_MANAGER_H

#include <mutex>

#include "single_delayed_task_mgr.h"

namespace OHOS {
namespace AppExecFwk {
class CriticalManager {
public:
    CriticalManager(const CriticalManager&) = delete;
    CriticalManager& operator=(const CriticalManager&) = delete;
    CriticalManager(CriticalManager&&) = delete;
    CriticalManager& operator=(CriticalManager&&) = delete;

    static CriticalManager& GetInstance();
    void SetMemMgrStatus(bool started);
    bool IsCritical();
    void BeforeRequest();
    void AfterRequest();
private:
    CriticalManager();
    ~CriticalManager() = default;

    std::shared_ptr<SingleDelayedTaskMgr> delayedTaskMgr_ = nullptr;
    static std::mutex mutex_;
    inline static int32_t counter_ = 0;
    inline static bool memMgrStarted_ = false;
    inline static bool critical_ = false;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_CRITICAL_MANAGER_H