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

#include "single_delayed_task_mgr.h"

#include <thread>

#include "app_log_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
SingleDelayedTaskMgr::SingleDelayedTaskMgr(const std::string &taskName, uint64_t delayedTimeMs)
    : taskName_(taskName), delayedTimeMs_(delayedTimeMs)
{}

void SingleDelayedTaskMgr::ScheduleDelayedTask(std::function<void()> func)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        executeTime_ = std::chrono::steady_clock::now() + std::chrono::milliseconds(delayedTimeMs_);
        if (isRunning_) {
            return;
        }
        isRunning_ = true;
    }

    std::weak_ptr<SingleDelayedTaskMgr> weakPtr = weak_from_this();
    auto task = [weakPtr, func]() {
        while (true) {
            auto sharedPtr = weakPtr.lock();
            if (sharedPtr == nullptr) {
                LOG_W(BMS_TAG_DEFAULT, "SingleDelayedTaskMgr null");
                return;
            }
            auto executeTime = sharedPtr->GetExecuteTime();
            auto now = std::chrono::steady_clock::now();
            std::chrono::milliseconds sleepTime =
                std::chrono::duration_cast<std::chrono::milliseconds>(executeTime - now);
            if (sleepTime.count() <= 0) {
                LOG_I(BMS_TAG_DEFAULT, "begin to execute %{public}s", sharedPtr->taskName_.c_str());
                break;
            }
            sharedPtr = nullptr;
            std::this_thread::sleep_for(sleepTime);
        }
        func();
        auto sharedPtr = weakPtr.lock();
        if (sharedPtr == nullptr) {
            LOG_W(BMS_TAG_DEFAULT, "SingleDelayedTaskMgr null");
            return;
        }
        sharedPtr->SetTaskFinished();
    };
    std::thread(task).detach();
}

std::chrono::time_point<std::chrono::steady_clock> SingleDelayedTaskMgr::GetExecuteTime() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return executeTime_;
}

void SingleDelayedTaskMgr::SetTaskFinished()
{
    std::lock_guard<std::mutex> lock(mutex_);
    isRunning_ = false;
}
}  // namespace AppExecFwk
}  // namespace OHOS
