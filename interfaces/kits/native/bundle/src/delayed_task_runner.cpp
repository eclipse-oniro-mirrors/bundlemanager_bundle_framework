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

#include "delayed_task_runner.h"

#include <thread>

#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {

DelayedTaskRunner::DelayedTaskRunner(uint64_t delayedTimeMs)
    : delayedTimeMs_(delayedTimeMs),
      executeTime_(std::chrono::steady_clock::now())
{}

void DelayedTaskRunner::ScheduleDelayedTask(std::function<void()> task)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        executeTime_ = std::chrono::steady_clock::now() + std::chrono::milliseconds(delayedTimeMs_);
        if (isRunning_) {
            return;
        }
        isRunning_ = true;
    }

    std::weak_ptr<DelayedTaskRunner> weakPtr = weak_from_this();
    std::thread([weakPtr, task]() {
        while (true) {
            auto sharedPtr = weakPtr.lock();
            if (sharedPtr == nullptr) {
                return;
            }
            auto executeTime = sharedPtr->GetExecuteTime();
            auto now = std::chrono::steady_clock::now();
            auto sleepTime = std::chrono::duration_cast<std::chrono::milliseconds>(executeTime - now);
            if (sleepTime.count() <= 0) {
                break;
            }
            sharedPtr = nullptr;
            std::this_thread::sleep_for(sleepTime);
        }
        task();
        auto sharedPtr = weakPtr.lock();
        if (sharedPtr == nullptr) {
            return;
        }
        sharedPtr->SetTaskFinished();
    }).detach();
}

std::chrono::time_point<std::chrono::steady_clock> DelayedTaskRunner::GetExecuteTime() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return executeTime_;
}

void DelayedTaskRunner::SetTaskFinished()
{
    std::lock_guard<std::mutex> lock(mutex_);
    isRunning_ = false;
}

} // namespace AppExecFwk
} // namespace OHOS
