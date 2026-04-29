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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_DELAYED_TASK_RUNNER_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_DELAYED_TASK_RUNNER_H

#include <chrono>
#include <functional>
#include <memory>
#include <mutex>

namespace OHOS {
namespace AppExecFwk {

class DelayedTaskRunner : public std::enable_shared_from_this<DelayedTaskRunner> {
public:
    explicit DelayedTaskRunner(uint64_t delayedTimeMs);
    ~DelayedTaskRunner() = default;

    void ScheduleDelayedTask(std::function<void()> task);

private:
    std::chrono::time_point<std::chrono::steady_clock> GetExecuteTime() const;
    void SetTaskFinished();

    const uint64_t delayedTimeMs_;
    std::chrono::time_point<std::chrono::steady_clock> executeTime_;
    mutable std::mutex mutex_;
    bool isRunning_ = false;
};

} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_DELAYED_TASK_RUNNER_H
