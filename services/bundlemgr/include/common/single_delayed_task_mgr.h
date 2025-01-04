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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_COMMON_SINGLE_DELAYED_TASK_MGR
#define FOUNDATION_BUNDLE_FRAMEWORK_COMMON_SINGLE_DELAYED_TASK_MGR

#include <chrono>
#include <functional>
#include <memory>
#include <mutex>

namespace OHOS {
namespace AppExecFwk {
class SingleDelayedTaskMgr : public std::enable_shared_from_this<SingleDelayedTaskMgr> {
public:
    SingleDelayedTaskMgr(const std::string &taskName, uint64_t delayedTimeMs);
    ~SingleDelayedTaskMgr() = default;
    void ScheduleDelayedTask(std::function<void()> func);
private:
    std::chrono::time_point<std::chrono::steady_clock> GetExecuteTime() const;
    void SetTaskFinished();

    const std::string taskName_;
    const uint64_t delayedTimeMs_;

    mutable std::mutex mutex_;
    std::chrono::time_point<std::chrono::steady_clock> executeTime_ = std::chrono::steady_clock::now();
    bool isRunning_ = false;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif
