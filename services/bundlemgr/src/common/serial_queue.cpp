/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "serial_queue.h"

#include <limits>

#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
using namespace ffrt;
namespace {
constexpr uint32_t CONVERSION_FACTOR = 1000; // ms to us
}

SerialQueue::SerialQueue(const std::string &queueName)
{
    APP_LOGI("create SerialQueue, queueName %{public}s", queueName.c_str());
    queue_ = std::make_shared<queue>(queueName.c_str());
}

SerialQueue::~SerialQueue()
{
    APP_LOGD("destroy SerialQueue");
}

void SerialQueue::ScheduleDelayTask(const std::string &taskName, uint64_t ms, std::function<void()> func)
{
    APP_LOGI("begin, taskName %{public}s", taskName.c_str());
    if (ms > std::numeric_limits<uint64_t>::max() / CONVERSION_FACTOR) {
        APP_LOGE("invalid ms, ScheduleDelayTask failed");
        return;
    }
    std::unique_lock<std::shared_mutex> lock(mutex_);
    task_handle task_handle = queue_->submit_h(func, task_attr().delay(ms * CONVERSION_FACTOR));
    if (task_handle == nullptr) {
        APP_LOGE("submit_h return null, ScheduleDelayTask failed");
        return;
    }
    taskMap_[taskName] = std::move(task_handle);
    APP_LOGI("ScheduleDelayTask success");
}

void SerialQueue::CancelDelayTask(const std::string &taskName)
{
    APP_LOGI("begin, taskName %{public}s", taskName.c_str());
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto item = taskMap_.find(taskName);
    if (item == taskMap_.end()) {
        APP_LOGW("task not found, CancelDelayTask failed");
        return;
    }
    if (item->second != nullptr) {
        int32_t ret = queue_->cancel(item->second);
        if (ret != 0) {
            APP_LOGW("CancelDelayTask failed %{public}d", ret);
        }
    }
    taskMap_.erase(taskName);
    APP_LOGI("CancelDelayTask success");
}
}  // namespace AppExecFwk
}  // namespace OHOS
