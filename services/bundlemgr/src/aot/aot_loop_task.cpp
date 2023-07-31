/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "aot/aot_loop_task.h"

#include <chrono>
#include <string>
#include <thread>

#include "aot/aot_handler.h"
#include "bundle_memory_guard.h"
#include "ffrt.h"
#include "parameters.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string AOT_INTERVAL = "bms.aot.idle.interval";
constexpr uint32_t EIGHT_HOURS_MS = 8 * 60 * 60 * 1000;
const std::string AOT_TASK = "AOTTask";
}

uint32_t AOTLoopTask::GetAOTIdleInterval()
{
    uint32_t interval = EIGHT_HOURS_MS;
    std::string str = system::GetParameter(AOT_INTERVAL, "");
    if (!str.empty()) {
        try {
            interval = static_cast<uint32_t>(std::stoi(str));
        } catch (...) {
            APP_LOGE("convert AOT_INTERVAL failed");
        }
    }
    APP_LOGI("aot idle interval ms : %{public}u", interval);
    return interval;
}

void AOTLoopTask::ScheduleLoopTask()
{
    APP_LOGI("ScheduleLoopTask begin");
    std::weak_ptr<AOTLoopTask> weakPtr = shared_from_this();
    auto task = [weakPtr]() {
        BundleMemoryGuard memoryGuard;
        while (true) {
            auto sharedPtr = weakPtr.lock();
            if (sharedPtr == nullptr) {
                APP_LOGD("stop AOT task");
                break;
            }
            AOTHandler::GetInstance().HandleIdle();
            ffrt::this_task::sleep_for(std::chrono::milliseconds(AOTLoopTask::GetAOTIdleInterval()));
        }
        APP_LOGD("AOT task done");
    };
    serialQueue_->ScheduleDelayTask(AOT_TASK, AOTLoopTask::GetAOTIdleInterval(), task);
}
}  // namespace AppExecFwk
}  // namespace OHOS