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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_AOT_AOT_LOOP_TASK
#define FOUNDATION_BUNDLE_FRAMEWORK_AOT_AOT_LOOP_TASK

#include <cstdint>
#include <memory>

#include "serial_queue.h"

namespace OHOS {
namespace AppExecFwk {
class AOTLoopTask : public std::enable_shared_from_this<AOTLoopTask> {
public:
    void ScheduleLoopTask();
    static uint32_t GetAOTIdleInterval();
private:
    std::shared_ptr<SerialQueue> serialQueue_ = std::make_shared<SerialQueue>("AOTQueue");
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_BUNDLE_FRAMEWORK_AOT_AOT_LOOP_TASK