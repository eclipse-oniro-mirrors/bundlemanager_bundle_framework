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

#include "aot/aot_handler.h"

namespace OHOS {
namespace AppExecFwk {
ChargeIdleListener::ChargeIdleListener(const EventFwk::CommonEventSubscribeInfo &subscribeInfo)
    : EventFwk::CommonEventSubscriber(subscribeInfo)
{}

void ChargeIdleListener::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    APP_LOGI("receive COMMON_EVENT_CHARGE_IDLE_MODE_CHANGED event");
    auto task = []() {
        AOTHandler::GetInstance().HandleIdle();
    };
    std::thread(task).detach();
}
}  // namespace AppExecFwk
}  // namespace OHOS