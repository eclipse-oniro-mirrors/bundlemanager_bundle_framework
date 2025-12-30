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

#include "app_log_wrapper.h"
#include "common_event_support.h"
#include "idle_condition_mgr/idle_condition_event_subscribe.h"
#include "idle_condition_mgr/idle_condition_mgr.h"
#include "parameters.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string RELABEL_PARAM = "persist.bms.relabel";
}

IdleConditionEventSubscriber::IdleConditionEventSubscriber(
    const EventFwk::CommonEventSubscribeInfo &subscribeInfo) : EventFwk::CommonEventSubscriber(subscribeInfo)
{}
IdleConditionEventSubscriber::~IdleConditionEventSubscriber()
{}
void IdleConditionEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    std::string param = OHOS::system::GetParameter(RELABEL_PARAM, "");
    if (param != "true") {
        return;
    }
    APP_LOGI("OnReceiveEvent received idle condition event");
    std::string action = data.GetWant().GetAction();
    auto idleMgr = DelayedSingleton<IdleConditionMgr>::GetInstance();
    if (idleMgr == nullptr) {
        APP_LOGE("failed, idleMgr is nullptr");
        return;
    }
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED) {
        idleMgr->OnScreenLocked();
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_POWER_CONNECTED) {
        idleMgr->OnPowerConnected();
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED) {
        idleMgr->OnUserUnlocked();
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED) {
        idleMgr->OnScreenUnlocked();
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_POWER_DISCONNECTED) {
        idleMgr->OnPowerDisconnected();
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_STOPPING) {
        idleMgr->OnUserStopping();
    }
}
} // namespace AppExecFwk
} // namespace OHOS