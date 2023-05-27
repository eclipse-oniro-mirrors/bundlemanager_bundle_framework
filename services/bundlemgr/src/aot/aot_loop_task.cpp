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

#include "aot/aot_handler.h"
#include "battery_srv_client.h"
#include "display_power_mgr_client.h"

namespace OHOS {
namespace AppExecFwk {
void AOTLoopTask::ScheduleLoopTask()
{
    running_ = true;
    // while (true) {
    //     if (CheckDeviceState()) {
    //         AgingHandler::GetInstance().HandleIdle();
    //     }
    // }
}

bool AOTLoopTask::CheckDeviceState()
{
    DisplayPowerMgr::DisplayState displayState =
        DisplayPowerMgr::DisplayPowerMgrClient::GetInstance().GetDisplayState();
    if (displayState == DisplayPowerMgr::DisplayState::DISPLAY_OFF) {
        APP_LOGD("displayState is on, don't AOT");
        return false;
    }
    APP_LOGD("screen is off and in charging state, begin to handle idle AOT");
    PowerMgr::BatteryChargeState batteryChargeState =
        OHOS::PowerMgr::BatterySrvClient::GetInstance().GetChargingStatus();
    if (batteryChargeState == PowerMgr::BatteryChargeState::CHARGE_STATE_ENABLE
        || batteryChargeState == PowerMgr::BatteryChargeState::CHARGE_STATE_FULL) {
        return true;
    }
    return false;
}
}  // namespace AppExecFwk
}  // namespace OHOS