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
#include <sys/statfs.h>

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* RELABEL_PARAM = "persist.bms.relabel";
constexpr const char* COMMON_EVENT_KEY_TEMPERATURE = "temperature";
constexpr const char* COMMERCIAL_MODE = "commercial";
constexpr const char* COMMERCIAL_MODE_PARAM = "const.logsystem.versiontype";
constexpr const char* USER_DATA_DIR = "/data";
constexpr double MIN_FREE_INODE_PERCENT = 0.2;
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
    if (!CheckInodeForCommericalDevice()) {
        APP_LOGE("inodes not satisfied");
        return;
    }
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
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED) {
        int32_t batteryTemperature = data.GetWant().GetIntParam(COMMON_EVENT_KEY_TEMPERATURE, 0);
        idleMgr->OnBatteryChangedByTemperature(batteryTemperature);
        idleMgr->OnBatteryChanged();
    }
}

bool IdleConditionEventSubscriber::CheckInodeForCommericalDevice()
{
    std::string versionType = OHOS::system::GetParameter(COMMERCIAL_MODE_PARAM, "");
    if (versionType != COMMERCIAL_MODE) {
        APP_LOGI("non commercial device");
        return true;
    }
    struct statfs stat;
    if (statfs(USER_DATA_DIR, &stat) != 0) {
        APP_LOGE("statfs failed for %{public}s, error %{public}d",
            USER_DATA_DIR, errno);
        return false;
    }
    uint32_t minFreeInodeNum = static_cast<uint32_t>(stat.f_files * MIN_FREE_INODE_PERCENT);
    if (stat.f_ffree > minFreeInodeNum) {
        APP_LOGI("free inodes over threshold");
        return false;
    }
    APP_LOGD("total inodes: %{public}llu, free inodes: %{public}llu",
        stat.f_files, stat.f_ffree);
    return true;
}
} // namespace AppExecFwk
} // namespace OHOS