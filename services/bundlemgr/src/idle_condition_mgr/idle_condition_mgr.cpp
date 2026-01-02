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

#include <chrono>
#include <thread>

#include "app_log_wrapper.h"
#include "battery_srv_client.h"
#include "ffrt.h"
#include "idle_condition_mgr/idle_condition_mgr.h"
#include "parameter.h"
#include "parameters.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* BMS_PARAM_RELABEL_BATTERY_CAPACITY = "ohos.bms.param.relabelBatteryCapacity";
constexpr const char* BMS_PARAM_RELABEL_WAIT_TIME = "ohos.bms.param.relabelWaitTimeMinutes";
constexpr int32_t RELABEL_WAIT_TIME_SECONDS = 5 * 60; // 5 minutes
constexpr int32_t RELABEL_MIN_BATTERY_CAPACITY = 20;
}

IdleConditionMgr::IdleConditionMgr() = default;

IdleConditionMgr::~IdleConditionMgr()
{
}

void IdleConditionMgr::OnScreenLocked()
{
    APP_LOGI("OnScreenLocked called");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        screenLocked_ = true;
    }
    TryStartRelabel();
}

void IdleConditionMgr::OnScreenUnlocked()
{
    APP_LOGI("OnScreenUnlocked called");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        screenLocked_ = false;
    }
    InterruptRelabel();
}

void IdleConditionMgr::OnUserUnlocked()
{
    APP_LOGI("OnUserUnlocked called");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        userUnlocked_ = true;
    }
    TryStartRelabel();
}

void IdleConditionMgr::OnUserStopping()
{
    APP_LOGI("OnUserStopping called");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        userUnlocked_ = false;
    }
    InterruptRelabel();
}

void IdleConditionMgr::OnPowerConnected()
{
    APP_LOGI("OnPowerConnected called");
    if (powerConnectedThreadActive_) {
        return;
    }
    powerConnectedThreadActive_ = true;
    std::weak_ptr<IdleConditionMgr> weakPtr = shared_from_this();
    auto task = [weakPtr]() {
        auto startTime = std::chrono::steady_clock::now();
        int32_t delayTime = OHOS::system::GetIntParameter<int32_t>(
            BMS_PARAM_RELABEL_WAIT_TIME, RELABEL_WAIT_TIME_SECONDS);
        auto endTime = startTime + std::chrono::seconds(delayTime);
        auto sharedPtr = weakPtr.lock();
        if (sharedPtr == nullptr) {
            APP_LOGE("stop power connect task");
            return;
        }
        while (std::chrono::steady_clock::now() < endTime) {
            if (!sharedPtr->powerConnectedThreadActive_) {
                APP_LOGI("power connected thread is not active");
                return;
            }
            ffrt::this_task::sleep_for(std::chrono::seconds(1));
        }
        {
            std::lock_guard<std::mutex> lock(sharedPtr->mutex_);
            sharedPtr->powerConnected_ = true;
        }
        sharedPtr->TryStartRelabel();
        sharedPtr->powerConnectedThreadActive_ = false;
        APP_LOGI("power connected task done");
    };
    ffrt::submit(task);
}

void IdleConditionMgr::OnPowerDisconnected()
{
    APP_LOGI("OnPowerDisconnected called");
    {
        std::lock_guard<std::mutex> lock(mutex_);
        powerConnected_ = false;
    }
    powerConnectedThreadActive_ = false;
    InterruptRelabel();
}

void IdleConditionMgr::OnBatteryChanged()
{
    APP_LOGI("OnBatteryChanged called");
    int32_t currentBatteryCap = OHOS::PowerMgr::BatterySrvClient::GetInstance().GetCapacity();
    int32_t relabelBatteryCapacity = OHOS::system::GetIntParameter<int32_t>(
        BMS_PARAM_RELABEL_BATTERY_CAPACITY, RELABEL_MIN_BATTERY_CAPACITY);
    if (currentBatteryCap < relabelBatteryCapacity) {
        APP_LOGD("battery capacity %{public}d less than %{public}d, interrupt relabel",
            currentBatteryCap, relabelBatteryCapacity);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            batterySatisfied_ = false;
        }
        InterruptRelabel();
    } else {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            batterySatisfied_ = true;
        }
        TryStartRelabel();
    }
}

bool IdleConditionMgr::CheckRelabelConditions()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (userUnlocked_ && screenLocked_ && powerConnected_ && batterySatisfied_) {
        if (isRelabeling_) {
            APP_LOGI("Already relabeling, no need to process");
            return false;
        }
        isRelabeling_ = true;
        return true;
    }
    return false;
}

void IdleConditionMgr::TryStartRelabel()
{
    if (!CheckRelabelConditions()) {
        APP_LOGI("Refresh conditions not met, no need to process");
        return;
    }
    std::weak_ptr<IdleConditionMgr> weakPtr = shared_from_this();
    auto task = [weakPtr] {
        APP_LOGI("Relabel task started");
        auto sharedPtr = weakPtr.lock();
        if (sharedPtr == nullptr) {
            APP_LOGD("stop relabel task");
            return;
        }
        if (!sharedPtr->CheckRelabelConditions()) {
            APP_LOGI("Refresh conditions not met");
            return;
        }
        // relabel logic here

        std::lock_guard<std::mutex> lock(sharedPtr->mutex_);
        sharedPtr->isRelabeling_ = false;
        APP_LOGI("Relabel task finished");
    };
    std::thread(task).detach();
}

void IdleConditionMgr::InterruptRelabel()
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!isRelabeling_) {
            APP_LOGI("No relabeling in progress, no need to interrupt");
            return;
        }
        isRelabeling_  = false;
    }
    // Interrupt logic here
    APP_LOGI("Relabeling interrupted");
}
} // namespace AppExecFwk
} // namespace OHOS