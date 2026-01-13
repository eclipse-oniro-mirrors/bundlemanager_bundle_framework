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
#include <sstream>
#include <thread>

#include "account_helper.h"
#include "app_log_wrapper.h"
#include "battery_srv_client.h"
#include "bms_update_selinux_mgr.h"
#include "bundle_mgr_service.h"
#include "ffrt.h"
#include "file_ex.h"
#include "idle_condition_mgr/idle_condition_mgr.h"
#include "mem_mgr_client.h"
#include "parameter.h"
#include "parameters.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* BMS_PARAM_RELABEL_BATTERY_CAPACITY = "ohos.bms.param.relabelBatteryCapacity";
constexpr const char* BMS_PARAM_RELABEL_WAIT_TIME = "ohos.bms.param.relabelWaitTimeMinutes";
constexpr const char* MEMORY_INFO_PATH = "/dev/memcg/memory.zswapd_presure_show";
constexpr const char* MEMORY_BUFFER_KEY = "buffer_size";
constexpr int32_t RELABEL_WAIT_TIME_SECONDS = 5 * 60; // 5 minutes
constexpr int32_t RELABEL_MIN_BATTERY_CAPACITY = 20;
constexpr int32_t RELABEL_MIN_BUFFER_SIZE = 700;
}


IdleConditionMgr::IdleConditionMgr()
{
    idleConditionListener_ = std::make_shared<IdleConditionListener>();
    Memory::MemMgrClient::GetInstance().SubscribeAppState(*idleConditionListener_);
    APP_LOGI("IdleConditionMgr created");
}

IdleConditionMgr::~IdleConditionMgr()
{
    Memory::MemMgrClient::GetInstance().UnsubscribeAppState(*idleConditionListener_);
    APP_LOGI("IdleConditionMgr destroyed");
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
 
void IdleConditionMgr::HandleOnTrim(Memory::SystemMemoryLevel level)
{
    APP_LOGI("HandleOnTrim called, level=%{public}d", level);
    switch (level) {
        case Memory::SystemMemoryLevel::UNKNOWN:
            [[fallthrough]];
        case Memory::SystemMemoryLevel::MEMORY_LEVEL_PURGEABLE:
            [[fallthrough]];
        case Memory::SystemMemoryLevel::MEMORY_LEVEL_MODERATE:
            TryStartRelabel();
            break;
        case Memory::SystemMemoryLevel::MEMORY_LEVEL_LOW:
            [[fallthrough]];
        case Memory::SystemMemoryLevel::MEMORY_LEVEL_CRITICAL:
            InterruptRelabel();
            break;
        default:
            break;
    }
}

bool IdleConditionMgr::IsBufferSufficient()
{
    std::string content;
    if (!LoadStringFromFile(MEMORY_INFO_PATH, content)) {
        APP_LOGE("Failed to read memory info");
        return false;
    }
    size_t pos = content.find(MEMORY_BUFFER_KEY);
    if (pos == std::string::npos) {
        APP_LOGE("Failed to find memory buffer info");
        return false;
    }
    std::string bufferMb = content.substr(pos);
    std::istringstream bufferStream(bufferMb);
    std::string statTag;
    std::string bufferSize;
    bufferStream >> statTag >> bufferSize;
    
    int32_t currentBufferSizeMb = -1;
    if (!OHOS::StrToInt(bufferSize, currentBufferSizeMb)) {
        APP_LOGE("Failed to convert buffer size to int: %s", bufferSize.c_str());
        return false;
    }
    return currentBufferSizeMb > RELABEL_MIN_BUFFER_SIZE;
}

bool IdleConditionMgr::IsThermalSatisfied()
{
    return PowerMgr::ThermalMgrClient::GetInstance().GetThermalLevel() < PowerMgr::ThermalLevel::WARM;
}

void IdleConditionMgr::OnBatteryChanged()
{
    APP_LOGI("OnBatteryChanged called");
    int32_t currentBatteryCap = OHOS::PowerMgr::BatterySrvClient::GetInstance().GetCapacity();
    int32_t relabelBatteryCapacity = OHOS::system::GetIntParameter<int32_t>(
        BMS_PARAM_RELABEL_BATTERY_CAPACITY, RELABEL_MIN_BATTERY_CAPACITY);
    if (currentBatteryCap < relabelBatteryCapacity) {
        APP_LOGD("battery capacity %{public}d less than %{public}d interrupt relabel",
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

void IdleConditionMgr::OnThermalLevelChanged(PowerMgr::ThermalLevel level)
{
    APP_LOGI("OnThermalLevelChanged called, level=%{public}d", level);
    if (level < PowerMgr::ThermalLevel::WARM) {
        TryStartRelabel();
    } else {
        APP_LOGD("thermal level %{public}d greater than %{public}d interrupt relabel",
            level, PowerMgr::ThermalLevel::WARM);
        InterruptRelabel();
    }
}

bool IdleConditionMgr::CheckRelabelConditions()
{
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
    if (installer == nullptr) {
        APP_LOGE("installer is null");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (userUnlocked_ && screenLocked_ && powerConnected_ && batterySatisfied_ && g_taskCounter.load() == 0) {
        return true;
    }
    APP_LOGI("userUnlocked_ %{public}d, screenLocked_ %{public}d, "
        "powerConnected_ %{public}d, batterySatisfied_ %{public}d, taskNum %{public}d",
        userUnlocked_.load(), screenLocked_.load(),
        powerConnected_.load(), batterySatisfied_.load(), g_taskCounter.load());
    return false;
}

bool IdleConditionMgr::SetIsRelabeling()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (isRelabeling_) {
        APP_LOGI("Already relabeling, no need to process");
        return false;
    }
    isRelabeling_ = true;
    return true;
}

void IdleConditionMgr::TryStartRelabel()
{
    if (!CheckRelabelConditions()) {
        APP_LOGI("Refresh conditions not met, no need to process");
        return;
    }
    if (!IsBufferSufficient()) {
        APP_LOGI("Buffer not sufficient, no need to process");
        return;
    }
    if (!IsThermalSatisfied()) {
        APP_LOGI("Thermal not satisfied, no need to process");
        return;
    }
    if (!SetIsRelabeling()) {
        APP_LOGI("Set isRelabeling failed");
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
            APP_LOGI("Refresh conditions not met, no need to process");
            return;
        }
        if (!sharedPtr->IsBufferSufficient()) {
            APP_LOGI("Buffer not sufficient, no need to process");
            return;
        }
        if (!sharedPtr->IsThermalSatisfied()) {
            APP_LOGI("Thermal not satisfied, no need to process");
            return;
        }
        int32_t userId = AccountHelper::GetCurrentActiveUserId();
        auto bmsUpdateSelinuxMgr = DelayedSingleton<BmsUpdateSelinuxMgr>::GetInstance();
        if (bmsUpdateSelinuxMgr == nullptr) {
            APP_LOGE("bms update selinux mgr is null");
            return;
        }
        bmsUpdateSelinuxMgr->StartUpdateSelinuxLabel(userId);

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
    auto bmsUpdateSelinuxMgr = DelayedSingleton<BmsUpdateSelinuxMgr>::GetInstance();
    if (bmsUpdateSelinuxMgr == nullptr) {
        APP_LOGE("bms update selinux mgr is null");
        return;
    }
    if (bmsUpdateSelinuxMgr->StopUpdateSelinuxLabel(ServiceConstants::StopReason::BUSY) != ERR_OK) {
        std::lock_guard<std::mutex> lock(mutex_);
        isRelabeling_ = true;
    }
    APP_LOGI("Relabeling interrupted");
}
} // namespace AppExecFwk
} // namespace OHOS