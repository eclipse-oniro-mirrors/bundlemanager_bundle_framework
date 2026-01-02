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

#include <thread>

#include "app_log_wrapper.h"
#include "idle_condition_mgr/idle_condition_mgr.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
}

IdleConditionMgr::IdleConditionMgr() = default;

IdleConditionMgr::~IdleConditionMgr()
{
}

void IdleConditionMgr::OnScreenLocked()
{
    APP_LOGI("OnScreenLocked called");
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        screenLocked_ = true;
    }
    TryStartRelabel();
}

void IdleConditionMgr::OnScreenUnlocked()
{
    APP_LOGI("OnScreenUnlocked called");
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        screenLocked_ = false;
    }
    InterruptRelabel();
}

void IdleConditionMgr::OnUserUnlocked()
{
    APP_LOGI("OnUserUnlocked called");
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        userUnlocked_ = true;
    }
    TryStartRelabel();
}

void IdleConditionMgr::OnUserStopping()
{
    APP_LOGI("OnUserStopping called");
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        userUnlocked_ = false;
    }
    InterruptRelabel();
}

void IdleConditionMgr::OnPowerConnected()
{
    APP_LOGI("OnPowerConnected called");
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        powerConnected_ = true;
    }
    TryStartRelabel();
}

void IdleConditionMgr::OnPowerDisconnected()
{
    APP_LOGI("OnPowerDisconnected called");
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        powerConnected_ = false;
    }
    InterruptRelabel();
}

bool IdleConditionMgr::CheckRefreshConditions()
{
    std::lock_guard<std::mutex> lock(stateMutex_);
    return userUnlocked_ && screenLocked_ && powerConnected_;
}

void IdleConditionMgr::TryStartRelabel()
{
    if (!CheckRefreshConditions()) {
        APP_LOGI("Refresh conditions not met, no need to process");
        return;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (isRelabeling_) {
            APP_LOGI("Already relabeling, no need to process");
            return;
        }
        isRelabeling_ = true;
    }
    auto task = [this] {
        APP_LOGI("Relabel task started");
        // relabel logic here

        std::lock_guard<std::mutex> lock(mutex_);
        isRelabeling_ = false;
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