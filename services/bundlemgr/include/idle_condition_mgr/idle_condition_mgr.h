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
#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IDLE_CONDITION_MGR_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IDLE_CONDITION_MGR_H

#include <atomic>
#include <mutex>

#include "idle_condition_listener.h"
#include "singleton.h"
#include "thermal_mgr_client.h"

namespace OHOS {
namespace AppExecFwk {
class IdleConditionMgr : public DelayedSingleton<IdleConditionMgr>,
    public std::enable_shared_from_this<IdleConditionMgr> {
public:
    IdleConditionMgr();
    ~IdleConditionMgr();

    void OnScreenLocked();
    void OnPowerConnected();
    void OnUserUnlocked();
    void OnScreenUnlocked();
    void OnPowerDisconnected();
    void OnUserStopping();
    void HandleOnTrim(Memory::SystemMemoryLevel level);
    void OnBatteryChanged();
    void OnThermalLevelChanged(PowerMgr::ThermalLevel level);
    void TryStartRelabel();
    void InterruptRelabel();

private:
    bool CheckRelabelConditions();
    bool IsBufferSufficient();
    bool SetIsRelabeling();

private:
    std::mutex mutex_;
    std::mutex stateMutex_;
    
    std::atomic<bool> userUnlocked_{false};
    std::atomic<bool> screenLocked_{false};
    std::atomic<bool> powerConnected_{false};
    std::atomic<bool> batterySatisfied_{false};
    std::atomic<bool> thermalSatisfied_{false};
    
    std::atomic<bool> isRelabeling_{false};
    std::atomic<bool> powerConnectedThreadActive_{false};
    std::shared_ptr<IdleConditionListener> idleConditionListener_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IDLE_CONDITION_MGR_H