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

#include "ipc/critical_manager.h"

#include "app_log_tag_wrapper.h"
#include "mem_mgr_client.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr uint32_t DELAY_MILLI_SECONDS = 5 * 1000;
constexpr const char* TASK_NAME = "CriticalTask";
}

std::mutex CriticalManager::mutex_;

CriticalManager::CriticalManager()
{
    delayedTaskMgr_ = std::make_shared<SingleDelayedTaskMgr>(TASK_NAME, DELAY_MILLI_SECONDS);
}

void CriticalManager::SetMemMgrStatus(bool started)
{
    std::lock_guard<std::mutex> lock(mutex_);
    memMgrStarted_ = started;
}

bool CriticalManager::IsCritical()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return critical_;
}

void CriticalManager::BeforeRequest()
{
    std::lock_guard<std::mutex> lock(mutex_);
    LOG_D(BMS_TAG_INSTALLD, "before counter: %{public}d, memmgr: %{public}d, critical: %{public}d",
        counter_, memMgrStarted_, critical_);
    counter_++;
    if (memMgrStarted_ && !critical_ && counter_ > 0) {
        LOG_I(BMS_TAG_INSTALLD, "SetCritical true");
        Memory::MemMgrClient::GetInstance().SetCritical(
            getpid(), true, INSTALLD_SERVICE_ID);
        critical_ = true;
    }
}

void CriticalManager::AfterRequest()
{
    std::lock_guard<std::mutex> lock(mutex_);
    LOG_D(BMS_TAG_INSTALLD, "after counter: %{public}d, memmgr: %{public}d, critical: %{public}d",
        counter_, memMgrStarted_, critical_);
    counter_--;
    auto delayTask = []() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (memMgrStarted_ && critical_ && counter_ == 0) {
            LOG_I(BMS_TAG_INSTALLD, "SetCritical false");
            Memory::MemMgrClient::GetInstance().SetCritical(
                getpid(), false, INSTALLD_SERVICE_ID);
            critical_ = false;
        }
    };
    delayedTaskMgr_->ScheduleDelayedTask(delayTask);
}

}  // namespace AppExecFwk
}  // namespace OHOS
