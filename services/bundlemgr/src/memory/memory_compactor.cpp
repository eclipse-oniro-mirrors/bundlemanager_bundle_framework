/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "memory/memory_compactor.h"

#include <chrono>
#include <thread>

#include "app_log_wrapper.h"
#include "bundle_mgr_service.h"
#include "common_event_manager.h"
#include "common_event_support.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t DEFRAG_DELAY_MS = 200;
}

std::mutex MemoryCompactor::mutex_;
std::once_flag MemoryCompactor::defragOnceFlag_;
std::shared_ptr<MemoryCompactor::ScreenOffEventSubscriber> MemoryCompactor::screenOffSubscriber_;

void MemoryCompactor::RegisterScreenOffListener()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (screenOffSubscriber_ != nullptr) {
        APP_LOGW_NOFUNC("screen off listener already registered");
        return;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    screenOffSubscriber_ = std::make_shared<ScreenOffEventSubscriber>(subscribeInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(screenOffSubscriber_)) {
        APP_LOGE_NOFUNC("register screen off event for memory defrag failed");
        screenOffSubscriber_.reset();
        return;
    }
    APP_LOGI_NOFUNC("register screen off event for memory defrag success");
}

void MemoryCompactor::UnregisterScreenOffListener()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (screenOffSubscriber_ == nullptr) {
        APP_LOGW_NOFUNC("screenOffSubscriber_ is null");
        return;
    }
    EventFwk::CommonEventManager::UnSubscribeCommonEvent(screenOffSubscriber_);
    screenOffSubscriber_.reset();
    APP_LOGI_NOFUNC("unregister screen off event success");
}

void MemoryCompactor::ScreenOffEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &event)
{
    if (event.GetWant().GetAction() != EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF) {
        return;
    }
    APP_LOGI_NOFUNC("receive first screen off event, trigger memory defrag");
    auto task = []() {
        MemoryCompactor::OnFirstScreenOff();
    };
    std::thread(task).detach();
}

void MemoryCompactor::OnFirstScreenOff()
{
    std::call_once(defragOnceFlag_, []() {
        UnregisterScreenOffListener();
        std::this_thread::sleep_for(std::chrono::milliseconds(DEFRAG_DELAY_MS));
        auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        if (dataMgr == nullptr) {
            APP_LOGE_NOFUNC("dataMgr is nullptr, skip memory defrag");
            return;
        }
        dataMgr->DefragMemory();
    });
}
}  // namespace AppExecFwk
}  // namespace OHOS
