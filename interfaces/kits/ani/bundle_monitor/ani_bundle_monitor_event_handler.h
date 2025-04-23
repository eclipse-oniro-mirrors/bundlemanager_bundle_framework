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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_ANI_BUNDLE_MONITOR_BUNDLE_MONITOR_EVENT_HANDLER_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_ANI_BUNDLE_MONITOR_BUNDLE_MONITOR_EVENT_HANDLER_H

#include <atomic>
#include <mutex>
#include <queue>
#include <thread>

#include "ani_bundle_monitor_callback_handler.h"
#include "common_event_manager.h"
#include "common_event_subscribe_info.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "common_fun_ani.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {

enum class MESSAGE_ID {
    INVALID = 0,
    INVOKE_ADD = 1,
    INVOKE_UPDATE = 2,
    INVOKE_REMOVE = 3,
};

struct ANIBundleMonitorEventHandlerMessage {
    MESSAGE_ID messageId = MESSAGE_ID::INVALID;
    BundleChangedInfo bundleChangedInfo;
};

class ANIBundleMonitorEventHandler : public EventFwk::CommonEventSubscriber {
public:
    explicit ANIBundleMonitorEventHandler(ani_vm* vm, const EventFwk::CommonEventSubscribeInfo& subscribeInfo);
    virtual ~ANIBundleMonitorEventHandler();
    void RegisterBundleChangedEvent(ani_env* env, const std::string& eventType, ani_object aniCallback);
    void UnregisterBundleChangedEvent(ani_env* env, const std::string& eventType, ani_object aniCallback);
    void UnregisterBundleChangedEvent(ani_env* env, const std::string& eventType);
    void OnReceiveEvent(const EventFwk::CommonEventData& eventData);

private:
    inline MESSAGE_ID GetMessageIdByType(const std::string& type)
    {
        if (type == "add" || type == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED) {
            return MESSAGE_ID::INVOKE_ADD;
        } else if (type == "update" || type == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED) {
            return MESSAGE_ID::INVOKE_UPDATE;
        } else if (type == "remove" || type == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) {
            return MESSAGE_ID::INVOKE_REMOVE;
        } else {
            APP_LOGE("incorrect type: %{public}s", type.c_str());
            return MESSAGE_ID::INVALID;
        }
    }
    void ProcessMessages();

private:
    ani_vm* vm_ = nullptr;
    ANIBundleMonitorCallbackHandler addCallbackHandler_;
    ANIBundleMonitorCallbackHandler updateCallbackHandler_;
    ANIBundleMonitorCallbackHandler removeCallbackHandler_;
    std::atomic<bool> processingFlag_ { false };
    std::atomic<bool> stopFlag_ { false };
    std::queue<ANIBundleMonitorEventHandlerMessage> messageQueue_;
    std::mutex messageQueueMutex_;
    DISALLOW_COPY_AND_MOVE(ANIBundleMonitorEventHandler);
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_ANI_BUNDLE_MONITOR_BUNDLE_MONITOR_EVENT_HANDLER_H