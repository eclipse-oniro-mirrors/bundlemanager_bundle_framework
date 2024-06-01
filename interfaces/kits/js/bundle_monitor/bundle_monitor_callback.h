/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MONITOR_BUNDLE_MONITOR_CALLBACK_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MONITOR_BUNDLE_MONITOR_CALLBACK_H

#include <future>
#include <vector>
#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "common_event_manager.h"
#include "common_event_support.h"
#include "common_event_subscriber.h"
#include "common_event_subscribe_info.h"
#include "event_listener.h"
#include "iremote_stub.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
class BundleMonitorCallback : public EventFwk::CommonEventSubscriber {
public:
    explicit BundleMonitorCallback(const EventFwk::CommonEventSubscribeInfo &subscribeInfo);
    virtual ~BundleMonitorCallback();
    void BundleMonitorOn(napi_env env, napi_value handler, const std::string &type);
    void BundleMonitorOff(napi_env env, napi_value handler, const std::string &type);
    void BundleMonitorOff(napi_env env, const std::string &type);
    void OnReceiveEvent(const EventFwk::CommonEventData &eventData);
private:
    void EventListenerAdd(napi_env env, napi_value handler,
        std::vector<std::shared_ptr<EventListener>> &eventListeners, const std::string &type);
    void EventListenerDelete(napi_env env, napi_value handler,
        const std::vector<std::shared_ptr<EventListener>> &eventListeners);
    void EventListenerDeleteAll(napi_env env, const std::vector<std::shared_ptr<EventListener>> &eventListeners);
    void BundleMonitorEmit(const std::string &type, std::string &bundleName, int32_t userId, int32_t appIndex);
    void EventListenerEmit(std::string &bundleName, int32_t userId, int32_t appIndex,
        const std::vector<std::shared_ptr<EventListener>> &eventListeners);
private:
    std::vector<std::shared_ptr<EventListener>> addListeners;
    std::vector<std::shared_ptr<EventListener>> updateListeners;
    std::vector<std::shared_ptr<EventListener>> removeListeners;
    DISALLOW_COPY_AND_MOVE(BundleMonitorCallback);
};
}
}

#endif // BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MONITOR_BUNDLE_MONITOR_CALLBACK_H