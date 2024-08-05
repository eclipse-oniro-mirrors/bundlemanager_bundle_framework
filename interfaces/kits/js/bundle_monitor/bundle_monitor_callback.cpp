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

#include <uv.h>
#include <shared_mutex>

#include "bundle_monitor_callback.h"

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "napi/native_common.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    const char* ADD = "add";
    const char* UPDATE = "update";
    const char* REMOVE = "remove";
    static std::shared_mutex g_addListenersMutex;
    static std::shared_mutex g_updateListenersMutex;
    static std::shared_mutex g_removeListenersMutex;
}

BundleMonitorCallback::BundleMonitorCallback(const EventFwk::CommonEventSubscribeInfo &subscribeInfo)
    : EventFwk::CommonEventSubscriber(subscribeInfo) {}

BundleMonitorCallback::~BundleMonitorCallback() {}

void BundleMonitorCallback::BundleMonitorOn(napi_env env, napi_value handler, const std::string &type)
{
    APP_LOGD("BundleMonitorOn Enter");
    if (type != ADD && type != UPDATE && type != REMOVE) {
        APP_LOGE("input wrong type for on interface");
        return;
    }
    if (type == ADD) {
        std::unique_lock<std::shared_mutex> lock(g_addListenersMutex);
        EventListenerAdd(env, handler, addListeners, type);
    } else if (type == UPDATE) {
        std::unique_lock<std::shared_mutex> lock(g_updateListenersMutex);
        EventListenerAdd(env, handler, updateListeners, type);
    } else {
        std::unique_lock<std::shared_mutex> lock(g_removeListenersMutex);
        EventListenerAdd(env, handler, removeListeners, type);
    }
}

void BundleMonitorCallback::EventListenerAdd(napi_env env, napi_value handler,
    std::vector<std::shared_ptr<EventListener>> &eventListeners, const std::string &type)
{
    for (uint32_t i = 0; i < eventListeners.size(); ++i) {
        if (eventListeners[i]->HasSameEnv(env)) {
            eventListeners[i]->Add(env, handler);
            return;
        }
    }
    std::shared_ptr<EventListener> listener = std::make_shared<EventListener>(env, type);
    listener->Add(env, handler);
    eventListeners.push_back(listener);
}

void BundleMonitorCallback::BundleMonitorOff(napi_env env, napi_value handler, const std::string &type)
{
    APP_LOGD("BundleMonitorOff Enter");
    if (type != ADD && type != UPDATE && type != REMOVE) {
        APP_LOGE("input wrong type for off interface");
        return;
    }
    if (type == ADD) {
        std::unique_lock<std::shared_mutex> lock(g_addListenersMutex);
        EventListenerDelete(env, handler, addListeners);
    } else if (type == UPDATE) {
        std::unique_lock<std::shared_mutex> lock(g_updateListenersMutex);
        EventListenerDelete(env, handler, updateListeners);
    } else {
        std::unique_lock<std::shared_mutex> lock(g_removeListenersMutex);
        EventListenerDelete(env, handler, removeListeners);
    }
}

void BundleMonitorCallback::BundleMonitorOff(napi_env env, const std::string &type)
{
    APP_LOGD("BundleMonitorOff Enter");
    if (type != ADD && type != UPDATE && type != REMOVE) {
        APP_LOGE("input wrong type for off interface");
        return;
    }
    if (type == ADD) {
        std::unique_lock<std::shared_mutex> lock(g_addListenersMutex);
        EventListenerDeleteAll(env, addListeners);
    } else if (type == UPDATE) {
        std::unique_lock<std::shared_mutex> lock(g_updateListenersMutex);
        EventListenerDeleteAll(env, updateListeners);
    } else {
        std::unique_lock<std::shared_mutex> lock(g_removeListenersMutex);
        EventListenerDeleteAll(env, removeListeners);
    }
}

void BundleMonitorCallback::EventListenerDelete(napi_env env, napi_value handler,
    const std::vector<std::shared_ptr<EventListener>> &eventListeners)
{
    APP_LOGD("EventListenerDelete Enter");
    for (auto listener : eventListeners) {
        if (listener->HasSameEnv(env)) {
            listener->Delete(env, handler);
            return;
        }
    }
}

void BundleMonitorCallback::EventListenerDeleteAll(napi_env env,
    const std::vector<std::shared_ptr<EventListener>> &eventListeners)
{
    APP_LOGD("EventListenerDeleteAll Enter");
    for (auto listener : eventListeners) {
        if (listener->HasSameEnv(env)) {
            listener->DeleteAll();
            return;
        }
    }
}

// operator on js thread
void BundleMonitorCallback::BundleMonitorEmit(const std::string &type,
    std::string &bundleName, int32_t userId, int32_t appIndex)
{
    APP_LOGD("BundleMonitorEmit enter type is %{public}s", type.c_str());
    if (type != ADD && type != UPDATE && type != REMOVE) {
        return;
    }
    if (type == ADD) {
        std::unique_lock<std::shared_mutex> lock(g_addListenersMutex);
        EventListenerEmit(bundleName, userId, appIndex, addListeners);
    } else if (type == UPDATE) {
        std::unique_lock<std::shared_mutex> lock(g_updateListenersMutex);
        EventListenerEmit(bundleName, userId, appIndex, updateListeners);
    } else {
        std::unique_lock<std::shared_mutex> lock(g_removeListenersMutex);
        EventListenerEmit(bundleName, userId, appIndex, removeListeners);
    }
}

void BundleMonitorCallback::EventListenerEmit(std::string &bundleName, int32_t userId, int32_t appIndex,
    const std::vector<std::shared_ptr<EventListener>> &eventListeners)
{
    for (auto listener : eventListeners) {
        listener->Emit(bundleName, userId, appIndex);
    }
}

void BundleMonitorCallback::OnReceiveEvent(const EventFwk::CommonEventData &eventData)
{
    APP_LOGD("OnReceiveEvent Enter");
    OHOS::AAFwk::Want want = eventData.GetWant();
    std::string action = want.GetAction();
    std::string bundleName = want.GetElement().GetBundleName();
    int userId = want.GetIntParam(Constants::USER_ID, Constants::INVALID_USERID);
    int32_t appIndex = want.GetIntParam(Constants::APP_INDEX, Constants::DEFAULT_APP_INDEX);
    APP_LOGD("OnReceiveEvent action = %{public}s, bundle = %{public}s, userId = %{public}d, appIndex = %{public}d",
        action.c_str(), bundleName.c_str(), userId, appIndex);
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED) {
        BundleMonitorEmit(ADD, bundleName, userId, appIndex);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED) {
        BundleMonitorEmit(UPDATE, bundleName, userId, appIndex);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) {
        BundleMonitorEmit(REMOVE, bundleName, userId, appIndex);
    } else {
        APP_LOGI("OnReceiveEvent action = %{public}s not support", action.c_str());
    }
}
}
}