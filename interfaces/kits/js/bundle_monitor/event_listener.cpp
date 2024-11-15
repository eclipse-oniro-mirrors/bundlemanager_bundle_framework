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

#include "event_listener.h"

#include "app_log_wrapper.h"
#include "common_func.h"
#include "napi/native_common.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* RESOURCE_NAME = "bmsMonitor";
};

void HandleEnvCleanup(void *data)
{
    APP_LOGI("env clean");
    if (data != nullptr) {
        EventListener *evtListener = static_cast<EventListener *>(data);
        evtListener->SetValid(false);
    }
}

void JsCallback(napi_env env, napi_value jsCb, void *context, void *data)
{
    APP_LOGD("JsCallback");
    AsyncCallbackInfo *asyncCallbackInfo = static_cast<AsyncCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        return;
    }
    std::unique_ptr<AsyncCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    if (scope == nullptr) {
        return;
    }
    napi_value result[ARGS_SIZE_ONE] = { 0 };
    napi_value placeHolder = nullptr;
    CHKRV_SCOPE(env, napi_create_object(env, &result[ARGS_POS_ZERO]), scope);
    CommonFunc::ConvertBundleChangeInfo(env, asyncCallbackInfo->bundleName,
        asyncCallbackInfo->userId, asyncCallbackInfo->appIndex, result[0]);
    napi_status status = napi_call_function(env, nullptr,
        jsCb, sizeof(result) / sizeof(result[0]), result, &placeHolder);
    if (status != napi_ok) {
        APP_LOGE("napi call %{public}d", status);
    }
    napi_close_handle_scope(env, scope);
    APP_LOGD("JsCallback OK");
}

EventListener::EventListener(napi_env env, const std::string& type) : env_(env), type_(type)
{
    napi_status status = napi_add_env_cleanup_hook(env_, HandleEnvCleanup, this);
    APP_LOGI("EventListener() %{public}d", status);
}

EventListener::~EventListener()
{
    napi_status status = napi_remove_env_cleanup_hook(env_, HandleEnvCleanup, this);
    APP_LOGI("~EventListener() %{public}d", status);
}

void EventListener::Add(napi_env env, napi_value handler)
{
    APP_LOGD("Add Init");
    if (!HasSameEnv(env) || Find(handler)) {
        return;
    }
    napi_ref callbackRef = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_reference(env_, handler, 1, &callbackRef));
    napi_threadsafe_function tsfn = nullptr;
    napi_value resName = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, RESOURCE_NAME, NAPI_AUTO_LENGTH, &resName));
    NAPI_CALL_RETURN_VOID(env, napi_create_threadsafe_function(env, handler,
        nullptr, resName, 0, 1, nullptr, nullptr, nullptr, JsCallback, &tsfn));

    callbackRefs_.push_back(std::make_pair(callbackRef, tsfn));
}

void EventListener::Delete(napi_env env, napi_value handler)
{
    APP_LOGD("Delete Init");
    if (!HasSameEnv(env)) {
        return;
    }
    for (auto it = callbackRefs_.begin(); it != callbackRefs_.end();) {
        napi_value callback = nullptr;
        napi_get_reference_value(env_, (*it).first, &callback);
        bool isEquals = false;
        napi_strict_equals(env_, handler, callback, &isEquals);
        if (isEquals) {
            napi_delete_reference(env_, (*it).first);
            napi_release_threadsafe_function((*it).second, napi_threadsafe_function_release_mode::napi_tsfn_release);
            it = callbackRefs_.erase(it);
        } else {
            ++it;
        }
    }
}

void EventListener::DeleteAll()
{
    callbackRefs_.clear();
}

bool EventListener::Find(napi_value handler)
{
    for (const auto &callbackRef : callbackRefs_) {
        napi_value callback = nullptr;
        napi_get_reference_value(env_, callbackRef.first, &callback);
        bool isEquals = false;
        napi_strict_equals(env_, handler, callback, &isEquals);
        if (isEquals) {
            return true;
        }
    }
    return false;
}

// operator on js thread
void EventListener::Emit(std::string &bundleName, int32_t userId, int32_t appIndex)
{
    APP_LOGD("EventListener Emit Init callback size is %{publuic}d",
        static_cast<int32_t>(callbackRefs_.size()));
    std::lock_guard<std::mutex> lock(validMutex_);
    if (!valid_) {
        APP_LOGE("env is invalid");
        return;
    }
    for (const auto &callbackRef : callbackRefs_) {
        EmitOnUV(bundleName, userId, appIndex, callbackRef);
    }
}

void EventListener::EmitOnUV(const std::string &bundleName, int32_t userId, int32_t appIndex,
    std::pair<napi_ref, napi_threadsafe_function> callbackRef)
{
    NAPI_CALL_RETURN_VOID(env_, napi_acquire_threadsafe_function(callbackRef.second));
    AsyncCallbackInfo *asyncCallbackInfo = new (std::nothrow) AsyncCallbackInfo {
        .bundleName = bundleName,
        .userId = userId,
        .appIndex = appIndex,
    };
    napi_status status = napi_call_threadsafe_function(callbackRef.second, asyncCallbackInfo,
        napi_threadsafe_function_call_mode::napi_tsfn_nonblocking);
    if (status != napi_ok) {
        APP_LOGE("napi call safe %{public}d", status);
        delete asyncCallbackInfo;
    }
}

bool EventListener::HasSameEnv(napi_env env) const
{
    return env_ == env;
}

void EventListener::SetValid(bool valid)
{
    std::lock_guard<std::mutex> lock(validMutex_);
    valid_ = valid;
    if (!valid) {
        env_ = nullptr;
    }
}
}
}