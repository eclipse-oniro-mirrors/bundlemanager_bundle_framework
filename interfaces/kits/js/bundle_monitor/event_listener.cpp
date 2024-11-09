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

void HandleEnvCleanup(void *data)
{
    if (data != nullptr) {
        EventListener *evtListener = static_cast<EventListener *>(data);
        evtListener->SetValid(false);
    }
}

EventListener::EventListener(napi_env env, const std::string& type) : env_(env), type_(type)
{
    napi_status status = napi_add_env_cleanup_hook(env_, HandleEnvCleanup, this);
    APP_LOGD("EventListener() %{public}d", status);
}

EventListener::~EventListener()
{
    napi_status status = napi_remove_env_cleanup_hook(env_, HandleEnvCleanup, this);
    APP_LOGD("~EventListener() %{public}d", status);
}

void EventListener::Add(napi_env env, napi_value handler)
{
    APP_LOGD("Add Init");
    if (!HasSameEnv(env) || Find(handler)) {
        return;
    }
    napi_ref callbackRef = nullptr;
    napi_create_reference(env_, handler, 1, &callbackRef);
    callbackRefs_.push_back(callbackRef);
}

void EventListener::Delete(napi_env env, napi_value handler)
{
    APP_LOGD("Delete Init");
    if (!HasSameEnv(env)) {
        return;
    }
    for (auto it = callbackRefs_.begin(); it != callbackRefs_.end();) {
        napi_value callback = nullptr;
        napi_get_reference_value(env_, *it, &callback);
        bool isEquals = false;
        napi_strict_equals(env_, handler, callback, &isEquals);
        if (isEquals) {
            napi_delete_reference(env_, *it);
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
        napi_get_reference_value(env_, callbackRef, &callback);
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

void EventListener::EmitOnUV(const std::string &bundleName, int32_t userId, int32_t appIndex, napi_ref callbackRef)
{
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    uv_work_t* work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        return;
    }
    AsyncCallbackInfo *asyncCallbackInfo = new (std::nothrow) AsyncCallbackInfo {
        .env = env_,
        .bundleName = bundleName,
        .userId = userId,
        .appIndex = appIndex,
        .callbackRef = callbackRef,
    };
    if (asyncCallbackInfo == nullptr) {
        delete work;
        return;
    }
    work->data = reinterpret_cast<void*>(asyncCallbackInfo);
    int ret = uv_queue_work(
        loop, work, [](uv_work_t* work) { APP_LOGI("EmitOnUV asyn work done"); },
        [](uv_work_t* work, int status) {
            AsyncCallbackInfo* asyncCallbackInfo = reinterpret_cast<AsyncCallbackInfo*>(work->data);
            if (asyncCallbackInfo == nullptr) {
                return;
            }
            std::unique_ptr<AsyncCallbackInfo> callbackPtr {asyncCallbackInfo};
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(asyncCallbackInfo->env, &scope);
            if (scope == nullptr) {
                return;
            }
            napi_value callback = nullptr;
            napi_value result[ARGS_SIZE_ONE] = { 0 };
            napi_value placeHolder = nullptr;
            napi_get_reference_value(asyncCallbackInfo->env, asyncCallbackInfo->callbackRef, &callback);
            CHKRV_SCOPE(asyncCallbackInfo->env, napi_create_object(asyncCallbackInfo->env,
                &result[ARGS_POS_ZERO]), scope);
            CommonFunc::ConvertBundleChangeInfo(asyncCallbackInfo->env, asyncCallbackInfo->bundleName,
                asyncCallbackInfo->userId, asyncCallbackInfo->appIndex, result[0]);
            napi_call_function(asyncCallbackInfo->env, nullptr,
                callback, sizeof(result) / sizeof(result[0]), result, &placeHolder);
            napi_close_handle_scope(asyncCallbackInfo->env, scope);
            if (work != nullptr) {
                delete work;
                work = nullptr;
            }
        });
    if (ret != 0) {
        delete asyncCallbackInfo;
        delete work;
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