/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "app_log_wrapper.h"
#include "bundle_status_callback.h"

#include "napi/native_common.h"

BundleStatusCallback::BundleStatusCallback(napi_env env, napi_ref addedCallback,
                                           napi_ref updatedCallback,
                                           napi_ref removeCallback)
    : env_(env), addedCallback_(addedCallback),
      updatedCallback_(updatedCallback), removeCallback_(removeCallback) {}

BundleStatusCallback::~BundleStatusCallback()
{
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    uv_work_t* work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        return;
    }
    DelRefCallbackInfo* delRefCallbackInfo = new (std::nothrow) DelRefCallbackInfo {
        .env_ = env_,
        .addedCallback_ = addedCallback_,
        .updatedCallback_ = updatedCallback_,
        .removeCallback_ = removeCallback_,
    };
    if (delRefCallbackInfo == nullptr) {
        delete work;
        return;
    }
    work->data = reinterpret_cast<void*>(delRefCallbackInfo);
    int ret = uv_queue_work(
        loop, work, [](uv_work_t* work) { APP_LOGI("~BundleStatusCallback asyn work done"); },
        [](uv_work_t* work, int status) {
            // JS Thread
            DelRefCallbackInfo* delRefCallbackInfo = reinterpret_cast<DelRefCallbackInfo*>(work->data);
            if (delRefCallbackInfo == nullptr) {
                return;
            }
            napi_delete_reference(delRefCallbackInfo->env_, delRefCallbackInfo->addedCallback_);
            napi_delete_reference(delRefCallbackInfo->env_, delRefCallbackInfo->updatedCallback_);
            napi_delete_reference(delRefCallbackInfo->env_, delRefCallbackInfo->removeCallback_);
            delete delRefCallbackInfo;
            delRefCallbackInfo = nullptr;
            delete work;
            work = nullptr;
        });
    if (ret != 0) {
        delete delRefCallbackInfo;
        delete work;
    }
}

void BundleStatusCallback::OnBundleAdded(const std::string& bundleName, const int userId, const int32_t appIndex)
{
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    uv_work_t* work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        APP_LOGW("BundleStatusCallback OnBundleAdded work is nullptr bundleName : %{public}s", bundleName.c_str());
        return;
    }
    AsyncCallbackInfo* asyncCallbackInfo = new (std::nothrow)AsyncCallbackInfo {
        .env_ = env_,
        .callback_ = addedCallback_,
        .bundleName_ = bundleName,
        .userId_ = userId,
        .appIndex_ = appIndex,
    };
    if (asyncCallbackInfo == nullptr) {
        APP_LOGW("BundleStatusCallback OnBundleAdded asyncCallbackInfo is nullptr bundleName : %{public}s",
            bundleName.c_str());
        delete work;
        return;
    }
    work->data = reinterpret_cast<void*>(asyncCallbackInfo);
    if (loop == nullptr) {
        APP_LOGW("BundleStatusCallback OnBundleAdded loop is nullptr bundleName : %{public}s", bundleName.c_str());
        delete work;
        return;
    }
    int ret = uv_queue_work(
        loop, work, [](uv_work_t* work) { APP_LOGI("BundleStatusCallback OnBundleAdded asyn work done"); },
        [](uv_work_t* work, int status) {
            // JS Thread
            APP_LOGI("BundleStatusCallback OnBundleAdded in JS Thread");
            AsyncCallbackInfo* asyncCallbackInfo =  reinterpret_cast<AsyncCallbackInfo*>(work->data);
            if (asyncCallbackInfo == nullptr) {
                APP_LOGE("asyncCallbackInfo is null");
                return;
            }
            std::unique_ptr<AsyncCallbackInfo> callbackPtr {asyncCallbackInfo};
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(asyncCallbackInfo->env_, &scope);
            if (scope == nullptr) {
                APP_LOGE("scope is null");
                return;
            }
            napi_value callback = nullptr;
            napi_value placeHolder = nullptr;
            napi_value result[2] = { 0 };
            napi_get_reference_value(asyncCallbackInfo->env_, asyncCallbackInfo->callback_, &callback);
            napi_create_string_utf8(
                asyncCallbackInfo->env_, asyncCallbackInfo->bundleName_.c_str(), NAPI_AUTO_LENGTH, &result[0]);
            napi_create_uint32(asyncCallbackInfo->env_, asyncCallbackInfo->userId_, &result[1]);
            napi_create_uint32(asyncCallbackInfo->env_, asyncCallbackInfo->appIndex_, &result[2]);
            napi_call_function(
                asyncCallbackInfo->env_, nullptr, callback, sizeof(result) / sizeof(result[0]), result, &placeHolder);
            napi_close_handle_scope(asyncCallbackInfo->env_, scope);
            if (work != nullptr) {
                delete work;
                work = nullptr;
            }
        });
    if (ret != 0) {
        APP_LOGE("OnBundleAdded failed due to call uv_queue_work failed");
        delete asyncCallbackInfo;
        delete work;
    }
}

void BundleStatusCallback::OnBundleUpdated(const std::string& bundleName, const int userId, const int32_t appIndex)
{
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    uv_work_t* work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        APP_LOGW("BundleStatusCallback OnBundleUpdated work is nullptr bundleName : %{public}s", bundleName.c_str());
        return;
    }
    AsyncCallbackInfo* asyncCallbackInfo = new (std::nothrow) AsyncCallbackInfo {
        .env_ = env_,
        .callback_ = updatedCallback_,
        .bundleName_ = bundleName,
        .userId_ = userId,
        .appIndex_ = appIndex,
    };
    if (asyncCallbackInfo == nullptr) {
        APP_LOGW("BundleStatusCallback OnBundleUpdated asyncCallbackInfo is nullptr bundleName : %{public}s",
            bundleName.c_str());
        delete work;
        return;
    }
    work->data = reinterpret_cast<void*>(asyncCallbackInfo);
    if (loop == nullptr) {
        APP_LOGW("BundleStatusCallback OnBundleUpdated loop is nullptr bundleName : %{public}s", bundleName.c_str());
        delete work;
        return;
    }
    int ret = uv_queue_work(
        loop, work, [](uv_work_t* work) { APP_LOGI("BundleStatusCallback OnBundleUpdated asyn work done"); },
        [](uv_work_t* work, int status) {
            APP_LOGI("BundleStatusCallback OnBundleUpdated in JS Thread");
            AsyncCallbackInfo* asyncCallbackInfo = reinterpret_cast<AsyncCallbackInfo*>(work->data);
            if (asyncCallbackInfo == nullptr) {
                APP_LOGE("asyncCallbackInfo is null");
                return;
            }
            std::unique_ptr<AsyncCallbackInfo> callbackPtr {asyncCallbackInfo};
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(asyncCallbackInfo->env_, &scope);
            if (scope == nullptr) {
                APP_LOGE("scope is null");
                return;
            }
            napi_value callback = nullptr;
            napi_value placeHolder = nullptr;
            napi_value result[2] = { 0 };
            napi_get_reference_value(asyncCallbackInfo->env_, asyncCallbackInfo->callback_, &callback);
            napi_create_string_utf8(
                asyncCallbackInfo->env_, asyncCallbackInfo->bundleName_.c_str(), NAPI_AUTO_LENGTH, &result[0]);
            napi_create_uint32(asyncCallbackInfo->env_, asyncCallbackInfo->userId_, &result[1]);
            napi_create_uint32(asyncCallbackInfo->env_, asyncCallbackInfo->appIndex_, &result[2]);
            napi_call_function(
                asyncCallbackInfo->env_, nullptr, callback, sizeof(result) / sizeof(result[0]), result, &placeHolder);
            napi_close_handle_scope(asyncCallbackInfo->env_, scope);
            if (work != nullptr) {
                delete work;
                work = nullptr;
            }
        });
    if (ret != 0) {
        APP_LOGE("OnBundleUpdated failed due to call uv_queue_work failed");
        if (asyncCallbackInfo != nullptr) {
            delete asyncCallbackInfo;
        }
        if (work != nullptr) {
            delete work;
        }
    }
}

void BundleStatusCallback::OnBundleRemoved(const std::string& bundleName, const int userId, const int32_t appIndex)
{
    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    uv_work_t* work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        APP_LOGW("BundleStatusCallback OnBundleRemoved work is nullptr bundleName : %{public}s", bundleName.c_str());
        return;
    }
    AsyncCallbackInfo* asyncCallbackInfo = new (std::nothrow) AsyncCallbackInfo {
        .env_ = env_,
        .callback_ = removeCallback_,
        .bundleName_ = bundleName,
        .userId_ = userId,
        .appIndex_ = appIndex,
    };
    if (asyncCallbackInfo == nullptr) {
        APP_LOGW("BundleStatusCallback OnBundleUpdated asyncCallbackInfo is nullptr bundleName : %{public}s",
            bundleName.c_str());
        delete work;
        return;
    }
    work->data = reinterpret_cast<void*>(asyncCallbackInfo);
    if (loop == nullptr) {
        APP_LOGW("BundleStatusCallback OnBundleRemoved loop is nullptr bundleName : %{public}s", bundleName.c_str());
        delete work;
        return;
    }
    int ret = uv_queue_work(
        loop, work, [](uv_work_t* work) { APP_LOGI("BundleStatusCallback OnBundleRemoved asyn work done"); },
        [](uv_work_t* work, int status) {
            APP_LOGI("BundleStatusCallback OnBundleRemoved in JS Thread");
            // JS Thread
            AsyncCallbackInfo* asyncCallbackInfo =  reinterpret_cast<AsyncCallbackInfo*>(work->data);
            if (asyncCallbackInfo == nullptr) {
                APP_LOGE("asyncCallbackInfo is null");
                return;
            }
            std::unique_ptr<AsyncCallbackInfo> callbackPtr {asyncCallbackInfo};
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(asyncCallbackInfo->env_, &scope);
            if (scope == nullptr) {
                APP_LOGE("scope is null");
                return;
            }
            napi_value callback = nullptr;
            napi_value placeHolder = nullptr;
            napi_value result[2] = { 0 };
            napi_get_reference_value(asyncCallbackInfo->env_, asyncCallbackInfo->callback_, &callback);
            napi_create_string_utf8(
                asyncCallbackInfo->env_, asyncCallbackInfo->bundleName_.c_str(), NAPI_AUTO_LENGTH, &result[0]);
            napi_create_uint32(asyncCallbackInfo->env_, asyncCallbackInfo->userId_, &result[1]);
            napi_create_uint32(asyncCallbackInfo->env_, asyncCallbackInfo->appIndex_, &result[2]);
            napi_call_function(
                asyncCallbackInfo->env_, nullptr, callback, sizeof(result) / sizeof(result[0]), result, &placeHolder);
            napi_close_handle_scope(asyncCallbackInfo->env_, scope);
            if (work != nullptr) {
                delete work;
                work = nullptr;
            }
        });
    if (ret != 0) {
        APP_LOGE("OnBundleRemoved failed due to call uv_queue_work failed");
        delete asyncCallbackInfo;
        delete work;
    }
}