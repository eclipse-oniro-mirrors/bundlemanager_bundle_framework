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
    DelRefCallbackInfo* delRefCallbackInfo = new (std::nothrow) DelRefCallbackInfo {
        .env_ = env_,
        .addedCallback_ = addedCallback_,
        .updatedCallback_ = updatedCallback_,
        .removeCallback_ = removeCallback_,
    };
    if (delRefCallbackInfo == nullptr) {
        ReleaseAll();
        return;
    }
    auto task = [delRefCallbackInfo]() {
        APP_LOGI("~BundleStatusCallback start");
        // JS Thread
        if (delRefCallbackInfo == nullptr) {
            return;
        }
        napi_delete_reference(delRefCallbackInfo->env_, delRefCallbackInfo->addedCallback_);
        napi_delete_reference(delRefCallbackInfo->env_, delRefCallbackInfo->updatedCallback_);
        napi_delete_reference(delRefCallbackInfo->env_, delRefCallbackInfo->removeCallback_);
        delete delRefCallbackInfo;
        APP_LOGI("~BundleStatusCallback end");
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_high)) {
        APP_LOGE("~BundleStatusCallback failed due to call napi_send_event failed");
        delete delRefCallbackInfo;
    }
}

void BundleStatusCallback::OnBundleAdded(const std::string& bundleName, const int userId)
{
    AsyncCallbackInfo* asyncCallbackInfo = new (std::nothrow)AsyncCallbackInfo {
        .userId_ = userId,
        .bundleName_ = bundleName,
        .env_ = env_,
        .callback_ = addedCallback_,
    };
    if (asyncCallbackInfo == nullptr) {
        APP_LOGW("BundleStatusCallback OnBundleAdded asyncCallbackInfo is nullptr bundleName : %{public}s",
            bundleName.c_str());
        return;
    }
    auto task = [asyncCallbackInfo]() {
        APP_LOGI("OnBundleAdded start");
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
        napi_call_function(
            asyncCallbackInfo->env_, nullptr, callback, sizeof(result) / sizeof(result[0]), result, &placeHolder);
        napi_close_handle_scope(asyncCallbackInfo->env_, scope);
        APP_LOGI("OnBundleAdded end");
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_high)) {
        APP_LOGE("OnBundleAdded failed due to call uv_queue_work failed");
        delete asyncCallbackInfo;
    }
}

void BundleStatusCallback::OnBundleUpdated(const std::string& bundleName, const int userId)
{
    AsyncCallbackInfo* asyncCallbackInfo = new (std::nothrow) AsyncCallbackInfo {
        .userId_ = userId,
        .bundleName_ = bundleName,
        .env_ = env_,
        .callback_ = updatedCallback_,
    };
    if (asyncCallbackInfo == nullptr) {
        APP_LOGW("BundleStatusCallback OnBundleUpdated asyncCallbackInfo is nullptr bundleName : %{public}s",
            bundleName.c_str());
        return;
    }
    auto task = [asyncCallbackInfo]() {
        APP_LOGI("OnBundleUpdated start");
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
        napi_call_function(
            asyncCallbackInfo->env_, nullptr, callback, sizeof(result) / sizeof(result[0]), result, &placeHolder);
        napi_close_handle_scope(asyncCallbackInfo->env_, scope);
        APP_LOGI("OnBundleUpdated end");
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_high)) {
        APP_LOGE("OnBundleUpdated failed due to call uv_queue_work failed");
        if (asyncCallbackInfo != nullptr) {
            delete asyncCallbackInfo;
        }
    }
}

void BundleStatusCallback::OnBundleRemoved(const std::string& bundleName, const int userId)
{
    AsyncCallbackInfo* asyncCallbackInfo = new (std::nothrow) AsyncCallbackInfo {
        .userId_ = userId,
        .bundleName_ = bundleName,
        .env_ = env_,
        .callback_ = removeCallback_,
    };
    if (asyncCallbackInfo == nullptr) {
        APP_LOGW("BundleStatusCallback OnBundleUpdated asyncCallbackInfo is nullptr bundleName : %{public}s",
            bundleName.c_str());
        return;
    }
    auto task = [asyncCallbackInfo]() {
        APP_LOGI("OnBundleRemoved start");
        // JS Thread
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
        napi_call_function(
            asyncCallbackInfo->env_, nullptr, callback, sizeof(result) / sizeof(result[0]), result, &placeHolder);
        napi_close_handle_scope(asyncCallbackInfo->env_, scope);
        APP_LOGI("OnBundleRemoved end");
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_high)) {
        APP_LOGE("OnBundleRemoved failed due to call napi_send_event failed");
        delete asyncCallbackInfo;
    }
}

void BundleStatusCallback::ReleaseAll()
{
    napi_delete_reference(env_, removeCallback_);
    removeCallback_ = nullptr;
    napi_delete_reference(env_, updatedCallback_);
    updatedCallback_ = nullptr;
    napi_delete_reference(env_, addedCallback_);
    addedCallback_ = nullptr;
}