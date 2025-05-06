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

#include "ani_bundle_monitor_callback_handler.h"

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "common_fun_ani.h"
#include "common_func.h"

namespace OHOS {
namespace AppExecFwk {

ANIBundleMonitorCallbackHandler::~ANIBundleMonitorCallbackHandler()
{
    stopFlag_ = true;
}

void ANIBundleMonitorCallbackHandler::AddCallback(ani_env* env, ani_object aniCallback)
{
    APP_LOGI("AddCallback entry");
    RETURN_IF_NULL(env);
    std::lock_guard<std::mutex> lock(callbackMutex_);
    for (auto iter = callbackList_.begin(); iter != callbackList_.end(); ++iter) {
        ani_boolean isEqual = ANI_FALSE;
        env->Reference_StrictEquals(aniCallback, *iter, &isEqual);
        if (isEqual == ANI_TRUE) {
            APP_LOGI("callback already exists");
            return;
        }
    }
    ani_ref callbackRef = nullptr;
    ani_status status = env->GlobalReference_Create(aniCallback, &callbackRef);
    if (status != ANI_OK) {
        APP_LOGE("GlobalReference_Create error. result: %{public}d", status);
        return;
    }
    if (callbackRef == nullptr) {
        APP_LOGE("callbackRef is null");
        return;
    }
    callbackList_.push_back(callbackRef);
    APP_LOGI("AddCallback exit");
}

void ANIBundleMonitorCallbackHandler::RemoveCallback(ani_env* env, ani_object aniCallback)
{
    APP_LOGI("RemoveCallback entry");
    RETURN_IF_NULL(env);
    std::lock_guard<std::mutex> lock(callbackMutex_);
    for (auto iter = callbackList_.begin(); iter != callbackList_.end();) {
        ani_boolean isEqual = ANI_FALSE;
        env->Reference_StrictEquals(aniCallback, *iter, &isEqual);
        if (isEqual == ANI_TRUE) {
            if (notifyCounter_ == 0) {
                APP_LOGD("direct clear");
                env->GlobalReference_Delete(*iter);
            } else {
                removedCallbackList_.emplace_back(*iter);
                APP_LOGD("delayed clear, size: %{public}d", removedCallbackList_.size());
            }
            iter = callbackList_.erase(iter);
            break;
        } else {
            ++iter;
        }
    }
    APP_LOGI("RemoveCallback exit");
}

void ANIBundleMonitorCallbackHandler::RemoveAllCallback(ani_env* env)
{
    APP_LOGI("RemoveAllCallback entry");
    RETURN_IF_NULL(env);
    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (notifyCounter_ == 0) {
        APP_LOGD("direct clear");
        ClearCallbackList(env, callbackList_);
    } else {
        removedCallbackList_.splice(removedCallbackList_.end(), callbackList_);
        APP_LOGD("delayed clear, size: %{public}d", removedCallbackList_.size());
    }
    APP_LOGI("RemoveAllCallback exit");
}

void ANIBundleMonitorCallbackHandler::InvokeCallback(ani_env* env, const BundleChangedInfo& info)
{
    APP_LOGI("InvokeCallback entry");
    RETURN_IF_NULL(env);
    ani_object aniInfo = CommonFunAni::CreateBundleChangedInfo(env, info.bundleName, info.userId, info.appIndex);
    if (aniInfo == nullptr) {
        APP_LOGE("CreateBundleChangedInfo failed");
        return;
    }
    std::vector<ani_ref> callbackArgs = { aniInfo };
    std::list<ani_ref> callbackListSnapshot;
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        ++notifyCounter_;
        callbackListSnapshot = callbackList_;
    }
    for (const auto& callbackRef : callbackListSnapshot) {
        if (stopFlag_) {
            return;
        }
        auto fnObject = reinterpret_cast<ani_fn_object>(callbackRef);
        if (fnObject == nullptr) {
            APP_LOGE("fnObject is null");
            continue;
        }
        ani_ref result = nullptr;
        ani_status ret = env->FunctionalObject_Call(fnObject, callbackArgs.size(), callbackArgs.data(), &result);
        if (ret != ANI_OK) {
            APP_LOGE("FunctionalObject_Call failed: %{public}d", ret);
        }
    }
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        --notifyCounter_;
        if (notifyCounter_ == 0) {
            APP_LOGD("notifyCounter_ is 0, run clear");
            ClearCallbackList(env, removedCallbackList_);
        }
    }
    APP_LOGI("InvokeCallback exit");
}
} // namespace AppExecFwk
} // namespace OHOS