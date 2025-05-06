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

#include "ani_bundle_monitor_event_handler.h"

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "common_fun_ani.h"
#include "common_func.h"

namespace OHOS {
namespace AppExecFwk {
ANIBundleMonitorEventHandler::ANIBundleMonitorEventHandler(
    ani_vm* vm, const EventFwk::CommonEventSubscribeInfo& subscribeInfo)
    : EventFwk::CommonEventSubscriber(subscribeInfo), vm_(vm)
{}

ANIBundleMonitorEventHandler::~ANIBundleMonitorEventHandler()
{
    addCallbackHandler_.Stop();
    updateCallbackHandler_.Stop();
    removeCallbackHandler_.Stop();
    stopFlag_ = true;
}

void ANIBundleMonitorEventHandler::RegisterBundleChangedEvent(
    ani_env* env, const std::string& eventType, ani_object aniCallback)
{
    RETURN_IF_NULL(env);
    auto id = GetMessageIdByType(eventType);
    switch (id) {
        case MESSAGE_ID::INVOKE_ADD:
            addCallbackHandler_.AddCallback(env, aniCallback);
            break;
        case MESSAGE_ID::INVOKE_UPDATE:
            updateCallbackHandler_.AddCallback(env, aniCallback);
            break;
        case MESSAGE_ID::INVOKE_REMOVE:
            removeCallbackHandler_.AddCallback(env, aniCallback);
            break;
        default:
            break;
    }
}

void ANIBundleMonitorEventHandler::UnregisterBundleChangedEvent(
    ani_env* env, const std::string& eventType, ani_object aniCallback)
{
    RETURN_IF_NULL(env);
    auto id = GetMessageIdByType(eventType);
    switch (id) {
        case MESSAGE_ID::INVOKE_ADD:
            addCallbackHandler_.RemoveCallback(env, aniCallback);
            break;
        case MESSAGE_ID::INVOKE_UPDATE:
            updateCallbackHandler_.RemoveCallback(env, aniCallback);
            break;
        case MESSAGE_ID::INVOKE_REMOVE:
            removeCallbackHandler_.RemoveCallback(env, aniCallback);
            break;
        default:
            break;
    }
}

void ANIBundleMonitorEventHandler::UnregisterBundleChangedEvent(ani_env* env, const std::string& eventType)
{
    RETURN_IF_NULL(env);
    auto id = GetMessageIdByType(eventType);
    switch (id) {
        case MESSAGE_ID::INVOKE_ADD:
            addCallbackHandler_.RemoveAllCallback(env);
            break;
        case MESSAGE_ID::INVOKE_UPDATE:
            updateCallbackHandler_.RemoveAllCallback(env);
            break;
        case MESSAGE_ID::INVOKE_REMOVE:
            removeCallbackHandler_.RemoveAllCallback(env);
            break;
        default:
            break;
    }
}

void ANIBundleMonitorEventHandler::OnReceiveEvent(const EventFwk::CommonEventData& eventData)
{
    OHOS::AAFwk::Want want = eventData.GetWant();
    std::string action = want.GetAction();
    std::string bundleName = want.GetElement().GetBundleName();
    int32_t userId = want.GetIntParam(Constants::USER_ID, Constants::INVALID_USERID);
    int32_t appIndex = want.GetIntParam(Constants::APP_INDEX, Constants::DEFAULT_APP_INDEX);

    APP_LOGI("monitor callback OnReceiveEvent action:%{public}s -n %{public}s -u %{public}d -i %{public}d",
        action.c_str(), bundleName.c_str(), userId, appIndex);
    auto id = GetMessageIdByType(action);
    if (id == MESSAGE_ID::INVALID) {
        APP_LOGW("invalid message id");
        return;
    }
    std::lock_guard lock(messageQueueMutex_);
    messageQueue_.emplace(
        ANIBundleMonitorEventHandlerMessage { id, BundleChangedInfo { bundleName, userId, appIndex } });
    if (processingFlag_) {
        APP_LOGD("processing, leave");
        return;
    }
    processingFlag_ = true;
    APP_LOGD("not processing, start new thread");
    std::thread(&ANIBundleMonitorEventHandler::ProcessMessages, this).detach();
}

void ANIBundleMonitorEventHandler::ProcessMessages()
{
    APP_LOGD("proc thread entry");

    RETURN_IF_NULL(vm_);
    ani_env* env = nullptr;
    ani_options aniArgs { 0, nullptr };
    ani_status status = vm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        APP_LOGE("AttachCurrentThread failed: %{public}d", status);
        processingFlag_ = false;
        return;
    }

    while (true) {
        ANIBundleMonitorEventHandlerMessage message;
        {
            std::lock_guard lock(messageQueueMutex_);
            APP_LOGD("messageQueue_ size: %{public}d", messageQueue_.size());
            if (stopFlag_) {
                processingFlag_ = false;
                APP_LOGD("stop flag, leave");
                return;
            }
            if (messageQueue_.empty()) {
                processingFlag_ = false;
                APP_LOGD("empty queue, leave");
                break;
            }

            message = std::move(messageQueue_.front());
            messageQueue_.pop();
        }

        switch (message.messageId) {
            case MESSAGE_ID::INVOKE_ADD:
                addCallbackHandler_.InvokeCallback(env, message.bundleChangedInfo);
                break;
            case MESSAGE_ID::INVOKE_UPDATE:
                updateCallbackHandler_.InvokeCallback(env, message.bundleChangedInfo);
                break;
            case MESSAGE_ID::INVOKE_REMOVE:
                removeCallbackHandler_.InvokeCallback(env, message.bundleChangedInfo);
                break;
            default:
                APP_LOGE("invalid message id");
                break;
        }
    }

    status = vm_->DetachCurrentThread();
    if (status != ANI_OK) {
        APP_LOGE("DetachCurrentThread failed: %{public}d", status);
    }

    APP_LOGD("proc thread exit");
}
} // namespace AppExecFwk
} // namespace OHOS