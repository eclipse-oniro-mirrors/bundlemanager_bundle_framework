/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "app_log_wrapper.h"
#include "common_event_support.h"
#include "service_router_data_mgr.h"
#include "sr_common_event_subscriber.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
SrCommonEventSubscriber::SrCommonEventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscribeInfo)
    : EventFwk::CommonEventSubscriber(subscribeInfo)
{
    APP_LOGD("SrCommonEventSubscriber created");
}

SrCommonEventSubscriber::~SrCommonEventSubscriber()
{
    APP_LOGD("SrCommonEventSubscriber destroyed");
}

void SrCommonEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &eventData)
{
    const AAFwk::Want& want = eventData.GetWant();
    std::string action = want.GetAction();
    std::string bundleName = want.GetElement().GetBundleName();
    if (action.empty() || eventHandler_ == nullptr) {
        APP_LOGE("%{public}s failed, empty action: %{public}s, or invalid event handler", __func__, action.c_str());
        return;
    }
    if (bundleName.empty() && action != EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED) {
        APP_LOGE("%{public}s failed, invalid param, action: %{public}s, bundleName: %{public}s",
            __func__, action.c_str(), bundleName.c_str());
        return;
    }
    APP_LOGI("%{public}s, action:%{public}s.", __func__, action.c_str());
    std::weak_ptr<SrCommonEventSubscriber> weakThis = shared_from_this();
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED) {
        int32_t userId = eventData.GetCode();
        auto task = [weakThis, userId]() {
            std::shared_ptr<SrCommonEventSubscriber> sharedThis = weakThis.lock();
            if (sharedThis) {
                APP_LOGI("%{public}d COMMON_EVENT_USER_SWITCHED", userId);
                ServiceRouterDataMgr::GetInstance().LoadAllBundleInfos();
            }
        };
        eventHandler_->PostTask(task);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED ||
        action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED) {
        int32_t userId = want.GetIntParam("userId", Constants::DEFAULT_USERID);
        auto task = [weakThis, bundleName, userId]() {
            APP_LOGI("bundle changed, bundleName: %{public}s, userId: %{public}d", bundleName.c_str(), userId);
            std::shared_ptr<SrCommonEventSubscriber> sharedThis = weakThis.lock();
            if (sharedThis) {
                ServiceRouterDataMgr::GetInstance().LoadBundleInfo(bundleName);
            }
        };
        eventHandler_->PostTask(task);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) {
        int32_t userId = want.GetIntParam("userId", Constants::DEFAULT_USERID);
        auto task = [weakThis, bundleName, userId]() {
            APP_LOGI("bundle remove, bundleName: %{public}s, userId: %{public}d", bundleName.c_str(), userId);
            std::shared_ptr<SrCommonEventSubscriber> sharedThis = weakThis.lock();
            if (sharedThis) {
                ServiceRouterDataMgr::GetInstance().DeleteBundleInfo(bundleName);
            }
        };
        eventHandler_->PostTask(task);
    } else {
        APP_LOGW("%{public}s warnning, invalid action.", __func__);
    }
}
} // AppExecFwk
} // OHOS