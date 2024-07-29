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

#include "bundle_resource_register.h"

#include "app_log_wrapper.h"
#include "bundle_resource_event_subscriber.h"
#ifdef ABILITY_RUNTIME_ENABLE
#include "app_mgr_client.h"
#include "bundle_resource_observer.h"
#endif
#include "common_event_manager.h"
#include "common_event_support.h"

namespace OHOS {
namespace AppExecFwk {
void BundleResourceRegister::RegisterConfigurationObserver()
{
#ifdef ABILITY_RUNTIME_ENABLE
    APP_LOGI("start");
    sptr<IConfigurationObserver> observer(new (std::nothrow) BundleResourceObserver());
    if (observer == nullptr) {
        APP_LOGE("fail to create observer");
        return;
    }
    auto appMgrClient = std::make_unique<AppMgrClient>();
    if (appMgrClient == nullptr) {
        APP_LOGE("fail to create appMgrClient");
        return;
    }
    appMgrClient->RegisterConfigurationObserver(observer);
    APP_LOGI("end");
#else
    APP_LOGI("ability runtime not support");
#endif
}

void BundleResourceRegister::RegisterCommonEventSubscriber()
{
    APP_LOGI("start");
    EventFwk::MatchingSkills matchingSkills;
    // for user changed
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);

    auto subscriberPtr = std::make_shared<BundleResourceEventSubscriber>(subscribeInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(subscriberPtr)) {
        APP_LOGE("subscribe event %{public}s failed",
            EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED.c_str());
        return;
    }
    APP_LOGI("end");
}
} // AppExecFwk
} // OHOS
