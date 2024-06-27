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

#include "bundle_resource_event_subscriber.h"

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_resource_callback.h"
#include "common_event_support.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string OLD_USER_ID = "oldId";
}
BundleResourceEventSubscriber::BundleResourceEventSubscriber(
    const EventFwk::CommonEventSubscribeInfo &subscribeInfo) : EventFwk::CommonEventSubscriber(subscribeInfo)
{}

BundleResourceEventSubscriber::~BundleResourceEventSubscriber()
{}

void BundleResourceEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    BundleResourceCallback callback;
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED) {
        // when reboot, user 0 switch to user 100, no need to flush resource rdb
        static bool isFirstSwitch = true;
        if (!isFirstSwitch) {
            int32_t oldUserId = Constants::INVALID_USERID;
            std::string oldId = data.GetWant().GetStringParam(OLD_USER_ID);
            if (oldId.empty() || !OHOS::StrToInt(oldId, oldUserId)) {
                APP_LOGE("oldId:%{public}s parse failed", oldId.c_str());
                oldUserId = Constants::INVALID_USERID;
            }
            callback.OnUserIdSwitched(oldUserId, data.GetCode());
        }
        isFirstSwitch = false;
    }
    // for other event
}
}  // namespace AppExecFwk
}  // namespace OHOS
