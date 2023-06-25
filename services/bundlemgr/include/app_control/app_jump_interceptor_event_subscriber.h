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

#ifndef FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_SERVICES_INCLUDE_APP_JUMP_INTERCEPTOR_EVENT_SUBSCRIBER_H
#define FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_SERVICES_INCLUDE_APP_JUMP_INTERCEPTOR_EVENT_SUBSCRIBER_H

#include "app_jump_interceptor_manager_db_interface.h"
#include "bundle_event_callback_host.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"

namespace OHOS {
namespace AppExecFwk {
class AppJumpInterceptorEventSubscriber : public BundleEventCallbackHost,
    public std::enable_shared_from_this<AppJumpInterceptorEventSubscriber> {
public:
    AppJumpInterceptorEventSubscriber(const std::shared_ptr<IAppJumpInterceptorlManagerDb> &appJumpDb);

    ~AppJumpInterceptorEventSubscriber();

    void OnReceiveEvent(const EventFwk::CommonEventData eventData) override;

private:
    std::shared_ptr<IAppJumpInterceptorlManagerDb> appJumpDb_ = nullptr;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_SERVICE_ROUTER_FRAMEWORK_SERVICES_INCLUDE_APP_JUMP_INTERCEPTOR_EVENT_SUBSCRIBER_H