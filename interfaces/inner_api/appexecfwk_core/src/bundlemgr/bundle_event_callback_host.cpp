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

#include "bundle_event_callback_host.h"

#include "app_log_wrapper.h"
#include "ipc_types.h"

namespace OHOS {
namespace AppExecFwk {
BundleEventCallbackHost::BundleEventCallbackHost()
{
    APP_LOGD("create BundleEventCallbackHost");
}

BundleEventCallbackHost::~BundleEventCallbackHost()
{
    APP_LOGD("destroy BundleEventCallbackHost");
}

int BundleEventCallbackHost::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    // to do
    return NO_ERROR;
}
}  // namespace AppExecFwk
}  // namespace OHOS
