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

#include "bundle_event_callback_proxy.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "ipc_types.h"
#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {
BundleEventCallbackProxy::BundleEventCallbackProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<IBundleEventCallback>(object)
{
    APP_LOGD("create BundleEventCallbackProxy");
}

BundleEventCallbackProxy::~BundleEventCallbackProxy()
{
    APP_LOGD("destroy BundleEventCallbackProxy");
}

void BundleEventCallbackProxy::OnReceiveEvent(const EventFwk::CommonEventData eventData)
{
    APP_LOGD("begin of OnReceiveEvent");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!data.WriteInterfaceToken(BundleEventCallbackProxy::GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed");
        return;
    }
    if (!data.WriteParcelable(&eventData)) {
        APP_LOGE("write CommonEventData failed");
        return;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        APP_LOGE("remote is null");
        return;
    }
    int32_t ret = remote->SendRequest(
        static_cast<int32_t>(BundleEventCallbackInterfaceCode::ON_RECEIVE_EVENT), data, reply, option);
    if (ret != ERR_OK) {
        APP_LOGW("SendRequest failed err %{public}d", ret);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
