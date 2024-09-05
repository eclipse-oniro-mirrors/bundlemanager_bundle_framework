/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "bundle_manager_callback_stub.h"

#include "app_log_wrapper.h"
#include "bundle_framework_services_ipc_interface_code.h"
#include "bundle_memory_guard.h"
#include "message_parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
BundleManagerCallbackStub::BundleManagerCallbackStub()
{
    APP_LOGI("BundleManagerCallbackStub is created");
}

int32_t BundleManagerCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    BundleMemoryGuard memoryGuard;
    APP_LOGI("bundle mgr callback onReceived message, message code %{public}u", code);
    std::u16string descriptor = BundleManagerCallbackStub::GetDescriptor();
    std::u16string token = data.ReadInterfaceToken();
    if (descriptor != token) {
        APP_LOGE("OnRemoteRequest token is invalid");
        return OBJECT_NULL;
    }
    switch (code) {
        case static_cast<uint32_t>(BundleManagerCallbackInterfaceCode::QUERY_RPC_ID_CALLBACK):
            return HandleQueryRpcIdCallBack(data, reply);
        default:
            APP_LOGW("BundleManagerCallbackStub receives unknown code %{public}d", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return NO_ERROR;
}

int32_t BundleManagerCallbackStub::HandleQueryRpcIdCallBack(MessageParcel &data, MessageParcel &reply)
{
    std::string queryRpcIdResult = Str16ToStr8(data.ReadString16());
    return OnQueryRpcIdFinished(queryRpcIdResult);
}
}  // namespace AppExecFwk
}  // namespace OHOS