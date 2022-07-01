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

#include "bundle_manager_callback_stub.h"

#include "app_log_wrapper.h"
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
    std::string token = Str16ToStr8(data.ReadInterfaceToken());
    std::string queryRpcIdResult = Str16ToStr8(data.ReadString16());
    APP_LOGI("BundleManagerCallbackStub code:%{public}d, queryRpcIdResult:%{public}s",
        code, queryRpcIdResult.c_str());
    return OnQueryRpcIdFinished(queryRpcIdResult);
}
}  // namespace AppExecFwk
}  // namespace OHOS