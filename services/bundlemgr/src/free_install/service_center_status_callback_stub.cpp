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

#include "service_center_status_callback_stub.h"

#include "app_log_tag_wrapper.h"
#include "app_log_wrapper.h"
#include "bundle_memory_guard.h"
#include "free_install_params.h"
#include "message_parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::u16string SEEVICE_CENTER_CALLBACK_TOKEN = u"abilitydispatcherhm.openapi.hapinstall.IHapInstallCallback";
}

ServiceCenterStatusCallbackStub::ServiceCenterStatusCallbackStub()
{
    LOG_I(BMS_TAG_FREE_INSTALL, "ServiceCenterStatusCallbackStub is created");
}

int32_t ServiceCenterStatusCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    BundleMemoryGuard memoryGuard;
    if (data.ReadInterfaceToken() != SEEVICE_CENTER_CALLBACK_TOKEN) {
        LOG_E(BMS_TAG_FREE_INSTALL, "verify interface token failed");
        return -1;
    }

    auto result = data.ReadString16();
    LOG_D(BMS_TAG_FREE_INSTALL, "OnRemoteRequest:code:%{public}d, result:%{public}s",
        code, Str16ToStr8(result).c_str());
    return OnInstallFinished(Str16ToStr8(result));
}
}  // namespace AppExecFwk
}  // namespace OHOS
