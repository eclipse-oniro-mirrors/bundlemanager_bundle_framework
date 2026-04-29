/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "get_largest_items_callback_host.h"

#include "app_log_wrapper.h"
#include "app_log_tag_wrapper.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_memory_guard.h"
#include "ipc_types.h"

namespace OHOS {
namespace AppExecFwk {
GetLargestItemsCallbackHost::GetLargestItemsCallbackHost()
{
    LOG_I(BMS_TAG_QUERY, "create get largest items callback host instance");
}

GetLargestItemsCallbackHost::~GetLargestItemsCallbackHost()
{
    LOG_I(BMS_TAG_QUERY, "destroy get largest items callback host instance");
}

int GetLargestItemsCallbackHost::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    BundleMemoryGuard memoryGuard;
    LOG_D(BMS_TAG_QUERY, "get largest items callback host onReceived message, the message code is %{public}u", code);
    std::u16string descripter = GetLargestItemsCallbackHost::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        LOG_E(BMS_TAG_QUERY, "descripter is not matched");
        return OBJECT_NULL;
    }

    switch (code) {
        case static_cast<uint32_t>(GetLargestItemsCallbackInterfaceCode::ON_GET_LARGEST_ITEMS_CALLBACK): {
            ErrCode errCode = data.ReadInt32();
            // Read size and data using ReadRawData
            size_t dataSize = data.ReadUint64();
            std::string largestItems;
            if (dataSize > 0) {
                const void *buffer = data.ReadRawData(dataSize);
                if (buffer != nullptr) {
                    largestItems.assign(reinterpret_cast<const char*>(buffer), dataSize);
                }
            }
            OnGetLargestItemsFinished(errCode, largestItems);
            break;
        }
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return NO_ERROR;
}
}  // namespace AppExecFwk
}  // namespace OHOS
