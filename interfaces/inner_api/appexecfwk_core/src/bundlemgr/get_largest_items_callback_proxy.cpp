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

#include "get_largest_items_callback_proxy.h"

#include "app_log_wrapper.h"
#include "app_log_tag_wrapper.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "ipc_types.h"
#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {
GetLargestItemsCallbackProxy::GetLargestItemsCallbackProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<IGetLargestItemsCallback>(object)
{
    LOG_I(BMS_TAG_QUERY, "create get largest items callback proxy instance");
}

GetLargestItemsCallbackProxy::~GetLargestItemsCallbackProxy()
{
    LOG_I(BMS_TAG_QUERY, "destroy get largest items callback proxy instance");
}

void GetLargestItemsCallbackProxy::OnGetLargestItemsFinished(ErrCode errCode, const std::string &largestItems)
{
    LOG_I(BMS_TAG_QUERY, "get largest items result %{public}d", errCode);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!data.WriteInterfaceToken(GetLargestItemsCallbackProxy::GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "fail to OnGetLargestItemsFinished due to write MessageParcel fail");
        return;
    }

    if (!data.WriteInt32(errCode)) {
        LOG_E(BMS_TAG_QUERY, "fail to call OnGetLargestItemsFinished, for write errCode failed");
        return;
    }

    // Use WriteRawData for large strings to avoid IPC size limit
    size_t dataSize = largestItems.size();
    if (!data.WriteUint64(dataSize)) {
        LOG_E(BMS_TAG_QUERY, "fail to call OnGetLargestItemsFinished, for write size failed");
        return;
    }

    if (dataSize > 0) {
        if (!data.WriteRawData(reinterpret_cast<const uint8_t*>(largestItems.c_str()), dataSize)) {
            LOG_E(BMS_TAG_QUERY, "fail to call OnGetLargestItemsFinished, for write data failed");
            return;
        }
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_E(BMS_TAG_QUERY, "fail to call OnGetLargestItemsFinished, for Remote() is nullptr");
        return;
    }

    int32_t ret = remote->SendRequest(
        static_cast<int32_t>(GetLargestItemsCallbackInterfaceCode::ON_GET_LARGEST_ITEMS_CALLBACK),
        data, reply, option);
    if (ret != NO_ERROR) {
        LOG_W(BMS_TAG_QUERY, "call OnGetLargestItemsFinished fail, for transact failed, error code: %{public}d", ret);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
