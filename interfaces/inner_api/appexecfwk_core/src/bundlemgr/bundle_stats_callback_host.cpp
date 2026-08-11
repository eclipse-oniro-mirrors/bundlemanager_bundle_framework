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

#include "bundle_stats_callback_host.h"

#include "app_log_wrapper.h"
#include "app_log_tag_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_memory_guard.h"
#include "ipc_types.h"

namespace OHOS {
namespace AppExecFwk {
BundleStatsCallbackHost::BundleStatsCallbackHost()
{
    LOG_D(BMS_TAG_QUERY, "create bundle stats callback host instance");
}

BundleStatsCallbackHost::~BundleStatsCallbackHost()
{
    LOG_D(BMS_TAG_QUERY, "destroy bundle stats callback host instance");
}

int BundleStatsCallbackHost::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    BundleMemoryGuard memoryGuard;
    LOG_D(BMS_TAG_QUERY, "bundle stats callback host onReceived message %{public}u", code);
    std::u16string descriptor = BundleStatsCallbackHost::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        LOG_E(BMS_TAG_QUERY, "descriptor is not matched");
        return OBJECT_NULL;
    }

    switch (code) {
        case static_cast<uint32_t>(BundleStatsCallbackInterfaceCode::ON_GET_BUNDLE_STATS_CALLBACK): {
            int32_t errCode = 0;
            if (!data.ReadInt32(errCode)) {
                LOG_E(BMS_TAG_QUERY, "fail to read errCode");
                return ERR_APPEXECFWK_PARCEL_ERROR;
            }
            std::vector<int64_t> bundleStats;
            if (!data.ReadInt64Vector(&bundleStats)) {
                LOG_E(BMS_TAG_QUERY, "fail to read bundleStats");
                return ERR_APPEXECFWK_PARCEL_ERROR;
            }
            OnGetBundleStatsFinished(errCode, bundleStats);
            break;
        }
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return NO_ERROR;
}
}  // namespace AppExecFwk
}  // namespace OHOS
