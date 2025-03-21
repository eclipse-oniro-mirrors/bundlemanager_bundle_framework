/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "bundle_mgr_ext_host.h"

#include "app_log_tag_wrapper.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_memory_guard.h"
#include "hitrace_meter.h"
#include "ipc_types.h"

namespace OHOS {
namespace AppExecFwk {
BundleMgrExtHost::BundleMgrExtHost()
{
    LOG_D(BMS_TAG_EXT, "create BundleMgrExtHost");
}

BundleMgrExtHost::~BundleMgrExtHost()
{
    LOG_D(BMS_TAG_EXT, "destroy BundleMgrExtHost");
}

int32_t BundleMgrExtHost::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    BundleMemoryGuard memoryGuard;
    std::u16string descriptor = BundleMgrExtHost::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        LOG_E(BMS_TAG_EXT, "descriptor invalid");
        return OBJECT_NULL;
    }

    switch (code) {
        case static_cast<uint32_t>(BundleMgrExtInterfaceCode::GET_BUNDLE_NAMES_FOR_UID_EXT):
            return HandleGetBundleNamesForUidExt(data, reply);
        default:
            LOG_W(BMS_TAG_EXT, "BundleMgrExtHost receive unknown code, code = %{public}d", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

ErrCode BundleMgrExtHost::HandleGetBundleNamesForUidExt(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int32_t uid = data.ReadInt32();
    std::vector<std::string> bundleNames;
    ErrCode ret = GetBundleNamesForUidExt(uid, bundleNames);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_EXT, "write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK && !reply.WriteStringVector(bundleNames)) {
        LOG_E(BMS_TAG_EXT, "write bundleNames failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}
} // AppExecFwk
} // OHOS
