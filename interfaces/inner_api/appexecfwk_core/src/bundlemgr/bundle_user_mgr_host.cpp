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
#include "bundle_user_mgr_host.h"

#include "appexecfwk_errors.h"
#include "app_log_wrapper.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_memory_guard.h"
#include "ipc_types.h"

namespace OHOS {
namespace AppExecFwk {
constexpr int32_t DISALLOWLISTMAXSIZE = 1000;
BundleUserMgrHost::BundleUserMgrHost()
{
    APP_LOGD("create BundleUserMgrHost instance");
}

BundleUserMgrHost::~BundleUserMgrHost()
{
    APP_LOGD("destroy BundleUserMgrHost instance");
}

int BundleUserMgrHost::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    BundleMemoryGuard memoryGuard;
    APP_LOGD("BundleUserMgrHost onReceived message, the message code is %{public}u", code);
    std::u16string descripter = BundleUserMgrHost::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        APP_LOGE("fail to write reply message in bundle user mgr host due to the reply is nullptr");
        return OBJECT_NULL;
    }

    ErrCode errCode = ERR_OK;
    switch (code) {
        case static_cast<uint32_t>(BundleUserMgrInterfaceCode::CREATE_USER): {
            errCode = HandleCreateNewUser(data, reply);
            break;
        }
        case static_cast<uint32_t>(BundleUserMgrInterfaceCode::REMOVE_USER): {
            errCode = HandleRemoveUser(data, reply);
            break;
        }
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    APP_LOGD("BundleUserMgr host finish to process message, errCode: %{public}d", errCode);
    return (errCode == ERR_OK) ? NO_ERROR : UNKNOWN_ERROR;
}

ErrCode BundleUserMgrHost::HandleCreateNewUser(Parcel &data, Parcel &reply)
{
    const int32_t userId = data.ReadInt32();
    const int32_t vectorSize = data.ReadInt32();
    if (vectorSize > DISALLOWLISTMAXSIZE) {
        APP_LOGE("Abnormal data size reading form parcel, size %{public}d", vectorSize);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::vector<std::string> disallowList;
    for (int32_t i = 0; i < vectorSize; i++) {
        disallowList.emplace_back(data.ReadString());
    }
    auto ret = CreateNewUser(userId, disallowList);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleUserMgrHost::HandleRemoveUser(Parcel &data, Parcel &reply)
{
    auto ret = RemoveUser(data.ReadInt32());
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
