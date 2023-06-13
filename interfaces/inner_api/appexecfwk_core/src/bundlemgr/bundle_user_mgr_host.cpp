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

#include "app_log_wrapper.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_memory_guard.h"
#include "ipc_types.h"

namespace OHOS {
namespace AppExecFwk {
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

    switch (code) {
        case static_cast<uint32_t>(BundleUserMgrInterfaceCode::CREATE_USER): {
            HandleCreateNewUser(data, reply);
            break;
        }
        case static_cast<uint32_t>(BundleUserMgrInterfaceCode::REMOVE_USER): {
            HandleRemoveUser(data, reply);
            break;
        }
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }

    return NO_ERROR;
}

void BundleUserMgrHost::HandleCreateNewUser(Parcel &data, Parcel &reply)
{
    CreateNewUser(data.ReadInt32());
}

void BundleUserMgrHost::HandleRemoveUser(Parcel &data, Parcel &reply)
{
    RemoveUser(data.ReadInt32());
}
}  // namespace AppExecFwk
}  // namespace OHOS
