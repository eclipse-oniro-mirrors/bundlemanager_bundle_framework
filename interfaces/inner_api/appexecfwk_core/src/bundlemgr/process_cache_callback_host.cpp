/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "process_cache_callback_host.h"

#include "app_log_wrapper.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_memory_guard.h"
#include "ipc_types.h"

namespace OHOS {
namespace AppExecFwk {
ProcessCacheCallbackHost::ProcessCacheCallbackHost()
{
    APP_LOGI("process clean cache callback host instance");
}

ProcessCacheCallbackHost::~ProcessCacheCallbackHost()
{
    APP_LOGI("destroyclean process callback host instance");
}

int ProcessCacheCallbackHost::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    BundleMemoryGuard memoryGuard;
    APP_LOGD("process cache callback host onReceived message, the message code is %{public}u", code);
    std::u16string descripter = ProcessCacheCallbackHost::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        APP_LOGE("fail to write reply message in process cache host due to the reply is nullptr");
        return OBJECT_NULL;
    }

    switch (code) {
        case static_cast<uint32_t>(ProcessCacheCallbackInterfaceCode::GET_ALL_BUNDLE_CACHE): {
            uint64_t cacheStat = data.ReadUint64();
            OnGetAllBundleCacheFinished(cacheStat);
            break;
        }
        case static_cast<uint32_t>(ProcessCacheCallbackInterfaceCode::CLEAN_ALL_BUNDLE_CACHE): {
            int32_t result = data.ReadInt32();
            OnCleanAllBundleCacheFinished(result);
            break;
        }
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return NO_ERROR;
}
}  // namespace AppExecFwk
}  // namespace OHOS
