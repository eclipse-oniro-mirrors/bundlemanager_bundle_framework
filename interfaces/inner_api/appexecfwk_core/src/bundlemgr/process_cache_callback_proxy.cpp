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

#include "process_cache_callback_proxy.h"

#include "app_log_wrapper.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include <cinttypes>
#include "ipc_types.h"
#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {
ProcessCacheCallbackProxy::ProcessCacheCallbackProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<IProcessCacheCallback>(object)
{
    APP_LOGI("create process cache callback proxy instance");
}

ProcessCacheCallbackProxy::~ProcessCacheCallbackProxy()
{
    APP_LOGI("destroy process cache callback proxy instance");
}

void ProcessCacheCallbackProxy::OnGetAllBundleCacheFinished(uint64_t cacheStat)
{
    APP_LOGI("process cacheStat: %{public}" PRIu64, cacheStat);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    if (!data.WriteInterfaceToken(ProcessCacheCallbackProxy::GetDescriptor())) {
        APP_LOGE("fail to OnGetAllBundleCacheFinished due to write MessageParcel fail");
        return;
    }
    if (!data.WriteUint64(cacheStat)) {
        APP_LOGE("fail to call OnGetAllBundleCacheFinished, for write parcel code failed");
        return;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        APP_LOGE("fail to call OnGetAllBundleCacheFinished, for Remote() is nullptr");
        return;
    }

    int32_t ret = remote->SendRequest(
        static_cast<int32_t>(ProcessCacheCallbackInterfaceCode::GET_ALL_BUNDLE_CACHE), data, reply, option);
    if (ret != NO_ERROR) {
        APP_LOGW("call OnGetAllBundleCacheFinished fail, for transact failed, error code: %{public}d", ret);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
