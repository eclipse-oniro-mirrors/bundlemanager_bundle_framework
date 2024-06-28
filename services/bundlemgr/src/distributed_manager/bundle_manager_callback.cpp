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

#include "bundle_manager_callback.h"

#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
BundleManagerCallback::BundleManagerCallback(const std::weak_ptr<BundleDistributedManager> &server)
    : server_(server)
{
    APP_LOGI("%{public}s", __func__);
}

int32_t BundleManagerCallback::OnQueryRpcIdFinished(const std::string &queryRpcIdResult)
{
    APP_LOGI("OnQueryRpcIdFinished %{public}s", queryRpcIdResult.c_str());
    auto server = server_.lock();
    if (server == nullptr) {
        APP_LOGE("pointer is nullptr.");
        return ERR_INVALID_VALUE;
    }
    server->OnQueryRpcIdFinished(queryRpcIdResult);
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
