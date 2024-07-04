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

#include "app_log_tag_wrapper.h"
#include "service_center_status_callback.h"

namespace OHOS {
namespace AppExecFwk {
ServiceCenterStatusCallback::ServiceCenterStatusCallback(const std::weak_ptr<BundleConnectAbilityMgr> &server)
    : server_(server)
{
    LOG_I(BMS_TAG_DEFAULT, "%{public}s", __func__);
}

int32_t ServiceCenterStatusCallback::OnInstallFinished(std::string installResult)
{
    LOG_I(BMS_TAG_DEFAULT, "%{public}s", __func__);
    auto server = server_.lock();
    if (server == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "pointer is nullptr.");
        return ERR_INVALID_VALUE;
    }
    server->OnServiceCenterCall(installResult);
    return ERR_OK;
}

int32_t ServiceCenterStatusCallback::OnDelayedHeartbeat(std::string installResult)
{
    LOG_I(BMS_TAG_DEFAULT, "%{public}s", __func__);
    auto server = server_.lock();
    if (server == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "pointer is nullptr.");
        return ERR_INVALID_VALUE;
    }
    server->OnDelayedHeartbeat(installResult);
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
