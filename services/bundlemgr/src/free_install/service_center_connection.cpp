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

#include "service_center_connection.h"

#include "app_log_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
ServiceCenterConnection::~ServiceCenterConnection()
{
    LOG_I(BMS_TAG_DEFAULT, "ServiceCenterConnection destory");
}

void ServiceCenterConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int32_t resultCode)
{
    LOG_I(BMS_TAG_DEFAULT, "OnAbilityConnectDone start");
    if (resultCode != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "OnAbilityConnectDone resultCode = %{public}d", resultCode);
        UpdateConnectState(ServiceCenterConnectState::DISCONNECTED);
        return;
    }

    if (remoteObject == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "OnAbilityConnectDone remoteObject is nullptr");
        UpdateConnectState(ServiceCenterConnectState::DISCONNECTED);
        return;
    }
    serviceCenterRemoteObject_ = remoteObject;

    deathRecipient_ = new (std::nothrow) ServiceCenterDeathRecipient(connectAbilityMgr_);
    if (deathRecipient_ == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "Failed to create ServiceCenterDeathRecipient");
        UpdateConnectState(ServiceCenterConnectState::CONNECTED);
        return;
    }

    if (!serviceCenterRemoteObject_->AddDeathRecipient(deathRecipient_)) {
        LOG_E(BMS_TAG_DEFAULT, "Failed to add AbilityManagerDeathRecipient");
    }
    UpdateConnectState(ServiceCenterConnectState::CONNECTED);
    LOG_I(BMS_TAG_DEFAULT, "OnAbilityConnectDone end");
}

void ServiceCenterConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int32_t resultCode)
{
    LOG_I(BMS_TAG_DEFAULT, "OnAbilityDisconnectDone start");
    if (serviceCenterRemoteObject_ != nullptr && deathRecipient_ != nullptr) {
        serviceCenterRemoteObject_->RemoveDeathRecipient(deathRecipient_);
    }

    serviceCenterRemoteObject_ = nullptr;
    UpdateConnectState(ServiceCenterConnectState::DISCONNECTED);
    LOG_I(BMS_TAG_DEFAULT, "OnAbilityDisconnectDone end");
}

void ServiceCenterConnection::UpdateConnectState(int32_t state)
{
    std::lock_guard<std::mutex> lock(mutex_);
    connectState_ = state;
    cv_.notify_all();
}

sptr<IRemoteObject> ServiceCenterConnection::GetRemoteObject()
{
    return serviceCenterRemoteObject_;
}
}  // namespace AppExecFwk
}  // namespace OHOS