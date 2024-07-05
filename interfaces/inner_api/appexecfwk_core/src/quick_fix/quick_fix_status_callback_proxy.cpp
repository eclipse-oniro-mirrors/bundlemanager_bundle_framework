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

#include "quick_fix_status_callback_proxy.h"

#include "app_log_tag_wrapper.h"
#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "ipc_types.h"
#include "parcel.h"
#include "parcel_macro.h"
#include "quick_fix_status_callback_interface.h"

namespace OHOS {
namespace AppExecFwk {
QuickFixStatusCallbackProxy::QuickFixStatusCallbackProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<IQuickFixStatusCallback>(object)
{
    LOG_I(BMS_TAG_DEFAULT, "create QuickFixStatusCallbackProxy.");
}

QuickFixStatusCallbackProxy::~QuickFixStatusCallbackProxy()
{
    LOG_I(BMS_TAG_DEFAULT, "destroy QuickFixStatusCallbackProxy.");
}

void QuickFixStatusCallbackProxy::OnPatchDeployed(const std::shared_ptr<QuickFixResult> &result)
{
    MessageParcel data;
    MessageParcel reply;
    WRITE_PARCEL_AND_RETURN(InterfaceToken, data, QuickFixStatusCallbackProxy::GetDescriptor());
    WRITE_PARCEL_AND_RETURN(Parcelable, data, result.get());
    if (!SendTransactCmd(QuickFixStatusCallbackInterfaceCode::ON_PATCH_DEPLOYED, data, reply)) {
        LOG_E(BMS_TAG_DEFAULT, "fail to OnPatchDeployed due to transact command fail");
    }
}

void QuickFixStatusCallbackProxy::OnPatchSwitched(const std::shared_ptr<QuickFixResult> &result)
{
    MessageParcel data;
    MessageParcel reply;
    WRITE_PARCEL_AND_RETURN(InterfaceToken, data, QuickFixStatusCallbackProxy::GetDescriptor());
    WRITE_PARCEL_AND_RETURN(Parcelable, data, result.get());
    if (!SendTransactCmd(QuickFixStatusCallbackInterfaceCode::ON_PATCH_SWITCHED, data, reply)) {
        LOG_E(BMS_TAG_DEFAULT, "fail to OnPatchSwitched due to transact command fail");
    }
}

void QuickFixStatusCallbackProxy::OnPatchDeleted(const std::shared_ptr<QuickFixResult> &result)
{
    MessageParcel data;
    MessageParcel reply;
    WRITE_PARCEL_AND_RETURN(InterfaceToken, data, QuickFixStatusCallbackProxy::GetDescriptor());
    WRITE_PARCEL_AND_RETURN(Parcelable, data, result.get());
    if (!SendTransactCmd(QuickFixStatusCallbackInterfaceCode::ON_PATCH_DELETED, data, reply)) {
        LOG_E(BMS_TAG_DEFAULT, "fail to OnPatchDeleted due to transact command fail");
    }
}

bool QuickFixStatusCallbackProxy::SendTransactCmd(
    QuickFixStatusCallbackInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "fail to send transact cmd %{public}d due to remote object", code);
        return false;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != NO_ERROR) {
        LOG_E(BMS_TAG_DEFAULT, "receive error transact code %{public}d in transact cmd %{public}d", result, code);
        return false;
    }
    return true;
}
} // AppExecFwk
} // OHOS
