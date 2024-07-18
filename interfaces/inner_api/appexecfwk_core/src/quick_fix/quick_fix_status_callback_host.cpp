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

#include "quick_fix_status_callback_host.h"

#include "app_log_tag_wrapper.h"
#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_memory_guard.h"
#include "ipc_types.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
QuickFixStatusCallbackHost::QuickFixStatusCallbackHost()
{
    LOG_I(BMS_TAG_DEFAULT, "create QuickFixStatusCallbackHost");
}

QuickFixStatusCallbackHost::~QuickFixStatusCallbackHost()
{
    LOG_I(BMS_TAG_DEFAULT, "destroy QuickFixStatusCallbackHost");
}

int QuickFixStatusCallbackHost::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    BundleMemoryGuard memoryGuard;
    LOG_D(BMS_TAG_DEFAULT, "QuickFixStatusCallbackHost onReceived message, the message code is %{public}u", code);
    std::u16string descripter = QuickFixStatusCallbackHost::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        LOG_E(BMS_TAG_DEFAULT, "fail to write reply message in clean cache host due to the reply is nullptr");
        return OBJECT_NULL;
    }
    switch (code) {
        case static_cast<uint32_t>(QuickFixStatusCallbackInterfaceCode::ON_PATCH_DEPLOYED):
            this->HandleOnPatchDeployed(data, reply);
            break;
        case static_cast<uint32_t>(QuickFixStatusCallbackInterfaceCode::ON_PATCH_SWITCHED):
            this->HandleOnPatchSwitched(data, reply);
            break;
        case static_cast<uint32_t>(QuickFixStatusCallbackInterfaceCode::ON_PATCH_DELETED):
            this->HandleOnPatchDeleted(data, reply);
            break;
        default :
            LOG_W(BMS_TAG_DEFAULT, "quickfix callback host receives unknown code, code = %{public}u", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    LOG_D(BMS_TAG_DEFAULT, "quickfix callback host finish to process message");
    return NO_ERROR;
}

void QuickFixStatusCallbackHost::HandleOnPatchDeployed(MessageParcel &data, MessageParcel &reply)
{
    LOG_I(BMS_TAG_DEFAULT, "start to process deployed patch callback message");
    std::shared_ptr<QuickFixResult> resPtr(data.ReadParcelable<DeployQuickFixResult>());
    if (resPtr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "read DeployQuickFixResult failed");
        std::shared_ptr<QuickFixResult> deployRes = std::make_shared<DeployQuickFixResult>();
        deployRes->SetResCode(ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR);
        OnPatchDeployed(deployRes);
        return;
    }

    OnPatchDeployed(resPtr);
}

void QuickFixStatusCallbackHost::HandleOnPatchSwitched(MessageParcel &data, MessageParcel &reply)
{
    LOG_I(BMS_TAG_DEFAULT, "start to process switched patch callback message");
    std::shared_ptr<QuickFixResult> resPtr(data.ReadParcelable<SwitchQuickFixResult>());
    if (resPtr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "read SwitchQuickFixResult failed");
        std::shared_ptr<QuickFixResult> switchRes = std::make_shared<SwitchQuickFixResult>();
        switchRes->SetResCode(ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR);
        OnPatchSwitched(switchRes);
        return;
    }

    OnPatchSwitched(resPtr);
}

void QuickFixStatusCallbackHost::HandleOnPatchDeleted(MessageParcel &data, MessageParcel &reply)
{
    LOG_I(BMS_TAG_DEFAULT, "start to process deleted patch callback message");
    std::shared_ptr<DeleteQuickFixResult> resPtr(data.ReadParcelable<DeleteQuickFixResult>());
    if (resPtr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "read DeleteQuickFixResult failed");
        std::shared_ptr<QuickFixResult> deleteRes = std::make_shared<DeleteQuickFixResult>();
        deleteRes->SetResCode(ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR);
        OnPatchDeleted(deleteRes);
        return;
    }

    OnPatchDeleted(resPtr);
}
} // AppExecFwk
} // OHOS
