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

#include "default_app_host.h"

#include "app_log_tag_wrapper.h"
#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_memory_guard.h"
#include "hitrace_meter.h"
#include "ipc_types.h"

namespace OHOS {
namespace AppExecFwk {
DefaultAppHost::DefaultAppHost()
{
    LOG_D(BMS_TAG_DEFAULT_APP, "create DefaultAppHost.");
}

DefaultAppHost::~DefaultAppHost()
{
    LOG_D(BMS_TAG_DEFAULT_APP, "destroy DefaultAppHost.");
}

int DefaultAppHost::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    BundleMemoryGuard memoryGuard;
    LOG_I(BMS_TAG_DEFAULT_APP, "DefaultAppHost OnRemoteRequest, message code : %{public}u", code);
    std::u16string descriptor = DefaultAppHost::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        LOG_E(BMS_TAG_DEFAULT_APP, "descriptor invalid.");
        return OBJECT_NULL;
    }

    switch (code) {
        case static_cast<uint32_t>(DefaultAppInterfaceCode::IS_DEFAULT_APPLICATION):
            return HandleIsDefaultApplication(data, reply);
        case static_cast<uint32_t>(DefaultAppInterfaceCode::GET_DEFAULT_APPLICATION):
            return HandleGetDefaultApplication(data, reply);
        case static_cast<uint32_t>(DefaultAppInterfaceCode::SET_DEFAULT_APPLICATION):
            return HandleSetDefaultApplication(data, reply);
        case static_cast<uint32_t>(DefaultAppInterfaceCode::RESET_DEFAULT_APPLICATION):
            return HandleResetDefaultApplication(data, reply);
        default:
            LOG_W(BMS_TAG_DEFAULT_APP, "DefaultAppHost receive unknown code, code = %{public}d", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

ErrCode DefaultAppHost::HandleIsDefaultApplication(Parcel& data, Parcel& reply)
{
    LOG_I(BMS_TAG_DEFAULT_APP, "begin to HandleIsDefaultApplication.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string type = data.ReadString();
    bool isDefaultApp = false;
    ErrCode ret = IsDefaultApplication(type, isDefaultApp);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT_APP, "write ret failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!reply.WriteBool(isDefaultApp)) {
            LOG_E(BMS_TAG_DEFAULT_APP, "write isDefaultApp failed.");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode DefaultAppHost::HandleGetDefaultApplication(Parcel& data, Parcel& reply)
{
    LOG_I(BMS_TAG_DEFAULT_APP, "begin to HandleGetDefaultApplication.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int32_t userId = data.ReadInt32();
    std::string type = data.ReadString();
    BundleInfo bundleInfo;
    ErrCode ret = GetDefaultApplication(userId, type, bundleInfo);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT_APP, "write ret failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!reply.WriteParcelable(&bundleInfo)) {
            LOG_E(BMS_TAG_DEFAULT_APP, "write bundleInfo failed.");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode DefaultAppHost::HandleSetDefaultApplication(Parcel& data, Parcel& reply)
{
    LOG_I(BMS_TAG_DEFAULT_APP, "begin to HandleSetDefaultApplication.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int32_t userId = data.ReadInt32();
    std::string type = data.ReadString();
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        LOG_E(BMS_TAG_DEFAULT_APP, "ReadParcelable<Want> failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = SetDefaultApplication(userId, type, *want);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT_APP, "write ret failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode DefaultAppHost::HandleResetDefaultApplication(Parcel& data, Parcel& reply)
{
    LOG_I(BMS_TAG_DEFAULT_APP, "begin to HandleResetDefaultApplication.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int32_t userId = data.ReadInt32();
    std::string type = data.ReadString();
    ErrCode ret = ResetDefaultApplication(userId, type);
    if (!reply.WriteInt32(ret)) {
        LOG_E(BMS_TAG_DEFAULT_APP, "write ret failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}
}
}
