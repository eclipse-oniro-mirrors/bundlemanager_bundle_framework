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

#include "default_app_proxy.h"

#include "app_log_tag_wrapper.h"
#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "hitrace_meter.h"
#include "ipc_types.h"
#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {
DefaultAppProxy::DefaultAppProxy(const sptr<IRemoteObject>& object)
    : IRemoteProxy<IDefaultApp>(object)
{
    LOG_D(BMS_TAG_DEFAULT, "create DefaultAppProxy");
}

DefaultAppProxy::~DefaultAppProxy()
{
    LOG_D(BMS_TAG_DEFAULT, "destroy DefaultAppProxy");
}

ErrCode DefaultAppProxy::IsDefaultApplication(const std::string& type, bool& isDefaultApp)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to call IsDefaultApplication");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(type)) {
        LOG_E(BMS_TAG_DEFAULT, "write type failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(DefaultAppInterfaceCode::IS_DEFAULT_APPLICATION, data, reply)) {
        LOG_E(BMS_TAG_DEFAULT, "SendRequest failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = reply.ReadInt32();
    if (ret == ERR_OK) {
        isDefaultApp = reply.ReadBool();
    }
    return ret;
}

ErrCode DefaultAppProxy::GetDefaultApplication(int32_t userId, const std::string& type, BundleInfo& bundleInfo)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to GetDefaultApplication");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);

    if (type.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "type is empty");
        return ERR_BUNDLE_MANAGER_INVALID_TYPE;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(type)) {
        LOG_E(BMS_TAG_DEFAULT, "write type failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfo<BundleInfo>(DefaultAppInterfaceCode::GET_DEFAULT_APPLICATION, data, bundleInfo);
}

ErrCode DefaultAppProxy::SetDefaultApplication(int32_t userId, const std::string& type, const Want& want)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to SetDefaultApplication");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(type)) {
        LOG_E(BMS_TAG_DEFAULT, "write type failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        LOG_E(BMS_TAG_DEFAULT, "write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(DefaultAppInterfaceCode::SET_DEFAULT_APPLICATION, data, reply)) {
        LOG_E(BMS_TAG_DEFAULT, "SendRequest failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return reply.ReadInt32();
}

ErrCode DefaultAppProxy::ResetDefaultApplication(int32_t userId, const std::string& type)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to ResetDefaultApplication");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);

    if (type.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "type is empty");
        return ERR_BUNDLE_MANAGER_INVALID_TYPE;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(type)) {
        LOG_E(BMS_TAG_DEFAULT, "write type failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(DefaultAppInterfaceCode::RESET_DEFAULT_APPLICATION, data, reply)) {
        LOG_E(BMS_TAG_DEFAULT, "SendRequest failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return reply.ReadInt32();
}

template<typename T>
ErrCode DefaultAppProxy::GetParcelableInfo(DefaultAppInterfaceCode code, MessageParcel& data, T& parcelableInfo)
{
    MessageParcel reply;
    if (!SendRequest(code, data, reply)) {
        LOG_E(BMS_TAG_DEFAULT, "SendRequest failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "host reply errCode : %{public}d", ret);
        return ret;
    }

    std::unique_ptr<T> info(reply.ReadParcelable<T>());
    if (info == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "ReadParcelable failed");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    parcelableInfo = *info;
    LOG_D(BMS_TAG_DEFAULT, "GetParcelableInfo success");
    return ERR_OK;
}

bool DefaultAppProxy::SendRequest(DefaultAppInterfaceCode code, MessageParcel& data, MessageParcel& reply)
{
    MessageOption option(MessageOption::TF_SYNC);
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "failed to send request %{public}d due to remote object null", code);
        return false;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != NO_ERROR) {
        LOG_E(BMS_TAG_DEFAULT, "receive error code %{public}d in transact %{public}d", result, code);
        return false;
    }
    return true;
}
}
}
