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

#include "default_app_host.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "hitrace_meter.h"
#include "ipc_types.h"

namespace OHOS {
namespace AppExecFwk {
DefaultAppHost::DefaultAppHost()
{
    APP_LOGD("create DefaultAppHost.");
}

DefaultAppHost::~DefaultAppHost()
{
    APP_LOGD("destroy DefaultAppHost.");
}

int DefaultAppHost::OnRemoteRequest(
    uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option)
{
    APP_LOGI("DefaultAppHost OnRemoteRequest, message code : %{public}u", code);
    std::u16string descriptor = DefaultAppHost::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        APP_LOGE("descriptor invalid.");
        return OBJECT_NULL;
    }

    switch (code) {
        case static_cast<uint32_t>(IDefaultApp::Message::IS_DEFAULT_APPLICATION): {
            HandleIsDefaultApplication(data, reply);
            break;
        }
        case static_cast<uint32_t>(IDefaultApp::Message::GET_DEFAULT_APPLICATION): {
            HandleGetDefaultApplication(data, reply);
            break;
        }
        case static_cast<uint32_t>(IDefaultApp::Message::SET_DEFAULT_APPLICATION): {
            HandleSetDefaultApplication(data, reply);
            break;
        }
        case static_cast<uint32_t>(IDefaultApp::Message::RESET_DEFAULT_APPLICATION): {
            HandleResetDefaultApplication(data, reply);
            break;
        }
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }

    return NO_ERROR;
}

ErrCode DefaultAppHost::HandleIsDefaultApplication(Parcel& data, Parcel& reply)
{
    APP_LOGI("begin to HandleIsDefaultApplication.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string type = data.ReadString();
    bool ret = IsDefaultApplication(type);

    if (!reply.WriteBool(ret)) {
        APP_LOGE("write ret failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return ERR_OK;
}

ErrCode DefaultAppHost::HandleGetDefaultApplication(Parcel& data, Parcel& reply)
{
    APP_LOGI("begin to HandleGetDefaultApplication.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int32_t userId = data.ReadInt32();
    std::string type = data.ReadString();
    BundleInfo bundleInfo;
    bool ret = GetDefaultApplication(userId, type, bundleInfo);

    if (!reply.WriteBool(ret)) {
        APP_LOGE("write ret failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteParcelable(&bundleInfo)) {
            APP_LOGE("write bundleInfo failed.");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }

    return ERR_OK;
}

ErrCode DefaultAppHost::HandleSetDefaultApplication(Parcel& data, Parcel& reply)
{
    APP_LOGI("begin to HandleSetDefaultApplication.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int32_t userId = data.ReadInt32();
    std::string type = data.ReadString();
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        APP_LOGE("ReadParcelable<Want> failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool ret = SetDefaultApplication(userId, type, *want);

    if (!reply.WriteBool(ret)) {
        APP_LOGE("write ret failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return ERR_OK;
}

ErrCode DefaultAppHost::HandleResetDefaultApplication(Parcel& data, Parcel& reply)
{
    APP_LOGI("begin to HandleResetDefaultApplication.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int32_t userId = data.ReadInt32();
    std::string type = data.ReadString();
    bool ret = ResetDefaultApplication(userId, type);

    if (!reply.WriteBool(ret)) {
        APP_LOGE("write ret failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return ERR_OK;
}
}
}
