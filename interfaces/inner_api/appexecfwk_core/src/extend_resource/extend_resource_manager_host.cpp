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

#include "extend_resource_manager_host.h"

#include <fcntl.h>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_memory_guard.h"
#include "hitrace_meter.h"
#include "ipc_types.h"

namespace OHOS {
namespace AppExecFwk {
ExtendResourceManagerHost::ExtendResourceManagerHost()
{
    APP_LOGI("create ExtendResourceManagerHost");
}

ExtendResourceManagerHost::~ExtendResourceManagerHost()
{
    APP_LOGI("destroy ExtendResourceManagerHost");
}

int ExtendResourceManagerHost::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    BundleMemoryGuard memoryGuard;
    APP_LOGI_NOFUNC("ExtendResourceManagerHost OnRemoteRequest, message code : %{public}u", code);
    std::u16string descriptor = ExtendResourceManagerHost::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        APP_LOGE("descriptor invalid");
        return OBJECT_NULL;
    }

    switch (code) {
        case static_cast<uint32_t>(ExtendResourceManagerInterfaceCode::ADD_EXT_RESOURCE):
            return HandleAddExtResource(data, reply);
        case static_cast<uint32_t>(ExtendResourceManagerInterfaceCode::REMOVE_EXT_RESOURCE):
            return HandleRemoveExtResource(data, reply);
        case static_cast<uint32_t>(ExtendResourceManagerInterfaceCode::GET_EXT_RESOURCE):
            return HandleGetExtResource(data, reply);
        case static_cast<uint32_t>(ExtendResourceManagerInterfaceCode::ENABLE_DYNAMIC_ICON):
            return HandleEnableDynamicIcon(data, reply);
        case static_cast<uint32_t>(ExtendResourceManagerInterfaceCode::DISABLE_DYNAMIC_ICON):
            return HandleDisableDynamicIcon(data, reply);
        case static_cast<uint32_t>(ExtendResourceManagerInterfaceCode::GET_DYNAMIC_ICON):
            return HandleGetDynamicIcon(data, reply);
        case static_cast<uint32_t>(ExtendResourceManagerInterfaceCode::CREATE_FD):
            return HandleCreateFd(data, reply);
        case static_cast<uint32_t>(ExtendResourceManagerInterfaceCode::GET_ALL_DYNAMIC_ICON_INFO):
            return HandleGetAllDynamicInfo(data, reply);
        default:
            APP_LOGW("ExtendResourceManagerHost receive unknown code %{public}d", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

ErrCode ExtendResourceManagerHost::HandleAddExtResource(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::vector<std::string> filePaths;
    if (!data.ReadStringVector(&filePaths)) {
        APP_LOGE("read filePaths failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = AddExtResource(bundleName, filePaths);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode ExtendResourceManagerHost::HandleRemoveExtResource(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::vector<std::string> moduleNames;
    if (!data.ReadStringVector(&moduleNames)) {
        APP_LOGE("read moduleNames failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = RemoveExtResource(bundleName, moduleNames);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode ExtendResourceManagerHost::HandleGetExtResource(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::vector<std::string> moduleNames;
    ErrCode ret = GetExtResource(bundleName, moduleNames);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteStringVector(moduleNames)) {
        APP_LOGE("write moduleNames failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode ExtendResourceManagerHost::HandleEnableDynamicIcon(MessageParcel& data, MessageParcel& reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string moduleName = data.ReadString();
    int32_t userId = data.ReadInt32();
    int32_t appIndex = data.ReadInt32();
    ErrCode ret = EnableDynamicIcon(bundleName, moduleName, userId, appIndex);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode ExtendResourceManagerHost::HandleDisableDynamicIcon(MessageParcel& data, MessageParcel& reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    int32_t userId = data.ReadInt32();
    int32_t appIndex = data.ReadInt32();
    ErrCode ret = DisableDynamicIcon(bundleName, userId, appIndex);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode ExtendResourceManagerHost::HandleGetDynamicIcon(MessageParcel& data, MessageParcel& reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    int32_t userId = data.ReadInt32();
    int32_t appIndex = data.ReadInt32();
    std::string moduleName;
    ErrCode ret = GetDynamicIcon(bundleName, userId, appIndex, moduleName);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret != ERR_OK) {
        return ERR_OK;
    }
    if (!reply.WriteString(moduleName)) {
        APP_LOGE("write moduleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode ExtendResourceManagerHost::HandleCreateFd(MessageParcel& data, MessageParcel& reply)
{
    APP_LOGD("begin to HandleCreateFd");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string fileName = data.ReadString();
    int32_t fd = -1;
    std::string path;
    auto ret = CreateFd(fileName, fd, path);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write ret failed");
        close(fd);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!reply.WriteFileDescriptor(fd)) {
            APP_LOGE("write fd failed");
            close(fd);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        if (!reply.WriteString(path)) {
            APP_LOGE("write path failed");
            close(fd);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    close(fd);
    return ERR_OK;
}

ErrCode ExtendResourceManagerHost::HandleGetAllDynamicInfo(MessageParcel& data, MessageParcel& reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int32_t userId = data.ReadInt32();
    std::vector<DynamicIconInfo> dynamicIconInfos;
    ErrCode ret = GetAllDynamicIconInfo(userId, dynamicIconInfos);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        return WriteParcelableVector<DynamicIconInfo>(dynamicIconInfos, reply);
    }
    return ERR_OK;
}

template<typename T>
ErrCode ExtendResourceManagerHost::WriteParcelableVector(std::vector<T> &parcelableVector, MessageParcel &reply)
{
    if (!reply.WriteInt32(parcelableVector.size())) {
        APP_LOGE("write ParcelableVector failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    for (auto &parcelable : parcelableVector) {
        if (!reply.WriteParcelable(&parcelable)) {
            APP_LOGE("write ParcelableVector failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}
} // AppExecFwk
} // namespace OHOS
