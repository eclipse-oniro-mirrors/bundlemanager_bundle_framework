/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "bundle_resource_host.h"

#include "app_log_wrapper.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_memory_guard.h"
#include "hitrace_meter.h"
#include "datetime_ex.h"
#include "ipc_types.h"
#include "json_util.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr size_t MAX_PARCEL_CAPACITY = 200 * 1024 * 1024; // 200M
}
BundleResourceHost::BundleResourceHost()
{
    APP_LOGD("start");
    funcMap_.emplace(static_cast<uint32_t>(BundleResourceInterfaceCode::GET_BUNDLE_RESOURCE_INFO),
        &BundleResourceHost::HandleGetBundleResourceInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleResourceInterfaceCode::GET_LAUNCHER_ABILITY_RESOURCE_INFO),
        &BundleResourceHost::HandleGetLauncherAbilityResourceInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleResourceInterfaceCode::GET_ALL_BUNDLE_RESOURCE_INFO),
        &BundleResourceHost::HandleGetAllBundleResourceInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleResourceInterfaceCode::GET_ALL_LAUNCHER_ABILITY_RESOURCE_INFO),
        &BundleResourceHost::HandleGetAllLauncherAbilityResourceInfo);
}

int32_t BundleResourceHost::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    BundleMemoryGuard memoryGuard;
    APP_LOGD("bundle resource host onReceived message, the message code is %{public}u", code);
    std::u16string descriptor = BundleResourceHost::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        APP_LOGE("fail to write reply message in bundle mgr host due to the reply is nullptr");
        return OBJECT_NULL;
    }

    ErrCode errCode = ERR_OK;
    if (funcMap_.find(code) != funcMap_.end() && funcMap_[code] != nullptr) {
        errCode = (this->*funcMap_[code])(data, reply);
    } else {
        APP_LOGW("bundle resource host receives unknown code, code = %{public}u", code);
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    APP_LOGD("bundle resource host finish to process message, errCode: %{public}d", errCode);
    return (errCode == ERR_OK) ? NO_ERROR : UNKNOWN_ERROR;
}

ErrCode BundleResourceHost::HandleGetBundleResourceInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    uint32_t flags = data.ReadUint32();
    BundleResourceInfo bundleResourceInfo;
    ErrCode ret = GetBundleResourceInfo(bundleName, flags, bundleResourceInfo);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        return WriteParcelInfo<BundleResourceInfo>(bundleResourceInfo, reply);
    }
    return ERR_OK;
}

ErrCode BundleResourceHost::HandleGetLauncherAbilityResourceInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    uint32_t flags = data.ReadUint32();
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    ErrCode ret = GetLauncherAbilityResourceInfo(bundleName, flags, launcherAbilityResourceInfos);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        return WriteVectorToParcel<LauncherAbilityResourceInfo>(launcherAbilityResourceInfos, reply);
    }
    return ERR_OK;
}

ErrCode BundleResourceHost::HandleGetAllBundleResourceInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    uint32_t flags = data.ReadUint32();
    std::vector<BundleResourceInfo> bundleResourceInfos;
    ErrCode ret = GetAllBundleResourceInfo(flags, bundleResourceInfos);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        return WriteVectorToParcel<BundleResourceInfo>(bundleResourceInfos, reply);
    }
    return ERR_OK;
}

ErrCode BundleResourceHost::HandleGetAllLauncherAbilityResourceInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    uint32_t flags = data.ReadUint32();
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    ErrCode ret = GetAllLauncherAbilityResourceInfo(flags, launcherAbilityResourceInfos);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        return WriteVectorToParcel<LauncherAbilityResourceInfo>(launcherAbilityResourceInfos, reply);
    }
    return ERR_OK;
}

template<typename T>
ErrCode BundleResourceHost::WriteParcelInfo(const T &parcelInfo, MessageParcel &reply) const
{
    Parcel tmpParcel;
    (void)tmpParcel.SetMaxCapacity(MAX_PARCEL_CAPACITY);
    if (!tmpParcel.WriteParcelable(&parcelInfo)) {
        APP_LOGE("write parcel failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    size_t dataSize = tmpParcel.GetDataSize();
    if (!reply.WriteUint32(dataSize)) {
        APP_LOGE("write parcel failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!reply.WriteRawData(reinterpret_cast<uint8_t *>(tmpParcel.GetData()), dataSize)) {
        APP_LOGE("write parcel failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

template<typename T>
ErrCode BundleResourceHost::WriteVectorToParcel(std::vector<T> &parcelVector, MessageParcel &reply)
{
    Parcel tempParcel;
    (void)tempParcel.SetMaxCapacity(MAX_PARCEL_CAPACITY);
    if (!tempParcel.WriteInt32(parcelVector.size())) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    for (auto &parcel : parcelVector) {
        if (!tempParcel.WriteParcelable(&parcel)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }

    size_t dataSize = tempParcel.GetDataSize();
    if (!reply.WriteInt32(static_cast<int32_t>(dataSize))) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!reply.WriteRawData(
        reinterpret_cast<uint8_t *>(tempParcel.GetData()), dataSize)) {
        APP_LOGE("Failed to write data");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return ERR_OK;
}
} // AppExecFwk
} // OHOS
