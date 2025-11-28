/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include "extension_ability_info.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr size_t MAX_PARCEL_CAPACITY = 1024 * 1024 * 1024; // max allow 1 GB resource size
constexpr size_t MAX_IPC_ALLOWED_CAPACITY = 100 * 1024 * 1024; // max ipc size 100MB
const std::string BUNDLE_RESOURCE_ASHMEM_NAME = "bundleResourceAshemeName";
const int32_t MAX_PARCE_LABLE_LIST_SIZE = 1000;
}
BundleResourceHost::BundleResourceHost()
{
    APP_LOGD("start");
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
    switch (code) {
        case static_cast<uint32_t>(BundleResourceInterfaceCode::GET_BUNDLE_RESOURCE_INFO):
            errCode = this->HandleGetBundleResourceInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleResourceInterfaceCode::GET_LAUNCHER_ABILITY_RESOURCE_INFO):
            errCode = this->HandleGetLauncherAbilityResourceInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleResourceInterfaceCode::GET_ALL_BUNDLE_RESOURCE_INFO):
            errCode = this->HandleGetAllBundleResourceInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleResourceInterfaceCode::GET_ALL_LAUNCHER_ABILITY_RESOURCE_INFO):
            errCode = this->HandleGetAllLauncherAbilityResourceInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleResourceInterfaceCode::ADD_RESOURCE_INFO_BY_BUNDLE_NAME):
            errCode = this->HandleAddResourceInfoByBundleName(data, reply);
            break;
        case static_cast<uint32_t>(BundleResourceInterfaceCode::ADD_RESOURCE_INFO_BY_ABILITY):
            errCode = this->HandleAddResourceInfoByAbility(data, reply);
            break;
        case static_cast<uint32_t>(BundleResourceInterfaceCode::DELETE_RESOURCE_INFO):
            errCode = this->HandleDeleteResourceInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleResourceInterfaceCode::GET_EXTENSION_ABILITY_RESOURCE_INFO):
            errCode = this->HandleGetExtensionAbilityResourceInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleResourceInterfaceCode::GET_ALL_UNINSTALL_BUNDLE_RESOURCE_INFO):
            errCode = this->HandleGetAllUninstallBundleResourceInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleResourceInterfaceCode::GET_LAUNCHER_ABILITY_RESOURCE_INFO_LIST):
            errCode = this->HandleGetLauncherAbilityResourceInfoList(data, reply);
            break;
        default:
            APP_LOGW("bundle resource host receives unknown %{public}u", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    APP_LOGD("bundle resource host finish to process message, errCode: %{public}d", errCode);
    return (errCode == ERR_OK) ? NO_ERROR : UNKNOWN_ERROR;
}

ErrCode BundleResourceHost::HandleGetBundleResourceInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    std::string bundleName = data.ReadString();
    uint32_t flags = data.ReadUint32();
    int32_t appIndex = data.ReadInt32();
    BundleResourceInfo bundleResourceInfo;
    ErrCode ret = GetBundleResourceInfo(bundleName, flags, bundleResourceInfo, appIndex);
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
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    std::string bundleName = data.ReadString();
    uint32_t flags = data.ReadUint32();
    int32_t appIndex = data.ReadInt32();
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    ErrCode ret = GetLauncherAbilityResourceInfo(bundleName, flags, launcherAbilityResourceInfos, appIndex);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        return WriteVectorToParcel<LauncherAbilityResourceInfo>(launcherAbilityResourceInfos, reply);
    }
    return ERR_OK;
}

ErrCode BundleResourceHost::HandleGetLauncherAbilityResourceInfoList(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    std::vector<BundleOptionInfo> optionsList;
    std::vector<LauncherAbilityResourceInfo> launcherAbilityResourceInfos;
    ErrCode readRet = ReadParcelableVector(data, optionsList);
    if (readRet != ERR_OK) {
        APP_LOGE("fail to read optionsList");
        return readRet;
    }
    uint32_t flags = data.ReadUint32();
    ErrCode ret = GetLauncherAbilityResourceInfoList(optionsList, flags, launcherAbilityResourceInfos);
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
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
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
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
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

ErrCode BundleResourceHost::HandleAddResourceInfoByBundleName(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    std::string bundleName = data.ReadString();
    int32_t userId = data.ReadInt32();
    ErrCode ret = AddResourceInfoByBundleName(bundleName, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleResourceHost::HandleAddResourceInfoByAbility(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    std::string bundleName = data.ReadString();
    std::string moduleName = data.ReadString();
    std::string abilityName = data.ReadString();
    int32_t userId = data.ReadInt32();
    ErrCode ret = AddResourceInfoByAbility(bundleName, moduleName, abilityName, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleResourceHost::HandleDeleteResourceInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    std::string key = data.ReadString();
    ErrCode ret = DeleteResourceInfo(key);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleResourceHost::HandleGetExtensionAbilityResourceInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    std::string bundleName = data.ReadString();
    ExtensionAbilityType extensionAbilityType = static_cast<ExtensionAbilityType>(data.ReadInt32());
    uint32_t flags = data.ReadUint32();
    int32_t appIndex = data.ReadInt32();
    std::vector<LauncherAbilityResourceInfo> extensionAbilityResourceInfos;
    ErrCode ret = GetExtensionAbilityResourceInfo(bundleName, extensionAbilityType, flags,
        extensionAbilityResourceInfos, appIndex);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        return WriteVectorToParcel<LauncherAbilityResourceInfo>(extensionAbilityResourceInfos, reply);
    }
    return ERR_OK;
}

ErrCode BundleResourceHost::HandleGetAllUninstallBundleResourceInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    int32_t userId = data.ReadInt32();
    uint32_t flags = data.ReadUint32();
    std::vector<BundleResourceInfo> bundleResourceInfos;
    ErrCode ret = GetAllUninstallBundleResourceInfo(userId, flags, bundleResourceInfos);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        return WriteVectorToParcel<BundleResourceInfo>(bundleResourceInfos, reply);
    }
    return ERR_OK;
}

int32_t BundleResourceHost::AllocatAshmemNum()
{
    std::lock_guard<std::mutex> lock(bundleAshmemMutex_);
    return ashmemNum_++;
}

ErrCode BundleResourceHost::WriteParcelableIntoAshmem(MessageParcel &tempParcel, MessageParcel &reply)
{
    size_t dataSize = tempParcel.GetDataSize();
    // The ashmem name must be unique.
    sptr<Ashmem> ashmem = Ashmem::CreateAshmem(
        (BUNDLE_RESOURCE_ASHMEM_NAME + std::to_string(AllocatAshmemNum())).c_str(), dataSize);
    if (ashmem == nullptr) {
        APP_LOGE("Create shared memory failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    // Set the read/write mode of the ashme.
    if (!ashmem->MapReadAndWriteAshmem()) {
        APP_LOGE("Map shared memory fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    // Write the size and content of each item to the ashmem.
    int32_t offset = 0;
    if (!ashmem->WriteToAshmem(reinterpret_cast<uint8_t *>(tempParcel.GetData()), dataSize, offset)) {
        APP_LOGE("Write info to shared memory fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!reply.WriteAshmem(ashmem)) {
        APP_LOGE("Write ashmem to tempParcel fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

template<typename T>
ErrCode BundleResourceHost::WriteParcelInfo(const T &parcelInfo, MessageParcel &reply)
{
    MessageParcel tmpParcel;
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
    if (dataSize > MAX_IPC_ALLOWED_CAPACITY) {
        APP_LOGI("datasize is too large, use ashmem");
        return WriteParcelableIntoAshmem(tmpParcel, reply);
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
    MessageParcel tempParcel;
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
    if (!reply.WriteUint32(dataSize)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (dataSize > MAX_IPC_ALLOWED_CAPACITY) {
        APP_LOGI("datasize is too large, use ashmem");
        return WriteParcelableIntoAshmem(tempParcel, reply);
    }
    if (!reply.WriteRawData(reinterpret_cast<uint8_t *>(tempParcel.GetData()), dataSize)) {
        APP_LOGE("write parcel failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

template<typename T>
ErrCode BundleResourceHost::ReadParcelableVector(MessageParcel &data, std::vector<T> &parcelableInfos)
{
    int32_t infoSize = data.ReadInt32();
    if (infoSize > MAX_PARCE_LABLE_LIST_SIZE) {
        APP_LOGE("elements num exceeds the limit 1000");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<T> info(data.ReadParcelable<T>());
        if (info == nullptr) {
            APP_LOGE("read parcelable infos failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        parcelableInfos.emplace_back(*info);
    }
    APP_LOGD("read parcelable infos success");
    return ERR_OK;
}
} // AppExecFwk
} // OHOS
