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

#include "bundle_resource_proxy.h"

#include "securec.h"
#include "string_ex.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "hitrace_meter.h"
#include "ipc_types.h"
#include "parcel.h"
#include "parcel_macro.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr size_t MAX_PARCEL_CAPACITY = 1024 * 1024 * 1024; // allow max 1GB resource size
constexpr size_t MAX_IPC_ALLOWED_CAPACITY = 100 * 1024 * 1024; // max ipc size 100MB
bool GetData(void *&buffer, size_t size, const void *data)
{
    if (data == nullptr) {
        APP_LOGE("failed due to null data");
        return false;
    }
    if ((size == 0) || size > MAX_PARCEL_CAPACITY) {
        APP_LOGE("failed due to wrong size");
        return false;
    }
    buffer = malloc(size);
    if (buffer == nullptr) {
        APP_LOGE("failed due to malloc buffer failed");
        return false;
    }
    if (memcpy_s(buffer, size, data, size) != EOK) {
        free(buffer);
        APP_LOGE("failed due to memcpy_s failed");
        return false;
    }
    return true;
}
}

BundleResourceProxy::BundleResourceProxy(const sptr<IRemoteObject>& object) : IRemoteProxy<IBundleResource>(object)
{}

ErrCode BundleResourceProxy::GetBundleResourceInfo(const std::string &bundleName,
    const uint32_t flags,
    BundleResourceInfo &bundleResourceInfo,
    const int32_t appIndex)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("start, bundleName:%{public}s, flags:%{public}u", bundleName.c_str(), flags);
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to write InterfaceToken");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to to write bundleName");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteUint32(flags)) {
        APP_LOGE("fail to write flags");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appIndex)) {
        APP_LOGE("fail to write flags");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelInfo<BundleResourceInfo>(
        BundleResourceInterfaceCode::GET_BUNDLE_RESOURCE_INFO, data, bundleResourceInfo);
}

ErrCode BundleResourceProxy::GetLauncherAbilityResourceInfo(const std::string &bundleName,
    const uint32_t flags,
    std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfo,
    const int32_t appIndex)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("start, bundleName:%{public}s, flags:%{public}u", bundleName.c_str(), flags);
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to write InterfaceToken");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to write bundleName");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteUint32(flags)) {
        APP_LOGE("fail to write flags");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appIndex)) {
        APP_LOGE("fail to write appIndex");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return GetVectorParcelInfo<LauncherAbilityResourceInfo>(
        BundleResourceInterfaceCode::GET_LAUNCHER_ABILITY_RESOURCE_INFO, data, launcherAbilityResourceInfo);
}

ErrCode BundleResourceProxy::GetAllBundleResourceInfo(const uint32_t flags,
    std::vector<BundleResourceInfo> &bundleResourceInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("start, flags:%{public}u", flags);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to write InterfaceToken");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteUint32(flags)) {
        APP_LOGE("fail to write flags");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return GetVectorParcelInfo<BundleResourceInfo>(
        BundleResourceInterfaceCode::GET_ALL_BUNDLE_RESOURCE_INFO, data, bundleResourceInfos);
}

ErrCode BundleResourceProxy::GetAllLauncherAbilityResourceInfo(const uint32_t flags,
    std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("start, flags:%{public}u", flags);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to write InterfaceToken");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteUint32(flags)) {
        APP_LOGE("fail to write flags");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return GetVectorParcelInfo<LauncherAbilityResourceInfo>(
        BundleResourceInterfaceCode::GET_ALL_LAUNCHER_ABILITY_RESOURCE_INFO, data, launcherAbilityResourceInfos);
}

ErrCode BundleResourceProxy::AddResourceInfoByBundleName(const std::string &bundleName, const int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("start, bundleName:%{public}s userId:%{private}d", bundleName.c_str(), userId);
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to write InterfaceToken");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to write bundleName");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to write userId");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!SendRequest(BundleResourceInterfaceCode::ADD_RESOURCE_INFO_BY_BUNDLE_NAME, data, reply)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        APP_LOGE("host reply err:%{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode BundleResourceProxy::AddResourceInfoByAbility(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, const int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("start, bundleName:%{public}s moduleName:%{public}s abilityName:%{public}s userId:%{private}d",
        bundleName.c_str(), moduleName.c_str(), abilityName.c_str(), userId);
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to write InterfaceToken");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to write bundleName");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(moduleName)) {
        APP_LOGE("fail to write moduleName");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(abilityName)) {
        APP_LOGE("fail to write abilityName");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to write userId");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!SendRequest(BundleResourceInterfaceCode::ADD_RESOURCE_INFO_BY_ABILITY, data, reply)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        APP_LOGE("host reply err:%{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode BundleResourceProxy::DeleteResourceInfo(const std::string &key)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("start, key:%{private}s", key.c_str());
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to write InterfaceToken");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(key)) {
        APP_LOGE("fail to write key");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!SendRequest(BundleResourceInterfaceCode::DELETE_RESOURCE_INFO, data, reply)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        APP_LOGE("host reply err:%{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

template<typename T>
ErrCode BundleResourceProxy::GetParcelInfo(BundleResourceInterfaceCode code, MessageParcel &data, T &parcelInfo)
{
    MessageParcel reply;
    if (!SendRequest(code, data, reply)) {
        APP_LOGE("SendTransactCmd failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        APP_LOGE("host reply err: %{public}d", ret);
        return ret;
    }
    size_t dataSize = reply.ReadUint32();
    void *buffer = nullptr;
    if (dataSize > MAX_IPC_ALLOWED_CAPACITY) {
        if (GetParcelInfoFromAshMem(reply, buffer) != ERR_OK) {
            APP_LOGE("read data from ashmem fail, length %{public}zu", dataSize);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    } else {
        if (!GetData(buffer, dataSize, reply.ReadRawData(dataSize))) {
            APP_LOGE("GetData failed dataSize: %{public}zu", dataSize);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }

    MessageParcel tmpParcel;
    if (!tmpParcel.ParseFrom(reinterpret_cast<uintptr_t>(buffer), dataSize)) {
        APP_LOGE("ParseFrom failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    std::unique_ptr<T> info(tmpParcel.ReadParcelable<T>());
    if (info == nullptr) {
        APP_LOGE("ReadParcelable failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    parcelInfo = *info;
    return ERR_OK;
}

template<typename T>
ErrCode BundleResourceProxy::GetVectorParcelInfo(
    BundleResourceInterfaceCode code, MessageParcel &data, std::vector<T> &parcelInfos)
{
    MessageParcel reply;
    if (!SendRequest(code, data, reply)) {
        APP_LOGE("SendTransactCmd failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    ErrCode res = reply.ReadInt32();
    if (res != ERR_OK) {
        APP_LOGE("failed err %{public}d", res);
        return res;
    }

    size_t dataSize = reply.ReadUint32();
    if (dataSize == 0) {
        APP_LOGW("Parcel no data");
        return ERR_OK;
    }

    void *buffer = nullptr;
    if (dataSize > MAX_IPC_ALLOWED_CAPACITY) {
        APP_LOGI("dataSize is too large, use ashmem");
        if (GetParcelInfoFromAshMem(reply, buffer) != ERR_OK) {
            APP_LOGE("read data from ashmem fail, length %{public}zu", dataSize);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    } else {
        if (!GetData(buffer, dataSize, reply.ReadRawData(dataSize))) {
            APP_LOGE("GetData failed dataSize: %{public}zu", dataSize);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }

    MessageParcel tempParcel;
    if (!tempParcel.ParseFrom(reinterpret_cast<uintptr_t>(buffer), dataSize)) {
        APP_LOGE("Fail to ParseFrom");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t infoSize = tempParcel.ReadInt32();
    CONTAINER_SECURITY_VERIFY(tempParcel, infoSize, &parcelInfos);
    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<T> info(tempParcel.ReadParcelable<T>());
        if (info == nullptr) {
            APP_LOGE("Read Parcelable infos failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        parcelInfos.emplace_back(*info);
    }

    return ERR_OK;
}

ErrCode BundleResourceProxy::GetParcelInfoFromAshMem(MessageParcel &reply, void *&data)
{
    sptr<Ashmem> ashMem = reply.ReadAshmem();
    if (ashMem == nullptr) {
        APP_LOGE("Ashmem is nullptr");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!ashMem->MapReadOnlyAshmem()) {
        APP_LOGE("MapReadOnlyAshmem failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t ashMemSize = ashMem->GetAshmemSize();
    int32_t offset = 0;
    const void* ashDataPtr = ashMem->ReadFromAshmem(ashMemSize, offset);
    if (ashDataPtr == nullptr) {
        APP_LOGE("ashDataPtr is nullptr");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if ((ashMemSize == 0) || ashMemSize > static_cast<int32_t>(MAX_PARCEL_CAPACITY)) {
        APP_LOGE("failed due to wrong size");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    data = malloc(ashMemSize);
    if (data == nullptr) {
        APP_LOGE("failed due to malloc data failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (memcpy_s(data, ashMemSize, ashDataPtr, ashMemSize) != EOK) {
        free(data);
        APP_LOGE("failed due to memcpy_s failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

bool BundleResourceProxy::SendRequest(BundleResourceInterfaceCode code,
    MessageParcel &data, MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        APP_LOGE("fail send transact cmd %{public}hhu due to remote object", code);
        return false;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != NO_ERROR) {
        APP_LOGE("receive error %{public}d in transact cmd %{public}hhu", result, code);
        return false;
    }
    return true;
}
} // AppExecFwk
} // OHOS
