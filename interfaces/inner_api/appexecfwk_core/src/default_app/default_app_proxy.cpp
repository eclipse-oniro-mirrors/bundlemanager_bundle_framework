/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "bundle_constants.h"
#include "hitrace_meter.h"
#include "ipc_types.h"
#include "parcel.h"
#include "securec.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr size_t MAX_PARCEL_CAPACITY_OF_ASHMEM = 1024 * 1024 * 1024; // allow max 1GB resource size
constexpr size_t MAX_IPC_ALLOWED_CAPACITY = 100 * 1024 * 1024; // max ipc size 100MB
bool GetData(size_t size, const void *data, void *&buffer)
{
    if (data == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "failed due to null data");
        return false;
    }
    if ((size == 0) || size > Constants::MAX_PARCEL_CAPACITY) {
        LOG_E(BMS_TAG_DEFAULT, "failed due to wrong size");
        return false;
    }
    buffer = malloc(size);
    if (buffer == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "failed due to malloc buffer failed");
        return false;
    }
    if (memcpy_s(buffer, size, data, size) != EOK) {
        free(buffer);
        LOG_E(BMS_TAG_DEFAULT, "failed due to memcpy_s failed");
        return false;
    }
    return true;
}
}
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
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);

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
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);

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
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);

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

ErrCode DefaultAppProxy::SetDefaultApplicationForAppClone(const int32_t userId, const int32_t appIndex,
    const std::string& type, const Want& want)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to SetDefaultApplicationForAppClone");
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appIndex)) {
        LOG_E(BMS_TAG_DEFAULT, "write appIndex failed");
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
    if (!SendRequest(DefaultAppInterfaceCode::SET_DEFAULT_APPLICATION_FOR_APP_CLONE, data, reply)) {
        LOG_E(BMS_TAG_DEFAULT, "SendRequest failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return reply.ReadInt32();
}

ErrCode DefaultAppProxy::SetDefaultApplicationForCustom(const int32_t userId, const std::string& type,
    const Want& want)
{
    LOG_NOFUNC_D(BMS_TAG_DEFAULT, "begin to SetDefaultApplicationForCustom");
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_NOFUNC_E(BMS_TAG_DEFAULT, "WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_NOFUNC_E(BMS_TAG_DEFAULT, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(type)) {
        LOG_NOFUNC_E(BMS_TAG_DEFAULT, "write type failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        LOG_NOFUNC_E(BMS_TAG_DEFAULT, "write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(DefaultAppInterfaceCode::SET_DEFAULT_APPLICATION_FOR_CUSTOM, data, reply)) {
        LOG_NOFUNC_E(BMS_TAG_DEFAULT, "SendRequest failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return reply.ReadInt32();
}

ErrCode DefaultAppProxy::GetDefaultApplicationCandidates(int32_t userId, const std::string& type,
    int32_t abilityFlags, std::vector<AbilityInfo>& abilityInfos)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to GetDefaultApplicationCandidates");
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);

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
    if (!data.WriteInt32(abilityFlags)) {
        LOG_E(BMS_TAG_DEFAULT, "write abilityFlags failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendRequest(DefaultAppInterfaceCode::GET_DEFAULT_APPLICATION_CANDIDATES, data, reply)) {
        LOG_E(BMS_TAG_DEFAULT, "SendRequest failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetVectorParcelInfo<AbilityInfo>(reply, abilityInfos);
}

ErrCode DefaultAppProxy::ResetDefaultApplication(int32_t userId, const std::string& type)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to ResetDefaultApplication");
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);

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
        LOG_E(BMS_TAG_DEFAULT, "failed to send request %{public}hhu due to remote object null", code);
        return false;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != NO_ERROR) {
        LOG_E(BMS_TAG_DEFAULT, "receive error code %{public}d in transact %{public}hhu", result, code);
        return false;
    }
    return true;
}

template<typename T>
ErrCode DefaultAppProxy::GetVectorParcelInfo(MessageParcel& reply, std::vector<T>& parcelInfos)
{
    ErrCode res = reply.ReadInt32();
    if (res != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "failed err %{public}d", res);
        return res;
    }

    size_t dataSize = reply.ReadUint32();
    if (dataSize == 0) {
        LOG_W(BMS_TAG_DEFAULT, "Parcel no data");
        return ERR_OK;
    }

    void *buffer = nullptr;
    if (dataSize > MAX_IPC_ALLOWED_CAPACITY) {
        LOG_I(BMS_TAG_DEFAULT, "dataSize is too large, use ashmem");
        if (GetParcelInfoFromAshMem(reply, dataSize, buffer) != ERR_OK) {
            LOG_E(BMS_TAG_DEFAULT, "read data from ashmem fail, length %{public}zu", dataSize);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    } else if (!GetData(dataSize, reply.ReadRawData(dataSize), buffer)) {
        LOG_E(BMS_TAG_DEFAULT, "GetData failed dataSize: %{public}zu", dataSize);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ParseVectorFromBuffer<T>(buffer, dataSize, parcelInfos);
}

template<typename T>
ErrCode DefaultAppProxy::ParseVectorFromBuffer(void* buffer, size_t dataSize, std::vector<T>& parcelInfos)
{
    MessageParcel tempParcel;
    if (!tempParcel.ParseFrom(reinterpret_cast<uintptr_t>(buffer), dataSize)) {
        LOG_E(BMS_TAG_DEFAULT, "Fail to ParseFrom");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t infoSize = tempParcel.ReadInt32();
    if (infoSize < 0 || static_cast<size_t>(infoSize) > tempParcel.GetReadableBytes() ||
        parcelInfos.max_size() < static_cast<size_t>(infoSize)) {
        LOG_E(BMS_TAG_DEFAULT, "invalid infoSize: %{public}d, readable: %{public}zu",
            infoSize, tempParcel.GetReadableBytes());
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<T> info(tempParcel.ReadParcelable<T>());
        if (info == nullptr) {
            LOG_E(BMS_TAG_DEFAULT, "Read Parcelable infos failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        parcelInfos.emplace_back(*info);
    }

    return ERR_OK;
}

ErrCode DefaultAppProxy::GetParcelInfoFromAshMem(MessageParcel& reply, size_t dataSize, void*& data)
{
    sptr<Ashmem> ashMem = reply.ReadAshmem();
    if (ashMem == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "Ashmem is nullptr");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!ashMem->MapReadOnlyAshmem()) {
        LOG_E(BMS_TAG_DEFAULT, "MapReadOnlyAshmem failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t ashMemSize = ashMem->GetAshmemSize();
    if (ashMemSize <= 0 || ashMemSize > static_cast<int32_t>(MAX_PARCEL_CAPACITY_OF_ASHMEM) ||
        static_cast<size_t>(ashMemSize) != dataSize) {
        LOG_E(BMS_TAG_DEFAULT, "invalid ashmem size");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t offset = 0;
    const void* ashDataPtr = ashMem->ReadFromAshmem(ashMemSize, offset);
    if (ashDataPtr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "ashDataPtr is nullptr");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (dataSize == 0 || dataSize > MAX_PARCEL_CAPACITY_OF_ASHMEM) {
        LOG_E(BMS_TAG_DEFAULT, "invalid data size %{public}zu", dataSize);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    data = malloc(dataSize);
    if (data == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "failed due to malloc data failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (memcpy_s(data, dataSize, ashDataPtr, dataSize) != EOK) {
        free(data);
        LOG_E(BMS_TAG_DEFAULT, "failed due to memcpy_s failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}
}
}
