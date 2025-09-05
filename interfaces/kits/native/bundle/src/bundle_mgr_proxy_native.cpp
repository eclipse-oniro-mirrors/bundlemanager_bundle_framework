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

#include "bundle_mgr_proxy_native.h"

#include "app_log_wrapper.h"
#include "app_log_tag_wrapper.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "parcel_macro.h"
#include "securec.h"
#include "string_ex.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    const std::u16string BMS_PROXY_INTERFACE_TOKEN = u"ohos.appexecfwk.BundleMgr";
    constexpr size_t MAX_PARCEL_CAPACITY = 1024 * 1024 * 1024; // allow max 1GB resource size
    constexpr size_t MAX_IPC_REWDATA_SIZE = 120 * 1024 * 1024; // max ipc size 120MB
bool GetData(void *&buffer, size_t size, const void *data)
{
    if (data == nullptr) {
        APP_LOGE("GetData failed due to null data");
        return false;
    }
    if (size == 0 || size > MAX_PARCEL_CAPACITY) {
        APP_LOGE("GetData failed due to zero size");
        return false;
    }
    buffer = malloc(size);
    if (buffer == nullptr) {
        APP_LOGE("GetData failed due to malloc buffer failed");
        return false;
    }
    if (memcpy_s(buffer, size, data, size) != EOK) {
        free(buffer);
        APP_LOGE("GetData failed due to memcpy_s failed");
        return false;
    }
    return true;
}
}

sptr<IRemoteObject> BundleMgrProxyNative::GetBmsProxy()
{
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        APP_LOGE("fail to get samgr");
        return nullptr;
    }
    return samgrProxy->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
}

bool BundleMgrProxyNative::GetBundleInfoForSelf(int32_t flags, BundleInfo &bundleInfo)
{
    LOG_I(BMS_TAG_QUERY, "begin to get bundle info for self");
    MessageParcel data;
    if (!data.WriteInterfaceToken(BMS_PROXY_INTERFACE_TOKEN)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfoForSelf due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteInt32(flags)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfoForSelf due to write flag fail");
        return false;
    }
    if (!GetParcelableInfo<BundleInfo>(GET_BUNDLE_INFO_FOR_SELF_NATIVE, data, bundleInfo)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfoForSelf from server");
        return false;
    }
    return true;
}

bool BundleMgrProxyNative::GetCompatibleDeviceTypeNative(std::string &deviceType)
{
    LOG_D(BMS_TAG_QUERY, "begin to get compatible device type");
    MessageParcel data;
    if (!data.WriteInterfaceToken(BMS_PROXY_INTERFACE_TOKEN)) {
        LOG_E(BMS_TAG_QUERY, "Write interfaceToken failed");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(GET_COMPATIBLED_DEVICE_TYPE_NATIVE, data, reply)) {
        return false;
    }
    int32_t res = reply.ReadInt32();
    if (res != NO_ERROR) {
        APP_LOGE("reply result failed");
        return false;
    }
    deviceType = reply.ReadString();
    APP_LOGD("get compatible device type success");
    return true;
}

ErrCode BundleMgrProxyNative::GetLauncherAbilityResourceInfoNative(
    std::string &fileType, std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfoArr)
{
    LOG_I(BMS_TAG_QUERY, "begin to get Launcher Ability Resource Info");
    MessageParcel data;
    if (!data.WriteInterfaceToken(BMS_PROXY_INTERFACE_TOKEN)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetLauncherAbilityResourceInfoNative due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(fileType)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetLauncherAbilityResourceInfoNative due to write flag fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = GetVectorFromParcelIntelligentWithErrCode<LauncherAbilityResourceInfo>(
        GET_LAUNCHER_ABILITY_RESOURE_INFO_NATIVE, data, launcherAbilityResourceInfoArr);
    return ret;
}

bool BundleMgrProxyNative::SendTransactCmd(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);

    sptr<IRemoteObject> remote = GetBmsProxy();
    if (remote == nullptr) {
        APP_LOGE("fail to send transact cmd %{public}d due to remote object", code);
        return false;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != NO_ERROR) {
        APP_LOGE("receive error transact code %{public}d in transact cmd %{public}d", result, code);
        return false;
    }
    return true;
}

template<typename T>
bool BundleMgrProxyNative::GetParcelableInfo(uint32_t code, MessageParcel &data, T &parcelableInfo)
{
    MessageParcel reply;
    if (!SendTransactCmd(code, data, reply)) {
        return false;
    }

    int32_t res = reply.ReadInt32();
    if (res != NO_ERROR) {
        APP_LOGE("reply result failed");
        return false;
    }
    std::unique_ptr<T> info(reply.ReadParcelable<T>());
    if (info == nullptr) {
        APP_LOGE("readParcelableInfo failed");
        return false;
    }
    parcelableInfo = *info;
    APP_LOGD("get parcelable info success");
    return true;
}

template<typename T>
ErrCode BundleMgrProxyNative::GetVectorFromParcelIntelligentWithErrCode(
    uint32_t code, MessageParcel &data, std::vector<T> &parcelableInfos)
{
    MessageParcel reply;
    if (!SendTransactCmd(code, data, reply)) {
        APP_LOGE("SendTransactCmd failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    ErrCode res = reply.ReadInt32();
    if (res != ERR_OK) {
        return res;
    }

    return InnerGetVectorFromParcelIntelligent<T>(reply, parcelableInfos);
}

template<typename T>
ErrCode BundleMgrProxyNative::InnerGetVectorFromParcelIntelligent(
    MessageParcel &reply, std::vector<T> &parcelableInfos)
{
    size_t dataSize = static_cast<size_t>(reply.ReadInt32());
    if (dataSize == 0) {
        APP_LOGW("Parcel no data");
        return ERR_OK;
    }

    void *buffer = nullptr;
    if (dataSize > MAX_IPC_REWDATA_SIZE) {
        APP_LOGI("dataSize is too large, use ashmem");
        if (GetParcelInfoFromAshMem(reply, buffer) != ERR_OK) {
            APP_LOGE("read data from ashmem fail, length %{public}zu", dataSize);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    } else {
        if (!GetData(buffer, dataSize, reply.ReadRawData(dataSize))) {
            APP_LOGE("Fail read raw data length %{public}zu", dataSize);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }

    MessageParcel tempParcel;
    if (!tempParcel.ParseFrom(reinterpret_cast<uintptr_t>(buffer), dataSize)) {
        APP_LOGE("Fail to ParseFrom");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t infoSize = tempParcel.ReadInt32();
    CONTAINER_SECURITY_VERIFY(tempParcel, infoSize, &parcelableInfos);
    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<T> info(tempParcel.ReadParcelable<T>());
        if (info == nullptr) {
            APP_LOGE("Read Parcelable infos failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        parcelableInfos.emplace_back(*info);
    }

    return ERR_OK;
}

ErrCode BundleMgrProxyNative::GetParcelInfoFromAshMem(MessageParcel &reply, void *&data)
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
}  // namespace AppExecFwk
}  // namespace OHOS