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

#include "overlay_manager_proxy.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "hitrace_meter.h"
#include "ipc_types.h"

namespace OHOS {
namespace AppExecFwk {
OverlayManagerProxy::OverlayManagerProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IOverlayManager>(object)
{
    APP_LOGI("create OverlayManagerProxy.");
}

OverlayManagerProxy::~OverlayManagerProxy()
{
    APP_LOGI("destroy OverlayManagerProxy.");
}


ErrCode OverlayManagerProxy::GetAllOverlayModuleInfo(const std::string &bundleName,
    std::vector<OverlayModuleInfo> &overlayModuleInfo, int32_t userId)
{
    APP_LOGD("begin to call GetAllOverlayModuleInfo.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);

    if (bundleName.empty()) {
        APP_LOGE("GetAllOverlayModuleInfo failed due to params error.");
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("write bundleName failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt32(userId)) {
        APP_LOGE("failed to GetAllOverlayModuleInfo due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return GetParcelableInfosWithErrCode<OverlayModuleInfo>(
        IOverlayManager::Message::GET_ALL_OVERLAY_MODULE_INFO, data, overlayModuleInfo);
}

ErrCode OverlayManagerProxy::GetOverlayModuleInfo(const std::string &bundleName, const std::string &moduleName,
    OverlayModuleInfo &overlayModuleInfo, int32_t userId)
{
    APP_LOGD("begin to call GetOverlayModuleInfo.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);

    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGE("GetOverlayModuleInfo failed due to params error.");
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("write bundleName failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(moduleName)) {
        APP_LOGE("write moduleName failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("failed to GetOverlayModuleInfo due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return GetParcelableInfo(IOverlayManager::Message::GET_OVERLAY_MODULE_INFO, data, overlayModuleInfo);
}

ErrCode OverlayManagerProxy::GetOverlayBundleInfoForTarget(const std::string &targetBundleName,
    std::vector<OverlayBundleInfo> &overlayBundleInfo, int32_t userId)
{
    APP_LOGD("begin to call GetOverlayBundleInfoForTarget.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);

    if (targetBundleName.empty()) {
        APP_LOGE("GetOverlayBundleInfoForTarget failed due to params error.");
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(targetBundleName)) {
        APP_LOGE("write targetBundleName failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt32(userId)) {
        APP_LOGE("failed to GetOverlayBundleInfoForTarget due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return GetParcelableInfosWithErrCode<OverlayBundleInfo>(
        IOverlayManager::Message::GET_OVERLAY_BUNDLE_INFO_FOR_TARGET, data, overlayBundleInfo);
}

ErrCode OverlayManagerProxy::GetOverlayModuleInfoForTarget(const std::string &targetBundleName,
    const std::string &targetModuleName, std::vector<OverlayModuleInfo> &overlayModuleInfo,
    int32_t userId)
{
    APP_LOGD("begin to call GetOverlayModuleInfoForTarget.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);

    if (targetBundleName.empty() || targetModuleName.empty()) {
        APP_LOGE("GetOverlayModuleInfoForTarget failed due to params error.");
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(targetBundleName)) {
        APP_LOGE("write targetBundleName failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(targetModuleName)) {
        APP_LOGE("write targetModuleName failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("failed to GetOverlayModuleInfoForTarget due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return GetParcelableInfosWithErrCode<OverlayModuleInfo>(
        IOverlayManager::Message::GET_OVERLAY_MODULE_INFO_FOR_TARGET, data, overlayModuleInfo);
}

ErrCode OverlayManagerProxy::SetOverlayEnabled(const std::string &bundleName, const std::string &moduleName,
    bool isEnabled, int32_t userId)
{
    APP_LOGD("begin to call SetOverlayEnabled.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGE("SetOverlayEnabled failed due to params error.");
        return ERR_BUNDLEMANAGER_OVERLAY_SET_OVERLAY_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("write bundleName failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(moduleName)) {
        APP_LOGE("write moduleName failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isEnabled)) {
        APP_LOGE("failed to SetOverlayEnabled due to write isEnabled fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("failed to SetOverlayEnabled due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(IOverlayManager::Message::SET_OVERLAY_ENABLED, data, reply)) {
        APP_LOGE("SendTransactCmd failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto res = reply.ReadInt32();
    if (res != ERR_OK) {
        APP_LOGE("failed to SetOverlayEnabled due to error %{public}d", res);
    }
    return res;
}

ErrCode OverlayManagerProxy::VerifySystemApi()
{
    APP_LOGD("begin to call VerifySystemApi.");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(IOverlayManager::Message::VERIFY_SYSTEM_APP, data, reply)) {
        APP_LOGE("SendTransactCmd failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto res = reply.ReadInt32();
    if (res != ERR_OK) {
        APP_LOGE("failed to VerifySystemApi due to error %{public}d", res);
    }
    return res;
}

template<typename T>
ErrCode OverlayManagerProxy::GetParcelableInfo(IOverlayManager::Message code, MessageParcel &data, T &parcelableInfo)
{
    MessageParcel reply;
    if (!SendTransactCmd(code, data, reply)) {
        APP_LOGE("SendTransactCmd failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    ErrCode res = reply.ReadInt32();
    if (res != ERR_OK) {
        APP_LOGE("GetParcelableInfo failed due to %{public}d", res);
        return res;
    }

    std::unique_ptr<T> info(reply.ReadParcelable<T>());
    if (info == nullptr) {
        APP_LOGE("readParcelableInfo failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    parcelableInfo = *info;
    APP_LOGD("get parcelable info success");
    return ERR_OK;
}

template<typename T>
ErrCode OverlayManagerProxy::GetParcelableInfosWithErrCode(IOverlayManager::Message code, MessageParcel &data,
    std::vector<T> &parcelableInfos)
{
    MessageParcel reply;
    if (!SendTransactCmd(code, data, reply)) {
        APP_LOGE("SendTransactCmd failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    ErrCode res = reply.ReadInt32();
    if (res == ERR_OK) {
        int32_t infoSize = reply.ReadInt32();
        for (int32_t i = 0; i < infoSize; i++) {
            std::unique_ptr<T> info(reply.ReadParcelable<T>());
            if (info == nullptr) {
                APP_LOGE("Read Parcelable infos failed");
                return ERR_APPEXECFWK_PARCEL_ERROR;
            }
            parcelableInfos.emplace_back(*info);
        }
        APP_LOGD("get parcelable infos success");
    }
    APP_LOGD("GetParcelableInfosWithErrCode ErrCode : %{public}d", res);
    return res;
}

bool OverlayManagerProxy::SendTransactCmd(IOverlayManager::Message code, MessageParcel &data, MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        APP_LOGE("fail to send transact cmd %{public}d due to remote object", code);
        return false;
    }
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != NO_ERROR) {
        APP_LOGE("receive error transact code %{public}d in transact cmd %{public}d", result, code);
        return false;
    }
    return true;
}
} // AppExecFwk
} // OHOS