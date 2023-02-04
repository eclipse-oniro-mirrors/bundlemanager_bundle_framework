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

#include "overlay_manager_host.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "hitrace_meter.h"
#include "ipc_types.h"

namespace OHOS {
namespace AppExecFwk {
OverlayManagerHost::OverlayManagerHost()
{
    APP_LOGI("create OverlayManagerHost.");
    init();
}

OverlayManagerHost::~OverlayManagerHost()
{
    APP_LOGI("destroy OverlayManagerHost.");
}

void OverlayManagerHost::init()
{
    funcMap_.emplace(IOverlayManager::Message::GET_ALL_OVERLAY_MODULE_INFO, &OverlayManagerHost::HandleGetAllOverlayModuleInfo);
    funcMap_.emplace(IOverlayManager::Message::GET_OVERLAY_MODULE_INFO, &OverlayManagerHost::HandleGetOverlayModuleInfo);
    funcMap_.emplace(IOverlayManager::Message::GET_OVERLAY_BUNDLE_INFO_FOR_TARGET,
        &OverlayManagerHost::HandleGetOverlayBundleInfoForTarget);
    funcMap_.emplace(IOverlayManager::Message::GET_OVERLAY_MODULE_INFO_FOR_TARGET,
        &OverlayManagerHost::HandleGetOverlayModuleInfoForTarget);
}


int OverlayManagerHost::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    APP_LOGD("bundle mgr host onReceived message, the message code is %{public}u", code);
    std::u16string descripter = OverlayManagerHost::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        APP_LOGE("fail to write reply message in bundle mgr host due to the reply is nullptr");
        return OBJECT_NULL;
    }

    ErrCode errCode = ERR_OK;
    if (funcMap_.find(code) != funcMap_.end() && funcMap_[code] != nullptr) {
        errCode = (this->*funcMap_[code])(data, reply);
    } else {
        APP_LOGW("ovarlayMgr host receives unknown code, code = %{public}u", code);
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    APP_LOGD("ovarlayMgr host finish to process message");
    return (errCode == ERR_OK) ? NO_ERROR : UNKNOWN_ERROR;
}

ErrCode OverlayManagerHost::HandleGetAllOverlayModuleInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    int userId = data.ReadInt32();
    APP_LOGD("bundleName %{public}s, userId %{public}d", bundleName.c_str(), userId);

    std::vector<OverlayModuleInfo> infos;
    auto res = GetAllOverlayModuleInfo(bundleName, infos, userId);
    if (!reply.WriteInt32(res)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (res == ERR_OK) {
        if (!WriteParcelableVector(infos, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode OverlayManagerHost::HandleGetOverlayModuleInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string moduleName = data.ReadString();
    int userId = data.ReadInt32();
    APP_LOGD("bundleName %{public}s, moduleName %{public}s, userId %{public}d", bundleName.c_str(),
        moduleName.c_str(), userId);

    OverlayModuleInfo info;
    auto res = GetOverlayModuleInfo(bundleName, moduleName, info, userId);
    if (!reply.WriteInt32(res)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (res == ERR_OK) {
        if (!reply.WriteParcelable(&info)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode OverlayManagerHost::HandleGetOverlayBundleInfoForTarget(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string targetBundleName = data.ReadString();
    int userId = data.ReadInt32();

    std::vector<OverlayBundleInfo> overlayBundleInfo;
    auto res = GetOverlayBundleInfoForTarget(targetBundleName, overlayBundleInfo, userId);
    if (!reply.WriteInt32(res)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (res == ERR_OK) {
        if (!WriteParcelableVector(overlayBundleInfo, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode OverlayManagerHost::HandleGetOverlayModuleInfoForTarget(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string targetBundleName = data.ReadString();
    std::string targetModuleName = data.ReadString();
    int userId = data.ReadInt32();

    std::vector<OverlayModuleInfo> overlayModuleInfo;
    auto res = GetOverlayModuleInfoForTarget(targetBundleName, targetModuleName, overlayModuleInfo, userId);
    if (!reply.WriteInt32(res)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (res == ERR_OK) {
        if (!WriteParcelableVector(overlayModuleInfo, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

template<typename T>
bool OverlayManagerHost::WriteParcelableVector(std::vector<T> &parcelableVector, MessageParcel &reply)
{
    if (!reply.WriteInt32(parcelableVector.size())) {
        APP_LOGE("write ParcelableVector failed");
        return false;
    }

    for (auto &parcelable : parcelableVector) {
        if (!reply.WriteParcelable(&parcelable)) {
            APP_LOGE("write ParcelableVector failed");
            return false;
        }
    }
    return true;
}
} // AppExecFwk
} // namespace OHOS
