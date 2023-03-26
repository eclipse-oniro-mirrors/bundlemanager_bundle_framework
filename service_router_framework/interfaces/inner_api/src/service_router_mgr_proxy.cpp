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

#include "service_router_mgr_proxy.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "parcel_macro.h"
#include "service_router_mgr_interface.h"

namespace OHOS {
namespace AppExecFwk {
ServiceRouterMgrProxy::ServiceRouterMgrProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<IServiceRouterManager>(object)
{
    APP_LOGD("ServiceRouterMgrProxy instance is created");
}

ServiceRouterMgrProxy::~ServiceRouterMgrProxy()
{
    APP_LOGD("ServiceRouterMgrProxy instance is destroyed");
}

int32_t ServiceRouterMgrProxy::QueryBusinessAbilityInfos(const BusinessAbilityFilter &filter,
    std::vector<BusinessAbilityInfo> &abilityInfos)
{
    APP_LOGD("ServiceRouterMgrProxy QueryBusinessAbilityInfos");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("write interfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&filter)) {
        APP_LOGE("write filter failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t res = GetParcelableInfos<BusinessAbilityInfo>(ServiceRouterMgrProxy::Message::QUERY_BUSINESS_ABILITY_INFOS,
        data, abilityInfos);
    if (res != OHOS::NO_ERROR) {
        APP_LOGE("fail to QueryBusinessAbilityInfos from server, error code: %{public}d", res);
    }
    return res;
}

int32_t ServiceRouterMgrProxy::QueryPurposeInfos(const Want &want, const std::string purposeName,
    std::vector<PurposeInfo> &purposeInfos)
{
    APP_LOGD("ServiceRouterMgrProxy QueryPurposeInfos");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("write interfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        APP_LOGE("write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(purposeName)) {
        APP_LOGE("write purposeName fail");
        return false;
    }
    int32_t res = GetParcelableInfos<PurposeInfo>(ServiceRouterMgrProxy::Message::QUERY_PURPOSE_INFOS, data,
        purposeInfos);
    if (res != OHOS::NO_ERROR) {
        APP_LOGE("fail to QueryPurposeInfos from server, error code: %{public}d", res);
    }
    return res;
}

int32_t ServiceRouterMgrProxy::StartUIExtensionAbility(const Want &want, const sptr<SessionInfo> &sessionInfo,
    int32_t userId, ExtensionAbilityType extensionType)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("write interfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        APP_LOGE("want write failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (sessionInfo) {
        if (!data.WriteBool(true) || !data.WriteParcelable(sessionInfo)) {
            APP_LOGE("flag and sessionInfo write failed.");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    } else {
        if (!data.WriteBool(false)) {
            APP_LOGE("flag write failed.");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }

    if (!data.WriteInt32(userId)) {
        APP_LOGE("StartExtensionAbility, userId write failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(static_cast<int32_t>(extensionType))) {
        APP_LOGE("StartExtensionAbility, extensionType write failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!Remote()) {
        APP_LOGE("StartExtensionAbility, Remote error.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        APP_LOGE("StartExtensionAbility, Remote() is NULL");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t error = remote->SendRequest(ServiceRouterMgrProxy::Message::START_UI_EXTENSION, data, reply, option);
    if (error != NO_ERROR) {
        APP_LOGE("StartExtensionAbility, Send request error: %{public}d", error);
        return error;
    }
    return reply.ReadInt32();
}

int32_t ServiceRouterMgrProxy::ConnectUIExtensionAbility(const Want &want, const sptr<IAbilityConnection> &connect,
    const sptr<SessionInfo> &sessionInfo, int32_t userId)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(GetDescriptor()) || !data.WriteParcelable(&want)) {
        APP_LOGE("write interfaceToken or want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!connect) {
        APP_LOGE("connect ability fail, connect is nullptr");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (connect->AsObject()) {
        if (!data.WriteBool(true) || !data.WriteRemoteObject(connect->AsObject())) {
            APP_LOGE("flag and connect write failed.");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    } else {
        if (!data.WriteBool(false)) {
            APP_LOGE("flag write failed.");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    if (sessionInfo) {
        if (!data.WriteBool(true) || !data.WriteParcelable(sessionInfo)) {
            APP_LOGE("flag and sessionInfo write failed.");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    } else {
        if (!data.WriteBool(false)) {
            APP_LOGE("flag write failed.");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("%{public}s, userId write failed.", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!Remote()) {
        APP_LOGE("connect ability fail, remote is nullptr");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t error = Remote()->SendRequest(ServiceRouterMgrProxy::Message::CONNECT_UI_EXTENSION, data, reply, option);
    if (error != NO_ERROR) {
        APP_LOGE("%{public}s, Send request error: %{public}d", __func__, error);
        return error;
    }
    return reply.ReadInt32();
}

int32_t ServiceRouterMgrProxy::SendRequest(ServiceRouterMgrProxy::Message code, MessageParcel &data,
    MessageParcel &reply)
{
    APP_LOGI("ServiceRouterMgrProxy SendRequest");
    sptr<IRemoteObject> remote = Remote();
    MessageOption option(MessageOption::TF_SYNC);
    if (remote == nullptr) {
        APP_LOGE("fail to send %{public}d cmd to service, remote object is null", code);
        return ERR_APPEXECFWK_FAILED_GET_REMOTE_PROXY;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != OHOS::NO_ERROR) {
        APP_LOGE("fail to send %{public}d cmd to service, transact error:%{public}d", code, result);
    }
    return result;
}

template <typename T>
int32_t ServiceRouterMgrProxy::GetParcelableInfos(
    ServiceRouterMgrProxy::Message code, MessageParcel &data, std::vector<T> &parcelableInfos)
{
    MessageParcel reply;
    int32_t result = SendRequest(code, data, reply);
    if (result != OHOS::NO_ERROR) {
        APP_LOGE("SendRequest result false");
        return result;
    }

    int32_t res = reply.ReadInt32();
    if (res != ERR_OK) {
        APP_LOGE("reply's result is %{public}d", res);
        return res;
    }

    int32_t infosSize = reply.ReadInt32();
    for (int32_t j = 0; j < infosSize; j++) {
        std::unique_ptr<T> info(reply.ReadParcelable<T>());
        if (!info) {
            APP_LOGE("Read parcelableInfos failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        parcelableInfos.emplace_back(*info);
    }
    APP_LOGI("get parcelableInfos success");
    return OHOS::NO_ERROR;
}
}  // namespace AAFwk
}  // namespace OHOS