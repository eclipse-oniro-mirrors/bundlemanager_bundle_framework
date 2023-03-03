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

int32_t ServiceRouterMgrProxy::QueryServiceInfos(const Want &want, const ExtensionServiceType &serviceType,
    std::vector<ServiceInfo> &serviceInfos)
{
    APP_LOGI("ServiceRouterMgrProxy QueryServiceInfos");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("write interfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        APP_LOGE("write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(static_cast<int32_t>(serviceType))) {
        APP_LOGE("fail to QueryServiceInfos due to write type fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t res = GetParcelableInfos<ServiceInfo>(ServiceRouterMgrProxy::Message::QUERY_SERVICE_INFOS, data,
        serviceInfos);
    if (res != OHOS::NO_ERROR) {
        APP_LOGE("fail to QueryServiceInfos from server, error code: %{public}d", res);
    }
    return res;
}

int32_t ServiceRouterMgrProxy::QueryPurposeInfos(const Want &want, const std::string purposeName,
    std::vector<PurposeInfo> &purposeInfos)
{
    APP_LOGI("ServiceRouterMgrProxy QueryPurposeInfos");
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

    if (!reply.ReadBool()) {
        APP_LOGE("reply's result is false");
        return ERR_APPEXECFWK_PARCEL_ERROR;
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