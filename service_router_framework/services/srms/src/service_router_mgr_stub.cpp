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

#include <vector>
#include "appexecfwk_errors.h"
#include "app_log_wrapper.h"
#include "service_router_mgr_stub.h"
#include "service_info.h"

namespace OHOS {
namespace AppExecFwk {
ServiceRouterMgrStub::ServiceRouterMgrStub()
{
    APP_LOGI("ServiceRouterMgrStub instance is created");
}

ServiceRouterMgrStub::~ServiceRouterMgrStub()
{
    APP_LOGI("ServiceRouterMgrStub instance is destroyed");
}

int ServiceRouterMgrStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    std::u16string descriptor = ServiceRouterMgrStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        APP_LOGI("local descriptor is not equal to remote");
        return ERR_INVALID_STATE;
    }

    switch (code)
    {
        case static_cast<uint32_t>(IServiceRouterManager::Message::QUERY_SERVICE_INFOS):
            return HandleQueryServiceInfos(data, reply);
        case static_cast<uint32_t>(IServiceRouterManager::Message::QUERY_INTENT_INFOS):
            return HandleQueryIntentInfos(data, reply);
        default:
            APP_LOGW("DistributedBmsHost receives unknown code, code = %{public}d", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return NO_ERROR;
}

int ServiceRouterMgrStub::HandleQueryServiceInfos(MessageParcel &data, MessageParcel &reply)
{
    APP_LOGI("ServiceRouterMgrStub handle query service infos");
    Want *want = data.ReadParcelable<Want>();
    ExtensionServiceType type = static_cast<ExtensionServiceType>(data.ReadInt32());
    std::vector<ServiceInfo> infos;
    int ret = QueryServiceInfos(*want, type, infos);
    if (ret != NO_ERROR) {
        APP_LOGE("QueryServiceInfos result:%{public}d", ret);
        return ret;
    }
    if (!reply.WriteBool(true))
    {
        APP_LOGE("QueryServiceInfos write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!WriteParcelableVector<ServiceInfo>(infos, reply))
    {
        APP_LOGE("QueryServiceInfos write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return NO_ERROR;
}

int ServiceRouterMgrStub::HandleQueryIntentInfos(MessageParcel &data, MessageParcel &reply)
{
    APP_LOGI("ServiceRouterMgrStub handle query service infos with muti param");
    Want *want = data.ReadParcelable<Want>();
    std::string intentName = data.ReadString();
    std::vector<IntentInfo> infos;
    int ret = QueryIntentInfos(*want, intentName, infos);
    if (ret != NO_ERROR) {
        APP_LOGE("QueryServiceInfos result:%{public}d", ret);
        return ret;
    }
    if (!reply.WriteBool(true))
    {
        APP_LOGE("QueryIntentInfos write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!WriteParcelableVector<IntentInfo>(infos, reply))
    {
        APP_LOGE("QueryIntentInfos write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return NO_ERROR;
}

template <typename T>
bool ServiceRouterMgrStub::WriteParcelableVector(std::vector<T> &parcelableVector, Parcel &reply)
{
    if (!reply.WriteInt32(parcelableVector.size()))
    {
        APP_LOGE("write ParcelableVector failed");
        return false;
    }

    for (auto &parcelable : parcelableVector)
    {
        if (!reply.WriteParcelable(&parcelable))
        {
            APP_LOGE("write ParcelableVector failed");
            return false;
        }
    }
    return true;
}
}  // namespace AAFwk
}  // namespace OHOS
