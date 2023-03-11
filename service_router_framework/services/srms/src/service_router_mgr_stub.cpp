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

#include "service_router_mgr_stub.h"

#include <vector>

#include "accesstoken_kit.h"
#include "appexecfwk_errors.h"
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "ipc_skeleton.h"
#include "service_info.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace AppExecFwk {
ServiceRouterMgrStub::ServiceRouterMgrStub()
{
    APP_LOGD("ServiceRouterMgrStub instance is created");
}

ServiceRouterMgrStub::~ServiceRouterMgrStub()
{
    APP_LOGD("ServiceRouterMgrStub instance is destroyed");
}

int ServiceRouterMgrStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    std::u16string descriptor = ServiceRouterMgrStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        APP_LOGE("local descriptor is not equal to remote");
        return ERR_INVALID_STATE;
    }

    switch (code) {
        case static_cast<uint32_t>(IServiceRouterManager::Message::QUERY_SERVICE_INFOS):
            return HandleQueryServiceInfos(data, reply);
        case static_cast<uint32_t>(IServiceRouterManager::Message::QUERY_PURPOSE_INFOS):
            return HandleQueryPurposeInfos(data, reply);
        case static_cast<uint32_t>(IServiceRouterManager::Message::START_UI_EXTENSION_ABILITY):
            return HandleStartUIExtensionAbility(data, reply);
        case static_cast<uint32_t>(IServiceRouterManager::Message::CONNECT_UI_EXTENSION_ABILITY):
            return HandleConnectUIExtensionAbility(data, reply);
        default:
            APP_LOGW("ServiceRouterMgrStub receives unknown code, code = %{public}d", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int ServiceRouterMgrStub::HandleQueryServiceInfos(MessageParcel &data, MessageParcel &reply)
{
    APP_LOGD("ServiceRouterMgrStub handle query service infos");
    if (!VerifySystemApp()) {
        APP_LOGE("verify system app failed");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify GET_BUNDLE_INFO_PRIVILEGED failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    Want *want = data.ReadParcelable<Want>();
    if (want == nullptr) {
        APP_LOGE("ReadParcelable<want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ExtensionServiceType type = static_cast<ExtensionServiceType>(data.ReadInt32());
    std::vector<ServiceInfo> infos;
    int ret = QueryServiceInfos(*want, type, infos);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!WriteParcelableVector<ServiceInfo>(infos, reply)) {
            APP_LOGE("QueryServiceInfos write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

int ServiceRouterMgrStub::HandleQueryPurposeInfos(MessageParcel &data, MessageParcel &reply)
{
    APP_LOGD("ServiceRouterMgrStub handle query purpose infos");
    if (!VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify GET_BUNDLE_INFO_PRIVILEGED failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    Want *want = data.ReadParcelable<Want>();
    if (want == nullptr) {
        APP_LOGE("ReadParcelable<want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::string purposeName = data.ReadString();
    std::vector<PurposeInfo> infos;
    int ret = QueryPurposeInfos(*want, purposeName, infos);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!WriteParcelableVector<PurposeInfo>(infos, reply)) {
            APP_LOGE("QueryPurposeInfos write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

int ServiceRouterMgrStub::HandleStartUIExtensionAbility(MessageParcel &data, MessageParcel &reply)
{
    APP_LOGD("ServiceRouterMgrStub handle start ui extension ability");
    Want *want = data.ReadParcelable<Want>();
    if (want == nullptr) {
        APP_LOGE("ReadParcelable<want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<SessionInfo> sessionInfo = nullptr;
    if (data.ReadBool()) {
        sessionInfo = data.ReadParcelable<SessionInfo>();
    }
    int32_t userId = data.ReadInt32();
    ExtensionAbilityType type = static_cast<ExtensionAbilityType>(data.ReadInt32());
    int32_t result = StartUIExtensionAbility(*want, sessionInfo, userId, type);
    if (!reply.WriteInt32(result)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    delete want;
    return ERR_OK;
}

int ServiceRouterMgrStub::HandleConnectUIExtensionAbility(MessageParcel &data, MessageParcel &reply)
{
    APP_LOGD("ServiceRouterMgrStub handle connect ui extension ability");
    if (!VerifySystemApp()) {
        APP_LOGE("verify system app failed");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    Want *want = data.ReadParcelable<Want>();
    if (want == nullptr) {
        APP_LOGE("ReadParcelable<want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IAbilityConnection> callback = nullptr;
    if (data.ReadBool()) {
        callback = iface_cast<IAbilityConnection>(data.ReadRemoteObject());
    }
    sptr<SessionInfo> sessionInfo = nullptr;
    if (data.ReadBool()) {
        sessionInfo = data.ReadParcelable<SessionInfo>();
    }
    int32_t userId = data.ReadInt32();
    int32_t result = ConnectUIExtensionAbility(*want, callback, sessionInfo, userId);
    if (!reply.WriteInt32(result)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    delete want;
    return ERR_OK;
}

bool ServiceRouterMgrStub::VerifyCallingPermission(const std::string &permissionName)
{
    APP_LOGD("VerifyCallingPermission permission %{public}s", permissionName.c_str());
    OHOS::Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    OHOS::Security::AccessToken::ATokenTypeEnum tokenType =
        OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType == OHOS::Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
        return true;
    }
    int32_t ret = OHOS::Security::AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permissionName);
    if (ret == OHOS::Security::AccessToken::PermissionState::PERMISSION_DENIED) {
        APP_LOGE("PERMISSION_DENIED: %{public}s", permissionName.c_str());
        return false;
    }
    return true;
}

bool ServiceRouterMgrStub::VerifySystemApp()
{
    APP_LOGD("verifying systemApp");
    Security::AccessToken::AccessTokenID callerToken = IPCSkeleton::GetCallingTokenID();
    Security::AccessToken::ATokenTypeEnum tokenType =
        Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE
        || IPCSkeleton::GetCallingUid() == Constants::ROOT_UID) {
        return true;
    }
    uint64_t accessTokenIdEx = IPCSkeleton::GetCallingFullTokenID();
    if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(accessTokenIdEx)) {
        APP_LOGE("non-system app calling system api");
        return false;
    }
    return true;
}

template <typename T>
bool ServiceRouterMgrStub::WriteParcelableVector(std::vector<T> &parcelableVector, Parcel &reply)
{
    if (!reply.WriteInt32(parcelableVector.size())) {
        APP_LOGE("write ParcelableVector size failed");
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
}  // namespace AAFwk
}  // namespace OHOS
