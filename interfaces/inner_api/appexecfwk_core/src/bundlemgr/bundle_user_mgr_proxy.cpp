/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "bundle_user_mgr_proxy.h"

#include "appexecfwk_errors.h"
#include "app_log_wrapper.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "ipc_types.h"
#include "parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
constexpr size_t DISALLOWLISTMAXSIZE = 1000;

BundleUserMgrProxy::BundleUserMgrProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<IBundleUserMgr>(object)
{
    APP_LOGD("create BundleUserMgrProxy instance");
}

BundleUserMgrProxy::~BundleUserMgrProxy()
{
    APP_LOGD("destroy BundleUserMgrProxy instance");
}

ErrCode BundleUserMgrProxy::CreateNewUser(int32_t userId, const std::vector<std::string> &disallowList,
    const std::optional<std::vector<std::string>> &allowList)
{
    APP_LOGD("CreateNewUser %{public}d", userId);
    MessageParcel data;
    if (!data.WriteInterfaceToken(BundleUserMgrProxy::GetDescriptor())) {
        APP_LOGE("fail to CreateNewUser due to write MessageParcel fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(static_cast<int32_t>(userId))) {
        APP_LOGE("fail to CreateNewUser due to write uid fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (WriteStrListToData(data, disallowList, DISALLOWLISTMAXSIZE) != ERR_OK) {
        APP_LOGE("Write disallowList failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!allowList.has_value()) {
        data.WriteBool(false);
    } else {
        data.WriteBool(true);
        std::vector<std::string> allowLst = allowList.value();
        if (WriteStrListToData(data, allowLst, DISALLOWLISTMAXSIZE) != ERR_OK) {
            APP_LOGE("Write allowLst failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        APP_LOGI("allowLst size %{public}zu", allowLst.size());
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleUserMgrInterfaceCode::CREATE_USER, data, reply)) {
        APP_LOGE("fail to CreateNewUser from server");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        APP_LOGE("host reply err %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

ErrCode BundleUserMgrProxy::WriteStrListToData(MessageParcel &data, const std::vector<std::string> &list,
    size_t maxListSize)
{
    size_t listSize =
        (list.size() > maxListSize) ? maxListSize : list.size();
    if (!data.WriteInt32(listSize)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    for (size_t index = 0; index < listSize; ++index) {
        if (!data.WriteString(list.at(index))) {
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleUserMgrProxy::RemoveUser(int32_t userId)
{
    APP_LOGD("RemoveUser %{public}d", userId);
    MessageParcel data;
    if (!data.WriteInterfaceToken(BundleUserMgrProxy::GetDescriptor())) {
        APP_LOGE("fail to RemoveUser due to write MessageParcel fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(static_cast<int32_t>(userId))) {
        APP_LOGE("fail to RemoveUser due to write uid fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleUserMgrInterfaceCode::REMOVE_USER, data, reply)) {
        APP_LOGE("fail to RemoveUser from server");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    
    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        APP_LOGE("host reply err %{public}d", ret);
        return ret;
    }
    return ERR_OK;
}

bool BundleUserMgrProxy::SendTransactCmd(BundleUserMgrInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        APP_LOGE("fail send transact cmd %{public}hhd due to remote object", code);
        return false;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != NO_ERROR) {
        APP_LOGE("receive error transact code %{public}d in transact cmd %{public}hhd", result, code);
        return false;
    }
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
