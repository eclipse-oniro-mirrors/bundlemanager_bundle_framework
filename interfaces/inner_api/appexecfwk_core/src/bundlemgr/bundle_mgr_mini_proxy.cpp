/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "bundle_mgr_mini_proxy.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "hitrace_meter.h"

namespace OHOS {
namespace AppExecFwk {
BundleMgrMiniProxy::BundleMgrMiniProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IBundleMgr>(impl)
{
    APP_LOGD("create BundleMgrMiniProxy");
}

BundleMgrMiniProxy::~BundleMgrMiniProxy()
{
    APP_LOGD("destroy ~BundleMgrMiniProxy");
}

ErrCode BundleMgrMiniProxy::GetNameForUid(const int uid, std::string &name)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetNameForUid of %{public}d", uid);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetNameForUid due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(uid)) {
        APP_LOGE("fail to GetNameForUid due to write uid fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmdWithLog(BundleMgrInterfaceCode::GET_NAME_FOR_UID, data, reply)) {
        APP_LOGE("fail to GetNameForUid from server");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        return ret;
    }
    name = reply.ReadString();
    return ERR_OK;
}

std::string BundleMgrMiniProxy::GetAppIdByBundleName(const std::string &bundleName, const int userId)
{
    if (bundleName.empty()) {
        APP_LOGE("failed to GetAppIdByBundleName due to bundleName empty");
        return Constants::EMPTY_STRING;
    }
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to get appId of %{public}s", bundleName.c_str());

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("failed to GetAppIdByBundleName due to write InterfaceToken fail");
        return Constants::EMPTY_STRING;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("failed to GetAppIdByBundleName due to write bundleName fail");
        return Constants::EMPTY_STRING;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("failed to GetAppIdByBundleName due to write uid fail");
        return Constants::EMPTY_STRING;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_APPID_BY_BUNDLE_NAME, data, reply)) {
        APP_LOGE("failed to GetAppIdByBundleName from server");
        return Constants::EMPTY_STRING;
    }
    std::string appId = reply.ReadString();
    APP_LOGD("appId is %{private}s", appId.c_str());
    return appId;
}

int BundleMgrMiniProxy::GetUidByBundleName(const std::string &bundleName, const int userId)
{
    return GetUidByBundleName(bundleName, userId, 0);
}

int32_t BundleMgrMiniProxy::GetUidByBundleName(const std::string &bundleName, const int32_t userId, int32_t appIndex)
{
    if (bundleName.empty()) {
        APP_LOGE("failed to GetUidByBundleName due to bundleName empty");
        return Constants::INVALID_UID;
    }
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to get uid of %{public}s, userId : %{public}d, appIndex : %{public}d", bundleName.c_str(),
        userId, appIndex);

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("failed to GetUidByBundleName due to write InterfaceToken fail");
        return Constants::INVALID_UID;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("failed to GetUidByBundleName due to write bundleName fail");
        return Constants::INVALID_UID;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("failed to GetUidByBundleName due to write uid fail");
        return Constants::INVALID_UID;
    }
    if (!data.WriteInt32(appIndex)) {
        APP_LOGE("failed to GetUidByBundleName due to write uid fail");
        return Constants::INVALID_UID;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_UID_BY_BUNDLE_NAME, data, reply)) {
        APP_LOGE("failed to GetUidByBundleName from server");
        return Constants::INVALID_UID;
    }
    int32_t uid = reply.ReadInt32();
    APP_LOGD("uid is %{public}d", uid);
    return uid;
}

bool BundleMgrMiniProxy::SendTransactCmd(BundleMgrInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        APP_LOGE("fail send transact cmd %{public}d due remote object", code);
        return false;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != NO_ERROR) {
        APP_LOGE("receive error transact code %{public}d in transact cmd %{public}d", result, code);
        return false;
    }
    return true;
}

bool BundleMgrMiniProxy::SendTransactCmdWithLog(BundleMgrInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        APP_LOGE("fail send transact cmd %{public}d due remote object", code);
        return false;
    }
    int32_t sptrRefCount = remote->GetSptrRefCount();
    int32_t wptrRefCount = remote->GetWptrRefCount();
    if (sptrRefCount <= 0 || wptrRefCount <= 0) {
        APP_LOGI("SendRequest before sptrRefCount: %{public}d wptrRefCount: %{public}d",
            sptrRefCount, wptrRefCount);
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != NO_ERROR) {
        APP_LOGE("receive error transact code %{public}d in transact cmd %{public}d", result, code);
        return false;
    }
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
