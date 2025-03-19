/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "bundle_mgr_ext_proxy.h"

#include "app_log_tag_wrapper.h"
#include "appexecfwk_core_constants.h"
#include "appexecfwk_errors.h"
#include "hitrace_meter.h"
#include "ipc_types.h"
#include "parcel_macro.h"

namespace OHOS {
namespace AppExecFwk {
BundleMgrExtProxy::BundleMgrExtProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IBundleMgrExt>(object)
{
    LOG_D(BMS_TAG_EXT, "create BundleMgrExtProxy");
}

BundleMgrExtProxy::~BundleMgrExtProxy()
{
    LOG_D(BMS_TAG_EXT, "destroy BundleMgrExtProxy");
}

ErrCode BundleMgrExtProxy::GetBundleNamesForUidExt(const int32_t uid, std::vector<std::string> &bundleNames)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_EXT, "begin to GetBundleNamesForUidExt of %{public}d", uid);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_EXT, "write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(uid)) {
        LOG_E(BMS_TAG_EXT, "write uid fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    ErrCode ret = SendTransactCmd(BundleMgrExtInterfaceCode::GET_BUNDLE_NAMES_FOR_UID_EXT, data, reply);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_EXT, "SendTransactCmd fail %{public}d", ret);
        return ret;
    }
    ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_EXT, "reply err:%{public}d", ret);
        return ret;
    }
    if (!reply.ReadStringVector(&bundleNames)) {
        LOG_E(BMS_TAG_EXT, "fail to get bundleNames reply");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ret;
}

ErrCode BundleMgrExtProxy::SendTransactCmd(BundleMgrExtInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_E(BMS_TAG_EXT, "fail send transact cmd %{public}d due remote object", static_cast<int32_t>(code));
        return ERR_APPEXECFWK_NULL_PTR;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != NO_ERROR) {
        LOG_E(BMS_TAG_EXT, "receive error transact code %{public}d in transact cmd %{public}d",
            result, static_cast<int32_t>(code));
        if (CoreConstants::IPC_ERR_MAP.find(result) != CoreConstants::IPC_ERR_MAP.end()) {
            return CoreConstants::IPC_ERR_MAP.at(result);
        }
        return result;
    }
    return ERR_OK;
}
} // AppExecFwk
} // OHOS