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

#include "bundle_mgr_proxy_native.h"

#include "app_log_wrapper.h"
#include "app_log_tag_wrapper.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "string_ex.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    const std::u16string BMS_PROXY_INTERFACE_TOKEN = u"ohos.appexecfwk.BundleMgr";
}

sptr<IRemoteObject> BundleMgrProxyNative::GetBmsProxy()
{
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        APP_LOGE("fail to get samgr.");
        return nullptr;
    }
    return samgrProxy->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
}

bool BundleMgrProxyNative::GetBundleInfoForSelf(int32_t flags, BundleInfo &bundleInfo)
{
    LOG_I(BMS_TAG_QUERY_BUNDLE, "begin to get bundle info for self");
    MessageParcel data;
    if (!data.WriteInterfaceToken(BMS_PROXY_INTERFACE_TOKEN)) {
        LOG_E(BMS_TAG_QUERY_BUNDLE, "fail to GetBundleInfoForSelf due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteInt32(flags)) {
        LOG_E(BMS_TAG_QUERY_BUNDLE, "fail to GetBundleInfoForSelf due to write flag fail");
        return false;
    }
    if (!GetParcelableInfo<BundleInfo>(GET_BUNDLE_INFO_FOR_SELF_NATIVE, data, bundleInfo)) {
        LOG_E(BMS_TAG_QUERY_BUNDLE, "fail to GetBundleInfoForSelf from server");
        return false;
    }
    return true;
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
}  // namespace AppExecFwk
}  // namespace OHOS