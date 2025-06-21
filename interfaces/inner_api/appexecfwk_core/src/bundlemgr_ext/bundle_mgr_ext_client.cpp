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
#include "bundle_mgr_ext_client.h"

#include "app_log_tag_wrapper.h"
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_mgr_proxy.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
BundleMgrExtClient &BundleMgrExtClient::GetInstance()
{
    static BundleMgrExtClient instance;
    return instance;
}

ErrCode BundleMgrExtClient::GetBundleNamesForUidExt(const int32_t uid, std::vector<std::string> &bundleNames)
{
    APP_LOGD("GetBundleNamesForUidExt begin");
    auto proxy = GetBundleMgrExtProxy();
    if (proxy == nullptr) {
        APP_LOGE("failed to get bundle mgr ext proxy");
        return ERR_APPEXECFWK_NULL_PTR;
    }

    int32_t funcResult = ERR_APPEXECFWK_IDL_GET_RESULT_ERROR;
    ErrCode res = proxy->GetBundleNamesForUidExt(uid, bundleNames, funcResult);
    if (res != ERR_OK) {
        APP_LOGE("ipc failed, errCode is %{public}d", res);
        funcResult = res;
    }
    APP_LOGD("GetBundleNamesForUidExt end, errCode is %{public}d", funcResult);
    return funcResult;
}

sptr<IBundleMgrExt> BundleMgrExtClient::GetBundleMgrExtProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (bundleMgrExtProxy_ != nullptr) {
        return bundleMgrExtProxy_;
    }
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        APP_LOGE("failed to get system ability manager");
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObject == nullptr) {
        APP_LOGE_NOFUNC("get bms sa failed");
        return nullptr;
    }
    auto bundleMgr = iface_cast<IBundleMgr>(remoteObject);
    if (bundleMgr == nullptr) {
        APP_LOGE_NOFUNC("iface_cast failed");
        return nullptr;
    }
    bundleMgrExtProxy_ = bundleMgr->GetBundleMgrExtProxy();
    if ((bundleMgrExtProxy_ == nullptr) || (bundleMgrExtProxy_->AsObject() == nullptr)) {
        APP_LOGE("failed to get bundleMgrExt proxy");
        return nullptr;
    }
    deathRecipient_ = new (std::nothrow) BundleMgrExtDeathRecipient();
    if (deathRecipient_ == nullptr) {
        APP_LOGE("failed to create bundleMgrExt death recipient");
        return nullptr;
    }
    if ((bundleMgrExtProxy_->AsObject()->IsProxyObject()) &&
        (!bundleMgrExtProxy_->AsObject()->AddDeathRecipient(deathRecipient_))) {
        APP_LOGE("Failed to add death recipient");
        bundleMgrExtProxy_ = nullptr;
        deathRecipient_ = nullptr;
        return nullptr;
    }

    return bundleMgrExtProxy_;
}

void BundleMgrExtClient::ResetBundleMgrExtProxy(const wptr<IRemoteObject>& remote)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (bundleMgrExtProxy_ == nullptr) {
        APP_LOGE("Proxy is nullptr");
        return;
    }
    auto serviceRemote = bundleMgrExtProxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
    }
    bundleMgrExtProxy_ = nullptr;
    deathRecipient_ = nullptr;
}

void BundleMgrExtClient::BundleMgrExtDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    if (remote == nullptr) {
        APP_LOGE("remote is nullptr");
        return;
    }
    BundleMgrExtClient::GetInstance().ResetBundleMgrExtProxy(remote);
}
} // namespace AppExecFwk
} // namespace OHOS