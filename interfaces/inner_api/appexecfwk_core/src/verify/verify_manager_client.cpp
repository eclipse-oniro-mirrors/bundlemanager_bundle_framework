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

#include "verify_manager_client.h"

#include "app_log_wrapper.h"
#include "app_log_tag_wrapper.h"
#include "bundle_file_util.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "bundle_mgr_service_death_recipient.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {

VerifyManagerClient::VerifyManagerClient()
{
    APP_LOGI("create VerifyManagerClient");
}

VerifyManagerClient::~VerifyManagerClient()
{
    APP_LOGI("destroy VerifyManagerClient");
}

ErrCode VerifyManagerClient::Verify(const std::vector<std::string>& abcPaths)
{
    APP_LOGI("begin to call Verify");
    if (abcPaths.empty()) {
        APP_LOGE("Verify failed due to params error");
        return ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR;
    }
    auto proxy = GetVerifyManagerProxy();
    if (proxy == nullptr) {
        APP_LOGE("failed to get verifyManager proxy");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    
    int32_t funcResult = ERR_APPEXECFWK_IDL_GET_RESULT_ERROR;
    ErrCode proxyRet = proxy->Verify(abcPaths, funcResult);
    if (proxyRet != ERR_OK) {
        APP_LOGE("transaction failed");
        return ERR_BUNDLE_MANAGER_VERIFY_SEND_REQUEST_FAILED;
    }
    APP_LOGD("Verify end, errCode is %{public}d", funcResult);
    return funcResult;
}

ErrCode VerifyManagerClient::RemoveFiles(const std::vector<std::string> &abcPaths)
{
    APP_LOGI("RemoveFiles");
    std::vector<std::string> realPaths;
    if (!BundleFileUtil::CheckFilePath(abcPaths, realPaths)) {
        APP_LOGE("RemoveFiles CheckFilePath failed");
        return ERR_BUNDLE_MANAGER_VERIFY_PARAM_ERROR;
    }

    for (const auto &path : realPaths) {
        if (!BundleFileUtil::DeleteDir(path)) {
            APP_LOGW("RemoveFile %{private}s failed, errno:%{public}d", path.c_str(), errno);
        }
    }

    return ERR_OK;
}

ErrCode VerifyManagerClient::DeleteAbc(const std::string& path)
{
    APP_LOGI("begin to call DeleteAbc");
    if (path.empty()) {
        APP_LOGE("DeleteAbc failed due to params error");
        return ERR_BUNDLE_MANAGER_DELETE_ABC_PARAM_ERROR;
    }
    auto proxy = GetVerifyManagerProxy();
    if (proxy == nullptr) {
        APP_LOGE("failed to get verifyManager proxy");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    
    int32_t funcResult = ERR_APPEXECFWK_IDL_GET_RESULT_ERROR;
    ErrCode proxyRet = proxy->DeleteAbc(path, funcResult);
    if (proxyRet != ERR_OK) {
        APP_LOGE("transaction failed");
        return ERR_BUNDLE_MANAGER_DELETE_ABC_SEND_REQUEST_FAILED;
    }
    APP_LOGD("DeleteAbc end, errCode is %{public}d", funcResult);
    return funcResult;
}

void VerifyManagerClient::ResetVerifyManagerProxy(const wptr<IRemoteObject>& remote)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (verifyManager_ == nullptr) {
        APP_LOGE("Proxy is nullptr");
        return;
    }
    auto serviceRemote = verifyManager_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
    }
    verifyManager_ = nullptr;
    deathRecipient_ = nullptr;
}

void VerifyManagerClient::VerifyManagerDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    if (remote == nullptr) {
        APP_LOGE("remote is nullptr");
        return;
    }
    VerifyManagerClient::GetInstance().ResetVerifyManagerProxy(remote);
}

sptr<IVerifyManager> VerifyManagerClient::GetVerifyManagerProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (verifyManager_ != nullptr) {
        return verifyManager_;
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
    verifyManager_ = bundleMgr->GetVerifyManager();
    if ((verifyManager_ == nullptr) || (verifyManager_->AsObject() == nullptr)) {
        APP_LOGE("failed to get verifyManager proxy");
        return nullptr;
    }
    deathRecipient_ = new (std::nothrow) VerifyManagerDeathRecipient();
    if (deathRecipient_ == nullptr) {
        APP_LOGE("failed to create verify manager death recipient");
        return nullptr;
    }

    if ((verifyManager_->AsObject()->IsProxyObject()) &&
        (!verifyManager_->AsObject()->AddDeathRecipient(deathRecipient_))) {
        APP_LOGE("Failed to add death recipient");
        verifyManager_ = nullptr;
        deathRecipient_ = nullptr;
        return nullptr;
    }
    return verifyManager_;
}

VerifyManagerClient& VerifyManagerClient::GetInstance()
{
    static VerifyManagerClient instance;
    return instance;
}
} // namespace AppExecFwk
} // namespace OHOS
