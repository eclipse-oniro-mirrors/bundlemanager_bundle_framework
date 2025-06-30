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

#include "overlay_manager_client.h"

#include "app_log_wrapper.h"
#include "bundle_mgr_proxy.h"
#include "bundle_mgr_service_death_recipient.h"
#include "iservice_registry.h"
#include "overlay_manager_proxy.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {

OverlayManagerClient &OverlayManagerClient::GetInstance()
{
    static OverlayManagerClient instance;
    return instance;
}

ErrCode OverlayManagerClient::GetAllOverlayModuleInfo(const std::string &bundleName,
    std::vector<OverlayModuleInfo> &overlayModuleInfos, int32_t userId)
{
    APP_LOGD("begin to call GetAllOverlayModuleInfo");
    if (bundleName.empty()) {
        APP_LOGE("GetAllOverlayModuleInfo failed due to params error");
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
    }
    auto proxy = GetOverlayManagerProxy();
    if (proxy == nullptr) {
        APP_LOGE("failed to get overlay manager proxy");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    int32_t funcResult = ERR_APPEXECFWK_IDL_GET_RESULT_ERROR;
    ErrCode ipcRet = proxy->GetAllOverlayModuleInfo(bundleName, userId, overlayModuleInfos, funcResult);
    if (ipcRet != ERR_OK) {
        APP_LOGE("ipc failed, errCode is %{public}d", ipcRet);
        return ipcRet;
    }
    APP_LOGD("GetAllOverlayModuleInfo end, errCode is %{public}d", funcResult);
    return funcResult;
}

ErrCode OverlayManagerClient::GetOverlayModuleInfo(const std::string &bundleName,
    const std::string &moduleName, OverlayModuleInfo &overlayModuleInfo, int32_t userId)
{
    APP_LOGD("begin to call GetOverlayModuleInfo");
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGE("GetOverlayModuleInfo failed due to params error");
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
    }
    auto proxy = GetOverlayManagerProxy();
    if (proxy == nullptr) {
        APP_LOGE("failed to get overlay manager proxy");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    ErrCode funcResult = ERR_APPEXECFWK_IDL_GET_RESULT_ERROR;
    ErrCode ipcRet = proxy->GetOverlayModuleInfo(bundleName, moduleName, userId, overlayModuleInfo, funcResult);
    if (ipcRet != ERR_OK) {
        APP_LOGE("ipc failed, errCode is %{public}d", ipcRet);
        return ipcRet;
    }
    APP_LOGD("GetOverlayModuleInfo end, errCode is %{public}d", funcResult);
    return funcResult;
}

ErrCode OverlayManagerClient::GetOverlayModuleInfo(const std::string &moduleName,
    OverlayModuleInfo &overlayModuleInfo, int32_t userId)
{
    APP_LOGD("begin to call GetOverlayModuleInfo");
    if (moduleName.empty()) {
        APP_LOGE("GetOverlayModuleInfo failed due to params error");
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
    }
    auto proxy = GetOverlayManagerProxy();
    if (proxy == nullptr) {
        APP_LOGE("failed to get overlay manager proxy");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    int32_t funcResult = ERR_APPEXECFWK_IDL_GET_RESULT_ERROR;
    ErrCode ipcRet = proxy->GetOverlayModuleInfo(moduleName, userId, overlayModuleInfo, funcResult);
    if (ipcRet != ERR_OK) {
        APP_LOGE("ipc failed, errCode is %{public}d", ipcRet);
        return ipcRet;
    }
    APP_LOGD("GetOverlayModuleInfo end, errCode is %{public}d", funcResult);
    return funcResult;
}

ErrCode OverlayManagerClient::GetTargetOverlayModuleInfo(const std::string &targetModuleName,
    std::vector<OverlayModuleInfo> &overlayModuleInfos, int32_t userId)
{
    APP_LOGD("begin to call GetTargetOverlayModuleInfo");
    if (targetModuleName.empty()) {
        APP_LOGE("GetTargetOverlayModuleInfo failed due to params error");
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
    }
    auto proxy = GetOverlayManagerProxy();
    if (proxy == nullptr) {
        APP_LOGE("failed to get overlay manager proxy");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    int32_t funcResult = ERR_APPEXECFWK_IDL_GET_RESULT_ERROR;
    ErrCode ipcRet = proxy->GetTargetOverlayModuleInfo(targetModuleName, userId, overlayModuleInfos, funcResult);
    if (ipcRet != ERR_OK) {
        APP_LOGE("ipc failed, errCode is %{public}d", ipcRet);
        return ipcRet;
    }
    APP_LOGD("GetTargetOverlayModuleInfo end, errCode is %{public}d", funcResult);
    return funcResult;
}

ErrCode OverlayManagerClient::GetOverlayModuleInfoByBundleName(const std::string &bundleName,
    const std::string &moduleName, std::vector<OverlayModuleInfo> &overlayModuleInfos, int32_t userId)
{
    APP_LOGD("begin to call GetOverlayModuleInfoByBundleName");
    if (bundleName.empty()) {
        APP_LOGE("GetOverlayModuleInfoByBundleName failed due to params error");
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
    }
    auto proxy = GetOverlayManagerProxy();
    if (proxy == nullptr) {
        APP_LOGE("failed to get overlay manager proxy");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    int32_t funcResult = ERR_APPEXECFWK_IDL_GET_RESULT_ERROR;
    ErrCode ipcRet = proxy->GetOverlayModuleInfoByBundleName(bundleName, moduleName, userId,
        overlayModuleInfos, funcResult);
    if (ipcRet != ERR_OK) {
        APP_LOGE("ipc failed, errCode is %{public}d", ipcRet);
        return ipcRet;
    }
    APP_LOGD("GetOverlayModuleInfoByBundleName end, errCode is %{public}d", funcResult);
    return funcResult;
}

ErrCode OverlayManagerClient::GetOverlayBundleInfoForTarget(const std::string &targetBundleName,
    std::vector<OverlayBundleInfo> &overlayBundleInfos, int32_t userId)
{
    APP_LOGD("begin to call GetOverlayBundleInfoForTarget");
    if (targetBundleName.empty()) {
        APP_LOGE("GetOverlayBundleInfoForTarget failed due to params error");
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
    }
    auto proxy = GetOverlayManagerProxy();
    if (proxy == nullptr) {
        APP_LOGE("failed to get overlay manager proxy");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    int32_t funcResult = ERR_APPEXECFWK_IDL_GET_RESULT_ERROR;
    ErrCode ipcRet = proxy->GetOverlayBundleInfoForTarget(targetBundleName, userId, overlayBundleInfos, funcResult);
    if (ipcRet != ERR_OK) {
        APP_LOGE("ipc failed, errCode is %{public}d", ipcRet);
        return ipcRet;
    }
    APP_LOGD("GetOverlayBundleInfoForTarget end, errCode is %{public}d", funcResult);
    return funcResult;
}

ErrCode OverlayManagerClient::GetOverlayModuleInfoForTarget(const std::string &targetBundleName,
    const std::string &targetModuleName, std::vector<OverlayModuleInfo> &overlayModuleInfos, int32_t userId)
{
    APP_LOGD("begin to call GetOverlayModuleInfoForTarget");
    if (targetBundleName.empty()) {
        APP_LOGE("GetOverlayModuleInfoForTarget failed due to params error");
        return ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
    }
    auto proxy = GetOverlayManagerProxy();
    if (proxy == nullptr) {
        APP_LOGE("failed to get overlay manager proxy");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    int32_t funcResult = ERR_APPEXECFWK_IDL_GET_RESULT_ERROR;
    ErrCode ipcRet = proxy->GetOverlayModuleInfoForTarget(targetBundleName, targetModuleName,
        userId, overlayModuleInfos, funcResult);
    if (ipcRet != ERR_OK) {
        APP_LOGE("ipc failed, errCode is %{public}d", ipcRet);
        return ipcRet;
    }
    APP_LOGD("GetOverlayModuleInfoForTarget end, errCode is %{public}d", funcResult);
    return funcResult;
}

ErrCode OverlayManagerClient::SetOverlayEnabled(const std::string& bundleName, const std::string& moduleName,
    bool isEnabled, int32_t userId)
{
    APP_LOGD("begin to call SetOverlayEnabled");
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGE("SetOverlayEnabled failed due to params error");
        return ERR_BUNDLEMANAGER_OVERLAY_SET_OVERLAY_PARAM_ERROR;
    }

    auto proxy = GetOverlayManagerProxy();
    if (proxy == nullptr) {
        APP_LOGE("failed to get overlay manager proxy");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    int32_t funcResult = ERR_APPEXECFWK_IDL_GET_RESULT_ERROR;
    ErrCode ipcRet = proxy->SetOverlayEnabled(bundleName, moduleName, isEnabled, userId, funcResult);
    if (ipcRet != ERR_OK) {
        APP_LOGE("ipc failed, errCode is %{public}d", ipcRet);
        return ipcRet;
    }
    APP_LOGD("SetOverlayEnabled end, errCode is %{public}d", funcResult);
    return funcResult;
}

ErrCode OverlayManagerClient::SetOverlayEnabledForSelf(const std::string& moduleName, bool isEnabled, int32_t userId)
{
    APP_LOGD("begin to call SetOverlayEnabledForSelf");
    if (moduleName.empty()) {
        APP_LOGE("SetOverlayEnabledForSelf failed due to params error");
        return ERR_BUNDLEMANAGER_OVERLAY_SET_OVERLAY_PARAM_ERROR;
    }
    auto proxy = GetOverlayManagerProxy();
    if (proxy == nullptr) {
        APP_LOGE("failed to get overlay manager proxy");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    int32_t funcResult = ERR_APPEXECFWK_IDL_GET_RESULT_ERROR;
    ErrCode ipcRet = proxy->SetOverlayEnabledForSelf(moduleName, isEnabled, userId, funcResult);
    if (ipcRet != ERR_OK) {
        APP_LOGE("ipc failed, errCode is %{public}d", ipcRet);
        return ipcRet;
    }
    APP_LOGD("SetOverlayEnabledForSelf end, errCode is %{public}d", funcResult);
    return funcResult;
}

void OverlayManagerClient::ResetOverlayManagerProxy(const wptr<IRemoteObject> &remote)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (overlayManagerProxy_ == nullptr) {
        APP_LOGE("Proxy is nullptr");
        return ;
    }
    auto serviceRemote = overlayManagerProxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
    }
    overlayManagerProxy_ = nullptr;
    deathRecipient_ = nullptr;
}

void OverlayManagerClient::OverlayManagerDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    if (remote == nullptr) {
        APP_LOGE("remote is nullptr");
        return;
    }
    OverlayManagerClient::GetInstance().ResetOverlayManagerProxy(remote);
}

sptr<IOverlayManager> OverlayManagerClient::GetOverlayManagerProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (overlayManagerProxy_ != nullptr) {
        return overlayManagerProxy_;
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
        APP_LOGE_NOFUNC("get bms sa failed");
        return nullptr;
    }
    overlayManagerProxy_ = bundleMgr->GetOverlayManagerProxy();
    if ((overlayManagerProxy_ == nullptr) || (overlayManagerProxy_->AsObject() == nullptr)) {
        APP_LOGE("failed to get overlay manager proxy");
        return nullptr;
    }
    deathRecipient_ = new (std::nothrow) OverlayManagerDeathRecipient();
    if (deathRecipient_ == nullptr) {
        APP_LOGE("failed to create OverlayManager death recipient");
        return nullptr;
    }
    if ((overlayManagerProxy_->AsObject()->IsProxyObject()) &&
        (!overlayManagerProxy_->AsObject()->AddDeathRecipient(deathRecipient_))) {
        APP_LOGE("Failed to add death recipient");
        overlayManagerProxy_ = nullptr;
        deathRecipient_ = nullptr;
        return nullptr;
    }
    return overlayManagerProxy_;
}
}
}