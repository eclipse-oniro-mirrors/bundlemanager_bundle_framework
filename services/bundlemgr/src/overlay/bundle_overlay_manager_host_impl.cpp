/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "bundle_overlay_manager_host_impl.h"

#include "bundle_memory_guard.h"
#include "bundle_permission_mgr.h"
#include "bundle_overlay_data_manager.h"
#include "bundle_overlay_manager.h"
#include "xcollie_helper.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
const std::string FUNCTION_GET_ALL_OVERLAY_MODULE_INFO = "OverlayManagerHost::GetAllOverlayModuleInfo";
const std::string FUNCTION_GET_OVERLAY_MODULE_INFO = "OverlayManagerHost::GetOverlayModuleInfo";
const std::string FUNCTION_GET_OVERLAY_MODULE_INFO_NO_BUNDLENAME =
    "OverlayManagerHost::GetOverlayModuleInfoWithoutBundleName";
const std::string FUNCTION_GET_TARGET_OVERLAY_MODULE_INFO = "OverlayManagerHost::GetTargetOverlayModuleInfo";
const std::string FUNCTION_GET_OVERLAY_MODULE_INFO_BY_BUNDLENAME =
    "OverlayManagerHost::GetOverlayModuleInfoByBundleName";
const std::string FUNCTION_GET_OVERLAY_BUNDLE_INFOFOR_TARGET = "OverlayManagerHost::GetOverlayBundleInfoForTarget";
const std::string FUNCTION_GET_OVERLAY_MODULE_INFOFOR_TARGET = "OverlayManagerHost::GetOverlayModuleInfoForTarget";
const std::string FUNCTION_SET_OVERLAY_ENABLED_FOR_SELF = "OverlayManagerHost::SetOverlayEnabledForSelf";
const std::string FUNCTION_SET_OVERLAY_ENABLED = "OverlayManagerHost::SetOverlayEnabled";

OverlayManagerHostImpl::OverlayManagerHostImpl()
{
    APP_LOGI("create");
}

OverlayManagerHostImpl::~OverlayManagerHostImpl()
{
    APP_LOGI("destory");
}

ErrCode OverlayManagerHostImpl::GetAllOverlayModuleInfo(const std::string &bundleName, int32_t userId,
    std::vector<OverlayModuleInfo> &overlayModuleInfo, int32_t& funcResult)
{
    APP_LOGD("start to get all overlay moduleInfo of bundle %{public}s", bundleName.c_str());
    int32_t timerId = XCollieHelper::SetRecoveryTimer(FUNCTION_GET_ALL_OVERLAY_MODULE_INFO);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    if (bundleName.empty()) {
        APP_LOGE("invalid param");
        funcResult = ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
        return ERR_OK;
    }
    if (!BundlePermissionMgr::CheckUserFromShell(userId)) {
        LOG_E(BMS_TAG_INSTALLER, "check shell user fail");
        funcResult = ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PERMISSION_DENIED;
        return ERR_OK;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }
    APP_LOGD("calling userId is %{public}d", userId);

    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("no permission to query overlay info of targetBundleName %{public}s", bundleName.c_str());
        funcResult = ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PERMISSION_DENIED;
        return ERR_OK;
    }
    funcResult = BundleOverlayManager::GetInstance()->GetAllOverlayModuleInfo(bundleName, overlayModuleInfo, userId);
    return ERR_OK;
}

ErrCode OverlayManagerHostImpl::GetOverlayModuleInfo(const std::string &bundleName, const std::string &moduleName,
    int32_t userId, OverlayModuleInfo &overlayModuleInfo, int32_t &funcResult)
{
    APP_LOGD("start to get overlay moduleInfo of bundle %{public}s and module %{public}s", bundleName.c_str(),
        moduleName.c_str());
    int32_t timerId = XCollieHelper::SetRecoveryTimer(FUNCTION_GET_OVERLAY_MODULE_INFO);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    if (!BundlePermissionMgr::CheckUserFromShell(userId)) {
        LOG_E(BMS_TAG_INSTALLER, "check shell user fail");
        funcResult = ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PERMISSION_DENIED;
        return ERR_OK;
    }
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGE("invalid param");
        funcResult = ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
        return ERR_OK;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }
    APP_LOGD("calling userId is %{public}d", userId);

    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("no permission to query overlay info of targetBundleName %{public}s", bundleName.c_str());
        funcResult = ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PERMISSION_DENIED;
        return ERR_OK;
    }
    funcResult = BundleOverlayManager::GetInstance()->GetOverlayModuleInfo(bundleName, moduleName, overlayModuleInfo,
        userId);
    return ERR_OK;
}

ErrCode OverlayManagerHostImpl::GetOverlayModuleInfo(const std::string &moduleName, int32_t userId,
    OverlayModuleInfo &overlayModuleInfo, int32_t &funcResult)
{
    APP_LOGD("start to get overlay moduleInfo of module %{public}s", moduleName.c_str());
    int32_t timerId = XCollieHelper::SetRecoveryTimer(FUNCTION_GET_OVERLAY_MODULE_INFO_NO_BUNDLENAME);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    if (moduleName.empty()) {
        APP_LOGE("invalid param");
        funcResult = ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
        return ERR_OK;
    }
    if (!BundlePermissionMgr::CheckUserFromShell(userId)) {
        LOG_E(BMS_TAG_INSTALLER, "check shell user fail");
        funcResult = ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PERMISSION_DENIED;
        return ERR_OK;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }
    APP_LOGD("calling userId is %{public}d", userId);

    std::string callingBundleName = OverlayDataMgr::GetInstance()->GetCallingBundleName();
    if (callingBundleName.empty()) {
        APP_LOGE("GetCallingBundleName failed");
        funcResult = ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
        return ERR_OK;
    }
    APP_LOGD("get overlay moduleInfo of bundle %{public}s", callingBundleName.c_str());
    funcResult = BundleOverlayManager::GetInstance()->GetOverlayModuleInfo(callingBundleName, moduleName,
        overlayModuleInfo, userId);
    return ERR_OK;
}

ErrCode OverlayManagerHostImpl::GetTargetOverlayModuleInfo(const std::string &targetModuleName, int32_t userId,
    std::vector<OverlayModuleInfo> &overlayModuleInfos, int32_t &funcResult)
{
    APP_LOGD("start to get target overlay moduleInfo of target module %{public}s", targetModuleName.c_str());
    int32_t timerId = XCollieHelper::SetRecoveryTimer(FUNCTION_GET_TARGET_OVERLAY_MODULE_INFO);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    if (targetModuleName.empty()) {
        APP_LOGE("invalid param");
        funcResult = ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
        return ERR_OK;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }
    APP_LOGD("calling userId is %{public}d", userId);

    std::string callingBundleName = OverlayDataMgr::GetInstance()->GetCallingBundleName();
    if (callingBundleName.empty()) {
        APP_LOGE("GetCallingBundleName failed");
        funcResult = ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
        return ERR_OK;
    }
    APP_LOGD("get target overlay moduleInfo of bundle %{public}s", callingBundleName.c_str());
    funcResult = BundleOverlayManager::GetInstance()->GetOverlayModuleInfoForTarget(callingBundleName,
        targetModuleName, overlayModuleInfos, userId);
    return ERR_OK;
}

ErrCode OverlayManagerHostImpl::GetOverlayModuleInfoByBundleName(const std::string &bundleName,
    const std::string &moduleName, int32_t userId, std::vector<OverlayModuleInfo> &overlayModuleInfos,
    int32_t &funcResult)
{
    APP_LOGD("start to get overlay moduleInfo of bundle %{public}s and module %{public}s", bundleName.c_str(),
        moduleName.c_str());
    int32_t timerId = XCollieHelper::SetRecoveryTimer(FUNCTION_GET_OVERLAY_MODULE_INFO_BY_BUNDLENAME);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    if (bundleName.empty()) {
        APP_LOGE("invalid param");
        funcResult = ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
        return ERR_OK;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }
    APP_LOGD("calling userId is %{public}d", userId);

    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app is not allowed to call this function");
        funcResult = ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
        return ERR_OK;
    }

    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
        APP_LOGE("no permission to query overlay info of bundleName %{public}s", bundleName.c_str());
        funcResult = ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PERMISSION_DENIED;
        return ERR_OK;
    }
    if (moduleName.empty()) {
        APP_LOGD("moduleName is empty, then to query all overlay module info in specified bundle");
        funcResult = BundleOverlayManager::GetInstance()->GetAllOverlayModuleInfo(bundleName, overlayModuleInfos,
            userId);
        return ERR_OK;
    }
    OverlayModuleInfo overlayModuleInfo;
    funcResult = BundleOverlayManager::GetInstance()->GetOverlayModuleInfo(bundleName, moduleName, overlayModuleInfo,
        userId);
    if (funcResult != ERR_OK) {
        APP_LOGE("GetOverlayModuleInfo failed due to errcode %{public}d", funcResult);
        return ERR_OK;
    }
    overlayModuleInfos.emplace_back(overlayModuleInfo);
    return ERR_OK;
}

ErrCode OverlayManagerHostImpl::GetOverlayBundleInfoForTarget(const std::string &targetBundleName, int32_t userId,
    std::vector<OverlayBundleInfo> &overlayBundleInfo, int32_t &funcResult)
{
    APP_LOGD("start to get target overlay bundleInfo of bundle %{public}s", targetBundleName.c_str());
    int32_t timerId = XCollieHelper::SetRecoveryTimer(FUNCTION_GET_OVERLAY_BUNDLE_INFOFOR_TARGET);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    if (!BundlePermissionMgr::CheckUserFromShell(userId)) {
        LOG_E(BMS_TAG_INSTALLER, "check shell user fail");
        funcResult = ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PERMISSION_DENIED;
        return ERR_OK;
    }
    if (targetBundleName.empty()) {
        APP_LOGE("invalid param");
        funcResult = ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
        return ERR_OK;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }
    APP_LOGD("calling userId is %{public}d", userId);

    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("no permission to query overlay info of targetBundleName %{public}s", targetBundleName.c_str());
        funcResult = ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PERMISSION_DENIED;
        return ERR_OK;
    }
    funcResult = BundleOverlayManager::GetInstance()->
        GetOverlayBundleInfoForTarget(targetBundleName, overlayBundleInfo, userId);
    return ERR_OK;
}

ErrCode OverlayManagerHostImpl::GetOverlayModuleInfoForTarget(const std::string &targetBundleName,
    const std::string &targetModuleName, int32_t userId, std::vector<OverlayModuleInfo> &overlayModuleInfo,
    int32_t &funcResult)
{
    APP_LOGD("start to get target overlay moduleInfo of target bundle %{public}s and target module %{public}s",
        targetBundleName.c_str(), targetModuleName.c_str());
    int32_t timerId = XCollieHelper::SetRecoveryTimer(FUNCTION_GET_OVERLAY_MODULE_INFOFOR_TARGET);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    if (!BundlePermissionMgr::CheckUserFromShell(userId)) {
        LOG_E(BMS_TAG_INSTALLER, "check shell user fail");
        funcResult = ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PERMISSION_DENIED;
        return ERR_OK;
    }
    if (targetBundleName.empty()) {
        APP_LOGE("invalid param");
        funcResult = ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PARAM_ERROR;
        return ERR_OK;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }
    APP_LOGD("calling userId is %{public}d", userId);

    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app is not allowed to call this function");
        funcResult = ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
        return ERR_OK;
    }

    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED) &&
        !BundlePermissionMgr::IsBundleSelfCalling(targetBundleName)) {
        APP_LOGE("no permission to query overlay info of targetBundleName %{public}s", targetBundleName.c_str());
        funcResult = ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PERMISSION_DENIED;
        return ERR_OK;
    }
    funcResult = BundleOverlayManager::GetInstance()->GetOverlayModuleInfoForTarget(targetBundleName,
        targetModuleName, overlayModuleInfo, userId);
    return ERR_OK;
}

ErrCode OverlayManagerHostImpl::SetOverlayEnabledForSelf(const std::string &moduleName, bool isEnabled,
    int32_t userId, int32_t &funcResult)
{
    int32_t timerId = XCollieHelper::SetRecoveryTimer(FUNCTION_SET_OVERLAY_ENABLED_FOR_SELF);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    if (moduleName.empty()) {
        APP_LOGE("invalid param");
        funcResult = ERR_BUNDLEMANAGER_OVERLAY_SET_OVERLAY_PARAM_ERROR;
        return ERR_OK;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }

    std::string callingBundleName = OverlayDataMgr::GetInstance()->GetCallingBundleName();
    if (callingBundleName.empty()) {
        APP_LOGE("GetCallingBundleName failed");
        funcResult = ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
        return ERR_OK;
    }
    APP_LOGD("set overlay enable %{public}d for bundle %{public}s", isEnabled, callingBundleName.c_str());
    funcResult = BundleOverlayManager::GetInstance()->SetOverlayEnabled(callingBundleName, moduleName, isEnabled,
        userId);
    return ERR_OK;
}

ErrCode OverlayManagerHostImpl::SetOverlayEnabled(const std::string &bundleName, const std::string &moduleName,
    bool isEnabled, int32_t userId, int32_t &funcResult)
{
    APP_LOGD("start");
    int32_t timerId = XCollieHelper::SetRecoveryTimer(FUNCTION_SET_OVERLAY_ENABLED);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGE("invalid param");
        funcResult = ERR_BUNDLEMANAGER_OVERLAY_SET_OVERLAY_PARAM_ERROR;
        return ERR_OK;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }
    APP_LOGD("calling userId is %{public}d", userId);

    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app is not allowed to call this function");
        funcResult = ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
        return ERR_OK;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_CHANGE_OVERLAY_ENABLED_STATE) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
        APP_LOGE("no permission to query overlay info of bundleName %{public}s", bundleName.c_str());
        funcResult = ERR_BUNDLEMANAGER_OVERLAY_QUERY_FAILED_PERMISSION_DENIED;
        return ERR_OK;
    }
    funcResult = BundleOverlayManager::GetInstance()->SetOverlayEnabled(bundleName, moduleName, isEnabled, userId);
    return ERR_OK;
}

int32_t OverlayManagerHostImpl::CallbackEnter([[maybe_unused]] uint32_t code)
{
    BundleMemoryGuard::SetBundleMemoryGuard();
    return ERR_NONE;
}

int32_t OverlayManagerHostImpl::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    BundleMemoryGuard::ClearBundleMemoryGuard();
    return ERR_NONE;
}
} // AppExecFwk
} // OHOS
