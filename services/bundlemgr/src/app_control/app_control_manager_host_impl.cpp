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

#include "app_control_manager_host_impl.h"

#include "app_log_tag_wrapper.h"
#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "app_control_constants.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    const std::string PERMISSION_DISPOSED_STATUS = "ohos.permission.MANAGE_DISPOSED_APP_STATUS";
}
AppControlManagerHostImpl::AppControlManagerHostImpl()
{
    appControlManager_ = DelayedSingleton<AppControlManager>::GetInstance();
    dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    callingNameMap_ = {
        {AppControlConstants::EDM_UID, AppControlConstants::EDM_CALLING}
    };
    ruleTypeMap_ = {
        {AppInstallControlRuleType::DISALLOWED_UNINSTALL, AppControlConstants::APP_DISALLOWED_UNINSTALL},
        {AppInstallControlRuleType::ALLOWED_INSTALL, AppControlConstants::APP_ALLOWED_INSTALL},
        {AppInstallControlRuleType::DISALLOWED_INSTALL, AppControlConstants::APP_DISALLOWED_INSTALL}
    };
}

AppControlManagerHostImpl::~AppControlManagerHostImpl()
{
}

ErrCode AppControlManagerHostImpl::AddAppInstallControlRule(const std::vector<std::string> &appIds,
    const AppInstallControlRuleType controlRuleType, int32_t userId)
{
    LOG_D(BMS_TAG_APP_CONTROL, "AddAppInstallControlRule start");
    std::string callingName = GetCallingName();
    std::string ruleType = GetControlRuleType(controlRuleType);
    if (callingName.empty()) {
        LOG_E(BMS_TAG_APP_CONTROL, "callingName is invalid");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    if (ruleType.empty()) {
        LOG_E(BMS_TAG_APP_CONTROL, "controlRuleType is invalid");
        return ERR_BUNDLE_MANAGER_APP_CONTROL_RULE_TYPE_INVALID;
    }
    auto ret = appControlManager_->AddAppInstallControlRule(callingName, appIds, ruleType, userId);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_APP_CONTROL, "AddAppInstallControlRule failed due to error %{public}d", ret);
        return ret;
    }
    if (ruleType == AppControlConstants::APP_DISALLOWED_UNINSTALL) {
        UpdateAppControlledInfo(userId);
    }
    return ERR_OK;
}

ErrCode AppControlManagerHostImpl::DeleteAppInstallControlRule(const AppInstallControlRuleType controlRuleType,
    const std::vector<std::string> &appIds, int32_t userId)
{
    LOG_D(BMS_TAG_APP_CONTROL, "DeleteAppInstallControlRule start");
    std::string ruleType = GetControlRuleType(controlRuleType);
    if (ruleType.empty()) {
        LOG_E(BMS_TAG_APP_CONTROL, "controlRuleType is invalid");
        return ERR_BUNDLE_MANAGER_APP_CONTROL_RULE_TYPE_INVALID;
    }
    std::string callingName = GetCallingName();
    if (callingName.empty()) {
        LOG_E(BMS_TAG_APP_CONTROL, "callingName is invalid");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto ret = appControlManager_->DeleteAppInstallControlRule(callingName, ruleType, appIds, userId);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_APP_CONTROL, "DeleteAppInstallControlRule failed due to error %{public}d", ret);
        return ret;
    }
    if (ruleType == AppControlConstants::APP_DISALLOWED_UNINSTALL) {
        UpdateAppControlledInfo(userId);
    }
    return ERR_OK;
}

ErrCode AppControlManagerHostImpl::DeleteAppInstallControlRule(const AppInstallControlRuleType controlRuleType,
    int32_t userId)
{
    LOG_D(BMS_TAG_APP_CONTROL, "CleanAppInstallControlRule start");
    std::string callingName = GetCallingName();
    std::string ruleType = GetControlRuleType(controlRuleType);
    if (callingName.empty()) {
        LOG_E(BMS_TAG_APP_CONTROL, "callingName is invalid");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    if (ruleType.empty()) {
        LOG_E(BMS_TAG_APP_CONTROL, "controlRuleType is invalid");
        return ERR_BUNDLE_MANAGER_APP_CONTROL_RULE_TYPE_INVALID;
    }
    auto ret = appControlManager_->DeleteAppInstallControlRule(callingName, ruleType, userId);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_APP_CONTROL, "CleanAppInstallControlRule failed due to error %{public}d", ret);
        return ret;
    }
    if (ruleType == AppControlConstants::APP_DISALLOWED_UNINSTALL) {
        UpdateAppControlledInfo(userId);
    }
    return ERR_OK;
}

ErrCode AppControlManagerHostImpl::GetAppInstallControlRule(
    const AppInstallControlRuleType controlRuleType, int32_t userId, std::vector<std::string> &appIds)
{
    LOG_D(BMS_TAG_APP_CONTROL, "GetAppInstallControlRule start");
    std::string callingName = GetCallingName();
    std::string ruleType = GetControlRuleType(controlRuleType);
    if (callingName.empty()) {
        LOG_E(BMS_TAG_APP_CONTROL, "callingName is invalid");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    if (ruleType.empty()) {
        LOG_E(BMS_TAG_APP_CONTROL, "controlRuleType is invalid");
        return ERR_BUNDLE_MANAGER_APP_CONTROL_RULE_TYPE_INVALID;
    }

    return appControlManager_->GetAppInstallControlRule(callingName, ruleType, userId, appIds);
}

ErrCode AppControlManagerHostImpl::AddAppRunningControlRule(
    const std::vector<AppRunningControlRule> &controlRules, int32_t userId)
{
    std::string callingName = GetCallingName();
    if (callingName.empty()) {
        LOG_E(BMS_TAG_APP_CONTROL, "callingName is invalid");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    return appControlManager_->AddAppRunningControlRule(callingName, controlRules, userId);
}

ErrCode AppControlManagerHostImpl::DeleteAppRunningControlRule(
    const std::vector<AppRunningControlRule> &controlRules, int32_t userId)
{
    std::string callingName = GetCallingName();
    if (callingName.empty()) {
        LOG_E(BMS_TAG_APP_CONTROL, "callingName is invalid");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    return appControlManager_->DeleteAppRunningControlRule(callingName, controlRules, userId);
}

ErrCode AppControlManagerHostImpl::DeleteAppRunningControlRule(int32_t userId)
{
    std::string callingName = GetCallingName();
    if (callingName.empty()) {
        LOG_E(BMS_TAG_APP_CONTROL, "callingName is invalid");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    return appControlManager_->DeleteAppRunningControlRule(callingName, userId);
}

ErrCode AppControlManagerHostImpl::GetAppRunningControlRule(int32_t userId, std::vector<std::string> &appIds)
{
    std::string callingName = GetCallingName();
    if (callingName.empty()) {
        LOG_E(BMS_TAG_APP_CONTROL, "callingName is invalid");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    return appControlManager_->GetAppRunningControlRule(callingName, userId, appIds);
}

ErrCode AppControlManagerHostImpl::GetAppRunningControlRule(
    const std::string &bundleName, int32_t userId, AppRunningControlRuleResult &controlRuleResult)
{
    int32_t uid = OHOS::IPCSkeleton::GetCallingUid();
    if (uid != AppControlConstants::FOUNDATION_UID) {
        LOG_W(BMS_TAG_APP_CONTROL, "calling permission denied, uid : %{public}d", uid);
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    return appControlManager_->GetAppRunningControlRule(bundleName, userId, controlRuleResult);
}

ErrCode AppControlManagerHostImpl::ConfirmAppJumpControlRule(const std::string &callerBundleName,
    const std::string &targetBundleName, int32_t userId)
{
    int32_t uid = OHOS::IPCSkeleton::GetCallingUid();
    if (uid != AppControlConstants::FOUNDATION_UID) {
        LOG_E(BMS_TAG_APP_CONTROL, "callingName is invalid, uid : %{public}d", uid);
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    return appControlManager_->ConfirmAppJumpControlRule(callerBundleName, targetBundleName, userId);
}

ErrCode AppControlManagerHostImpl::AddAppJumpControlRule(const std::vector<AppJumpControlRule> &controlRules,
    int32_t userId)
{
    int32_t uid = OHOS::IPCSkeleton::GetCallingUid();
    if (uid != AppControlConstants::FOUNDATION_UID) {
        LOG_E(BMS_TAG_APP_CONTROL, "callingName is invalid, uid : %{public}d", uid);
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    return appControlManager_->AddAppJumpControlRule(controlRules, userId);
}

ErrCode AppControlManagerHostImpl::DeleteAppJumpControlRule(const std::vector<AppJumpControlRule> &controlRules,
    int32_t userId)
{
    int32_t uid = OHOS::IPCSkeleton::GetCallingUid();
    if (uid != AppControlConstants::FOUNDATION_UID) {
        LOG_E(BMS_TAG_APP_CONTROL, "callingName is invalid, uid : %{public}d", uid);
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    return appControlManager_->DeleteAppJumpControlRule(controlRules, userId);
}

ErrCode AppControlManagerHostImpl::DeleteRuleByCallerBundleName(const std::string &callerBundleName, int32_t userId)
{
    int32_t uid = OHOS::IPCSkeleton::GetCallingUid();
    if (uid != AppControlConstants::FOUNDATION_UID) {
        LOG_E(BMS_TAG_APP_CONTROL, "callingName is invalid, uid : %{public}d", uid);
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    return appControlManager_->DeleteRuleByCallerBundleName(callerBundleName, userId);
}

ErrCode AppControlManagerHostImpl::DeleteRuleByTargetBundleName(const std::string &targetBundleName, int32_t userId)
{
    int32_t uid = OHOS::IPCSkeleton::GetCallingUid();
    if (uid != AppControlConstants::FOUNDATION_UID) {
        LOG_E(BMS_TAG_APP_CONTROL, "callingName is invalid, uid : %{public}d", uid);
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    return appControlManager_->DeleteRuleByTargetBundleName(targetBundleName, userId);
}

ErrCode AppControlManagerHostImpl::GetAppJumpControlRule(const std::string &callerBundleName,
    const std::string &targetBundleName, int32_t userId, AppJumpControlRule &controlRule)
{
    int32_t uid = OHOS::IPCSkeleton::GetCallingUid();
    if (uid != AppControlConstants::FOUNDATION_UID) {
        LOG_W(BMS_TAG_APP_CONTROL, "calling permission denied, uid : %{public}d", uid);
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    return appControlManager_->GetAppJumpControlRule(callerBundleName, targetBundleName, userId, controlRule);
}

std::string AppControlManagerHostImpl::GetCallingName()
{
    int32_t uid = OHOS::IPCSkeleton::GetCallingUid();
    auto item = callingNameMap_.find(uid);
    if (item == callingNameMap_.end()) {
        LOG_W(BMS_TAG_APP_CONTROL, "calling uid is invalid, uid : %{public}d", uid);
        return "";
    }
    return item->second;
}

std::string AppControlManagerHostImpl::GetControlRuleType(const AppInstallControlRuleType controlRuleType)
{
    auto item = ruleTypeMap_.find(controlRuleType);
    if (item == ruleTypeMap_.end()) {
        LOG_W(BMS_TAG_APP_CONTROL, "controlRuleType:%{public}d is invalid", static_cast<int32_t>(controlRuleType));
        return "";
    }
    return item->second;
}

int32_t AppControlManagerHostImpl::GetCallingUserId()
{
    return OHOS::IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
}

ErrCode AppControlManagerHostImpl::SetDisposedStatus(const std::string &appId, const Want &want, int32_t userId)
{
    LOG_D(BMS_TAG_APP_CONTROL, "host begin to SetDisposedStatus");
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_APP_CONTROL, "non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(PERMISSION_DISPOSED_STATUS)) {
        LOG_W(BMS_TAG_APP_CONTROL, "verify permission ohos.permission.MANAGE_DISPOSED_STATUS failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = GetCallingUserId();
    }
    ErrCode ret = appControlManager_->SetDisposedStatus(appId, want, userId);
    if (ret != ERR_OK) {
        LOG_W(BMS_TAG_APP_CONTROL, "host SetDisposedStatus error:%{public}d", ret);
    }
    return ret;
}

ErrCode AppControlManagerHostImpl::DeleteDisposedStatus(const std::string &appId, int32_t userId)
{
    LOG_D(BMS_TAG_APP_CONTROL, "host begin to DeleteDisposedStatus");
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_APP_CONTROL, "non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(PERMISSION_DISPOSED_STATUS)) {
        LOG_W(BMS_TAG_APP_CONTROL, "verify permission ohos.permission.MANAGE_DISPOSED_STATUS failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = GetCallingUserId();
    }
    ErrCode ret = appControlManager_->DeleteDisposedStatus(appId, userId);
    if (ret != ERR_OK) {
        LOG_W(BMS_TAG_APP_CONTROL, "host DeletetDisposedStatus error:%{public}d", ret);
    }
    int32_t uid = OHOS::IPCSkeleton::GetCallingUid();
    std::string callerName;
    GetCallerByUid(uid, callerName);
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = GetCallingUserId();
    }
    ret = appControlManager_->DeleteDisposedRule(callerName, appId, userId);

    return ret;
}

ErrCode AppControlManagerHostImpl::GetDisposedStatus(const std::string &appId, Want &want, int32_t userId)
{
    LOG_D(BMS_TAG_APP_CONTROL, "host begin to GetDisposedStatus");
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_APP_CONTROL, "non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(PERMISSION_DISPOSED_STATUS)) {
        LOG_W(BMS_TAG_APP_CONTROL, "verify permission ohos.permission.MANAGE_DISPOSED_STATUS failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = GetCallingUserId();
    }
    ErrCode ret = appControlManager_->GetDisposedStatus(appId, want, userId);
    if (ret != ERR_OK) {
        LOG_W(BMS_TAG_APP_CONTROL, "host GetDisposedStatus error:%{public}d", ret);
    }
    return ret;
}

void AppControlManagerHostImpl::UpdateAppControlledInfo(int32_t userId) const
{
    LOG_D(BMS_TAG_APP_CONTROL, "start to UpdateAppControlledInfo under userId %{public}d", userId);
    std::vector<std::string> appIds;
    ErrCode ret = appControlManager_->GetAppInstallControlRule(AppControlConstants::EDM_CALLING,
        AppControlConstants::APP_DISALLOWED_UNINSTALL, userId, appIds);
    if (ret != ERR_OK) {
        LOG_W(BMS_TAG_APP_CONTROL, "not update GetAppInstallControlRule failed code:%{public}d", ret);
        return;
    }
    auto bundleInfos = dataMgr_->GetAllInnerBundleInfos();
    for (const auto &info : bundleInfos) {
        InnerBundleUserInfo userInfo;
        if (!info.second.GetInnerBundleUserInfo(userId, userInfo)) {
            LOG_W(BMS_TAG_APP_CONTROL, "current bundle (%{public}s) is not installed at current userId (%{public}d)",
                info.first.c_str(), userId);
            continue;
        }
        auto iterator = std::find(appIds.begin(), appIds.end(), info.second.GetAppId());
        userInfo.isRemovable = (iterator != appIds.end()) ? false : true;
        dataMgr_->AddInnerBundleUserInfo(info.first, userInfo);
    }
}

void AppControlManagerHostImpl::GetCallerByUid(const int32_t uid, std::string &callerName)
{
    auto item = callingNameMap_.find(uid);
    if (item != callingNameMap_.end()) {
        callerName = item->second;
        return;
    }
    auto ret = dataMgr_->GetNameForUid(uid, callerName);
    if (ret != ERR_OK) {
        LOG_W(BMS_TAG_APP_CONTROL, "caller not recognized");
        callerName = std::to_string(uid);
    }
}

ErrCode AppControlManagerHostImpl::GetDisposedRule(const std::string &appId, DisposedRule &rule, int32_t userId)
{
    LOG_D(BMS_TAG_APP_CONTROL, "host begin to GetDisposedRule");
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_APP_CONTROL, "non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(PERMISSION_DISPOSED_STATUS)) {
        LOG_W(BMS_TAG_APP_CONTROL, "verify permission ohos.permission.MANAGE_DISPOSED_STATUS failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    int32_t uid = OHOS::IPCSkeleton::GetCallingUid();
    std::string callerName;
    GetCallerByUid(uid, callerName);
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = GetCallingUserId();
    }
    auto ret = appControlManager_->GetDisposedRule(callerName, appId, rule, userId);
    if (ret != ERR_OK) {
        LOG_W(BMS_TAG_APP_CONTROL, "host GetDisposedStatus error:%{public}d", ret);
    }
    return ret;
}

ErrCode AppControlManagerHostImpl::SetDisposedRule(const std::string &appId, DisposedRule &rule, int32_t userId)
{
    LOG_D(BMS_TAG_APP_CONTROL, "host begin to SetDisposedRule");
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_APP_CONTROL, "non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(PERMISSION_DISPOSED_STATUS)) {
        LOG_W(BMS_TAG_APP_CONTROL, "verify permission ohos.permission.MANAGE_DISPOSED_STATUS failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    int32_t uid = OHOS::IPCSkeleton::GetCallingUid();
    std::string callerName;
    GetCallerByUid(uid, callerName);
    if (uid == AppControlConstants::EDM_UID) {
        rule.isEdm = true;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = GetCallingUserId();
    }
    auto ret = appControlManager_->SetDisposedRule(callerName, appId, rule, userId);
    if (ret != ERR_OK) {
        LOG_W(BMS_TAG_APP_CONTROL, "host GetDisposedStatus error:%{public}d", ret);
    }
    return ret;
}

ErrCode AppControlManagerHostImpl::GetAbilityRunningControlRule(
    const std::string &bundleName, int32_t userId, std::vector<DisposedRule>& disposedRules)
{
    int32_t uid = OHOS::IPCSkeleton::GetCallingUid();
    if (uid != AppControlConstants::FOUNDATION_UID) {
        LOG_E(BMS_TAG_APP_CONTROL, "callingName is invalid, uid : %{public}d", uid);
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    return appControlManager_->GetAbilityRunningControlRule(bundleName, userId, disposedRules);
}
} // AppExecFwk
} // OHOS