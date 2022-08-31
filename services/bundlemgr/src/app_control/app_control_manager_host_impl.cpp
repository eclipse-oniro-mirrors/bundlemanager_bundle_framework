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

#include "app_control_manager_host_impl.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "app_control_constants.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AppExecFwk {
AppControlManagerHostImpl::AppControlManagerHostImpl()
{
    appControlManager_ = DelayedSingleton<AppControlManager>::GetInstance();
    callingNameMap_ = {
        {AppControlConstants::EDM_UID, AppControlConstants::EDM_CALLING}
    };
    ruleTypeMap_ = {
        {AppInstallControlRuleType::DISALLOWED_UNINSTALL, AppControlConstants::APP_DISALLOWED_UNINSTALL},
        {AppInstallControlRuleType::DISALLOWED_INSTALL, AppControlConstants::APP_DISALLOWED_INSTALL},
        {AppInstallControlRuleType::ALLOWED_INSTALL, AppControlConstants::APP_ALLOWED_INSTALL},
    };
}

AppControlManagerHostImpl::~AppControlManagerHostImpl()
{
}

ErrCode AppControlManagerHostImpl::AddAppInstallControlRule(const std::vector<std::string> &appIds,
    const AppInstallControlRuleType controlRuleType, int32_t userId)
{
    APP_LOGD("AddAppInstallControlRule start");
    std::string callingName = GetCallingName();
    std::string ruleType = GetControlRuleType(controlRuleType);
    if (callingName.empty()) {
        APP_LOGE("callingName is invalid");
        return ERR_BUNDLEMANAGER_APP_CONTROL_PERMISSION_DENIED;
    }
    if (ruleType.empty()) {
        APP_LOGE("controlRuleType is invalid");
        return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    return appControlManager_->AddAppInstallControlRule(callingName, appIds, ruleType, userId);
}

ErrCode AppControlManagerHostImpl::DeleteAppInstallControlRule(const std::vector<std::string> &appIds, int32_t userId)
{
    APP_LOGD("DeleteAppInstallControlRule start");
    std::string callingName = GetCallingName();
    if (callingName.empty()) {
        APP_LOGE("callingName is invalid");
        return ERR_BUNDLEMANAGER_APP_CONTROL_PERMISSION_DENIED;
    }
    return appControlManager_->DeleteAppInstallControlRule(callingName, appIds, userId);
}

ErrCode AppControlManagerHostImpl::DeleteAppInstallControlRule(const AppInstallControlRuleType controlRuleType,
    int32_t userId)
{
    APP_LOGD("CleanAppInstallControlRule start");
    std::string callingName = GetCallingName();
    std::string ruleType = GetControlRuleType(controlRuleType);
    if (callingName.empty()) {
        APP_LOGE("callingName is invalid");
        return ERR_BUNDLEMANAGER_APP_CONTROL_PERMISSION_DENIED;
    }
    if (ruleType.empty()) {
        APP_LOGE("controlRuleType is invalid");
        return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    return appControlManager_->DeleteAppInstallControlRule(callingName, ruleType, userId);
}

ErrCode AppControlManagerHostImpl::GetAppInstallControlRule(
    const AppInstallControlRuleType controlRuleType, int32_t userId, std::vector<std::string> &appIds)
{
    APP_LOGD("GetAppInstallControlRule start");
    std::string callingName = GetCallingName();
    std::string ruleType = GetControlRuleType(controlRuleType);
    if (callingName.empty()) {
        APP_LOGE("callingName is invalid");
        return ERR_BUNDLEMANAGER_APP_CONTROL_PERMISSION_DENIED;
    }
    if (ruleType.empty()) {
        APP_LOGE("controlRuleType is invalid");
        return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    return appControlManager_->GetAppInstallControlRule(callingName, ruleType, userId, appIds);
}

ErrCode AppControlManagerHostImpl::SetDisposedStatus(const std::string &appId, const Want &want)
{
    APP_LOGD("host begin to SetDisposedStatus");
    ErrCode ret = appControlManager_->SetDisposedStatus(appId, want);
    if (ret != ERR_OK) {
        APP_LOGW("host SetDisposedStatus error:%{public}d", ret);
    }
    return ret;
}

ErrCode AppControlManagerHostImpl::DeleteDisposedStatus(const std::string &appId)
{
    APP_LOGD("host begin to DeleteDisposedStatus");
    ErrCode ret = appControlManager_->DeleteDisposedStatus(appId);
    if (ret != ERR_OK) {
        APP_LOGW("host SetDisposedStatus error:%{public}d", ret);
    }
    return ret;
}

ErrCode AppControlManagerHostImpl::GetDisposedStatus(const std::string &appId, Want &want)
{
    APP_LOGE("host begin to GetDisposedStatus");
    ErrCode ret = appControlManager_->GetDisposedStatus(appId, want);
    if (ret != ERR_OK) {
        APP_LOGW("host SetDisposedStatus error:%{public}d", ret);
    }
    return ret;
}

std::string AppControlManagerHostImpl::GetCallingName()
{
    int32_t uid = OHOS::IPCSkeleton::GetCallingUid();
    auto item = callingNameMap_.find(uid);
    if (item == callingNameMap_.end()) {
        APP_LOGW("calling uid is invalid");
        return "";
    }
    return item->second;
}

std::string AppControlManagerHostImpl::GetControlRuleType(const AppInstallControlRuleType controlRuleType)
{
    auto item = ruleTypeMap_.find(controlRuleType);
    if (item == ruleTypeMap_.end()) {
        APP_LOGW("controlRuleType:%{public}d is invalid", static_cast<int32_t>(controlRuleType));
        return "";
    }
    return item->second;
}
}
}