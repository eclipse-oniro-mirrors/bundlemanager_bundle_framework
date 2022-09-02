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

#include "app_control_manager.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_constants.h"
#include "app_control_manager_rdb.h"

namespace OHOS {
namespace AppExecFwk {
AppControlManager::AppControlManager()
{
    appControlManagerDb_ = std::make_shared<AppControlManagerRdb>();
}

AppControlManager::~AppControlManager()
{
}

ErrCode AppControlManager::AddAppInstallControlRule(const std::string &callingName,
    const std::vector<std::string> &appIds, const std::string &controlRuleType, int32_t userId)
{
    APP_LOGD("AddAppInstallControlRule");
    return appControlManagerDb_->AddAppInstallControlRule(callingName, appIds, controlRuleType, userId);
}

ErrCode AppControlManager::DeleteAppInstallControlRule(const std::string &callingName,
    const std::vector<std::string> &appIds, int32_t userId)
{
    APP_LOGD("DeleteAppInstallControlRule");
    return appControlManagerDb_->DeleteAppInstallControlRule(callingName, appIds, userId);
}

ErrCode AppControlManager::DeleteAppInstallControlRule(const std::string &callingName,
    const std::string &controlRuleType, int32_t userId)
{
    APP_LOGD("CleanInstallControlRule");
    return appControlManagerDb_->DeleteAppInstallControlRule(callingName, controlRuleType, userId);
}

ErrCode AppControlManager::GetAppInstallControlRule(const std::string &callingName,
    const std::string &controlRuleType, int32_t userId, std::vector<std::string> &appIds)
{
    APP_LOGD("GetAppInstallControlRule");
    return appControlManagerDb_->GetAppInstallControlRule(callingName, controlRuleType, userId, appIds);
}

ErrCode AppControlManager::AddAppRunningControlRule(const std::string &callingName,
    const std::vector<InnerAppRunningControlRule> &controlRule, int32_t userId)
{
    APP_LOGD("AddAppRunningControlRule");
    return appControlManagerDb_->AddAppRunningControlRule(callingName, controlRule, userId);
}

ErrCode AppControlManager::DeleteAppRunningControlRule(const std::string &callingName,
    const std::vector<InnerAppRunningControlRule> &controlRule, int32_t userId)
{
    return appControlManagerDb_->DeleteAppRunningControlRule(callingName, controlRule, userId);
}

ErrCode AppControlManager::DeleteAppRunningControlRule(const std::string &callingName, int32_t userId)
{
    return appControlManagerDb_->DeleteAppRunningControlRule(callingName, userId);
}

ErrCode AppControlManager::GetAppRunningControlRule(
    const std::string &callingName, int32_t userId, std::vector<std::string> &appIds)
{
    return appControlManagerDb_->GetAppRunningControlRule(callingName, userId, appIds);
}
}
}