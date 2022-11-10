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

#include "app_control_constants.h"
#include "app_control_manager_rdb.h"
#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "application_info.h"
#include "bundle_constants.h"
#include "bundle_info.h"
#include "bundle_mgr_service.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    const std::string APP_MARKET_CALLING = "app market";
}

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
    const std::string &controlRuleType, const std::vector<std::string> &appIds, int32_t userId)
{
    APP_LOGD("DeleteAppInstallControlRule");
    return appControlManagerDb_->DeleteAppInstallControlRule(callingName, controlRuleType, appIds, userId);
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
    const std::vector<AppRunningControlRule> &controlRules, int32_t userId)
{
    APP_LOGD("AddAppRunningControlRule");
    return appControlManagerDb_->AddAppRunningControlRule(callingName, controlRules, userId);
}

ErrCode AppControlManager::DeleteAppRunningControlRule(const std::string &callingName,
    const std::vector<AppRunningControlRule> &controlRules, int32_t userId)
{
    return appControlManagerDb_->DeleteAppRunningControlRule(callingName, controlRules, userId);
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

ErrCode AppControlManager::SetDisposedStatus(const std::string &appId, const Want& want, int32_t userId)
{
    return appControlManagerDb_->SetDisposedStatus(
        APP_MARKET_CALLING, appId, want, userId);
}

ErrCode AppControlManager::DeleteDisposedStatus(const std::string &appId, int32_t userId)
{
    return appControlManagerDb_->DeleteDisposedStatus(
        APP_MARKET_CALLING, appId, userId);
}

ErrCode AppControlManager::GetDisposedStatus(const std::string &appId, Want& want, int32_t userId)
{
    return appControlManagerDb_->GetDisposedStatus(
        APP_MARKET_CALLING, appId, want, userId);
}

ErrCode AppControlManager::GetAppRunningControlRule(
    const std::string &bundleName, int32_t userId, AppRunningControlRuleResult &controlRuleResult)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    BundleInfo bundleInfo;
    ErrCode ret = dataMgr->GetBundleInfoV9(bundleName,
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE), bundleInfo, userId);
    if (ret != ERR_OK) {
        APP_LOGE("DataMgr GetBundleInfoV9 failed");
        return ret;
    }
    return appControlManagerDb_->GetAppRunningControlRule(bundleInfo.appId, userId, controlRuleResult);
}
}
}