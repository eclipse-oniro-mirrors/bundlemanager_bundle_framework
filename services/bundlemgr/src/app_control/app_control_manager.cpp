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

#include "ability_manager_helper.h"
#include "account_helper.h"
#include "app_control_constants.h"
#include "app_control_manager_rdb.h"
#include "app_jump_interceptor_manager_rdb.h"
#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "application_info.h"
#include "bundle_constants.h"
#include "bundle_info.h"
#include "bundle_mgr_service.h"
#include "parameters.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    const std::string APP_MARKET_CALLING = "app market";
}

AppControlManager::AppControlManager()
{
    appControlManagerDb_ = std::make_shared<AppControlManagerRdb>();
    bool isAppJumpEnabled = OHOS::system::GetBoolParameter(
        OHOS::AppExecFwk::PARAMETER_APP_JUMP_INTERCEPTOR_ENABLE, false);
    APP_LOGE("GetBoolParameter -> isAppJumpEnabled:%{public}s", (isAppJumpEnabled ? "true" : "false"));
    if (isAppJumpEnabled) {
        APP_LOGI("App jump intercetor enabled, start init to AppJumpInterceptorManagerRdb");
        appJumpInterceptorManagerDb_ = std::make_shared<AppJumpInterceptorManagerRdb>();
        appJumpInterceptorManagerDb_->SubscribeCommonEvent();
    } else {
        APP_LOGI("App jump intercetor disabled");
    }
}

AppControlManager::~AppControlManager()
{
}

ErrCode AppControlManager::AddAppInstallControlRule(const std::string &callingName,
    const std::vector<std::string> &appIds, const std::string &controlRuleType, int32_t userId)
{
    APP_LOGD("AddAppInstallControlRule");
    auto ret = appControlManagerDb_->AddAppInstallControlRule(callingName, appIds, controlRuleType, userId);
    if ((ret == ERR_OK) && !isAppInstallControlEnabled_) {
        isAppInstallControlEnabled_ = true;
    }
    return ret;
}

ErrCode AppControlManager::DeleteAppInstallControlRule(const std::string &callingName,
    const std::string &controlRuleType, const std::vector<std::string> &appIds, int32_t userId)
{
    APP_LOGD("DeleteAppInstallControlRule");
    auto ret = appControlManagerDb_->DeleteAppInstallControlRule(callingName, controlRuleType, appIds, userId);
    if ((ret == ERR_OK) && isAppInstallControlEnabled_) {
        SetAppInstallControlStatus();
    }
    return ret;
}

ErrCode AppControlManager::DeleteAppInstallControlRule(const std::string &callingName,
    const std::string &controlRuleType, int32_t userId)
{
    APP_LOGD("CleanInstallControlRule");
    auto ret = appControlManagerDb_->DeleteAppInstallControlRule(callingName, controlRuleType, userId);
    if ((ret == ERR_OK) && isAppInstallControlEnabled_) {
        SetAppInstallControlStatus();
    }
    return ret;
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
    ErrCode ret = appControlManagerDb_->AddAppRunningControlRule(callingName, controlRules, userId);
    if (ret == ERR_OK) {
        KillRunningApp(controlRules, userId);
    }
    return ret;
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

ErrCode AppControlManager::ConfirmAppJumpControlRule(const std::string &callerBundleName,
    const std::string &targetBundleName, int32_t userId)
{
    if (appJumpInterceptorManagerDb_ == nullptr) {
        APP_LOGE("DataMgr rdb is not init");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return appJumpInterceptorManagerDb_->ConfirmAppJumpControlRule(callerBundleName, targetBundleName, userId);
}

ErrCode AppControlManager::AddAppJumpControlRule(const std::vector<AppJumpControlRule> &controlRules, int32_t userId)
{
    if (appJumpInterceptorManagerDb_ == nullptr) {
        APP_LOGE("DataMgr rdb is not init");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return appJumpInterceptorManagerDb_->AddAppJumpControlRule(controlRules, userId);
}

ErrCode AppControlManager::DeleteAppJumpControlRule(const std::vector<AppJumpControlRule> &controlRules, int32_t userId)
{
    if (appJumpInterceptorManagerDb_ == nullptr) {
        APP_LOGE("DataMgr rdb is not init");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return appJumpInterceptorManagerDb_->DeleteAppJumpControlRule(controlRules, userId);
}

ErrCode AppControlManager::DeleteRuleByCallerBundleName(const std::string &callerBundleName, int32_t userId)
{
    if (appJumpInterceptorManagerDb_ == nullptr) {
        APP_LOGE("DataMgr rdb is not init");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return appJumpInterceptorManagerDb_->DeleteRuleByCallerBundleName(callerBundleName, userId);
}

ErrCode AppControlManager::DeleteRuleByTargetBundleName(const std::string &targetBundleName, int32_t userId)
{
    if (appJumpInterceptorManagerDb_ == nullptr) {
        APP_LOGE("DataMgr rdb is not init");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return appJumpInterceptorManagerDb_->DeleteRuleByTargetBundleName(targetBundleName, userId);
}

ErrCode AppControlManager::GetAppJumpControlRule(const std::string &callerBundleName,
    const std::string &targetBundleName, int32_t userId, AppJumpControlRule &controlRule)
{
    if (appJumpInterceptorManagerDb_ == nullptr) {
        APP_LOGE("DataMgr rdb is not init");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    auto ret = appJumpInterceptorManagerDb_->GetAppJumpControlRule(callerBundleName, targetBundleName,
        userId, controlRule);
    return ret;
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

void AppControlManager::KillRunningApp(const std::vector<AppRunningControlRule> &rules, int32_t userId) const
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is null");
        return;
    }
    std::for_each(rules.cbegin(), rules.cend(), [&dataMgr, userId](const auto &rule) {
        std::string bundleName = dataMgr->GetBundleNameByAppId(rule.appId);
        if (bundleName.empty()) {
            APP_LOGW("GetBundleNameByAppId failed");
            return;
        }
        BundleInfo bundleInfo;
        ErrCode ret = dataMgr->GetBundleInfoV9(
            bundleName, static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE), bundleInfo, userId);
        if (ret != ERR_OK) {
            APP_LOGW("GetBundleInfoV9 failed");
            return;
        }
        AbilityManagerHelper::UninstallApplicationProcesses(bundleName, bundleInfo.uid);
    });
}

bool AppControlManager::IsAppInstallControlEnabled() const
{
    return isAppInstallControlEnabled_;
}

void AppControlManager::SetAppInstallControlStatus()
{
    isAppInstallControlEnabled_ = false;
    std::vector<std::string> appIds;
    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    if (currentUserId == Constants::INVALID_USERID) {
        currentUserId = Constants::START_USERID;
    }
    ErrCode ret = appControlManagerDb_->GetAppInstallControlRule(AppControlConstants::EDM_CALLING,
        AppControlConstants::APP_DISALLOWED_UNINSTALL, currentUserId, appIds);
    if ((ret == ERR_OK) && !appIds.empty()) {
        isAppInstallControlEnabled_ = true;
    }
}
}
}