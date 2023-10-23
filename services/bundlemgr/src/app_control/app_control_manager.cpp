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
    const std::string INVALID_MESSAGE = "INVALID_MESSAGE";
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
    std::lock_guard<std::mutex> lock(appRunningControlMutex_);
    ErrCode ret = appControlManagerDb_->AddAppRunningControlRule(callingName, controlRules, userId);
    if (ret == ERR_OK) {
        for (const auto &rule : controlRules) {
            std::string key = rule.appId + std::string("_") + std::to_string(userId);
            auto iter = appRunningControlRuleResult_.find(key);
            if (iter != appRunningControlRuleResult_.end()) {
                appRunningControlRuleResult_.erase(iter);
            }
        }
        KillRunningApp(controlRules, userId);
    }
    return ret;
}

ErrCode AppControlManager::DeleteAppRunningControlRule(const std::string &callingName,
    const std::vector<AppRunningControlRule> &controlRules, int32_t userId)
{
    std::lock_guard<std::mutex> lock(appRunningControlMutex_);
    auto ret = appControlManagerDb_->DeleteAppRunningControlRule(callingName, controlRules, userId);
    if (ret == ERR_OK) {
        for (const auto &rule : controlRules) {
            std::string key = rule.appId + std::string("_") + std::to_string(userId);
            auto iter = appRunningControlRuleResult_.find(key);
            if (iter != appRunningControlRuleResult_.end()) {
                appRunningControlRuleResult_.erase(iter);
            }
        }
    }
    return ret;
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
    auto ret = appControlManagerDb_->SetDisposedStatus(APP_MARKET_CALLING, appId, want, userId);
    if (ret != ERR_OK) {
        APP_LOGE("SetDisposedStatus to rdb failed");
        return ret;
    }
    std::string key = appId + std::string("_") + std::to_string(userId);
    std::lock_guard<std::mutex> lock(appRunningControlMutex_);
    auto iter = appRunningControlRuleResult_.find(key);
    if (iter != appRunningControlRuleResult_.end()) {
        appRunningControlRuleResult_.erase(iter);
    }
    return ERR_OK;
}

ErrCode AppControlManager::DeleteDisposedStatus(const std::string &appId, int32_t userId)
{
    auto ret = appControlManagerDb_->DeleteDisposedStatus(APP_MARKET_CALLING, appId, userId);
    if (ret != ERR_OK) {
        APP_LOGE("DeleteDisposedStatus to rdb failed");
        return ret;
    }
    std::string key = appId + std::string("_") + std::to_string(userId);
    std::lock_guard<std::mutex> lock(appRunningControlMutex_);
    auto iter = appRunningControlRuleResult_.find(key);
    if (iter != appRunningControlRuleResult_.end()) {
        appRunningControlRuleResult_.erase(iter);
    }
    return ERR_OK;
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
        APP_LOGW("DataMgr GetBundleInfoV9 failed");
        return ret;
    }
    std::string key = bundleInfo.appId + std::string("_") + std::to_string(userId);
    std::lock_guard<std::mutex> lock(appRunningControlMutex_);
    if (appRunningControlRuleResult_.find(key) != appRunningControlRuleResult_.end()) {
        controlRuleResult = appRunningControlRuleResult_[key];
        if (controlRuleResult.controlMessage == INVALID_MESSAGE) {
            controlRuleResult.controlMessage = std::string();
            return ERR_BUNDLE_MANAGER_BUNDLE_NOT_SET_CONTROL;
        }
        return ERR_OK;
    }
    ret = appControlManagerDb_->GetAppRunningControlRule(bundleInfo.appId, userId, controlRuleResult);
    if (ret != ERR_OK) {
        controlRuleResult.controlMessage = INVALID_MESSAGE;
    }
    appRunningControlRuleResult_.emplace(key, controlRuleResult);
    return ret;
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

ErrCode AppControlManager::SetDisposedRule(
    const std::string &callerName, const std::string &appId, const DisposedRule& rule, int32_t userId)
{
    auto ret = appControlManagerDb_->SetDisposedRule(callerName, appId, rule, userId);
    if (ret != ERR_OK) {
        APP_LOGE("SetDisposedStatus to rdb failed");
        return ret;
    }
    return ERR_OK;
}

ErrCode AppControlManager::GetDisposedRule(
    const std::string &callerName, const std::string &appId, DisposedRule& rule, int32_t userId)
{
    auto ret = appControlManagerDb_->GetDisposedRule(callerName, appId, rule, userId);
    if (ret != ERR_OK) {
        APP_LOGE("GetDisposedRule to rdb failed");
        return ret;
    }
    return ERR_OK;
}

ErrCode AppControlManager::GetAbilityRunningControlRule(
    const std::string &bundleName, int32_t userId, std::vector<DisposedRule>& disposedRules)
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
        APP_LOGW("DataMgr GetBundleInfoV9 failed");
        return ret;
    }
    ret = appControlManagerDb_->GetAbilityRunningControlRule(bundleInfo.appId, userId, disposedRules);
    if (ret != ERR_OK) {
        APP_LOGW("GetAbilityRunningControlRule from rdb failed");
        return ret;
    }
    return ret;
}
}
}