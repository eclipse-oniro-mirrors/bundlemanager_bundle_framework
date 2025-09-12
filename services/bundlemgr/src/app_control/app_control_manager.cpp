/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "app_log_tag_wrapper.h"
#include "bundle_mgr_service.h"
#include "bundle_parser.h"
#include "hitrace_meter.h"
#include "parameters.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    constexpr const char* APP_MARKET_CALLING = "app market";
    constexpr const char* INVALID_MESSAGE = "INVALID_MESSAGE";
    constexpr const char* ATOMIC_SERVICE = "atomicservice";
    constexpr const char* APP_CONTROL_EDM_DEFAULT_MESSAGE = "The app has been disabled by EDM";
}

AppControlManager::AppControlManager()
{
    appControlManagerDb_ = std::make_shared<AppControlManagerRdb>();
    commonEventMgr_ = std::make_shared<BundleCommonEventMgr>();
    std::string configPath = BundleUtil::GetNoDisablingConfigPath();
    ErrCode ret = BundleParser::ParseNoDisablingList(configPath, noControllingList_);
    if (ret != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT, "GetNoDisablingList failed");
    }
    ret = GenerateRunningRuleSettingStatusMap();
    if (ret != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT, "GenerateRunningRuleSettingStatusMap failed");
    }
}

AppControlManager::~AppControlManager()
{
}

ErrCode AppControlManager::GenerateRunningRuleSettingStatusMap()
{
    std::vector<int32_t> userIds;
    auto ret = appControlManagerDb_->GetAllUserIdsForRunningControl(userIds);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetAllUserIdsForRunningControl failed");
        return ret;
    }
    if (userIds.empty()) {
        return ERR_OK;
    }
    std::string appId;
    AppRunningControlRule controlRuleResult;
    for (auto userId : userIds) {
        auto ret = appControlManagerDb_->GetAppRunningControlRuleByUserId(userId, appId, controlRuleResult);
        if (ret != ERR_OK) {
            LOG_E(BMS_TAG_DEFAULT, "GetAppRunningControlRuleByUserId failed for userId=%d", userId);
            continue;
        }
        if (appId.empty()) {
            SetRunningRuleSettingStatusByUserId(userId, RunningRuleSettingStatus::NO_SET);
            continue;
        }
        if (controlRuleResult.allowRunning) {
            SetRunningRuleSettingStatusByUserId(userId, RunningRuleSettingStatus::WHITE_LIST);
        } else {
            SetRunningRuleSettingStatusByUserId(userId, RunningRuleSettingStatus::BLACK_LIST);
        }
    }
    return ERR_OK;
}

ErrCode AppControlManager::AddAppInstallControlRule(const std::string &callingName,
    const std::vector<std::string> &appIds, const std::string &controlRuleType, int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "AddAppInstallControlRule");
    auto ret = appControlManagerDb_->AddAppInstallControlRule(callingName, appIds, controlRuleType, userId);
    if ((ret == ERR_OK) && !isAppInstallControlEnabled_) {
        isAppInstallControlEnabled_ = true;
    }
    return ret;
}

ErrCode AppControlManager::DeleteAppInstallControlRule(const std::string &callingName,
    const std::string &controlRuleType, const std::vector<std::string> &appIds, int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "DeleteAppInstallControlRule");
    auto ret = appControlManagerDb_->DeleteAppInstallControlRule(callingName, controlRuleType, appIds, userId);
    if ((ret == ERR_OK) && isAppInstallControlEnabled_) {
        SetAppInstallControlStatus();
    }
    return ret;
}

ErrCode AppControlManager::DeleteAppInstallControlRule(const std::string &callingName,
    const std::string &controlRuleType, int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "CleanInstallControlRule");
    auto ret = appControlManagerDb_->DeleteAppInstallControlRule(callingName, controlRuleType, userId);
    if ((ret == ERR_OK) && isAppInstallControlEnabled_) {
        SetAppInstallControlStatus();
    }
    return ret;
}

ErrCode AppControlManager::GetAppInstallControlRule(const std::string &callingName,
    const std::string &controlRuleType, int32_t userId, std::vector<std::string> &appIds)
{
    LOG_D(BMS_TAG_DEFAULT, "GetAppInstallControlRule");
    return appControlManagerDb_->GetAppInstallControlRule(callingName, controlRuleType, userId, appIds);
}

ErrCode AppControlManager::AddAppRunningControlRule(const std::string &callingName,
    const std::vector<AppRunningControlRule> &controlRules, int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "AddAppRunningControlRule");
    ErrCode ret = CheckControlRules(controlRules, userId);
    if (ret != ERR_OK) {
        return ret;
    }
    ret = appControlManagerDb_->AddAppRunningControlRule(callingName, controlRules, userId);
    if (ret != ERR_OK) {
        return ret;
    }
    auto status = GetRunningRuleSettingStatusByUserId(userId);
    if (status == RunningRuleSettingStatus::NO_SET) {
        DeleteAppRunningControlRuleCacheForUserId(userId);
    }
    if (controlRules[0].allowRunning == true) {
        SetRunningRuleSettingStatusByUserId(userId, RunningRuleSettingStatus::WHITE_LIST);
    } else {
        SetRunningRuleSettingStatusByUserId(userId, RunningRuleSettingStatus::BLACK_LIST);
    }
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    for (const auto &rule : controlRules) {
        std::string key = rule.appId + std::string("_") + std::to_string(userId);
        DeleteAppRunningControlRuleCache(key);
        std::string transformedAppId = dataMgr->AppIdAndAppIdentifierTransform(rule.appId);
        std::string transformedKey = transformedAppId + std::string("_") + std::to_string(userId);
        DeleteAppRunningControlRuleCache(transformedKey);
    }
    KillRunningApp(controlRules, userId);
    return ERR_OK;
}

ErrCode AppControlManager::CheckControlRules(
    const std::vector<AppRunningControlRule> &controlRules, int32_t userId)
{
    if (controlRules.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "controlRules is empty");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    auto firstAllowRunning = controlRules[0].allowRunning;
    for (const auto &rule : controlRules) {
        if (rule.allowRunning != firstAllowRunning) {
            LOG_E(BMS_TAG_DEFAULT, "mixed rules are not allowed");
            return ERR_BUNDLE_MANAGER_CONTROL_RULE_NOT_CONSISTENT;
        }
    }
    RunningRuleSettingStatus runningRuleSettingStatus =
        firstAllowRunning ? RunningRuleSettingStatus::WHITE_LIST : RunningRuleSettingStatus::BLACK_LIST;
    auto status = GetRunningRuleSettingStatusByUserId(userId);
    if (status != RunningRuleSettingStatus::NO_SET && status != runningRuleSettingStatus) {
        LOG_E(BMS_TAG_DEFAULT, "rules are inconsistent with history");
        return ERR_BUNDLE_MANAGER_CONTROL_RULE_NOT_CONSISTENT;
    }
    return ERR_OK;
}

AppControlManager::RunningRuleSettingStatus AppControlManager::GetRunningRuleSettingStatusByUserId(int32_t userId)
{
    std::lock_guard<std::mutex> lock(runningRuleSettingStatusMutex_);
    auto it = runningRuleSettingStatusMap_.find(userId);
    if (it != runningRuleSettingStatusMap_.end()) {
        return it->second;
    }
    return RunningRuleSettingStatus::NO_SET;
}

void AppControlManager::SetRunningRuleSettingStatusByUserId(
    int32_t userId, RunningRuleSettingStatus runningRuleSettingStatus)
{
    std::lock_guard<std::mutex> lock(runningRuleSettingStatusMutex_);
    auto it = runningRuleSettingStatusMap_.find(userId);
    if (it != runningRuleSettingStatusMap_.end()) {
        runningRuleSettingStatusMap_.erase(it);
    }
    runningRuleSettingStatusMap_.emplace(userId, runningRuleSettingStatus);
}

ErrCode AppControlManager::DeleteAppRunningControlRule(const std::string &callingName,
    const std::vector<AppRunningControlRule> &controlRules, int32_t userId)
{
    ErrCode ret = CheckControlRules(controlRules, userId);
    if (ret != ERR_OK) {
        return ret;
    }
    ret = appControlManagerDb_->DeleteAppRunningControlRule(callingName, controlRules, userId);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "DeleteAppRunningControlRule failed");
        return ret;
    }
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    for (const auto &rule : controlRules) {
        std::string key = rule.appId + std::string("_") + std::to_string(userId);
        DeleteAppRunningControlRuleCache(key);
        std::string transformedAppId = dataMgr->AppIdAndAppIdentifierTransform(rule.appId);
        std::string transformedKey = transformedAppId + std::string("_") + std::to_string(userId);
        DeleteAppRunningControlRuleCache(transformedKey);
    }
    std::vector<std::string> appIds;
    ret = appControlManagerDb_->GetAppIdsByUserId(userId, appIds);
    if (appIds.empty()) {
        SetRunningRuleSettingStatusByUserId(userId, RunningRuleSettingStatus::NO_SET);
        DeleteAppRunningControlRuleCacheForUserId(userId);
    }
    return ret;
}

ErrCode AppControlManager::DeleteAppRunningControlRule(const std::string &callingName, int32_t userId)
{
    ErrCode res = appControlManagerDb_->DeleteAppRunningControlRule(callingName, userId);
    if (res != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "DeleteAppRunningControlRule failed");
        return res;
    }
    DeleteAppRunningControlRuleCacheForUserId(userId);
    SetRunningRuleSettingStatusByUserId(userId, RunningRuleSettingStatus::NO_SET);
    return res;
}

ErrCode AppControlManager::GetAppRunningControlRule(
    const std::string &callingName, int32_t userId, std::vector<std::string> &appIds, bool &allowRunning)
{
    return appControlManagerDb_->GetAppRunningControlRule(callingName, userId, appIds, allowRunning);
}

ErrCode AppControlManager::ConfirmAppJumpControlRule(const std::string &callerBundleName,
    const std::string &targetBundleName, int32_t userId)
{
    if (appJumpInterceptorManagerDb_ == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr rdb is not init");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return appJumpInterceptorManagerDb_->ConfirmAppJumpControlRule(callerBundleName, targetBundleName, userId);
}

ErrCode AppControlManager::AddAppJumpControlRule(const std::vector<AppJumpControlRule> &controlRules, int32_t userId)
{
    if (appJumpInterceptorManagerDb_ == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr rdb is not init");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return appJumpInterceptorManagerDb_->AddAppJumpControlRule(controlRules, userId);
}

ErrCode AppControlManager::DeleteAppJumpControlRule(const std::vector<AppJumpControlRule> &controlRules, int32_t userId)
{
    if (appJumpInterceptorManagerDb_ == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr rdb is not init");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return appJumpInterceptorManagerDb_->DeleteAppJumpControlRule(controlRules, userId);
}

ErrCode AppControlManager::DeleteRuleByCallerBundleName(const std::string &callerBundleName, int32_t userId)
{
    if (appJumpInterceptorManagerDb_ == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr rdb is not init");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return appJumpInterceptorManagerDb_->DeleteRuleByCallerBundleName(callerBundleName, userId);
}

ErrCode AppControlManager::DeleteRuleByTargetBundleName(const std::string &targetBundleName, int32_t userId)
{
    if (appJumpInterceptorManagerDb_ == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr rdb is not init");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return appJumpInterceptorManagerDb_->DeleteRuleByTargetBundleName(targetBundleName, userId);
}

ErrCode AppControlManager::GetAppJumpControlRule(const std::string &callerBundleName,
    const std::string &targetBundleName, int32_t userId, AppJumpControlRule &controlRule)
{
    if (appJumpInterceptorManagerDb_ == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr rdb is not init");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    auto ret = appJumpInterceptorManagerDb_->GetAppJumpControlRule(callerBundleName, targetBundleName,
        userId, controlRule);
    return ret;
}

ErrCode AppControlManager::SetDisposedStatus(const std::string &appId, const Want& want, int32_t userId)
{
    if (!CheckCanDispose(appId, userId)) {
        LOG_E(BMS_TAG_DEFAULT, "appid in white-list");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto ret = appControlManagerDb_->SetDisposedStatus(APP_MARKET_CALLING, appId, want, userId);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "SetDisposedStatus to rdb failed");
        return ret;
    }
    std::string key = appId + std::string("_") + std::to_string(userId);
    std::lock_guard<std::mutex> lock(appRunningControlMutex_);
    auto iter = appRunningControlRuleResult_.find(key);
    if (iter != appRunningControlRuleResult_.end()) {
        appRunningControlRuleResult_.erase(iter);
    }

    commonEventMgr_->NotifySetDisposedRule(appId, userId, want.ToString(), Constants::MAIN_APP_INDEX);
    return ERR_OK;
}

ErrCode AppControlManager::DeleteDisposedStatus(const std::string &appId, int32_t userId)
{
    auto ret = appControlManagerDb_->DeleteDisposedStatus(APP_MARKET_CALLING, appId, userId);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "DeleteDisposedStatus to rdb failed");
        return ret;
    }
    std::string key = appId + std::string("_") + std::to_string(userId);
    std::lock_guard<std::mutex> lock(appRunningControlMutex_);
    auto iter = appRunningControlRuleResult_.find(key);
    if (iter != appRunningControlRuleResult_.end()) {
        appRunningControlRuleResult_.erase(iter);
    }
    commonEventMgr_->NotifyDeleteDisposedRule(appId, userId, Constants::MAIN_APP_INDEX);
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
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    std::string appId;
    std::string appIdentifier;
    ErrCode ret = dataMgr->GetAppIdAndAppIdentifierByBundleName(bundleName, appId, appIdentifier);
    if (ret != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT, "getAppId failed,-n:%{public}s", bundleName.c_str());
        return ret;
    }
    std::string key = appId + std::string("_") + std::to_string(userId);
    auto statusRet = GetAppRunningControlRuleCache(key, controlRuleResult);
    if (statusRet) {
        if (controlRuleResult.controlMessage == INVALID_MESSAGE) {
            controlRuleResult.controlMessage = std::string();
            return ERR_BUNDLE_MANAGER_BUNDLE_NOT_SET_CONTROL;
        }
        return ERR_OK;
    }
    ret = appIdentifier.empty() ? appControlManagerDb_->GetAppRunningControlRule(appId, userId, controlRuleResult) :
        appControlManagerDb_->GetAppRunningControlRule(appIdentifier, userId, controlRuleResult);
    if (ret != ERR_OK && !appIdentifier.empty()) {
        ret = appControlManagerDb_->GetAppRunningControlRule(appId, userId, controlRuleResult);
    }
    bool findRule = (ret == ERR_OK);
    ret = CheckAppControlRuleIntercept(bundleName, userId, findRule, controlRuleResult);
    SetAppRunningControlRuleCache(key, controlRuleResult);
    return ret;
}

ErrCode AppControlManager::CheckAppControlRuleIntercept(const std::string &bundleName,
    int32_t userId, bool findRule, AppRunningControlRuleResult &controlRuleResult)
{
    auto status = GetRunningRuleSettingStatusByUserId(userId);
    if (findRule) {
        if (!controlRuleResult.isEdm) {
            return ERR_OK;
        }
        if (status == RunningRuleSettingStatus::NO_SET || status == RunningRuleSettingStatus::WHITE_LIST) {
            controlRuleResult.controlMessage = INVALID_MESSAGE;
            return ERR_BUNDLE_MANAGER_BUNDLE_NOT_SET_CONTROL;
        }
        return ERR_OK;
    }

    if (status == RunningRuleSettingStatus::BLACK_LIST || status == RunningRuleSettingStatus::NO_SET) {
        controlRuleResult.controlMessage = INVALID_MESSAGE;
    } else {
        auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
        if (dataMgr == nullptr) {
            LOG_E(BMS_TAG_DEFAULT, "dataMgr is null");
            return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
        }
        auto bundleInfos = dataMgr->GetAllInnerBundleInfos();
        auto iter = bundleInfos.find(bundleName);
        if (iter == bundleInfos.end()) {
            APP_LOGW("%{public}s not found", bundleName.c_str());
            return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
        }
        if (iter->second.IsSystemApp()) {
            controlRuleResult.controlMessage = INVALID_MESSAGE;
        } else {
            controlRuleResult.controlMessage = APP_CONTROL_EDM_DEFAULT_MESSAGE;
            return ERR_OK;
        }
    }
    return ERR_BUNDLE_MANAGER_BUNDLE_NOT_SET_CONTROL;
}

void AppControlManager::SetAppRunningControlRuleCache(
    const std::string &key, AppRunningControlRuleResult controlRuleResult)
{
    std::lock_guard<std::mutex> lock(appRunningControlMutex_);
    appRunningControlRuleResult_.emplace(key, controlRuleResult);
}

bool AppControlManager::GetAppRunningControlRuleCache(
    const std::string &key, AppRunningControlRuleResult &controlRuleResult)
{
    std::lock_guard<std::mutex> lock(appRunningControlMutex_);
    if (appRunningControlRuleResult_.find(key) != appRunningControlRuleResult_.end()) {
        controlRuleResult = appRunningControlRuleResult_[key];
        return true;
    }
    return false;
}

void AppControlManager::DeleteAppRunningControlRuleCache(const std::string &key)
{
    std::lock_guard<std::mutex> lock(appRunningControlMutex_);
    auto iter = appRunningControlRuleResult_.find(key);
    if (iter != appRunningControlRuleResult_.end()) {
        appRunningControlRuleResult_.erase(iter);
    }
}

void AppControlManager::DeleteAppRunningControlRuleCacheForUserId(int32_t userId)
{
    std::lock_guard<std::mutex> lock(appRunningControlMutex_);
    for (auto it = appRunningControlRuleResult_.begin(); it != appRunningControlRuleResult_.end();) {
        std::string key = it->first;
        std::string targetUserId = std::to_string(userId);
        if (key.size() >= targetUserId.size() &&
            key.compare(key.size() - targetUserId.size(), targetUserId.size(), targetUserId) == 0) {
            it = appRunningControlRuleResult_.erase(it);
        } else {
            ++it;
        }
    }
}

void AppControlManager::KillRunningApp(const std::vector<AppRunningControlRule> &rules, int32_t userId) const
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "dataMgr is null");
        return;
    }
    std::for_each(rules.cbegin(), rules.cend(), [&dataMgr, userId](const auto &rule) {
        std::string bundleName = dataMgr->GetBundleNameByAppId(rule.appId);
        if (bundleName.empty()) {
            LOG_W(BMS_TAG_DEFAULT, "GetBundleNameByAppId failed");
            return;
        }
        BundleInfo bundleInfo;
        ErrCode ret = dataMgr->GetBundleInfoV9(
            bundleName, static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE), bundleInfo, userId);
        if (ret != ERR_OK) {
            LOG_W(BMS_TAG_DEFAULT, "GetBundleInfoV9 failed");
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

ErrCode AppControlManager::SetDisposedRule(const std::string &callerName, const std::string &appId,
    const DisposedRule& rule, int32_t appIndex, int32_t userId)
{
    if (!CheckCanDispose(appId, userId)) {
        LOG_E(BMS_TAG_DEFAULT, "%{public}s set rule, user:%{public}d index:%{public}d",
            callerName.c_str(), userId, appIndex);
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    std::string transformedAppId = dataMgr->AppIdAndAppIdentifierTransform(appId);
    ErrCode ret = appControlManagerDb_->DeleteDisposedRule(callerName, { appId, transformedAppId }, appIndex, userId);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "delete failed caller:%{public}s id:%{private}s user:%{public}d index:%{public}d",
            callerName.c_str(), appId.c_str(), userId, appIndex);
        return ret;
    }
    ret = appControlManagerDb_->SetDisposedRule(callerName, appId, rule, appIndex, userId);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "SetDisposedRule to rdb failed, %{public}s set rule, user:%{public}d index:%{public}d",
            callerName.c_str(), userId, appIndex);
        return ret;
    }
    std::string appIdKey = GenerateAppRunningRuleCacheKey(appId, userId, appIndex);
    std::string transformedAppIdKey = GenerateAppRunningRuleCacheKey(transformedAppId, userId, appIndex);
    DeleteAbilityRunningRuleCache({ appIdKey, transformedAppIdKey });
    LOG_D(BMS_TAG_DEFAULT, "%{public}s set rule, user:%{public}d index:%{public}d",
        callerName.c_str(), userId, appIndex);
    commonEventMgr_->NotifySetDisposedRule(appId, userId, rule.ToString(), appIndex);
    return ERR_OK;
}

ErrCode AppControlManager::GetDisposedRule(
    const std::string &callerName, const std::string &appId, DisposedRule& rule, int32_t appIndex, int32_t userId)
{
    auto ret = appControlManagerDb_->GetDisposedRule(callerName, appId, rule, appIndex, userId);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetDisposedRule to rdb failed");
        return ret;
    }
    return ERR_OK;
}

ErrCode AppControlManager::DeleteDisposedRule(
    const std::string &callerName, const std::string &appId, int32_t appIndex, int32_t userId)
{
    auto ret = appControlManagerDb_->DeleteDisposedRule(callerName, { appId }, appIndex, userId);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "failed caller:%{public}s id:%{private}s user:%{public}d index:%{public}d",
            callerName.c_str(), appId.c_str(), userId, appIndex);
        return ret;
    }
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    std::string transformedAppId = dataMgr->AppIdAndAppIdentifierTransform(appId);
    std::string appIdKey = GenerateAppRunningRuleCacheKey(appId, userId, appIndex);
    std::string transformedAppIdKey = GenerateAppRunningRuleCacheKey(transformedAppId, userId, appIndex);
    DeleteAbilityRunningRuleCache({ appIdKey, transformedAppIdKey});
    commonEventMgr_->NotifyDeleteDisposedRule(appId, userId, appIndex);
    return ERR_OK;
}

ErrCode AppControlManager::DeleteAllDisposedRuleByBundle(const InnerBundleInfo &bundleInfo, int32_t appIndex,
    int32_t userId)
{
    std::string appIdentifier = bundleInfo.GetAppIdentifier();
    std::string appId = bundleInfo.GetAppId();
    if (appControlManagerDb_ == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "appControlManagerDb is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    auto ret = appControlManagerDb_->DeleteAllDisposedRuleByBundle({ appId, appIdentifier }, appIndex, userId);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "rdb delete failed ret:%{public}d, appId:%{private}s", ret, appId.c_str());
        return ret;
    }
    std::string key = appId + std::string("_") + std::to_string(userId);
    DeleteAppRunningRuleCache(key);
    key = key + std::string("_");
    std::string cacheKey = key + std::to_string(appIndex);
    DeleteAbilityRunningRuleCache({ cacheKey });
    commonEventMgr_->NotifyDeleteDisposedRule(appId, userId, appIndex);
    if (appIndex != Constants::MAIN_APP_INDEX) {
        return ERR_OK;
    }
    // if appIndex is main app clear all clone app cache
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    std::string bundleName = bundleInfo.GetBundleName();
    std::vector<int32_t> appIndexVec = dataMgr->GetCloneAppIndexes(bundleName, Constants::ALL_USERID);
    for (const int32_t index : appIndexVec) {
        std::string ruleCacheKey = key + std::to_string(index);
        DeleteAbilityRunningRuleCache({ ruleCacheKey });
        commonEventMgr_->NotifyDeleteDisposedRule(appId, userId, index);
    }
    return ERR_OK;
}

void AppControlManager::DeleteAppRunningRuleCache(std::string &key)
{
    std::lock_guard<std::mutex> lock(appRunningControlMutex_);
    auto iter = appRunningControlRuleResult_.find(key);
    if (iter != appRunningControlRuleResult_.end()) {
        appRunningControlRuleResult_.erase(iter);
    }
}

bool AppControlManager::GetAbilityRunningRuleCache(const std::string &key, std::vector<DisposedRule> &disposedRules)
{
    std::lock_guard<std::mutex> lock(abilityRunningControlRuleMutex_);
    auto iter = abilityRunningControlRuleCache_.find(key);
    if (iter != abilityRunningControlRuleCache_.end()) {
        disposedRules = iter->second;
        return true;
    }
    return false;
}

void AppControlManager::SetAbilityRunningRuleCache(const std::string &key,
    const std::vector<DisposedRule> &disposedRules)
{
    std::lock_guard<std::mutex> cacheLock(abilityRunningControlRuleMutex_);
    abilityRunningControlRuleCache_[key] = disposedRules;
}

void AppControlManager::DeleteAbilityRunningRuleCache(const std::vector<std::string> &keyList)
{
    for (const std::string &key : keyList) {
        std::lock_guard<std::mutex> cacheLock(abilityRunningControlRuleMutex_);
        auto cacheIter = abilityRunningControlRuleCache_.find(key);
        if (cacheIter != abilityRunningControlRuleCache_.end()) {
            abilityRunningControlRuleCache_.erase(cacheIter);
        }
    }
}
ErrCode AppControlManager::GetAbilityRunningControlRule(
    const std::string &bundleName, int32_t appIndex, int32_t userId, std::vector<DisposedRule> &disposedRules)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    std::string appId;
    std::string appIdentifier;
    ErrCode ret = dataMgr->GetAppIdAndAppIdentifierByBundleName(bundleName, appId, appIdentifier);
    if (ret != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT, "DataMgr GetBundleInfoAppId failed");
        return ret;
    }
    std::string key = GenerateAppRunningRuleCacheKey(appId, userId, appIndex);
    bool findCache = GetAbilityRunningRuleCache(key, disposedRules);
    if (findCache) {
        PrintDisposedRuleInfo(disposedRules, appId);
        return ERR_OK;
    }
    std::vector<std::string> appIdList;
    if (!appId.empty()) {
        appIdList.emplace_back(appId);
    }
    if (!appIdentifier.empty()) {
        appIdList.emplace_back(appIdentifier);
    }
    ret = appControlManagerDb_->GetAbilityRunningControlRule(appIdList, appIndex, userId, disposedRules);
    if (ret != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT, "GetAbilityRunningControlRule from rdb failed");
        return ret;
    }
    if (GetDisposedRuleOnlyForBms(appId, disposedRules)) {
        LOG_I(BMS_TAG_DEFAULT, "find from bms cache -n %{public}s", bundleName.c_str());
    };
    SetAbilityRunningRuleCache(key, disposedRules);
    PrintDisposedRuleInfo(disposedRules, appId);
    return ret;
}

bool AppControlManager::CheckCanDispose(const std::string &appId, int32_t userId)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return false;
    }
    for (const auto &bundleName : noControllingList_) {
        BundleInfo bundleInfo;
        ErrCode ret = dataMgr->GetBundleInfoV9(bundleName,
            static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE), bundleInfo, userId);
        if (ret != ERR_OK) {
            continue;
        }
        if (appId == bundleInfo.appId) {
            return false;
        }
    }
    return true;
}

bool AppControlManager::GetDisposedRuleOnlyForBms(const std::string &appId, std::vector<DisposedRule> &disposedRules)
{
    std::lock_guard<std::mutex> lock(abilityRunningControlRuleMutex_);
    auto iterBms = abilityRunningControlRuleCacheForBms_.find(appId);
    if (iterBms != abilityRunningControlRuleCacheForBms_.end()) {
        disposedRules.emplace_back(iterBms->second);
        return true;
    };
    return false;
}

void AppControlManager::SetDisposedRuleOnlyForBms(const std::string &appId)
{
    std::lock_guard<std::mutex> lock(abilityRunningControlRuleMutex_);
    for (auto iter = abilityRunningControlRuleCache_.begin(); iter != abilityRunningControlRuleCache_.end();) {
        if (iter->first.find(appId) == 0) {
            iter = abilityRunningControlRuleCache_.erase(iter);
        } else {
            ++iter;
        }
    }

    DisposedRule disposedRule;
    disposedRule.componentType = ComponentType::UI_ABILITY;
    disposedRule.disposedType = DisposedType::BLOCK_APPLICATION;
    disposedRule.controlType = ControlType::DISALLOWED_LIST;
    abilityRunningControlRuleCacheForBms_[appId] = disposedRule;
}

void AppControlManager::DeleteDisposedRuleOnlyForBms(const std::string &appId)
{
    std::lock_guard<std::mutex> lock(abilityRunningControlRuleMutex_);
    for (auto iter = abilityRunningControlRuleCache_.begin(); iter != abilityRunningControlRuleCache_.end();) {
        if (iter->first.find(appId) == 0) {
            iter = abilityRunningControlRuleCache_.erase(iter);
        } else {
            ++iter;
        }
    }

    auto iterBms = abilityRunningControlRuleCacheForBms_.find(appId);
    if (iterBms != abilityRunningControlRuleCacheForBms_.end()) {
        abilityRunningControlRuleCacheForBms_.erase(iterBms);
    }
}

ErrCode AppControlManager::SetUninstallDisposedRule(const std::string &callerName, const std::string &appIdentifier,
    const UninstallDisposedRule& rule, int32_t appIndex, int32_t userId)
{
    auto ret = appControlManagerDb_->SetUninstallDisposedRule(callerName, appIdentifier, rule, appIndex, userId);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "set to rdb failed");
        return ret;
    }
    LOG_I(BMS_TAG_DEFAULT, "%{public}s set uninstall rule, user:%{public}d index:%{public}d",
        callerName.c_str(), userId, appIndex);
    return ERR_OK;
}

ErrCode AppControlManager::GetUninstallDisposedRule(const std::string &appIdentifier, int32_t appIndex,
    int32_t userId, UninstallDisposedRule& rule)
{
    auto ret = appControlManagerDb_->GetUninstallDisposedRule(appIdentifier, appIndex, userId, rule);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "get from rdb failed");
        return ret;
    }
    return ERR_OK;
}

ErrCode AppControlManager::DeleteUninstallDisposedRule(
    const std::string &callerName, const std::string &appIdentifier, int32_t appIndex, int32_t userId)
{
    auto ret = appControlManagerDb_->DeleteUninstallDisposedRule(callerName, appIdentifier, appIndex, userId);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "delete from rdb failed");
        return ret;
    }
    return ERR_OK;
}

void AppControlManager::PrintDisposedRuleInfo(const std::vector<DisposedRule> &disposedRules, const std::string &key)
{
    if (key.find(ATOMIC_SERVICE) != std::string::npos) {
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "get rule by %{public}s", key.c_str());
    }
    for (const auto &rule : disposedRules) {
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "control rule caller:%{public}s time:%{public}" PRId64,
        rule.callerName.c_str(), rule.setTime);
    }
}

std::string AppControlManager::GenerateAppRunningRuleCacheKey(
    const std::string &appId, int32_t userId, int32_t appIndex)
{
    return appId + std::string("_") + std::to_string(userId) + std::string("_") + std::to_string(appIndex);
}
}
}