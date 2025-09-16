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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_CONTROL_MANAGER_H
#define FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_CONTROL_MANAGER_H

#include <mutex>
#include <unordered_map>

#include "app_control_manager_db_interface.h"
#include "app_jump_interceptor_manager_db_interface.h"
#include "bundle_common_event_mgr.h"
#include "singleton.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
class AppControlManager : public DelayedSingleton<AppControlManager> {
public:
    using Want = OHOS::AAFwk::Want;
    enum RunningRuleSettingStatus : int32_t {
        NO_SET,
        BLACK_LIST,
        WHITE_LIST,
    };

    AppControlManager();
    ~AppControlManager();

    ErrCode AddAppInstallControlRule(const std::string &callingName,
        const std::vector<std::string> &appIds, const std::string &controlRuleType, int32_t userId);

    ErrCode DeleteAppInstallControlRule(const std::string &callingName, const std::string &controlRuleType,
        const std::vector<std::string> &appIds, int32_t userId);

    ErrCode DeleteAppInstallControlRule(const std::string &callingName,
        const std::string &controlRuleType, int32_t userId);

    ErrCode GetAppInstallControlRule(const std::string &callingName,
        const std::string &controlRuleType, int32_t userId, std::vector<std::string> &appIds);

    ErrCode AddAppRunningControlRule(const std::string &callingName,
        const std::vector<AppRunningControlRule> &controlRules, int32_t userId);
    ErrCode DeleteAppRunningControlRule(const std::string &callingName,
        const std::vector<AppRunningControlRule> &controlRules, int32_t userId);
    ErrCode DeleteAppRunningControlRule(const std::string &callingName, int32_t userId);
    ErrCode GetAppRunningControlRule(
        const std::string &callingName, int32_t userId, std::vector<std::string> &appIds, bool &allowRunning);
    ErrCode GetAppRunningControlRule(
        const std::string &bundleName, int32_t userId, AppRunningControlRuleResult &controlRule);

    ErrCode ConfirmAppJumpControlRule(const std::string &callerBundleName, const std::string &targetBundleName,
        int32_t userId);
    ErrCode AddAppJumpControlRule(const std::vector<AppJumpControlRule> &controlRules, int32_t userId);
    ErrCode DeleteAppJumpControlRule(const std::vector<AppJumpControlRule> &controlRules, int32_t userId);
    ErrCode DeleteRuleByCallerBundleName(const std::string &callerBundleName, int32_t userId);
    ErrCode DeleteRuleByTargetBundleName(const std::string &targetBundleName, int32_t userId);
    ErrCode GetAppJumpControlRule(const std::string &callerBundleName, const std::string &targetBundleName,
        int32_t userId, AppJumpControlRule &controlRule);

    ErrCode SetDisposedStatus(const std::string &appId, const Want& want, int32_t userId);

    ErrCode DeleteDisposedStatus(const std::string &appId, int32_t userId);

    ErrCode GetDisposedStatus(const std::string &appId, Want& want, int32_t userId);

    bool IsAppInstallControlEnabled() const;

    void SetAppInstallControlStatus();

    ErrCode SetDisposedRule(const std::string &callerName, const std::string &appId,
        const DisposedRule &DisposedRule, int32_t appIndex, int32_t userId);

    ErrCode GetDisposedRule(const std::string &callerName, const std::string &appId,
        DisposedRule &DisposedRule, int32_t appIndex, int32_t userId);
    
    ErrCode GetDisposedRules(const std::string &callingName,
        int32_t userId, std::vector<DisposedRuleConfiguration> &disposedRuleConfigurations);

    ErrCode DeleteDisposedRule(const std::string &callerName, const std::string &appId,
        int32_t appIndex, int32_t userId);

    ErrCode GetAbilityRunningControlRule(const std::string &bundleName, int32_t appIndex, int32_t userId,
        std::vector<DisposedRule>& disposedRules);

    ErrCode DeleteAllDisposedRuleByBundle(const InnerBundleInfo &bundleInfo, int32_t appIndex, int32_t userId);

    void SetDisposedRuleOnlyForBms(const std::string &appId);

    void DeleteDisposedRuleOnlyForBms(const std::string &appId);

    ErrCode SetUninstallDisposedRule(const std::string &callerName, const std::string &appIdentifier,
        const UninstallDisposedRule& rule, int32_t appIndex, int32_t userId);

    ErrCode GetUninstallDisposedRule(const std::string &appIdentifier, int32_t appIndex,
        int32_t userId, UninstallDisposedRule& rule);

    ErrCode DeleteUninstallDisposedRule(const std::string &callerName, const std::string &appIdentifier,
        int32_t appIndex, int32_t userId);

private:
    void KillRunningApp(const std::vector<AppRunningControlRule> &rules, int32_t userId) const;
    ErrCode KillRunningAppOutWhiteList(const std::vector<AppRunningControlRule> &rules, int32_t userId) const;
    void DeleteAppRunningRuleCache(std::string &key);
    bool GetAbilityRunningRuleCache(const std::string &key, std::vector<DisposedRule> &disposedRules);
    void SetAbilityRunningRuleCache(const std::string &key, const std::vector<DisposedRule> &disposedRules);
    void DeleteAbilityRunningRuleCache(const std::vector<std::string> &keyList);
    bool GetDisposedRuleOnlyForBms(const std::string &appId, std::vector<DisposedRule> &disposedRules);
    void DeleteAbilityRunningRuleBmsCache(const std::string &appId);
    bool CheckCanDispose(const std::string &appId, int32_t userId);
    void PrintDisposedRuleInfo(const std::vector<DisposedRule> &disposedRules, const std::string &key);
    std::string GenerateAppRunningRuleCacheKey(const std::string &appId, int32_t userId, int32_t appIndex);
    ErrCode GenerateRunningRuleSettingStatusMap();
    ErrCode CheckControlRules(const std::vector<AppRunningControlRule> &controlRules, int32_t userId);
    void SetRunningRuleSettingStatusByUserId(int32_t userId, RunningRuleSettingStatus runningRuleSettingStatus);
    RunningRuleSettingStatus GetRunningRuleSettingStatusByUserId(int32_t userId);
    void SetAppRunningControlRuleCache(const std::string &key, AppRunningControlRuleResult controlRuleResult);
    bool GetAppRunningControlRuleCache(const std::string &key, AppRunningControlRuleResult &controlRuleResult);
    void DeleteAppRunningControlRuleCache(const std::string &key);
    void DeleteAppRunningControlRuleCacheForUserId(int32_t userId);
    void DeleteRunningRuleSettingStatusCache(int32_t userId);
    ErrCode CheckAppControlRuleIntercept(const std::string &bundleName,
        int32_t userId, bool isSuccess, AppRunningControlRuleResult &controlRuleResult);

    bool isAppInstallControlEnabled_ = false;
    std::mutex appRunningControlMutex_;
    std::mutex abilityRunningControlRuleMutex_;
    std::mutex runningRuleSettingStatusMutex_;
    std::shared_ptr<IAppControlManagerDb> appControlManagerDb_;
    std::shared_ptr<IAppJumpInterceptorlManagerDb> appJumpInterceptorManagerDb_;
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr_;
    std::unordered_map<std::string, AppRunningControlRuleResult> appRunningControlRuleResult_;
    std::unordered_map<std::string, std::vector<DisposedRule>> abilityRunningControlRuleCache_;
    std::unordered_map<std::string, DisposedRule> abilityRunningControlRuleCacheForBms_;
    std::vector<std::string> noControllingList_;
    std::unordered_map<int32_t, AppControlManager::RunningRuleSettingStatus> runningRuleSettingStatusMap_;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_CONTROL_MANAGER_H
