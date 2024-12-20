/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_CONTROL_MANAGER_HOST_IMPL_H
#define FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_CONTROL_MANAGER_HOST_IMPL_H

#include "app_control_host.h"
#include "app_control_manager.h"
#include "bundle_data_mgr.h"

namespace OHOS {
namespace AppExecFwk {
class AppControlManagerHostImpl : public OHOS::AppExecFwk::AppControlHost {
public:
    AppControlManagerHostImpl();
    virtual ~AppControlManagerHostImpl();

    virtual ErrCode AddAppInstallControlRule(const std::vector<std::string> &appIds,
        const AppInstallControlRuleType controlRuleType, int32_t userId) override;

    virtual ErrCode DeleteAppInstallControlRule(const AppInstallControlRuleType controlRuleType,
        const std::vector<std::string> &appIds, int32_t userId) override;

    virtual ErrCode DeleteAppInstallControlRule(
        const AppInstallControlRuleType controlRuleType, int32_t userId) override;

    virtual ErrCode GetAppInstallControlRule(const AppInstallControlRuleType controlRuleType, int32_t userId,
        std::vector<std::string> &appIds) override;

    // for app running control rule
    virtual ErrCode AddAppRunningControlRule(
        const std::vector<AppRunningControlRule> &controlRules, int32_t userId) override;
    virtual ErrCode DeleteAppRunningControlRule(
        const std::vector<AppRunningControlRule> &controlRules, int32_t userId) override;
    virtual ErrCode DeleteAppRunningControlRule(int32_t userId) override;
    virtual ErrCode GetAppRunningControlRule(int32_t userId, std::vector<std::string> &appIds) override;
    virtual ErrCode GetAppRunningControlRule(
        const std::string &bundleName, int32_t userId, AppRunningControlRuleResult &controlRule) override;

    // for app jump control rule
    virtual ErrCode ConfirmAppJumpControlRule(const std::string &callerBundleName, const std::string &targetBundleName,
        int32_t userId) override;
    virtual ErrCode AddAppJumpControlRule(const std::vector<AppJumpControlRule> &controlRules, int32_t userId) override;
    virtual ErrCode DeleteAppJumpControlRule(const std::vector<AppJumpControlRule> &controlRules,
        int32_t userId) override;
    virtual ErrCode DeleteRuleByCallerBundleName(const std::string &callerBundleName, int32_t userId) override;
    virtual ErrCode DeleteRuleByTargetBundleName(const std::string &targetBundleName, int32_t userId) override;
    virtual ErrCode GetAppJumpControlRule(const std::string &callerBundleName, const std::string &targetBundleName,
        int32_t userId, AppJumpControlRule &controlRule) override;

    virtual ErrCode SetDisposedStatus(
        const std::string &appId, const Want &want, int32_t userId) override;

    virtual ErrCode DeleteDisposedStatus(
        const std::string &appId, int32_t userId) override;

    virtual ErrCode GetDisposedStatus(
        const std::string &appId, Want &want, int32_t userId) override;

    virtual ErrCode SetDisposedRule(
        const std::string &appId, DisposedRule &DisposedRule, int32_t userId) override;

    virtual ErrCode GetDisposedRule(
        const std::string &appId, DisposedRule &DisposedRule, int32_t userId) override;

    virtual ErrCode GetAbilityRunningControlRule(const std::string &bundleName, int32_t userId,
        std::vector<DisposedRule>& disposedRules, int32_t appIndex = Constants::MAIN_APP_INDEX) override;
    
    virtual ErrCode SetDisposedRuleForCloneApp(
        const std::string &appId, DisposedRule &DisposedRule, int32_t appIndex, int32_t userId) override;

    virtual ErrCode GetDisposedRuleForCloneApp(
        const std::string &appId, DisposedRule &DisposedRule, int32_t appIndex, int32_t userId) override;

    virtual ErrCode DeleteDisposedRuleForCloneApp(
        const std::string &appId, int32_t appIndex, int32_t userId) override;
    
    virtual ErrCode GetUninstallDisposedRule(const std::string &appIdentifier, int32_t appIndex,
        int32_t userId, UninstallDisposedRule &rule) override;
    
    virtual ErrCode SetUninstallDisposedRule(const std::string &appIdentifier, const UninstallDisposedRule &rule,
        int32_t appIndex, int32_t userId) override;
    
    virtual ErrCode DeleteUninstallDisposedRule(const std::string &appIdentifier, int32_t appIndex,
        int32_t userId) override;

private:
    int32_t GetCallingUserId();
    std::string GetCallingName();
    std::string GetControlRuleType(const AppInstallControlRuleType controlRuleType);
    void UpdateAppControlledInfo(int32_t userId, const std::vector<std::string> &modifyAppIds) const;
    void GetCallerByUid(const int32_t uid, std::string &callerName);

    std::shared_ptr<AppControlManager> appControlManager_ = nullptr;
    std::shared_ptr<BundleDataMgr> dataMgr_ = nullptr;
    std::unordered_map<int32_t, std::string> callingNameMap_;
    std::unordered_map<AppInstallControlRuleType, std::string> ruleTypeMap_;
};
}
}
#endif // FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_CONTROL_MANAGER_HOST_IMPL_H
