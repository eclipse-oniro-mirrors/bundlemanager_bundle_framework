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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_CONTROL_MANAGER_RDB_H
#define FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_CONTROL_MANAGER_RDB_H

#include "app_control_manager_db_interface.h"

#include "rdb_data_manager.h"

namespace OHOS {
namespace AppExecFwk {
class AppControlManagerRdb : public IAppControlManagerDb {
public:
    AppControlManagerRdb();
    ~AppControlManagerRdb();

    virtual ErrCode AddAppInstallControlRule(const std::string &callingName, const std::vector<std::string> &appIds,
        const std::string &controlRuleType, int32_t userId) override;
    virtual ErrCode DeleteAppInstallControlRule(const std::string &callingName, const std::string &controlRuleType,
        const std::vector<std::string> &appIds, int32_t userId) override;
    virtual ErrCode DeleteAppInstallControlRule(const std::string &callingName, const std::string &controlRuleType,
        int32_t userId) override;
    virtual ErrCode GetAppInstallControlRule(const std::string &callingName,
        const std::string &controlRuleType, int32_t userId, std::vector<std::string> &appIds) override;

    virtual ErrCode AddAppRunningControlRule(const std::string &callingName,
        const std::vector<AppRunningControlRule> &controlRules, int32_t userId) override;
    virtual ErrCode DeleteAppRunningControlRule(const std::string &callingName,
        const std::vector<AppRunningControlRule> &controlRules, int32_t userId) override;
    virtual ErrCode DeleteAppRunningControlRule(const std::string &callingName, int32_t userId) override;
    virtual ErrCode GetAppRunningControlRule(const std::string &callingName,
        int32_t userId, std::vector<std::string> &appIds, bool &allowRunning) override;
    virtual ErrCode GetAppRunningControlRule(const std::string &appIds,
        int32_t userId, AppRunningControlRuleResult &controlRuleResult) override;
    virtual ErrCode SetDisposedStatus(const std::string &callingName,
        const std::string &appId, const Want& want, int32_t userId) override;
    virtual ErrCode DeleteDisposedStatus(const std::string &callingName,
        const std::string &appId, int32_t userId) override;
    virtual ErrCode GetDisposedStatus(const std::string &callingName,
        const std::string &appId, Want& want, int32_t userId) override;
    virtual ErrCode SetDisposedRule(const std::string &callingName,
        const std::string &appId, const DisposedRule& rule, int32_t appIndex, int32_t userId) override;
    virtual ErrCode GetDisposedRule(const std::string &callingName,
        const std::string &appId, DisposedRule& rule, int32_t appIndex, int32_t userId) override;
    virtual ErrCode GetDisposedRules(const std::string &callingName,
        int32_t userId, std::vector<DisposedRuleConfiguration> &disposedRuleConfigurations) override;
    virtual ErrCode DeleteDisposedRule(const std::string &callingName,
        const std::vector<std::string> &appIdList, int32_t appIndex, int32_t userId) override;
    virtual ErrCode DeleteAllDisposedRuleByBundle(const std::vector<std::string> &appIdList,
        int32_t appIndex, int32_t userId) override;
    virtual ErrCode GetAbilityRunningControlRule(const std::vector<std::string> &appIdList, int32_t appIndex,
        int32_t userId, std::vector<DisposedRule>& disposedRules) override;
    
    virtual ErrCode SetUninstallDisposedRule(const std::string &callingName, const std::string &appIdentifier,
        const UninstallDisposedRule &rule, int32_t appIndex, int32_t userId) override;
    virtual ErrCode DeleteUninstallDisposedRule(const std::string &callingName, const std::string &appIdentifier,
        int32_t appIndex, int32_t userId) override;
    virtual ErrCode GetUninstallDisposedRule(const std::string &appIdentifier, int32_t appIndex,
        int32_t userId, UninstallDisposedRule &rule) override;
    virtual ErrCode GetAppRunningControlRuleByUserId(int32_t userId, std::string &appId,
        AppRunningControlRule &controlRuleResult) override;
    virtual ErrCode GetAllUserIdsForRunningControl(std::vector<int32_t> &outUserIds) override;
    virtual ErrCode GetAppIdsByUserId(int32_t userId, std::vector<std::string> &appIds) override;

private:
    ErrCode DeleteOldControlRule(const std::string &callingName, const std::string &controlRuleType,
        const std::string &appId, int32_t userId);
    ErrCode OptimizeDisposedPredicates(const std::string &callingName, const std::string &appId,
        int32_t userId, int32_t appIndex, NativeRdb::AbsRdbPredicates &absRdbPredicates);
    ErrCode GetDisposedRuleFromResultSet(
        std::shared_ptr<NativeRdb::ResultSet> absSharedResultSet, std::vector<DisposedRule> &disposedRules);
    ErrCode ConvertToDisposedRuleConfiguration(
        const std::shared_ptr<NativeRdb::ResultSet> &absSharedResultSet,
        DisposedRuleConfiguration &disposedRuleConfiguration);
    std::shared_ptr<RdbDataManager> rdbDataManager_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_CONTROL_MANAGER_RDB_H