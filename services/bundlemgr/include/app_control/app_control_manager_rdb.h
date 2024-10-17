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
        int32_t userId, std::vector<std::string> &appIds) override;
    virtual ErrCode GetAppRunningControlRule(const std::string &appId,
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
    virtual ErrCode DeleteDisposedRule(const std::string &callingName,
        const std::string &appId, int32_t appIndex, int32_t userId) override;
    virtual ErrCode DeleteAllDisposedRuleByBundle(const std::string &appId, int32_t appIndex, int32_t userId) override;
    virtual ErrCode GetAbilityRunningControlRule(const std::string &bundleName, int32_t appIndex, int32_t userId,
        std::vector<DisposedRule>& disposedRules) override;

private:
    ErrCode DeleteOldControlRule(const std::string &callingName, const std::string &controlRuleType,
        const std::string &appId, int32_t userId);
    ErrCode OptimizeDisposedPredicates(const std::string &callingName, const std::string &appId,
        int32_t userId, int32_t appIndex, NativeRdb::AbsRdbPredicates &absRdbPredicates);
    void PrintDisposedRuleInfo(const std::shared_ptr<NativeRdb::AbsSharedResultSet> &absSharedResultSet,
        const DisposedRule &rule);
    std::shared_ptr<RdbDataManager> rdbDataManager_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_CONTROL_MANAGER_RDB_H