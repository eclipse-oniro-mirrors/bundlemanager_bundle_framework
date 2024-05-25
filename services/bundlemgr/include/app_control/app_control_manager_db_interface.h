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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_CONTROL_MANAGER_DB_INTERFACE_H
#define FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_CONTROL_MANAGER_DB_INTERFACE_H

#include <string>
#include <vector>

#include "app_control_interface.h"
#include "app_running_control_rule.h"

namespace OHOS {
namespace AppExecFwk {
class IAppControlManagerDb {
public:
    using Want = OHOS::AAFwk::Want;

    IAppControlManagerDb() = default;
    virtual ~IAppControlManagerDb() = default;

    virtual ErrCode AddAppInstallControlRule(const std::string &callingName,
        const std::vector<std::string> &appIds, const std::string &controlRuleType, int32_t userId) = 0;
    virtual ErrCode DeleteAppInstallControlRule(const std::string &callingName, const std::string &controlRuleType,
        const std::vector<std::string> &appIds, int32_t userId) = 0;
    virtual ErrCode DeleteAppInstallControlRule(const std::string &callingName,
        const std::string &controlRuleType, int32_t userId) = 0;
    virtual ErrCode GetAppInstallControlRule(const std::string &callingName,
        const std::string &controlRuleType, int32_t userId, std::vector<std::string> &appIds) = 0;
    virtual ErrCode AddAppRunningControlRule(const std::string &callingName,
        const std::vector<AppRunningControlRule> &controlRules, int32_t userId) = 0;
    virtual ErrCode DeleteAppRunningControlRule(const std::string &callingName,
        const std::vector<AppRunningControlRule> &controlRules, int32_t userId) = 0;
    virtual ErrCode DeleteAppRunningControlRule(const std::string &callingName, int32_t userId) = 0;
    virtual ErrCode GetAppRunningControlRule(const std::string &callingName,
        int32_t userId, std::vector<std::string> &appIds) = 0;
    virtual ErrCode GetAppRunningControlRule(const std::string &appId,
        int32_t userId, AppRunningControlRuleResult &controlRuleResult) = 0;

    virtual ErrCode SetDisposedStatus(const std::string &callingName,
        const std::string &appId, const Want& want, int32_t userId) = 0;
    virtual ErrCode DeleteDisposedStatus(const std::string &callingName,
        const std::string &appId, int32_t userId) = 0;
    virtual ErrCode GetDisposedStatus(const std::string &callingNmae,
        const std::string &appId, Want& want, int32_t userId) = 0;
    virtual ErrCode SetDisposedRule(const std::string &callingName,
        const std::string &appId, const DisposedRule& rule, int32_t appIndex, int32_t userId) = 0;
    virtual ErrCode GetDisposedRule(const std::string &callingName,
        const std::string &appId, DisposedRule& rule, int32_t appIndex, int32_t userId) = 0;
    virtual ErrCode DeleteDisposedRule(const std::string &callingName,
        const std::string &appId, int32_t appIndex, int32_t userId) = 0;
    virtual ErrCode GetAbilityRunningControlRule(const std::string &bundleName, int32_t appIndex, int32_t userId,
        std::vector<DisposedRule>& disposedRules) = 0;
    virtual ErrCode DeleteAllDisposedRuleByBundle(const std::string &appId, int32_t appIndex, int32_t userId) = 0;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_CONTROL_MANAGER_DB_INTERFACE_H