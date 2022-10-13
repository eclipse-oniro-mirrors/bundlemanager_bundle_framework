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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_CONTROL_MANAGER_HOST_IMPL_H
#define FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_CONTROL_MANAGER_HOST_IMPL_H

#include "app_control_host.h"
#include "app_control_manager.h"

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

    virtual ErrCode SetDisposedStatus(const std::string &appId, const Want &want) override;

    virtual ErrCode DeleteDisposedStatus(const std::string &appId) override;

    virtual ErrCode GetDisposedStatus(const std::string &appId, Want &want) override;
private:
    int32_t GetCallingUserId();
    std::string GetCallingName();
    std::string GetControlRuleType(const AppInstallControlRuleType controlRuleType);
    std::unordered_map<int32_t, std::string> callingNameMap_;
    std::unordered_map<AppInstallControlRuleType, std::string> ruleTypeMap_;
    std::shared_ptr<AppControlManager> appControlManager_ = nullptr;
};
}
}
#endif // FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_CONTROL_MANAGER_HOST_IMPL_H
