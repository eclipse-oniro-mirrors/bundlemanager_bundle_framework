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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_I_APP_CONTROL_MGR_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_I_APP_CONTROL_MGR_H

#include <string>
#include <vector>

#include "app_running_control_rule_result.h"
#include "app_running_control_rule.h"
#include "iremote_broker.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
enum class AppInstallControlRuleType {
    UNSPECIFIED = 0,
    DISALLOWED_UNINSTALL,
    ALLOWED_INSTALL,
};

enum class AppRunControlRuleType {
    DISALLOWED_RUN = 10,
};

class IAppControlMgr : public IRemoteBroker {
public:
    using Want = OHOS::AAFwk::Want;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.bundleManager.appControl");

    virtual ErrCode AddAppInstallControlRule(const std::vector<std::string> &appIds,
        const AppInstallControlRuleType controlRuleType, int32_t userId) = 0;
    virtual ErrCode DeleteAppInstallControlRule(const AppInstallControlRuleType controlRuleType,
        const std::vector<std::string> &appIds, int32_t userId) = 0;
    virtual ErrCode DeleteAppInstallControlRule(const AppInstallControlRuleType controlRuleType, int32_t userId) = 0;
    virtual ErrCode GetAppInstallControlRule(
        const AppInstallControlRuleType controlRuleType, int32_t userId, std::vector<std::string> &appIds) = 0;
    
    virtual ErrCode AddAppRunningControlRule(
        const std::vector<AppRunningControlRule> &controlRules, int32_t userId) = 0;
    virtual ErrCode DeleteAppRunningControlRule(
        const std::vector<AppRunningControlRule> &controlRules, int32_t userId) = 0;
    virtual ErrCode DeleteAppRunningControlRule(int32_t userId) = 0;
    virtual ErrCode GetAppRunningControlRule(int32_t userId, std::vector<std::string> &appIds) = 0;
    virtual ErrCode GetAppRunningControlRule(
        const std::string &bundleName, int32_t userId, AppRunningControlRuleResult &controlRuleResult) = 0;

    virtual ErrCode SetDisposedStatus(const std::string &appId, const Want &want) = 0;
    virtual ErrCode DeleteDisposedStatus(const std::string &appId) = 0;
    virtual ErrCode GetDisposedStatus(const std::string &appId, Want &want) = 0;

    enum Message : uint32_t {
        ADD_APP_INSTALL_CONTROL_RULE = 0,
        DELETE_APP_INSTALL_CONTROL_RULE,
        CLEAN_APP_INSTALL_CONTROL_RULE,
        GET_APP_INSTALL_CONTROL_RULE,

        ADD_APP_RUNNING_CONTROL_RULE,
        DELETE_APP_RUNNING_CONTROL_RULE,
        CLEAN_APP_RUNNING_CONTROL_RULE,
        GET_APP_RUNNING_CONTROL_RULE,
        GET_APP_RUNNING_CONTROL_RULE_RESULT,
        SET_DISPOSED_STATUS,
        DELETE_DISPOSED_STATUS,
        GET_DISPOSED_STATUS,
    };
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_I_APP_CONTROL_MGR_H
