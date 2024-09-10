/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "appexecfwk_errors.h"
#include "app_jump_control_rule.h"
#include "app_running_control_rule_result.h"
#include "app_running_control_rule.h"
#include "bundle_constants.h"
#include "disposed_rule.h"
#include "iremote_broker.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
enum class AppInstallControlRuleType {
    UNSPECIFIED = 0,
    DISALLOWED_UNINSTALL,
    ALLOWED_INSTALL,
    DISALLOWED_INSTALL,
};

enum class AppRunControlRuleType {
    DISALLOWED_RUN = 10,
};

class IAppControlMgr : public IRemoteBroker {
public:
    using Want = OHOS::AAFwk::Want;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.bundleManager.appControl");

    virtual ErrCode AddAppInstallControlRule(const std::vector<std::string> &appIds,
        const AppInstallControlRuleType controlRuleType, int32_t userId)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode DeleteAppInstallControlRule(const AppInstallControlRuleType controlRuleType,
        const std::vector<std::string> &appIds, int32_t userId)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode DeleteAppInstallControlRule(const AppInstallControlRuleType controlRuleType, int32_t userId)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode GetAppInstallControlRule(
        const AppInstallControlRuleType controlRuleType, int32_t userId, std::vector<std::string> &appIds)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode AddAppRunningControlRule(
        const std::vector<AppRunningControlRule> &controlRules, int32_t userId)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode DeleteAppRunningControlRule(
        const std::vector<AppRunningControlRule> &controlRules, int32_t userId)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode DeleteAppRunningControlRule(int32_t userId)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode GetAppRunningControlRule(int32_t userId, std::vector<std::string> &appIds)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode GetAppRunningControlRule(
        const std::string &bundleName, int32_t userId, AppRunningControlRuleResult &controlRuleResult)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode ConfirmAppJumpControlRule(const std::string &callerBundleName, const std::string &targetBundleName,
        int32_t userId)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode AddAppJumpControlRule(const std::vector<AppJumpControlRule> &controlRules, int32_t userId)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode DeleteAppJumpControlRule(const std::vector<AppJumpControlRule> &controlRules, int32_t userId)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode DeleteRuleByCallerBundleName(const std::string &callerBundleName, int32_t userId)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode DeleteRuleByTargetBundleName(const std::string &targetBundleName, int32_t userId)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode GetAppJumpControlRule(const std::string &callerBundleName, const std::string &targetBundleName,
        int32_t userId, AppJumpControlRule &controlRule)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode SetDisposedStatus(
        const std::string &appId, const Want &want, int32_t userId = Constants::UNSPECIFIED_USERID)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode DeleteDisposedStatus(const std::string &appId, int32_t userId = Constants::UNSPECIFIED_USERID)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode GetDisposedStatus(
        const std::string &appId, Want &want, int32_t userId = Constants::UNSPECIFIED_USERID)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode GetDisposedRule(
        const std::string &appId, DisposedRule& disposedRule, int32_t userId = Constants::UNSPECIFIED_USERID)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode SetDisposedRule(
        const std::string &appId, DisposedRule& disposedRule, int32_t userId = Constants::UNSPECIFIED_USERID)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode GetAbilityRunningControlRule(const std::string &bundleName, int32_t userId,
        std::vector<DisposedRule>& disposedRules, int32_t appIndex = Constants::MAIN_APP_INDEX)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode GetDisposedRuleForCloneApp(const std::string &appId, DisposedRule& disposedRule,
        int32_t appIndex, int32_t userId = Constants::UNSPECIFIED_USERID)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode SetDisposedRuleForCloneApp(const std::string &appId, DisposedRule& disposedRule,
        int32_t appIndex, int32_t userId = Constants::UNSPECIFIED_USERID)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    virtual ErrCode DeleteDisposedRuleForCloneApp(const std::string &appId, int32_t appIndex,
        int32_t userId = Constants::UNSPECIFIED_USERID)
    {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_I_APP_CONTROL_MGR_H
