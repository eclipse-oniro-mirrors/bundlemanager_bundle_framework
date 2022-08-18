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

#include "iremote_broker.h"

namespace OHOS {
namespace AppExecFwk {
enum class AppInstallControlRuleType {
    DISALLOWED_UNINSTALL = 0,
    DISALLOWED_INSTALL,
    ALLOWED_INSTALL,
    UNSPECIFIED,
};

class IAppControlMgr : public IRemoteBroker {
public:

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.bundleManager.appControl");

    virtual ErrCode AddAppInstallControlRule(const std::vector<std::string> &appIds,
        const AppInstallControlRuleType controlRuleType, int32_t userId) = 0;
    virtual ErrCode DeleteAppInstallControlRule(const std::vector<std::string> &appIds,
        int32_t userId) = 0;
    virtual ErrCode DeleteAppInstallControlRule(const AppInstallControlRuleType controlRuleType, int32_t userId) = 0;
    virtual ErrCode GetAppInstallControlRule(
        const AppInstallControlRuleType controlRuleType, int32_t userId, std::vector<std::string> &appIds) = 0;

    enum Message : uint32_t {
        ADD_APP_INSTALL_CONTROL_RULE = 0,
        DELETE_APP_INSTALL_CONTROL_RULE,
        CLEAN_APP_INSTALL_CONTROL_RULE,
        GET_APP_INSTALL_CONTROL_RULE,
    };
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_I_APP_CONTROL_MGR_H
