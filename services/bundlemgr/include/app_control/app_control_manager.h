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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_CONTROL_MANAGER_H
#define FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_CONTROL_MANAGER_H

#include <unordered_map>

#include "app_control_manager_db_interface.h"
#include "singleton.h"

namespace OHOS {
namespace AppExecFwk {
class AppControlManager : public DelayedSingleton<AppControlManager> {
public:
    AppControlManager();
    ~AppControlManager();

    ErrCode AddAppInstallControlRule(const std::string &callingName,
        const std::vector<std::string> &appIds, const std::string &controlRuleType, int32_t userId);

    ErrCode DeleteAppInstallControlRule(const std::string &callingName,
        const std::vector<std::string> &appIds, int32_t userId);

    ErrCode DeleteAppInstallControlRule(const std::string &callingName,
        const std::string &controlRuleType, int32_t userId);

    ErrCode GetAppInstallControlRule(const std::string &callingName,
        const std::string &controlRuleType, int32_t userId, std::vector<std::string> &appIds);

    ErrCode AddAppRunningControlRule(const std::string &callingName,
        const std::vector<InnerAppRunningControlRule> &controlRule, int32_t userId);
    ErrCode DeleteAppRunningControlRule(const std::string &callingName,
        const std::vector<InnerAppRunningControlRule> &controlRule, int32_t userId);
    ErrCode DeleteAppRunningControlRule(const std::string &callingName, int32_t userId);
    ErrCode GetAppRunningControlRule(const std::string &callingName, int32_t userId, std::vector<std::string> &appIds);
private:
    std::shared_ptr<IAppControlManagerDb> appControlManagerDb_;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_APP_CONTROL_MANAGER_H
