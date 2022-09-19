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
#ifndef FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_INNER_APP_RUNNING_CONTROL_RULE_H
#define FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_INNER_APP_RUNNING_CONTROL_RULE_H

#include <string>

#include "app_running_control_rule_param.h"
#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {

class InnerAppRunningControlRule {
public:
    InnerAppRunningControlRule();
    InnerAppRunningControlRule(const AppRunningControlRuleParam &ruleParam, AppRunningControlRuleType ruleType);
    ~InnerAppRunningControlRule();

    void SetControlRuleParam(AppRunningControlRuleParam &ruleParam);
    AppRunningControlRuleParam GetControlRuleParam() const;

    void SetControlRuleType(AppRunningControlRuleType ruleType);
    AppRunningControlRuleType GetControlRuleType() const;

private:
    AppRunningControlRuleParam ruleParam_;
    AppRunningControlRuleType ruleType_;
};

} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_INNER_APP_RUNNING_CONTROL_RULE_H