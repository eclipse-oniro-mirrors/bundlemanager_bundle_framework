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

#include "inner_app_running_control_rule.h"

namespace OHOS {
namespace AppExecFwk {
InnerAppRunningControlRule::InnerAppRunningControlRule()
{
}

InnerAppRunningControlRule::InnerAppRunningControlRule(const AppRunningControlRuleParam &ruleParam,
    AppRunningControlRuleType ruleType) : ruleParam_(ruleParam), ruleType_(ruleType)
{
}

InnerAppRunningControlRule::~InnerAppRunningControlRule()
{
}

void InnerAppRunningControlRule::SetControlRuleParam(AppRunningControlRuleParam &ruleParam)
{
    ruleParam_ = ruleParam;
}

AppRunningControlRuleParam InnerAppRunningControlRule::GetControlRuleParam() const
{
    return ruleParam_;
}

void InnerAppRunningControlRule::SetControlRuleType(AppRunningControlRuleType ruleType)
{
    ruleType_ = ruleType;
}

AppRunningControlRuleType InnerAppRunningControlRule::GetControlRuleType() const
{
    return ruleType_;
}
}
}