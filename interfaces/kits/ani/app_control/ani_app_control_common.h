/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_APP_CONTROL_COMMON_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_APP_CONTROL_COMMON_H

#include <ani.h>
#include "disposed_rule.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;

class AniAppControlCommon {
public:
    static ani_object ConvertDisposedRule(ani_env* env, const DisposedRule& disposedRule);
    static ani_object ConvertDisposedRuleConfiguration(
        ani_env* env, const DisposedRuleConfiguration& disposedRuleConfiguration);
    static ani_object ConvertUninstallDisposedRule(ani_env* env, const UninstallDisposedRule& uninstallDisposedRule);
    static bool ParseWantWithoutVerification(ani_env* env, ani_object object, Want& want);
    static bool ParseDisposedRule(ani_env* env, ani_object object, DisposedRule& disposedRule);
    static bool ParseUninstallDisposedRule(ani_env* env,
        ani_object object, UninstallDisposedRule& uninstallDisposedRule);
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_APP_CONTROL_COMMON_H