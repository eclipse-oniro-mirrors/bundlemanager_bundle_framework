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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_BUSINESS_ERROR_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_BUSINESS_ERROR_H

#include <ani.h>
#include "appexecfwk_errors.h"
#include "bundle_errors.h"

namespace OHOS {
namespace AppExecFwk {
class BusinessErrorAni {
public:
    static ani_object WrapError(ani_env *env, const std::string &msg);
    static ani_object CreateError(ani_env *env, int32_t code, const std::string &msg);
    static ani_object CreateCommonError(
        ani_env *env, int32_t err, const std::string &functionName = "", const std::string &permissionName = "");
    static ani_object CreateEnumError(ani_env *env, const std::string &parameter, const std::string &enumClass);
    static void ThrowTooFewParametersError(ani_env *env, int32_t err);
    static void ThrowCommonError(ani_env *env, int32_t err,
        const std::string &parameter, const std::string &type);
    static void ThrowEnumError(ani_env *env, const std::string &parameter, const std::string &type);
    static void ThrowError(ani_env *env, int32_t err, const std::string &msg = "");
private:
    static void ThrowError(ani_env *env, ani_object err);
};
} // namespace AppExecFwk
} // namespace OHOS
#endif