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

#include <ani_signature_builder.h>

#include "app_control_interface.h"
#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* NS_NAME_APPCONTROL = "@ohos.bundle.appControl.appControl";
} // namespace

static void AniSetDisposedStatus(ani_env* env, ani_string aniAppId, ani_object aniWant, ani_boolean aniIsSync)
{
    APP_LOGI("AppControl not supported");
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        isSync ? SET_DISPOSED_STATUS_SYNC : SET_DISPOSED_STATUS, "");
}

static ani_object AniGetDisposedStatus(ani_env* env, ani_string aniAppId, ani_boolean aniIsSync)
{
    APP_LOGI("AppControl not supported");
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        isSync ? GET_DISPOSED_STATUS_SYNC : GET_DISPOSED_STATUS, "");
    return nullptr;
}

static void AniDeleteDisposedStatus(ani_env* env, ani_string aniAppId, ani_int aniAppIndex, ani_boolean aniIsSync)
{
    APP_LOGI("AppControl not supported");
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        isSync ? DELETE_DISPOSED_STATUS_SYNC : DELETE_DISPOSED_STATUS, "");
}

static ani_object AniGetDisposedRule(ani_env* env, ani_string aniAppId, ani_int aniAppIndex)
{
    APP_LOGI("AppControl not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_DISPOSED_STATUS_SYNC, "");
    return nullptr;
}

static ani_object AniGetAllDisposedRules(ani_env* env)
{
    APP_LOGI("AppControl not supported");
    BusinessErrorAni::ThrowCommonNewError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_ALL_DISPOSED_RULES, "");
    return nullptr;
}

static void AniSetDisposedRule(ani_env* env, ani_string aniAppId, ani_object aniRule, ani_int aniAppIndex)
{
    APP_LOGI("AppControl not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, SET_DISPOSED_STATUS_SYNC, "");
}

static void AniSetUninstallDisposedRule(ani_env* env,
    ani_string aniAppIdentifier, ani_object aniRule, ani_int aniAppIndex)
{
    APP_LOGI("AppControl not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, SET_UNINSTALL_DISPOSED_RULE, "");
}

static ani_object AniGetUninstallDisposedRule(ani_env* env, ani_string aniAppIdentifier, ani_int aniAppIndex)
{
    APP_LOGI("AppControl not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_UNINSTALL_DISPOSED_RULE, "");
    return nullptr;
}

static void AniDeleteUninstallDisposedRule(ani_env* env, ani_string aniAppIdentifier, ani_int aniAppIndex)
{
    APP_LOGI("AppControl not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, DELETE_UNINSTALL_DISPOSED_RULE, "");
}

static void SetDisposedRules(ani_env* env, ani_object aniDisposedRuleConfigurations)
{
    APP_LOGI("AppControl not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, SET_DISPOSED_RULES, "");
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor appControl called");
    ani_env* env;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(status, "Unsupported ANI_VERSION_1");

    arkts::ani_signature::Namespace nsName =
        arkts::ani_signature::Builder::BuildNamespace(NS_NAME_APPCONTROL);
    ani_namespace kitNs = nullptr;
    status = env->FindNamespace(nsName.Descriptor().c_str(), &kitNs);
    if (status != ANI_OK) {
        APP_LOGE("FindNamespace: %{public}s fail with %{public}d", NS_NAME_APPCONTROL, status);
        return status;
    }

    std::array methods = {
        ani_native_function { "setDisposedStatusNative", nullptr, reinterpret_cast<void*>(AniSetDisposedStatus) },
        ani_native_function { "getDisposedStatusNative", nullptr, reinterpret_cast<void*>(AniGetDisposedStatus) },
        ani_native_function { "deleteDisposedStatusNative", nullptr, reinterpret_cast<void*>(AniDeleteDisposedStatus) },
        ani_native_function { "getDisposedRuleNative", nullptr, reinterpret_cast<void*>(AniGetDisposedRule) },
        ani_native_function { "getAllDisposedRulesNative", nullptr, reinterpret_cast<void*>(AniGetAllDisposedRules) },
        ani_native_function { "setDisposedRuleNative", nullptr, reinterpret_cast<void*>(AniSetDisposedRule) },
        ani_native_function { "setUninstallDisposedRuleNative", nullptr,
            reinterpret_cast<void*>(AniSetUninstallDisposedRule) },
        ani_native_function { "getUninstallDisposedRuleNative", nullptr,
            reinterpret_cast<void*>(AniGetUninstallDisposedRule) },
        ani_native_function { "deleteUninstallDisposedRuleNative", nullptr,
            reinterpret_cast<void*>(AniDeleteUninstallDisposedRule) },
        ani_native_function { "setDisposedRules", nullptr, reinterpret_cast<void*>(SetDisposedRules) },
    };

    status = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    if (status != ANI_OK) {
        APP_LOGE("Namespace_BindNativeFunctions: %{public}s fail with %{public}d", NS_NAME_APPCONTROL, status);
        return status;
    }

    *result = ANI_VERSION_1;

    APP_LOGI("ANI_Constructor finished");

    return ANI_OK;
}
}
} // AppExecFwk
} // OHOS