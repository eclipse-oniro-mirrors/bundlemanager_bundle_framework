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
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* NS_NAME_APPCONTROL = "@ohos.bundle.appControl.appControl";
} // namespace

static void SetDisposedStatusSync(ani_env* env, ani_string aniAppId, ani_object aniWant)
{
    APP_LOGI("AppControl not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, SET_DISPOSED_STATUS, "");
}

static ani_object GetDisposedStatusSync(ani_env* env, ani_string aniAppId)
{
    APP_LOGI("AppControl not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_DISPOSED_STATUS, "");
    return nullptr;
}

static void DeleteDisposedStatusSync(ani_env* env, ani_string aniAppId, ani_double aniAppIndex)
{
    APP_LOGI("AppControl not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, DELETE_DISPOSED_STATUS, "");
}

static ani_object GetDisposedRule(ani_env* env, ani_string aniAppId, ani_double aniAppIndex)
{
    APP_LOGI("AppControl not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_DISPOSED_STATUS_SYNC, "");
    return nullptr;
}

static void SetDisposedRule(ani_env* env, ani_string aniAppId, ani_object aniRule, ani_double aniAppIndex)
{
    APP_LOGI("AppControl not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, SET_DISPOSED_STATUS_SYNC, "");
}

static void SetUninstallDisposedRule(ani_env* env,
    ani_string aniAppIdentifier, ani_object aniRule, ani_double aniAppIndex)
{
    APP_LOGI("AppControl not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, SET_UNINSTALL_DISPOSED_RULE, "");
}

static ani_object GetUninstallDisposedRule(ani_env* env, ani_string aniAppIdentifier, ani_double aniAppIndex)
{
    APP_LOGI("AppControl not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_UNINSTALL_DISPOSED_RULE, "");
    return nullptr;
}

static void DeleteUninstallDisposedRule(ani_env* env, ani_string aniAppIdentifier, ani_double aniAppIndex)
{
    APP_LOGI("AppControl not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, DELETE_UNINSTALL_DISPOSED_RULE, "");
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor appControl called");
    ani_env* env;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(status, "Unsupported ANI_VERSION_1");

    arkts::ani_signature::Namespace freeInstallNS =
        arkts::ani_signature::Builder::BuildNamespace(NS_NAME_APPCONTROL);
    ani_namespace kitNs = nullptr;
    status = env->FindNamespace(freeInstallNS.Descriptor().c_str(), &kitNs);
    if (status != ANI_OK) {
        APP_LOGE("FindNamespace: %{public}s fail with %{public}d", NS_NAME_APPCONTROL, status);
        return status;
    }

    std::array methods = {
        ani_native_function { "setDisposedStatusSync", nullptr, reinterpret_cast<void*>(SetDisposedStatusSync) },
        ani_native_function { "getDisposedStatusSync", nullptr, reinterpret_cast<void*>(GetDisposedStatusSync) },
        ani_native_function { "deleteDisposedStatusSyncNative", nullptr,
            reinterpret_cast<void*>(DeleteDisposedStatusSync) },
        ani_native_function { "getDisposedRuleNative", nullptr, reinterpret_cast<void*>(GetDisposedRule) },
        ani_native_function { "setDisposedRuleNative", nullptr, reinterpret_cast<void*>(SetDisposedRule) },
        ani_native_function { "setUninstallDisposedRuleNative", nullptr,
            reinterpret_cast<void*>(SetUninstallDisposedRule) },
        ani_native_function { "getUninstallDisposedRuleNative", nullptr,
            reinterpret_cast<void*>(GetUninstallDisposedRule) },
        ani_native_function { "deleteUninstallDisposedRuleNative", nullptr,
            reinterpret_cast<void*>(DeleteUninstallDisposedRule) }
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