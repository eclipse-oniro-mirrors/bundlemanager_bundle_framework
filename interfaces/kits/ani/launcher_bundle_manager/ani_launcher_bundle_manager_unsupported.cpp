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
#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "business_error_ani.h"
#include "common_func.h"

namespace OHOS {
namespace AppExecFwk {
namespace  {
constexpr const char* START_SHORTCUT = "StartShortcut";
constexpr const char* GET_SHORTCUT_INFO_SYNC = "GetShortcutInfoSync";
constexpr const char* GET_LAUNCHER_ABILITY_INFO_SYNC = "GetLauncherAbilityInfoSync";
constexpr const char* GET_ALL_LAUNCHER_ABILITY_INFO = "GetAllLauncherAbilityInfo";
}

static void StartShortcut([[maybe_unused]] ani_env *env, ani_object aniShortcutInfo)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Launcher not supported");
    BusinessErrorAni::ThrowParameterTypeError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, START_SHORTCUT, "");
    return nullptr;
}

static ani_object GetShortcutInfoSync([[maybe_unused]] ani_env *env, ani_string aniBundleName, ani_double aniUserId)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Launcher not supported");
    BusinessErrorAni::ThrowParameterTypeError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_SHORTCUT_INFO_SYNC, "");
    return nullptr;
}

static ani_object GetLauncherAbilityInfoSync([[maybe_unused]] ani_env *env,
    ani_string aniBundleName, ani_double aniUserId)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Launcher not supported");
    BusinessErrorAni::ThrowParameterTypeError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_LAUNCHER_ABILITY_INFO_SYNC, "");
    return nullptr;
}

static ani_object GetAllLauncherAbilityInfo([[maybe_unused]] ani_env *env, ani_double aniUserId)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Launcher not supported");
    BusinessErrorAni::ThrowParameterTypeError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_ALL_LAUNCHER_ABILITY_INFO, "");
    return nullptr;
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    APP_LOGI("ANI_Constructor called");
    ani_env* env;
    if (vm == nullptr) {
        APP_LOGE("ANI_Constructor vm is nullptr");
        return static_cast<ani_status>(ANI_CONSTRUCTOR_ENV_ERR);
    }
    if (vm->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        APP_LOGE("Unsupported ANI_VERSION_1");
        return static_cast<ani_status>(ANI_CONSTRUCTOR_ENV_ERR);
    }
    if (env == nullptr) {
        APP_LOGE("ANI_Constructor env is nullptr");
        return static_cast<ani_status>(ANI_CONSTRUCTOR_ENV_ERR);
    }
    static const char* nsName = "L@ohos/bundle/launcherBundleManager/launcherBundleManager;";
    ani_namespace kitNs;
    if (env->FindNamespace(nsName, &kitNs) != ANI_OK) {
        APP_LOGE("Not found nameSpace name: %{public}s", nsName);
        return static_cast<ani_status>(ANI_CONSTRUCTOR_FIND_NAMESPACE_ERR);
    }

    std::array methods = {
        ani_native_function {
            "StartShortcutSync",
            "LbundleManager/ShortcutInfo/ShortcutInfo;:V",
            reinterpret_cast<void*>(StartShortcutSync)
        },
        ani_native_function {
            "GetShortcutInfoSync",
            "Lstd/core/String;D:Lescompat/Array;",
            reinterpret_cast<void*>(GetShortcutInfoSync)
        },
        ani_native_function {
            "GetLauncherAbilityInfoSync",
            "Lstd/core/String;D:Lescompat/Array;",
            reinterpret_cast<void*>(GetLauncherAbilityInfoSync)
        },
        ani_native_function {
            "GetAllLauncherAbilityInfo",
            "D:Lescompat/Array;",
            reinterpret_cast<void*>(GetAllLauncherAbilityInfo)
        },
    };

    if (env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size()) != ANI_OK) {
        APP_LOGE("Cannot bind native methods to %{public}s", nsName);
        return static_cast<ani_status>(ANI_CONSTRUCTOR_BIND_NATIVE_FUNC_ERR);
    };

    *result = ANI_VERSION_1;
    APP_LOGI("ANI_Constructor finished");
    return ANI_OK;
}
} // extern "C"
} // AppExecFwk
} // OHOS