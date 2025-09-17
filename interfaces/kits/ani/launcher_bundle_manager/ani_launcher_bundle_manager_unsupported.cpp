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

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* NS_NAME_LAUNCHERMANAGER = "@ohos.bundle.launcherBundleManager.launcherBundleManager";
}

static void AniStartShortcut(ani_env *env, ani_object aniShortcutInfo, ani_object aniStartOptions)
{
    APP_LOGI("SystemCapability.BundleManager.BundleFramework.Launcher not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, START_SHORTCUT, "");
    return;
}

static ani_object AniGetShortcutInfo(ani_env *env,
    ani_string aniBundleName, ani_int aniUserId, ani_boolean aniIsSync)
{
    APP_LOGI("SystemCapability.BundleManager.BundleFramework.Launcher not supported");
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        isSync ? GET_SHORTCUT_INFO_SYNC : GET_SHORTCUT_INFO, "");
    return nullptr;
}

static ani_object AniGetLauncherAbilityInfo(ani_env *env,
    ani_string aniBundleName, ani_int aniUserId, ani_boolean aniIsSync)
{
    APP_LOGI("SystemCapability.BundleManager.BundleFramework.Launcher not supported");
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        isSync ? GET_LAUNCHER_ABILITY_INFO_SYNC : GET_LAUNCHER_ABILITY_INFO, "");
    return nullptr;
}

static ani_object AniGetAllLauncherAbilityInfo(ani_env *env, ani_int aniUserId)
{
    APP_LOGI("SystemCapability.BundleManager.BundleFramework.Launcher not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_ALL_LAUNCHER_ABILITY_INFO, "");
    return nullptr;
}

static ani_object GetShortcutInfoByAppIndex(ani_env* env, ani_string aniBundleName, ani_int aniAppIndex)
{
    APP_LOGI("SystemCapability.BundleManager.BundleFramework.Launcher not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_SHORTCUT_INFO_BY_APPINDEX, "");
    return nullptr;
}

static void StartShortcutWithReasonNative(
    ani_env* env, ani_object aniShortcutInfo, ani_string aniStartReason, ani_object aniStartOptions)
{
    APP_LOGI("SystemCapability.BundleManager.BundleFramework.Launcher not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, START_SHORTCUT_WITH_REASON, "");
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    APP_LOGI("ANI_Constructor launcherBundleManager called");
    ani_env* env;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(status, "Unsupported ANI_VERSION_1");

    arkts::ani_signature::Namespace nsName = arkts::ani_signature::Builder::BuildNamespace(NS_NAME_LAUNCHERMANAGER);
    ani_namespace kitNs = nullptr;
    status = env->FindNamespace(nsName.Descriptor().c_str(), &kitNs);
    if (status != ANI_OK) {
        APP_LOGE("FindNamespace: %{public}s fail with %{public}d", NS_NAME_LAUNCHERMANAGER, status);
        return status;
    }

    std::array methods = {
        ani_native_function { "startShortcutNative", nullptr, reinterpret_cast<void*>(AniStartShortcut) },
        ani_native_function { "getShortcutInfoNative", nullptr, reinterpret_cast<void*>(AniGetShortcutInfo) },
        ani_native_function { "getLauncherAbilityInfoNative", nullptr,
            reinterpret_cast<void*>(AniGetLauncherAbilityInfo) },
        ani_native_function { "getAllLauncherAbilityInfoNative", nullptr,
            reinterpret_cast<void*>(AniGetAllLauncherAbilityInfo) },
        ani_native_function { "getShortcutInfoByAppIndex", nullptr,
            reinterpret_cast<void*>(GetShortcutInfoByAppIndex) },
        ani_native_function { "startShortcutWithReasonNative", nullptr,
            reinterpret_cast<void*>(StartShortcutWithReasonNative) },
    };

    status = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    if (status != ANI_OK) {
        APP_LOGE("Namespace_BindNativeFunctions: %{public}s fail with %{public}d", NS_NAME_LAUNCHERMANAGER, status);
        return status;
    }

    *result = ANI_VERSION_1;

    APP_LOGI("ANI_Constructor finished");

    return ANI_OK;
}
} // extern "C"
} // AppExecFwk
} // OHOS