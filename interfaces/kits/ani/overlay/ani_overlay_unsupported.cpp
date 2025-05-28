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
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* NS_NAME_OVERLAY = "@ohos.bundle.overlay.overlay";
} // namespace

static void SetOverlayEnabled(ani_env *env, ani_string aniModuleName, ani_boolean aniIsEnabled)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Overlay not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, SET_OVERLAY_ENABLED, "");
    return;
}

static void SetOverlayEnabledByBundleName(ani_env *env,
    ani_string aniBundleName, ani_string aniModuleName, ani_boolean aniIsEnabled)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Overlay not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, SET_OVERLAY_ENABLED_BY_BUNDLE_NAME, "");
    return;
}

static ani_object GetOverlayModuleInfo(ani_env *env, ani_string aniModuleName)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Overlay not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_OVERLAY_MODULE_INFO, "");
    return nullptr;
}

static ani_object GetTargetOverlayModuleInfos(ani_env *env, ani_string aniTargetModuleName)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Overlay not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_TARGET_OVERLAY_MODULE_INFOS, "");
    return nullptr;
}

static ani_object GetOverlayModuleInfoByBundleName(ani_env *env, ani_string aniBundleName, ani_string aniModuleName)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Overlay not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_OVERLAY_MODULE_INFO_BY_BUNDLE_NAME, "");
    return nullptr;
}

static ani_object GetTargetOverlayModuleInfosByBundleName(ani_env *env,
    ani_string aniTargetBundleName, ani_string aniModuleName)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Overlay not supported");
    BusinessErrorAni::ThrowCommonError(
        env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_TARGET_OVERLAY_MODULE_INFOS_BY_BUNDLE_NAME, "");
    return nullptr;
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor overlay called");
    ani_env* env;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(status, "Unsupported ANI_VERSION_1");

    arkts::ani_signature::Namespace freeInstallNS = arkts::ani_signature::Builder::BuildNamespace(NS_NAME_OVERLAY);
    ani_namespace kitNs = nullptr;
    status = env->FindNamespace(freeInstallNS.Descriptor().c_str(), &kitNs);
    if (status != ANI_OK) {
        APP_LOGE("FindNamespace: %{public}s fail with %{public}d", NS_NAME_OVERLAY, status);
        return status;
    }

    std::array methods = {
        ani_native_function { "setOverlayEnabledNative", nullptr,
            reinterpret_cast<void*>(SetOverlayEnabled) },
        ani_native_function { "setOverlayEnabledByBundleNameNative", nullptr,
            reinterpret_cast<void*>(SetOverlayEnabledByBundleName) },
        ani_native_function { "getOverlayModuleInfoNative", nullptr,
            reinterpret_cast<void*>(GetOverlayModuleInfo) },
        ani_native_function { "getTargetOverlayModuleInfosNative", nullptr,
            reinterpret_cast<void*>(GetTargetOverlayModuleInfos) },
        ani_native_function { "getOverlayModuleInfoByBundleNameNative", nullptr,
            reinterpret_cast<void*>(GetOverlayModuleInfoByBundleName) },
        ani_native_function { "getTargetOverlayModuleInfosByBundleNameNative", nullptr,
            reinterpret_cast<void*>(GetTargetOverlayModuleInfosByBundleName) }
    };

    status = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    if (status != ANI_OK) {
        APP_LOGE("Namespace_BindNativeFunctions: %{public}s fail with %{public}d", NS_NAME_OVERLAY, status);
        return status;
    }

    *result = ANI_VERSION_1;

    APP_LOGI("ANI_Constructor finished");

    return ANI_OK;
}
}
} // AppExecFwk
} // OHOS