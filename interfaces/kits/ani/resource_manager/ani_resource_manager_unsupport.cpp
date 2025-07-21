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
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* NS_NAME_RESOURCEMANAGER = "@ohos.bundle.bundleResourceManager.bundleResourceManager";
}

static ani_object AniGetBundleResourceInfo(ani_env* env, ani_string aniBundleName,
    ani_long aniResFlag, ani_int aniAppIndex)
{
    APP_LOGI("SystemCapability.BundleManager.BundleFramework.Resource not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_BUNDLE_RESOURCE_INFO, "");
    return nullptr;
}

static ani_object AniGetLauncherAbilityResourceInfo(ani_env* env, ani_string aniBundleName,
    ani_long aniResFlag, ani_int aniAppIndex)
{
    APP_LOGI("SystemCapability.BundleManager.BundleFramework.Resource not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_LAUNCHER_ABILITY_RESOURCE_INFO, "");
    return nullptr;
}

static ani_object AniGetAllBundleResourceInfo(ani_env* env, ani_long aniResFlag)
{
    APP_LOGI("SystemCapability.BundleManager.BundleFramework.Resource not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_ALL_BUNDLE_RESOURCE_INFO, "");
    return nullptr;
}

static ani_object AniGetAllLauncherAbilityResourceInfo(ani_env* env, ani_long aniResFlag)
{
    APP_LOGI("SystemCapability.BundleManager.BundleFramework.Resource not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_ALL_LAUNCHER_ABILITY_RESOURCE_INFO, "");
    return nullptr;
}

static ani_object GetExtensionAbilityResourceInfoNative(ani_env* env, ani_string aniBundleName,
    ani_enum_item aniExtensionAbilityType, ani_int aniResourceFlags, ani_int aniAppIndex)
{
    APP_LOGI("SystemCapability.BundleManager.BundleFramework.Resource not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_EXTENSION_ABILITY_RESOURCE_INFO, "");
    return nullptr;
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor resourceManager called");
    ani_env* env;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(status, "Unsupported ANI_VERSION_1");

    arkts::ani_signature::Namespace nsName = arkts::ani_signature::Builder::BuildNamespace(NS_NAME_RESOURCEMANAGER);
    ani_namespace kitNs = nullptr;
    status = env->FindNamespace(nsName.Descriptor().c_str(), &kitNs);
    if (status != ANI_OK) {
        APP_LOGE("FindNamespace: %{public}s fail with %{public}d", NS_NAME_RESOURCEMANAGER, status);
        return status;
    }

    std::array methods = {
        ani_native_function { "getBundleResourceInfoNative", nullptr,
            reinterpret_cast<void*>(AniGetBundleResourceInfo) },
        ani_native_function { "getLauncherAbilityResourceInfoNative", nullptr,
            reinterpret_cast<void*>(AniGetLauncherAbilityResourceInfo) },
        ani_native_function { "getAllBundleResourceInfoNative", nullptr,
            reinterpret_cast<void*>(AniGetAllBundleResourceInfo) },
        ani_native_function { "getAllLauncherAbilityResourceInfoNative", nullptr,
            reinterpret_cast<void*>(AniGetAllLauncherAbilityResourceInfo) },
        ani_native_function { "getExtensionAbilityResourceInfoNative", nullptr,
            reinterpret_cast<void*>(GetExtensionAbilityResourceInfoNative) }
    };

    status = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    if (status != ANI_OK) {
        APP_LOGE("Namespace_BindNativeFunctions: %{public}s fail with %{public}d", NS_NAME_RESOURCEMANAGER, status);
        return status;
    }

    *result = ANI_VERSION_1;

    APP_LOGI("ANI_Constructor finished");

    return ANI_OK;
}
}
} // AppExecFwk
} // OHOS