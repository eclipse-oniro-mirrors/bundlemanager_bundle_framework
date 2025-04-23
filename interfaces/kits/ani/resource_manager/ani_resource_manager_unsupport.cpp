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
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {

static ani_object GetBundleResourceInfo(ani_env* env, ani_string aniBundleName,
    ani_double aniResFlag, ani_double aniAppIndex)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Resource not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_BUNDLE_RESOURCE_INFO, "");
    return nullptr;
}

static ani_ref GetLauncherAbilityResourceInfo(ani_env* env, ani_string aniBundleName,
    ani_double aniResFlag, ani_double aniAppIndex)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Resource not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_LAUNCHER_ABILITY_RESOURCE_INFO, "");
    return nullptr;
}

static ani_ref GetAllBundleResourceInfo(ani_env* env, ani_double aniResFlag)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Resource not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_ALL_BUNDLE_RESOURCE_INFO, "");
    return nullptr;
}

static ani_ref GetAllLauncherAbilityResourceInfo(ani_env* env, ani_double aniResFlag)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Resource not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_ALL_LAUNCHER_ABILITY_RESOURCE_INFO, "");
    return nullptr;
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor resourceMgr called");
    ani_env* env;
    ani_status res = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Unsupported ANI_VERSION_1");

    static const char* nsName = "L@ohos/bundle/bundleResourceManager/bundleResourceManager;";
    ani_namespace kitNs;
    res = env->FindNamespace(nsName, &kitNs);
    RETURN_ANI_STATUS_IF_NOT_OK(
        res, "Not found nameSpace L@ohos/bundle/bundleResourceManager/bundleResourceManager;");

    std::array methods = {
        ani_native_function {
            "getBundleResourceInfoNative",
            nullptr,
            reinterpret_cast<void*>(GetBundleResourceInfo)
        },
        ani_native_function {
            "getLauncherAbilityResourceInfoNative",
            nullptr,
            reinterpret_cast<void*>(GetLauncherAbilityResourceInfo)
        },
        ani_native_function {
            "getAllBundleResourceInfoNative",
            nullptr,
            reinterpret_cast<void*>(GetAllBundleResourceInfo)
        },
        ani_native_function {
            "getAllLauncherAbilityResourceInfoNative",
            nullptr,
            reinterpret_cast<void*>(GetAllLauncherAbilityResourceInfo)
        }
    };

    res = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    RETURN_ANI_STATUS_IF_NOT_OK(res, "Cannot bind native methods");

    *result = ANI_VERSION_1;

    APP_LOGI("ANI_Constructor finished");

    return ANI_OK;
}
}
} // AppExecFwk
} // OHOS