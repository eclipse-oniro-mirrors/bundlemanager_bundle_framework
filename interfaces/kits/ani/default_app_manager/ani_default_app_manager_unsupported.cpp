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
constexpr const char* NS_NAME_DEFAULTAPPMANAGER = "@ohos.bundle.defaultAppManager.defaultAppManager";
} // namespace

static ani_boolean IsDefaultApplicationSync(ani_env *env, ani_string aniType)
{
    APP_LOGI("SystemCapability.BundleManager.BundleFramework.DefaultApp not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, IS_DEFAULT_APPLICATION, "");
    return false;
}

static ani_object GetDefaultApplicationSync(ani_env *env, ani_string aniType, ani_double aniUserId)
{
    APP_LOGI("SystemCapability.BundleManager.BundleFramework.DefaultApp not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_DEFAULT_APPLICATION, "");
    return nullptr;
}

static void SetDefaultApplicationSync(ani_env *env, ani_string aniType, ani_object aniElementName, ani_double aniUserId)
{
    APP_LOGI("SystemCapability.BundleManager.BundleFramework.DefaultApp not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, SET_DEFAULT_APPLICATION, "");
}

static void ResetDefaultApplicationSync(ani_env *env, ani_string aniType, ani_double aniUserId)
{
    APP_LOGI("SystemCapability.BundleManager.BundleFramework.DefaultApp not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, RESET_DEFAULT_APPLICATION, "");
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor defaultAppManager called");
    ani_env* env;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(status, "Unsupported ANI_VERSION_1");

    arkts::ani_signature::Namespace nsName =
        arkts::ani_signature::Builder::BuildNamespace(NS_NAME_DEFAULTAPPMANAGER);
    ani_namespace kitNs = nullptr;
    status = env->FindNamespace(nsName.Descriptor().c_str(), &kitNs);
    if (status != ANI_OK) {
        APP_LOGE("FindNamespace: %{public}s fail with %{public}d", NS_NAME_DEFAULTAPPMANAGER, status);
        return status;
    }

    std::array methods = {
        ani_native_function { "isDefaultApplicationSync", nullptr, reinterpret_cast<void*>(IsDefaultApplicationSync) },
        ani_native_function { "getDefaultApplicationSyncNative", nullptr,
            reinterpret_cast<void*>(GetDefaultApplicationSync) },
        ani_native_function { "setDefaultApplicationSyncNative", nullptr,
            reinterpret_cast<void*>(SetDefaultApplicationSync) },
        ani_native_function { "resetDefaultApplicationSyncNative", nullptr,
            reinterpret_cast<void*>(ResetDefaultApplicationSync) }
    };

    status = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    if (status != ANI_OK) {
        APP_LOGE(
            "Namespace_BindNativeFunctions: %{public}s fail with %{public}d", NS_NAME_DEFAULTAPPMANAGER, status);
        return status;
    }

    *result = ANI_VERSION_1;

    APP_LOGI("ANI_Constructor finished");

    return ANI_OK;
}
}
} // AppExecFwk
} // OHOS