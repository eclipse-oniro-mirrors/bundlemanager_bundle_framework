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
constexpr const char* NS_NAME_DEFAULTAPPMANAGER = "@ohos.bundle.defaultAppManager.defaultAppManager";
} // namespace

static ani_boolean AniIsDefaultApplication(ani_env *env, ani_string aniType, ani_boolean aniIsSync)
{
    APP_LOGI("SystemCapability.BundleManager.BundleFramework.DefaultApp not supported");
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        isSync ? IS_DEFAULT_APPLICATION_SYNC : IS_DEFAULT_APPLICATION, "");
    return false;
}

static ani_object AniGetDefaultApplication(ani_env *env,
    ani_string aniType, ani_int aniUserId, ani_boolean aniIsSync)
{
    APP_LOGI("SystemCapability.BundleManager.BundleFramework.DefaultApp not supported");
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        isSync ? GET_DEFAULT_APPLICATION_SYNC : GET_DEFAULT_APPLICATION, "");
    return nullptr;
}

static void AniSetDefaultApplication(ani_env *env,
    ani_string aniType, ani_object aniElementName, ani_int aniUserId, ani_boolean aniIsSync)
{
    APP_LOGI("SystemCapability.BundleManager.BundleFramework.DefaultApp not supported");
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        isSync ? SET_DEFAULT_APPLICATION_SYNC : SET_DEFAULT_APPLICATION, "");
}

static void AniResetDefaultApplication(ani_env *env, ani_string aniType, ani_int aniUserId, ani_boolean aniIsSync)
{
    APP_LOGI("SystemCapability.BundleManager.BundleFramework.DefaultApp not supported");
    bool isSync = CommonFunAni::AniBooleanToBool(aniIsSync);
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        isSync ? RESET_DEFAULT_APPLICATION_SYNC : RESET_DEFAULT_APPLICATION, "");
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
        ani_native_function { "isDefaultApplicationNative", nullptr, reinterpret_cast<void*>(AniIsDefaultApplication) },
        ani_native_function { "getDefaultApplicationNative", nullptr,
            reinterpret_cast<void*>(AniGetDefaultApplication) },
        ani_native_function { "setDefaultApplicationNative", nullptr,
            reinterpret_cast<void*>(AniSetDefaultApplication) },
        ani_native_function { "resetDefaultApplicationNative", nullptr,
            reinterpret_cast<void*>(AniResetDefaultApplication) }
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