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
#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "enum_util.h"
#include "napi_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* NS_NAME_FREEINSTALL = "@ohos.bundle.freeInstall.freeInstall";
} // namespace

static void SetHapModuleUpgradeFlagNative(
    ani_env* env, ani_string aniBundleName, ani_string aniModuleName, ani_enum_item aniUpgradeFlag)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.FreeInstall not supported");
    BusinessErrorAni::ThrowCommonError(
        env, ERROR_SYSTEM_ABILITY_NOT_FOUND, RESOURCE_NAME_OF_SET_HAP_MODULE_UPGRADE_FLAG, "");
}

static bool IsHapModuleRemovableNative(ani_env* env, ani_string aniBundleName, ani_string aniModuleName)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.FreeInstall not supported");
    BusinessErrorAni::ThrowCommonError(
        env, ERROR_SYSTEM_ABILITY_NOT_FOUND, RESOURCE_NAME_OF_IS_HAP_MODULE_REMOVABLE, "");
    return false;
}

static ani_object GetBundlePackInfoNative(ani_env* env, ani_string aniBundleName, ani_enum_item aniBundlePackFlag)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.FreeInstall not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, RESOURCE_NAME_OF_GET_BUNDLE_PACK_INFO, "");
    return nullptr;
}

static ani_object GetDispatchInfoNative(ani_env* env)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.FreeInstall not supported");
    BusinessErrorAni::ThrowCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, RESOURCE_NAME_OF_GET_DISPATCH_INFO, "");
    return nullptr;
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor called");
    ani_env* env;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &env);
    RETURN_ANI_STATUS_IF_NOT_OK(status, "Unsupported ANI_VERSION_1");

    arkts::ani_signature::Namespace freeInstallNS = arkts::ani_signature::Builder::BuildNamespace(NS_NAME_FREEINSTALL);
    ani_namespace kitNs = nullptr;
    status = env->FindNamespace(freeInstallNS.Descriptor().c_str(), &kitNs);
    if (status != ANI_OK) {
        APP_LOGE("FindNamespace: %{public}s fail with %{public}d", NS_NAME_FREEINSTALL, status);
        return status;
    }
    std::array methods = {
        ani_native_function {
            "SetHapModuleUpgradeFlagNative", nullptr, reinterpret_cast<void*>(SetHapModuleUpgradeFlagNative) },
        ani_native_function {
            "IsHapModuleRemovableNative", nullptr, reinterpret_cast<void*>(IsHapModuleRemovableNative) },
        ani_native_function { "GetBundlePackInfoNative", nullptr, reinterpret_cast<void*>(GetBundlePackInfoNative) },
        ani_native_function { "GetDispatchInfoNative", nullptr, reinterpret_cast<void*>(GetDispatchInfoNative) },
    };

    status = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    if (status != ANI_OK) {
        APP_LOGE("Namespace_BindNativeFunctions: %{public}s fail with %{public}d", NS_NAME_FREEINSTALL, status);
        return status;
    }

    *result = ANI_VERSION_1;

    APP_LOGI("ANI_Constructor finished");

    return ANI_OK;
}
}
} // namespace AppExecFwk
} // namespace OHOS
