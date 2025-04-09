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

namespace OHOS {
namespace AppExecFwk {
namespace  {
    constexpr const char* GET_BUNDLE_RESOURCE_INFO = "GetBundleResourceInfo";
}

static ani_object GetBundleResourceInfo([[maybe_unused]] ani_env* env, ani_string aniBundleName,
    ani_double resFlag, ani_double appIdx)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Resource not supported");
    BusinessErrorAni::ThrowParameterTypeError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, GET_BUNDLE_RESOURCE_INFO, "");
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
            "Lstd/core/String;DD:LbundleManager/BundleResourceInfo/BundleResourceInfo;",
            reinterpret_cast<void*>(GetBundleResourceInfo)
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