/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "bundle_resource.h"

#include <string>

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "business_error.h"

namespace OHOS {
namespace AppExecFwk {
napi_value GetBundleResourceInfo(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Resource not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "getBundleResourceInfo");
    napi_throw(env, error);
    return nullptr;
}

napi_value GetLauncherAbilityResourceInfo(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Resource not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "getLauncherAbilityResourceInfo");
    napi_throw(env, error);
    return nullptr;
}

napi_value GetAllBundleResourceInfo(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Resource not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "getAllBundleResourceInfo");
    napi_throw(env, error);
    return nullptr;
}

napi_value GetAllLauncherAbilityResourceInfo(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Resource not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "getAllLauncherAbilityResourceInfo");
    napi_throw(env, error);
    return nullptr;
}

void CreateBundleResourceFlagObject(napi_env env, napi_value value)
{
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &value));
}
} // AppExecFwk
} // OHOS
