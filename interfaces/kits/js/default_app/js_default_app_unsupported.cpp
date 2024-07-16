/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "js_default_app.h"

#include <string>

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "business_error.h"
#include "common_func.h"

namespace OHOS {
namespace AppExecFwk {

napi_value IsDefaultApplication(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.DefaultApp not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "isDefaultApplication");
    napi_throw(env, error);
    return nullptr;
}

napi_value IsDefaultApplicationSync(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.DefaultApp not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "isDefaultApplicationSync");
    napi_throw(env, error);
    return nullptr;
}

napi_value GetDefaultApplication(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.DefaultApp not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "getDefaultApplication");
    napi_throw(env, error);
    return nullptr;
}

napi_value GetDefaultApplicationSync(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.DefaultApp not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "getDefaultApplicationSync");
    napi_throw(env, error);
    return nullptr;
}

napi_value SetDefaultApplication(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.DefaultApp not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "setDefaultApplication");
    napi_throw(env, error);
    return nullptr;
}

napi_value SetDefaultApplicationSync(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.DefaultApp not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "setDefaultApplicationSync");
    napi_throw(env, error);
    return nullptr;
}

napi_value ResetDefaultApplication(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.DefaultApp not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "resetDefaultApplication");
    napi_throw(env, error);
    return nullptr;
}

napi_value ResetDefaultApplicationSync(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.DefaultApp not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "resetDefaultApplicationSync");
    napi_throw(env, error);
    return nullptr;
}
} // AppExecFwk
} // OHOS