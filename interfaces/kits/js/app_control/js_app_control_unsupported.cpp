/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "js_app_control.h"

#include <string>

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "business_error.h"
#include "common_func.h"

namespace OHOS {
namespace AppExecFwk {
napi_value GetDisposedStatus(napi_env env, napi_callback_info info)
{
    APP_LOGE("AppControl not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "getDisposedStatus");
    napi_throw(env, error);
    return nullptr;
}

napi_value SetDisposedStatus(napi_env env, napi_callback_info info)
{
    APP_LOGE("AppControl not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "setDisposedStatus");
    napi_throw(env, error);
    return nullptr;
}

napi_value DeleteDisposedStatus(napi_env env, napi_callback_info info)
{
    APP_LOGE("AppControl not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "deleteDisposedStatus");
    napi_throw(env, error);
    return nullptr;
}

napi_value GetDisposedStatusSync(napi_env env, napi_callback_info info)
{
    APP_LOGE("AppControl not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "getDisposedStatusSync");
    napi_throw(env, error);
    return nullptr;
}

napi_value SetDisposedStatusSync(napi_env env, napi_callback_info info)
{
    APP_LOGE("AppControl not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "setDisposedStatusSync");
    napi_throw(env, error);
    return nullptr;
}

napi_value DeleteDisposedStatusSync(napi_env env, napi_callback_info info)
{
    APP_LOGE("AppControl not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "deleteDisposedStatusSync");
    napi_throw(env, error);
    return nullptr;
}

napi_value GetDisposedRule(napi_env env, napi_callback_info info)
{
    APP_LOGE("AppControl not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "GetDisposedRule");
    napi_throw(env, error);
    return nullptr;
}

napi_value SetDisposedRule(napi_env env, napi_callback_info info)
{
    APP_LOGE("AppControl not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "SetDisposedRule");
    napi_throw(env, error);
    return nullptr;
}

napi_value GetUninstallDisposedRule(napi_env env, napi_callback_info info)
{
    APP_LOGE("AppControl not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "GetUninstallDisposedRule");
    napi_throw(env, error);
    return nullptr;
}

napi_value SetUninstallDisposedRule(napi_env env, napi_callback_info info)
{
    APP_LOGE("AppControl not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "SetUninstallDisposedRule");
    napi_throw(env, error);
    return nullptr;
}

napi_value DeleteUninstallDisposedRule(napi_env env, napi_callback_info info)
{
    APP_LOGE("AppControl not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "deleteUninstallDisposedRule");
    napi_throw(env, error);
    return nullptr;
}

void CreateComponentType(napi_env env, napi_value value)
{
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &value));
}

void CreateDisposedType(napi_env env, napi_value value)
{
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &value));
}

void CreateControlType(napi_env env, napi_value value)
{
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &value));
}
} // AppExecFwk
} // OHOS
