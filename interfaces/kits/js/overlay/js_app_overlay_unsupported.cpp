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

#include "js_app_overlay.h"

#include <string>

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "business_error.h"
#include "common_func.h"

namespace OHOS {
namespace AppExecFwk {
napi_value SetOverlayEnabled(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Overlay not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "setOverlayEnabled");
    napi_throw(env, error);
    return nullptr;
}

napi_value SetOverlayEnabledByBundleName(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Overlay not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "setOverlayEnabledByBundleName");
    napi_throw(env, error);
    return nullptr;
}

napi_value GetOverlayModuleInfo(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Overlay not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "getOverlayModuleInfo");
    napi_throw(env, error);
    return nullptr;
}

napi_value GetTargetOverlayModuleInfos(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Overlay not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "getTargetOverlayModuleInfos");
    napi_throw(env, error);
    return nullptr;
}

napi_value GetOverlayModuleInfoByBundleName(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Overlay not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "getOverlayModuleInfoByBundleName");
    napi_throw(env, error);
    return nullptr;
}

napi_value GetTargetOverlayModuleInfosByBundleName(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Overlay not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "getTargetOverlayModuleInfosByBundleName");
    napi_throw(env, error);
    return nullptr;
}
} // AppExecFwk
} // OHOS
