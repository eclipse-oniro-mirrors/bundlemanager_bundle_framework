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

#include "launcher_bundle_manager.h"

#include <string>

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "business_error.h"
#include "common_func.h"

namespace OHOS {
namespace AppExecFwk {
napi_value GetLauncherAbilityInfo(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Launcher not supported.");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "GetLauncherAbilityInfo");
    napi_throw(env, error);
    return nullptr;
}

napi_value GetAllLauncherAbilityInfo(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Launcher not supported.");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "GetAllLauncherAbilityInfo");
    napi_throw(env, error);
    return nullptr;
}

napi_value GetShortcutInfo(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.Launcher not supported.");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND,
        "GetShortcutInfo");
    napi_throw(env, error);
    return nullptr;
}
} // AppExecFwk
} // OHOS
