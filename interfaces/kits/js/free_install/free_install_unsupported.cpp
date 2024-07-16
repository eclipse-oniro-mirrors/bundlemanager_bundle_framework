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
#include "free_install.h"

#include <string>

#include "app_log_wrapper.h"
#include "bundle_errors.h"
#include "business_error.h"
#include "common_func.h"

namespace OHOS {
namespace AppExecFwk {

napi_value IsHapModuleRemovable(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.FreeInstall not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, "isHapModuleRemovable");
    napi_throw(env, error);
    return nullptr;
}

napi_value SetHapModuleUpgradeFlag(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.FreeInstall not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, "setHapModuleUpgradeFlag");
    napi_throw(env, error);
    return nullptr;
}

napi_value GetBundlePackInfo(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.FreeInstall not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, "getBundlePackInfo");
    napi_throw(env, error);
    return nullptr;
}

napi_value GetDispatchInfo(napi_env env, napi_callback_info info)
{
    APP_LOGE("SystemCapability.BundleManager.BundleFramework.FreeInstall not supported");
    napi_value error = BusinessError::CreateCommonError(env, ERROR_SYSTEM_ABILITY_NOT_FOUND, "getDispatchInfo");
    napi_throw(env, error);
    return nullptr;
}

void CreateUpgradeFlagObject(napi_env env, napi_value value)
{}

void CreateBundlePackFlagObject(napi_env env, napi_value value)
{}
} // AppExecFwk
} // OHOS
