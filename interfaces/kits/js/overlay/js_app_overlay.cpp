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

#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
napi_value SetOverlayEnabled(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI SetOverlayEnabled called");
    return nullptr;
}

napi_value SetOverlayEnabledByBundleName(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI SetOverlayEnabledByBundleName called");
    return nullptr;
}

napi_value GetOverlayModuleInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetOverlayModuleInfo called");
    return nullptr;
}

napi_value GetTargetOverlayModuleInfos(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetTargetOverlayModuleInfos called");
    return nullptr;
}

napi_value GetOverlayModuleInfoByBundleName(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetOverlayModuleInfoByBundleName called");
    return nullptr;
}

napi_value GetOverlayModuleInfosByBundleName(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetOverlayModuleInfosByBundleName called");
    return nullptr;
}

napi_value GetTargetOverlayModuleInfosByBundleName(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetTargetOverlayModuleInfosByBundleName called");
    return nullptr;
}

napi_value GetTargetOverlayModuleInfosByModuleName(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI GetTargetOverlayModuleInfosByModuleName called");
    return nullptr;
}
} // AppExecFwk
} // OHOS