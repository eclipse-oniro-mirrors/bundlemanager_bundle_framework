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

#include <cstdio>
#include <cstring>
#include <pthread.h>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "js_app_overlay.h"

namespace OHOS {
namespace AppExecFwk {
static napi_value OverlayExport(napi_env env, napi_value exports)
{
    APP_LOGI("export overlay begin");
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("setOverlayEnabled", SetOverlayEnabled),
        DECLARE_NAPI_FUNCTION("setOverlayEnabledByBundleName", SetOverlayEnabledByBundleName),
        DECLARE_NAPI_FUNCTION("getOverlayModuleInfo", GetOverlayModuleInfo),
        DECLARE_NAPI_FUNCTION("getTargetOverlayModuleInfos", GetTargetOverlayModuleInfos),
        DECLARE_NAPI_FUNCTION("getOverlayModuleInfoByBundleName", GetOverlayModuleInfoByBundleName),
        DECLARE_NAPI_FUNCTION("getTargetOverlayModuleInfosByBundleName", GetTargetOverlayModuleInfosByBundleName),
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    APP_LOGD("init js overlay success");
    return exports;
}

static napi_module app_overlay_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = OverlayExport,
    .nm_modname = "bundle.overlay",
    .nm_priv = ((void *)0),
    .reserved = {0}
};

extern "C" __attribute__((constructor)) void AppOverlayRegister(void)
{
    napi_module_register(&app_overlay_module);
}
}
}