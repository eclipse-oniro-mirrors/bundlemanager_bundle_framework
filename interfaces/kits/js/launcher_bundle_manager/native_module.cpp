/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include <pthread.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "launcher_bundle_manager.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AppExecFwk {
static napi_value LauncherBundleManagerExport(napi_env env, napi_value exports)
{
    APP_LOGD("LauncherBundleManagerExport init");
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("getLauncherAbilityInfo", GetLauncherAbilityInfo),
        DECLARE_NAPI_FUNCTION("getLauncherAbilityInfoSync", GetLauncherAbilityInfoSync),
        DECLARE_NAPI_FUNCTION("getAllLauncherAbilityInfo", GetAllLauncherAbilityInfo),
        DECLARE_NAPI_FUNCTION("getShortcutInfo", GetShortcutInfo),
        DECLARE_NAPI_FUNCTION("getShortcutInfoSync", GetShortcutInfoSync),
        DECLARE_NAPI_FUNCTION("getShortcutInfoByAppIndex", GetShortcutInfoByAppIndex),
        DECLARE_NAPI_FUNCTION("startShortcut", StartShortcut),
        DECLARE_NAPI_FUNCTION("startShortcutWithReason", StartShortcutWithReason),
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}

static napi_module bundle_manager_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = LauncherBundleManagerExport,
    .nm_modname = "bundle.launcherBundleManager",
    .nm_priv = ((void *)0),
    .reserved = {0}
};

extern "C" __attribute__((constructor)) void BundleManagerRegister(void)
{
    napi_module_register(&bundle_manager_module);
}
}
}