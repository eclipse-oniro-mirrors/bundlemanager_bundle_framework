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

#include <cstdio>
#include <cstring>
#include <pthread.h>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "free_install.h"

namespace OHOS {
namespace AppExecFwk {
static napi_value FreeInstallExport(napi_env env, napi_value exports)
{
    napi_value upgradeFlag = nullptr;
    NAPI_CALL(env, napi_create_object(env, &upgradeFlag));
    CreateUpgradeFlagObject(env, upgradeFlag);

    napi_value bundlePackFlag = nullptr;
    NAPI_CALL(env, napi_create_object(env, &bundlePackFlag));
    CreateBundlePackFlagObject(env, bundlePackFlag);

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("UpgradeFlag", upgradeFlag),
        DECLARE_NAPI_PROPERTY("BundlePackFlag", bundlePackFlag),
        DECLARE_NAPI_FUNCTION("isHapModuleRemovable", IsHapModuleRemovable),
        DECLARE_NAPI_FUNCTION("setHapModuleUpgradeFlag", SetHapModuleUpgradeFlag),
        DECLARE_NAPI_FUNCTION("getBundlePackInfo", GetBundlePackInfo),
        DECLARE_NAPI_FUNCTION("getDispatchInfo", GetDispatchInfo)
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    APP_LOGI("init js free install success");
    return exports;
}

static napi_module free_install_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = FreeInstallExport,
    .nm_modname = "bundle.freeInstall",
    .nm_priv = ((void *)0),
    .reserved = {0}
};

extern "C" __attribute__((constructor)) void FreeInstallRegister(void)
{
    napi_module_register(&free_install_module);
}
}
}