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
#include "installer.h"

namespace OHOS {
namespace AppExecFwk {
static napi_value BundleInstallerExport(napi_env env, napi_value exports)
{
    APP_LOGD("export bundle installer begin.");
    napi_value m_classBundleInstaller;

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("getBundleInstaller", GetBundleInstaller),
        DECLARE_NAPI_FUNCTION("getBundleInstallerSync", GetBundleInstallerSync),
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("install", Install),
        DECLARE_NAPI_FUNCTION("recover", Recover),
        DECLARE_NAPI_FUNCTION("uninstall", Uninstall),
        DECLARE_NAPI_FUNCTION("updateBundleForSelf", UpdateBundleForSelf),
        DECLARE_NAPI_FUNCTION("addExtResource", AddExtResource),
        DECLARE_NAPI_FUNCTION("removeExtResource", RemoveExtResource),
        DECLARE_NAPI_FUNCTION("uninstallUpdates", UninstallAndRecover),
        DECLARE_NAPI_FUNCTION("createAppTwin", CreateAppTwin),
    };

    NAPI_CALL(env,
        napi_define_class(env,
            "BundleInstaller",
            NAPI_AUTO_LENGTH,
            BundleInstallerConstructor,
            nullptr,
            sizeof(properties) / sizeof(*properties),
            properties,
            &m_classBundleInstaller));
    napi_create_reference(env, m_classBundleInstaller, 1, &g_classBundleInstaller);
    APP_LOGD("export bundle installer success.");
    return exports;
}

static napi_module bundle_installer_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = BundleInstallerExport,
    .nm_modname = "bundle.installer",
    .nm_priv = ((void *)0),
    .reserved = {0}
};

extern "C" __attribute__((constructor)) void BundleInstallerRegister(void)
{
    napi_module_register(&bundle_installer_module);
}
}
}
