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
#include "bundle_resource.h"

namespace OHOS {
namespace AppExecFwk {
static napi_value BundleResourceExport(napi_env env, napi_value exports)
{
    napi_value resourceFlag = nullptr;
    NAPI_CALL(env, napi_create_object(env, &resourceFlag));
    CreateBundleResourceFlagObject(env, resourceFlag);

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("getBundleResourceInfo", GetBundleResourceInfo),
        DECLARE_NAPI_FUNCTION("getLauncherAbilityResourceInfo", GetLauncherAbilityResourceInfo),
        DECLARE_NAPI_FUNCTION("getAllBundleResourceInfo", GetAllBundleResourceInfo),
        DECLARE_NAPI_FUNCTION("getAllLauncherAbilityResourceInfo", GetAllLauncherAbilityResourceInfo),
        DECLARE_NAPI_PROPERTY("ResourceFlag", resourceFlag),
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    APP_LOGI("init bundle resource success");
    return exports;
}

static napi_module bundle_resource_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = BundleResourceExport,
    .nm_modname = "bundle.bundleResourceManager",
    .nm_priv = ((void *)0),
    .reserved = {0}
};

extern "C" __attribute__((constructor)) void BundleResourceRegister(void)
{
    napi_module_register(&bundle_resource_module);
}
}
}