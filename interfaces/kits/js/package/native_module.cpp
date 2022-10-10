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
#include <pthread.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "package.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "js_runtime_utils.h"
#include "napi/native_node_api.h"

using namespace OHOS::AbilityRuntime;
namespace OHOS {
namespace AppExecFwk {
EXTERN_C_START
/*
 * function for module exports
 */

static NativeValue* JsPackageInit(NativeEngine *engine, NativeValue *exports)
{
    APP_LOGE("JsPackageInit is called");
    if (engine == nullptr || exports == nullptr) {
        APP_LOGE("Invalid input parameters");
        return nullptr;
    }

    NativeObject* object = OHOS::AbilityRuntime::ConvertNativeValueTo<NativeObject>(exports);
    if (object == nullptr) {
        APP_LOGE("object is nullptr");
        return nullptr;
    }

    std::unique_ptr<JsPackage> jsPackage = std::make_unique<JsPackage>();
    object->SetNativePointer(jsPackage.release(), JsPackage::Finalizer, nullptr);

    const char *moduleName = "JsPackage";
    OHOS::AbilityRuntime::BindNativeFunction(*engine, *object, "hasInstalled", moduleName, JsPackage::HasInstalled);
    
    return exports;
}

static napi_value Init(napi_env env, napi_value exports)
{
    HILOG_INFO("napi_moudule Init start ...");
    return reinterpret_cast<napi_value>(
        JsPackageInit(reinterpret_cast<NativeEngine*>(env), reinterpret_cast<NativeValue*>(exports)));
}
EXTERN_C_END

/*
 * Module define
 */
static napi_module _module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "package",
    .nm_priv = ((void *)0),
    .reserved = {0}
};
/*
 * Module register function
 */
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&_module);
}
}  // namespace AppExecFwk
}  // namespace OHOS