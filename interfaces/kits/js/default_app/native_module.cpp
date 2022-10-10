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

#include "hilog_wrapper.h"
#include "js_runtime_utils.h"
#include "napi/native_node_api.h"
#include "app_log_wrapper.h"
#include "js_default_app.h"

using namespace OHOS::AbilityRuntime;
namespace OHOS {
namespace AppExecFwk {
static void SetNamedProperty(napi_env env, napi_value dstObj, const char *objName, const char *propName)
{
    napi_value prop = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, objName, NAPI_AUTO_LENGTH, &prop));
    NAPI_CALL_RETURN_VOID(env,  napi_set_named_property(env, dstObj, propName, prop));
}

static void CreateApplicationType(napi_env env, napi_value value)
{
    SetNamedProperty(env, value, "BROWSER", "BROWSER");
    SetNamedProperty(env, value, "IMAGE", "IMAGE");
    SetNamedProperty(env, value, "AUDIO", "AUDIO");
    SetNamedProperty(env, value, "VIDEO", "VIDEO");
    SetNamedProperty(env, value, "PDF", "PDF");
    SetNamedProperty(env, value, "WORD", "WORD");
    SetNamedProperty(env, value, "EXCEL", "EXCEL");
    SetNamedProperty(env, value, "PPT", "PPT");
}

static NativeValue* JsDefaultAppInit(NativeEngine *engine, NativeValue *exports)
{
    APP_LOGD("JsDefaultAppInit is called");
    if (engine == nullptr || exports == nullptr) {
        APP_LOGE("Invalid input parameters");
        return nullptr;
    }

    NativeObject *object = ConvertNativeValueTo<NativeObject>(exports);
    if (object == nullptr) {
        APP_LOGE("object is nullptr");
        return nullptr;
    }

    std::unique_ptr<JsDefaultApp> jsDefaultAppUnsupported = std::make_unique<JsDefaultApp>();

    object->SetNativePointer(jsDefaultAppUnsupported.release(), JsDefaultApp::JsFinalizer, nullptr);

    const char *moduleName = "JsDefaultApp";
    BindNativeFunction(*engine, *object, "isDefaultApplication", moduleName, JsDefaultApp::JsIsDefaultApplication);

    return exports;
}

static napi_value DefaultAppExport(napi_env env, napi_value exports)
{
    napi_value applicationType = nullptr;
    NAPI_CALL(env, napi_create_object(env, &applicationType));
    CreateApplicationType(env, applicationType);

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("getDefaultApplication", GetDefaultApplication),
        DECLARE_NAPI_FUNCTION("setDefaultApplication", SetDefaultApplication),
        DECLARE_NAPI_FUNCTION("resetDefaultApplication", ResetDefaultApplication),
        DECLARE_NAPI_PROPERTY("ApplicationType", applicationType),
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    APP_LOGD("init js default app success.");
    return reinterpret_cast<napi_value>(JsDefaultAppInit(reinterpret_cast<NativeEngine*>(env),
        reinterpret_cast<NativeValue*>(exports)));
}

static napi_module default_app_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = DefaultAppExport,
    .nm_modname = "bundle.defaultAppManager",
    .nm_priv = ((void *)0),
    .reserved = {0}
};

extern "C" __attribute__((constructor)) void DefaultAppRegister(void)
{
    napi_module_register(&default_app_module);
}
}
}
