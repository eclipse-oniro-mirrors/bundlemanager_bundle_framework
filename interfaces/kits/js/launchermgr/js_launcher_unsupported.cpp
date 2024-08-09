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

#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t INDEX_ZERO = 0;
constexpr int32_t UNSUPPORTED_FEATURE_ERRCODE = 801;
const std::string UNSUPPORTED_FEATURE_MESSAGE = "unsupported BundleManagerService feature";
constexpr int32_t INDEX_ONE = 1;
constexpr int32_t INDEX_TWO = 2;
constexpr int32_t INDEX_THREE = 3;
constexpr int32_t NAPI_RETURN_ONE = 1;
}
static napi_value JsLauncherCommon(napi_env env, size_t argc, napi_value *argv)
{
    napi_ref callback = nullptr;
    if (argc > INDEX_ZERO) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[argc - INDEX_ONE], &valueType);
        if (valueType == napi_function) {
            napi_create_reference(env, argv[argc - INDEX_ONE], NAPI_RETURN_ONE, &callback);
        }
    }
    napi_value promise = nullptr;
    napi_deferred deferred = nullptr;
    if (callback == nullptr) {
        napi_create_promise(env, &deferred, &promise);
    } else {
        napi_get_undefined(env, &promise);
    }

    napi_value result[INDEX_TWO] = { 0 };
    napi_create_int32(env, UNSUPPORTED_FEATURE_ERRCODE, &result[INDEX_ZERO]);
    napi_create_string_utf8(env, UNSUPPORTED_FEATURE_MESSAGE.c_str(),
        NAPI_AUTO_LENGTH, &result[INDEX_ONE]);
    if (callback) {
        napi_value callbackTemp = nullptr;
        napi_value placeHolder = nullptr;
        napi_get_reference_value(env, callback, &callbackTemp);
        napi_call_function(env, nullptr, callbackTemp,
            sizeof(result) / sizeof(result[0]), result, &placeHolder);
    } else {
        napi_reject_deferred(env, deferred, result[INDEX_ZERO]);
    }
    napi_delete_reference(env, callback);
    return promise;
}

static napi_value JSLauncherServiceOn(napi_env env, napi_callback_info info)
{
    size_t argc = INDEX_THREE;
    napi_value argv[INDEX_THREE] = { 0 };
    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisArg, &data);

    return JsLauncherCommon(env, argc, argv);
}

static napi_value JSLauncherServiceOff(napi_env env, napi_callback_info info)
{
    size_t argc = INDEX_TWO;
    napi_value argv[INDEX_TWO] = { 0 };
    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisArg, &data);

    return JsLauncherCommon(env, argc, argv);
}

static napi_value JSGetAllLauncherAbilityInfos(napi_env env, napi_callback_info info)
{
    size_t argc = INDEX_TWO;
    napi_value argv[INDEX_TWO] = { 0 };
    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisArg, &data);

    return JsLauncherCommon(env, argc, argv);
}

static napi_value JSGetLauncherAbilityInfos(napi_env env, napi_callback_info info)
{
    size_t argc = INDEX_THREE;
    napi_value argv[INDEX_THREE] = { 0 };
    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisArg, &data);

    return JsLauncherCommon(env, argc, argv);
}

static napi_value JSGetShortcutInfos(napi_env env, napi_callback_info info)
{
    size_t argc = INDEX_TWO;
    napi_value argv[INDEX_TWO] = { 0 };
    napi_value thisArg = nullptr;
    void *data = nullptr;

    napi_get_cb_info(env, info, &argc, argv, &thisArg, &data);

    return JsLauncherCommon(env, argc, argv);
}

static napi_value LauncherServiceExport(napi_env env, napi_value exports)
{
    static napi_property_descriptor launcherDesc[] = {
        DECLARE_NAPI_FUNCTION("on", JSLauncherServiceOn),
        DECLARE_NAPI_FUNCTION("off", JSLauncherServiceOff),
        DECLARE_NAPI_FUNCTION("getAllLauncherAbilityInfos", JSGetAllLauncherAbilityInfos),
        DECLARE_NAPI_FUNCTION("getLauncherAbilityInfos", JSGetLauncherAbilityInfos),
        DECLARE_NAPI_FUNCTION("getShortcutInfos", JSGetShortcutInfos),
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(launcherDesc) / sizeof(launcherDesc[0]), launcherDesc));
    return exports;
}

static napi_module launcherServiceModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = LauncherServiceExport,
    .nm_modname = "bundle.innerBundleManager",
    .nm_priv = ((void*)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void LauncherServiceRegister()
{
    napi_module_register(&launcherServiceModule);
}
} // AppExecFwk
} // OHOS