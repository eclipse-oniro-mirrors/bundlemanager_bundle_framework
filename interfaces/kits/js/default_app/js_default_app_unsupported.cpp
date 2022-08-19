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

#include "js_default_app.h"

#include <string>

#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t UNSUPPORTED_FEATURE_ERRCODE = 801;
const std::string UNSUPPORTED_FEATURE_MESSAGE = "unsupported BundleManagerService feature";
constexpr size_t ARGS_SIZE_ZERO = 0;
constexpr size_t ARGS_SIZE_ONE = 1;
constexpr size_t ARGS_SIZE_TWO = 2;
constexpr size_t ARGS_SIZE_THREE = 3;
constexpr size_t ARGS_SIZE_FOUR = 4;
constexpr int32_t NAPI_RETURN_ONE = 1;
}

napi_value DefaultAppCommon(napi_env env, size_t argc, napi_value *argv)
{
    napi_ref callback = nullptr;
    if (argc > ARGS_SIZE_ZERO) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[argc - ARGS_SIZE_ONE], &valueType);
        if (valueType == napi_function) {
            napi_create_reference(env, argv[argc - ARGS_SIZE_ONE], NAPI_RETURN_ONE, &callback);
        }
    }
    napi_value promise = nullptr;
    napi_deferred deferred = nullptr;
    if (callback == nullptr) {
        napi_create_promise(env, &deferred, &promise);
    } else {
        napi_get_undefined(env, &promise);
    }
    
    napi_value result[ARGS_SIZE_TWO] = { 0 };
    napi_create_int32(env, UNSUPPORTED_FEATURE_ERRCODE, &result[ARGS_SIZE_ZERO]);
    napi_create_string_utf8(env, UNSUPPORTED_FEATURE_MESSAGE.c_str(),
        NAPI_AUTO_LENGTH, &result[ARGS_SIZE_ONE]);
    if (callback) {
        napi_value callbackTemp = nullptr;
        napi_value placeHolder = nullptr;
        napi_get_reference_value(env, callback, &callbackTemp);
        napi_call_function(env, nullptr, callbackTemp,
            sizeof(result) / sizeof(result[0]), result, &placeHolder);
    } else {
        napi_reject_deferred(env, deferred, result[ARGS_SIZE_ZERO]);
    }
    napi_delete_reference(env, callback);
    return promise;
}

napi_value IsDefaultApplication(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisArg, &data);

    return DefaultAppCommon(env, argc, argv);
}

napi_value GetDefaultApplication(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisArg, &data);

    return DefaultAppCommon(env, argc, argv);
}

napi_value SetDefaultApplication(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisArg, &data);

    return DefaultAppCommon(env, argc, argv);
}

napi_value ResetDefaultApplication(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisArg, &data);

    return DefaultAppCommon(env, argc, argv);
}
} // AppExecFwk
} // OHOS