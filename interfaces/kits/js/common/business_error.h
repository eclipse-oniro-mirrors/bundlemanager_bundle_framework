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

#ifndef BUSINESS_ERROR_H
#define BUSINESS_ERROR_H

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AppExecFwk {
class BusinessError {
public:
static void ThrowError(napi_env env, int32_t err, const std::string &msg = "");

static void ThrowParameterTypeError(napi_env env, int32_t err,
    const std::string &parameter, const std::string &type);

static void ThrowTooFewParametersError(napi_env env, int32_t err);

static napi_value CreateCommonError(napi_env env, int32_t err,
    const std::string &functionName = "", const std::string &permissionName = "");

static napi_value CreateError(napi_env env, int32_t err, const std::string &msg);

static void ThrowEnumError(napi_env env,
    const std::string &parameter, const std::string &type);

static napi_value CreateEnumError(napi_env env,
    const std::string &parameter, const std::string &enumClass);
};

#define CHECK_STRING_EMPTY(env, str, strName)                                              \
    do {                                                                           \
        if ((str).empty()) {                                                   \
            APP_LOGE("Parameter error. %{public}s is empty", (strName).c_str());                        \
            std::string errMessage = "BusinessError 401: Parameter error. parameter " + (strName) + " is empty";  \
            auto businessError = BusinessError::CreateError(env, 401, errMessage);                      \
            napi_throw(env, businessError);                                        \
            return nullptr;                                                        \
        }                                                                          \
    } while (0)
}
}
#endif