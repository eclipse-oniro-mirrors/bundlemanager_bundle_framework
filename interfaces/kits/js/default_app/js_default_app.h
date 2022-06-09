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

#ifndef NAPI_JS_DEFAULT_APP_H
#define NAPI_JS_DEFAULT_APP_H

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AppExecFwk {
struct DefaultAppInfo {
    explicit DefaultAppInfo(napi_env napiEnv);
    ~DefaultAppInfo();

    int32_t userId = 0;
    std::string type;
    bool result = false;
    int32_t errCode = 0;
    std::string errMsg;
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;
};

napi_value IsDefaultApplication(napi_env env, napi_callback_info info);
napi_value GetDefaultApplication(napi_env env, napi_callback_info info);
napi_value SetDefaultApplication(napi_env env, napi_callback_info info);
napi_value ResetDefaultApplication(napi_env env, napi_callback_info info);
}
}
#endif