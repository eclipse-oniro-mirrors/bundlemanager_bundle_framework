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

#ifndef JS_APP_CONTROL_H
#define JS_APP_CONTROL_H

#include "base_cb_info.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
struct DisposedStatus : public BaseCallbackInfo {
    explicit DisposedStatus(napi_env napiEnv) : BaseCallbackInfo(napiEnv) {}

    std::string appId;
    OHOS::AAFwk::Want want;
};

napi_value GetDisposedStatus(napi_env env, napi_callback_info info);
napi_value SetDisposedStatus(napi_env env, napi_callback_info info);
napi_value DeleteDisposedStatus(napi_env env, napi_callback_info info);
napi_value GetDisposedStatusSync(napi_env env, napi_callback_info info);
napi_value SetDisposedStatusSync(napi_env env, napi_callback_info info);
napi_value DeleteDisposedStatusSync(napi_env env, napi_callback_info info);
napi_value GetDisposedRule(napi_env env, napi_callback_info info);
napi_value SetDisposedRule(napi_env env, napi_callback_info info);
napi_value GetUninstallDisposedRule(napi_env env, napi_callback_info info);
napi_value SetUninstallDisposedRule(napi_env env, napi_callback_info info);
napi_value DeleteUninstallDisposedRule(napi_env env, napi_callback_info info);
void CreateComponentType(napi_env env, napi_value value);
void CreateDisposedType(napi_env env, napi_value value);
void CreateControlType(napi_env env, napi_value value);
}  // namespace AppExecFwk
}  // namespace OHOS
#endif /* JS_APP_CONTROL_H */