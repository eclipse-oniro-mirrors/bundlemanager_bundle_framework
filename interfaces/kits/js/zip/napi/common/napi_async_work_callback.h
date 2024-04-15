/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef INTERFACES_KITS_JS_ZIP_NAPI_COMMON_NAPI_ASYNC_WORK_CALLBACK_H
#define INTERFACES_KITS_JS_ZIP_NAPI_COMMON_NAPI_ASYNC_WORK_CALLBACK_H

#include "napi_async_work_factory.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
class NapiAsyncWorkCallback : public NapiAsyncWorkFactory {
public:
    NapiAsyncWorkCallback(const NapiAsyncWorkCallback &) = delete;
    NapiAsyncWorkCallback &operator=(const NapiAsyncWorkCallback &) = delete;
    NapiAsyncWorkCallback(napi_env env, NapiValue thisPtr, NapiValue cb);
    ~NapiAsyncWorkCallback() override = default;

    NapiValue Schedule(std::string procedureName, NContextCBExec cbExec, NContextCBComplete cbComplete) final;

private:
    NAsyncContextCallback *ctx_ = nullptr;
};
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // INTERFACES_KITS_JS_ZIP_NAPI_COMMON_NAPI_ASYNC_WORK_CALLBACK_H