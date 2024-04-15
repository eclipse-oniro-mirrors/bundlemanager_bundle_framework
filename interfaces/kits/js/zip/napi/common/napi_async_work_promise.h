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

#ifndef INTERFACES_KITS_JS_ZIP_NAPI_COMMON_NAPI_ASYNC_WORK_PROMISE_H
#define INTERFACES_KITS_JS_ZIP_NAPI_COMMON_NAPI_ASYNC_WORK_PROMISE_H

#include "napi_async_work_factory.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
class NapiAsyncWorkPromise : public NapiAsyncWorkFactory {
public:
    NapiAsyncWorkPromise(const NapiAsyncWorkPromise &) = delete;
    NapiAsyncWorkPromise &operator=(const NapiAsyncWorkPromise &) = delete;
    NapiAsyncWorkPromise(napi_env env, NapiValue thisPtr);
    ~NapiAsyncWorkPromise() override = default;

    NapiValue Schedule(std::string procedureName, NContextCBExec cbExec, NContextCBComplete cbComplete) override;

private:
    NAsyncContextPromise *ctx_;
};
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // INTERFACES_KITS_JS_ZIP_NAPI_COMMON_NAPI_ASYNC_WORK_PROMISE_H