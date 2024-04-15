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

#ifndef INTERFACES_KITS_JS_ZIP_NAPI_COMMON_NAPI_ASYNC_CONTEXT_H
#define INTERFACES_KITS_JS_ZIP_NAPI_COMMON_NAPI_ASYNC_CONTEXT_H

#include "napi_business_error.h"
#include "napi_value.h"
#include "napi_reference.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
using NContextCBExec = std::function<NapiBusinessError(napi_env)>;
using NContextCBComplete = std::function<NapiValue(napi_env, NapiBusinessError)>;

class NapiAsyncContext {
public:
    NapiBusinessError err_;
    NapiValue res_;
    NContextCBExec cbExec_;
    NContextCBComplete cbComplete_;
    napi_async_work awork_;
    NapiReference thisPtr_;

    explicit NapiAsyncContext(NapiValue thisPtr)
        : err_(0), res_(NapiValue()), cbExec_(nullptr), cbComplete_(nullptr), awork_(nullptr), thisPtr_(thisPtr)
    {}
    virtual ~NapiAsyncContext() = default;
};

class NAsyncContextPromise : public NapiAsyncContext {
public:
    napi_deferred deferred_ = nullptr;
    explicit NAsyncContextPromise(NapiValue thisPtr) : NapiAsyncContext(thisPtr)
    {}
    ~NAsyncContextPromise() override = default;
};

class NAsyncContextCallback : public NapiAsyncContext {
public:
    NapiReference cb_;
    NAsyncContextCallback(NapiValue thisPtr, NapiValue cb) : NapiAsyncContext(thisPtr), cb_(cb)
    {}
    ~NAsyncContextCallback() override = default;
};

class NAsyncContextLegacy : public NapiAsyncContext {
public:
    NapiReference cbSucc_;
    NapiReference cbFail_;
    NapiReference cbFinal_;
    NAsyncContextLegacy(NapiValue thisPtr, NapiValue cbSucc, NapiValue cbFail, NapiValue cbFinal)
        : NapiAsyncContext(thisPtr), cbSucc_(cbSucc), cbFail_(cbFail), cbFinal_(cbFinal)
    {}
    ~NAsyncContextLegacy() override = default;
};
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // INTERFACES_KITS_JS_ZIP_NAPI_COMMON_NAPI_ASYNC_CONTEXT_H