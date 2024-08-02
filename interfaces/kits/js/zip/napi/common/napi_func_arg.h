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

#ifndef INTERFACES_KITS_JS_ZIP_NAPI_COMMON_NAPI_FUNC_ARG_H
#define INTERFACES_KITS_JS_ZIP_NAPI_COMMON_NAPI_FUNC_ARG_H

#include "header.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
enum ArgumentCount : uint8_t {
    ZERO = 0,
    ONE = 1,
    TWO = 2,
    THREE = 3,
    FOUR = 4,
    FIVE = 5,
    SIX = 6,
    SEVEN = 7,
};

enum ArgumentPosition : uint8_t {
    FIRST = 0,
    SECOND = 1,
    THIRD = 2,
    FOURTH = 3,
    FIFTH = 4,
    SIXTH = 5,
    SEVENTH = 6,
};

class NapiFuncArg final {
public:
    NapiFuncArg(napi_env env, napi_callback_info info);
    virtual ~NapiFuncArg();

    bool InitArgs(size_t argc);
    bool InitArgs(size_t minArgc, size_t maxArgc);

    size_t GetArgc() const;
    napi_value GetThisVar() const;

    napi_value operator[](size_t argPos) const;
    napi_value GetArg(size_t argPos) const;

private:
    napi_env env_ = nullptr;
    napi_callback_info info_ = nullptr;

    size_t argc_ = 0;
    std::unique_ptr<napi_value[]> argv_ = {nullptr};
    napi_value thisVar_ = nullptr;

    bool InitArgs(std::function<bool()> argcChecker);

    void SetArgc(size_t argc);
    void SetThisVar(napi_value thisVar);
};
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // INTERFACES_KITS_JS_ZIP_NAPI_COMMON_NAPI_FUNC_ARG_H