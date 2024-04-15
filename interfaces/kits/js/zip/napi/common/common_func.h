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

#ifndef INTERFACES_KITS_JS_ZIP_NAPI_COMMON_COMMON_FUNC_H
#define INTERFACES_KITS_JS_ZIP_NAPI_COMMON_COMMON_FUNC_H

#include "napi_func_arg.h"
#include "napi_value.h"
#include "uv.h"
#include "zlib.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
struct CommonFunc {
    static bool SetZStreamValue(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, unsigned long, void *, size_t> GetAdler32Arg(napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, unsigned long, unsigned long, size_t> GetAdler32CombineArg(
        napi_env env, const NapiFuncArg &funcArg);
    static std::tuple<bool, uint64_t, void *, size_t> GetCrc64Arg(napi_env env, const NapiFuncArg &funcArg);
};
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // INTERFACES_KITS_JS_ZIP_NAPI_COMMON_COMMON_FUNC_H