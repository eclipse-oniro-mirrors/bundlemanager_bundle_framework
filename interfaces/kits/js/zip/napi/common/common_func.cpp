/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "common_func.h"

#include <dirent.h>
#include <fcntl.h>
#include <memory>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include "app_log_wrapper.h"
#include "napi_class.h"
#include "napi_business_error.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
using namespace std;

tuple<bool, int64_t, void *, size_t> CommonFunc::GetAdler32Arg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    int64_t adler = 0U;

    // The first argument
    NapiValue adlerNVal(env, funcArg[ArgumentPosition::FIRST]);
    tie(succ, adler) = adlerNVal.ToInt64();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, nullptr, 0};
    }

    // The second argument
    NapiValue bufNVal(env, funcArg[ArgumentPosition::SECOND]);
    void *buf = nullptr;
    size_t bufLen = 0;
    tie(succ, buf, bufLen) = bufNVal.ToArrayBuffer();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, nullptr, 0};
    }

    return {true, adler, buf, bufLen};
}

tuple<bool, int64_t, void *, size_t> CommonFunc::GetCrc64Arg(napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    int64_t crc64 = 0U;

    // The first argument
    NapiValue crc64NVal(env, funcArg[ArgumentPosition::FIRST]);
    tie(succ, crc64) = crc64NVal.ToInt64();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, nullptr, 0};
    }

    // The second argument
    NapiValue bufNVal(env, funcArg[ArgumentPosition::SECOND]);
    void *buf = nullptr;
    size_t bufLen = 0;
    tie(succ, buf, bufLen) = bufNVal.ToArrayBuffer();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, nullptr, 0};
    }

    return {true, crc64, buf, bufLen};
}

tuple<bool, unsigned long, unsigned long, int64_t> CommonFunc::GetAdler32CombineArg(
    napi_env env, const NapiFuncArg &funcArg)
{
    bool succ = false;
    uint64_t adler1 = 0U;
    uint64_t adler2 = 0U;
    int64_t len = 0;

    NapiValue adler1NVal(env, funcArg[ArgumentPosition::FIRST]);
    tie(succ, adler1) = adler1NVal.ToInt64();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, 0, 0};
    }

    NapiValue adler2NVal(env, funcArg[ArgumentPosition::SECOND]);
    tie(succ, adler2) = adler2NVal.ToInt64();
    if (!succ) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, 0, 0};
    }

    NapiValue bufLenNVal(env, funcArg[ArgumentPosition::THIRD]);
    tie(succ, len) = bufLenNVal.ToInt64();
    if (!succ || len < 0) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return {false, 0, 0, 0};
    }
    return {true, adler1, adler2, len};
}
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS