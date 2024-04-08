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

#ifndef INTERFACES_KITS_JS_ZIP_NAPI_COMMON_BUSINESS_ERROR_H
#define INTERFACES_KITS_JS_ZIP_NAPI_COMMON_BUSINESS_ERROR_H

#include <string>
#include <unordered_map>

#include "header.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
constexpr int32_t ERRNO_NOERR = 0;
constexpr int32_t ZLIB_SYS_CAP_TAG = 17800000;
const std::string ZLIB_TAG_ERR_CODE = "code";
const std::string ZLIB_TAG_ERR_MSG = "message";

enum ELegacy {
    ELEGACY_INVAL = 202,
    ELEGACY_IO = 300,
    ELEGACY_NOENT = 301,
    ELEGACY_ARGUMENT = 400,
};

enum ErrCodeSystem {
    ERR_CODE_SYSTEM_LEGACY,
    ERR_CODE_SYSTEM_POSIX,
};

enum ErrCodeSuffix {
    E_PERM = 1,
    E_NOENT,
    E_SRCH,
    E_INTR,
    E_IO,
    E_NXIO,
    E_2BIG,
    E_BADF,
    E_MEMORY,
};

const std::unordered_map<int32_t, std::pair<int32_t, std::string>> errCodeTable{
    {EFAULT, {ZLIB_SYS_CAP_TAG + E_PERM, "Bad address"}},
    {EINVAL, {ELEGACY_ARGUMENT + E_PERM, "Invalid argument"}},
    {-1, {ZLIB_SYS_CAP_TAG + E_SRCH, "System error"}},
    {-2, {ZLIB_SYS_CAP_TAG + E_INTR, "ZStream error"}},
    {-3, {ZLIB_SYS_CAP_TAG + E_IO, "Data error"}},
    {-4, {ZLIB_SYS_CAP_TAG + E_NXIO, "Memory allocation failed"}},
    {-5, {ZLIB_SYS_CAP_TAG + E_2BIG, "Buffer error"}},
    {-6, {ZLIB_SYS_CAP_TAG + E_BADF, "Version error"}},
    {ENOSTR, {ZLIB_SYS_CAP_TAG + E_MEMORY, "Internal structure error"}}};

class NapiBusinessError {
public:
    NapiBusinessError();
    explicit NapiBusinessError(ELegacy eLegacy);
    explicit NapiBusinessError(int32_t ePosix);
    explicit NapiBusinessError(int32_t ePosix, bool throwCode);
    NapiBusinessError(const NapiBusinessError &) = default;
    ~NapiBusinessError() = default;

    NapiBusinessError &operator=(const NapiBusinessError &) = default;

    explicit operator bool() const;

    void SetErrno(ELegacy eLegacy);
    void SetErrno(int32_t ePosix);
    int32_t GetErrno(ErrCodeSystem cs);

    std::string GetDefaultErrstr();
    napi_value GetNapiErr(napi_env env);
    napi_value GetNapiErr(napi_env env, const std::string &errMsg);
    void ThrowErr(napi_env env);
    void ThrowErr(napi_env env, int32_t code);
    void ThrowErr(napi_env env, const std::string &errMsg);

private:
    int32_t errno_ = ERRNO_NOERR;
    ErrCodeSystem codingSystem_ = ERR_CODE_SYSTEM_POSIX;
    bool throwCode_ = false;
};
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // INTERFACES_KITS_JS_ZIP_NAPI_COMMON_BUSINESS_ERROR_H